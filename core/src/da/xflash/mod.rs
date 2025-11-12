/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
#[macro_use]
mod macros;
mod cmds;
mod exts;
pub mod flash;
mod storage;
use std::sync::Arc;

use log::{debug, error, info, warn};
use storage::detect_storage;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::devinfo::DeviceInfo;
use crate::core::storage::{PartitionKind, Storage, StorageType};
use crate::da::xflash::cmds::*;
use crate::da::xflash::exts::{boot_extensions, read32_ext, write32_ext};
use crate::da::{DA, DAProtocol};
use crate::error::{Error, Result, XFlashError};
use crate::exploit::Exploit;
use crate::exploit::carbonara::Carbonara;

pub struct XFlash {
    pub conn: Connection,
    pub da: DA,
    pub dev_info: DeviceInfo,
    using_exts: bool,
    read_packet_length: Option<usize>,
    write_packet_length: Option<usize>,
}

#[async_trait::async_trait]
impl DAProtocol for XFlash {
    async fn upload_da(&mut self) -> Result<bool> {
        let (da1addr, da1length, da1data, da1sig_len) = match self.da.get_da1() {
            Some(da1) => (da1.addr, da1.length, da1.data.clone(), da1.sig_len),
            None => return Err(Error::penumbra("DA1 region not found")),
        };

        self.upload_stage1(da1addr, da1length, da1data, da1sig_len)
            .await
            .map_err(|e| Error::proto(format!("Failed to upload DA1: {}", e)))?;

        // Let's get the packet length in DA1, so that we can have decent speeds
        flash::get_packet_length(self).await?;

        let da2 = match self.da.get_da2() {
            Some(da2) => da2.clone(),
            None => return Err(Error::penumbra("DA2 region not found")),
        };
        let da2addr = da2.addr;
        let da2sig_len = da2.sig_len as usize;

        let da2_original_data = da2.data[..da2.data.len().saturating_sub(da2sig_len)].to_vec();

        // TODO: Patch DA2 with Carbonara
        let carbonara_da = Arc::new(Mutex::new(self.da.clone()));
        let mut carbonara = Carbonara::new(carbonara_da);

        let da2data = match carbonara.run(self).await {
            Ok(_) => match carbonara.get_patched_da2() {
                Some(patched_da2) => patched_da2.data.clone(),
                None => da2_original_data,
            },
            Err(_) => da2_original_data,
        };

        match self.boot_to(da2addr, &da2data).await {
            Ok(true) => {
                info!("[Penumbra] Successfully uploaded and executed DA2");
                // Refetch packet lengths after DA2, since DA2 operates on higher speeds
                flash::get_packet_length(self).await?;
                self.boot_extensions().await?;
                Ok(true)
            }
            Ok(false) => return Err(Error::proto("Failed to execute DA2")),
            Err(e) => return Err(Error::proto(format!("Error uploading DA2: {}", e))),
        }
    }

    async fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool> {
        info!(
            "[Penumbra] Sending BOOT_TO command to address 0x{:08X} with 0x{:X} bytes",
            addr,
            data.len()
        );

        self.send_cmd(Cmd::BootTo).await?;

        // Addr (LE) | Length (LE)
        // 00000040000000002c83050000000000 -> addr=0x4000000, len=0x0005832c
        let mut param = Vec::new();
        param.extend_from_slice(&(addr as u64).to_le_bytes());
        param.extend_from_slice(&(data.len() as u64).to_le_bytes());

        self.send_data(&[&param, data]).await?;

        status_any!(self, 0, Cmd::SyncSignal as u32);

        info!("[Penumbra] Successfully booted to DA2");
        Ok(true)
    }

    async fn send_data(&mut self, data: &[&[u8]]) -> Result<bool> {
        let mut hdr: [u8; 12];

        for param in data {
            hdr = self.generate_header(param);

            self.conn.port.write_all(&hdr).await?;

            let mut pos = 0;
            let max_chunk_size = self.write_packet_length.unwrap_or(0x8000);

            while pos < param.len() {
                let end = param.len().min(pos + max_chunk_size);
                let chunk = &param[pos..end];
                debug!("[TX] Sending chunk (0x{:X} bytes)", chunk.len());
                self.conn.port.write_all(chunk).await?;
                pos = end;
            }

            debug!("[TX] Completed sending 0x{:X} bytes", param.len());
        }

        status_ok!(self);

        Ok(true)
    }

    async fn get_status(&mut self) -> Result<u32> {
        let mut hdr = [0u8; 12];
        match timeout(Duration::from_millis(3000), self.conn.port.read_exact(&mut hdr)).await {
            Ok(result) => result?,
            Err(_) => {
                debug!("Status timeout");
                return Err(Error::io("Status read timed out"));
            }
        };

        debug!("[RX] Status Header: {:02X?}", hdr);
        let len = self.parse_header(&hdr)?;

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;
        let status = match len {
            2 => u16::from_le_bytes(data[0..2].try_into().unwrap()) as u32,
            4 => {
                let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
                if val == Cmd::Magic as u32 { 0 } else { val }
            }
            _ if data.len() >= 4 => u32::from_le_bytes(data[0..4].try_into().unwrap()),
            _ if !data.is_empty() => data[0] as u32,
            _ => 0xFFFFFFFF,
        };

        debug!("[RX] Status: 0x{:08X}", status);
        match status {
            0 => Ok(status),
            sync if sync == Cmd::SyncSignal as u32 => Ok(status),
            _ => Err(Error::XFlash(XFlashError::from_code(status))),
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<bool> {
        self.send_data(&[data]).await
    }

    async fn read_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        flash::read_flash(self, addr, size, section, progress, writer).await
    }

    async fn write_flash(
        &mut self,
        addr: u64,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::write_flash(self, addr, size, reader, section, progress).await
    }

    async fn download(
        &mut self,
        part_name: String,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::download(self, part_name, size, reader, progress).await
    }

    async fn get_usb_speed(&mut self) -> Result<u32> {
        let usb_speed = self.devctrl(Cmd::GetUsbSpeed, None).await?;
        debug!("USB Speed Data: {:?}", usb_speed);
        Ok(u32::from_le_bytes(usb_speed[0..4].try_into().unwrap()))
    }

    fn get_connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()> {
        self.conn.connection_type = conn_type;
        Ok(())
    }

    async fn read32(&mut self, addr: u32) -> Result<u32> {
        if self.using_exts {
            return read32_ext(self, addr).await;
        }
        debug!("Reading 32-bit register at address 0x{:08X}", addr);
        let param = addr.to_le_bytes();
        let resp = self.devctrl(Cmd::DeviceCtrlReadRegister, Some(&[&param])).await?;
        debug!("[RX] Read Register Response: {:02X?}", resp);
        if resp.len() < 4 {
            debug!("Short read: expected 4 bytes, got {}", resp.len());
            return Err(Error::io("Short register read"));
        }
        Ok(u32::from_le_bytes(resp[0..4].try_into().unwrap()))
    }

    async fn write32(&mut self, addr: u32, value: u32) -> Result<()> {
        if self.using_exts {
            return write32_ext(self, addr, value).await;
        }
        let mut param = Vec::new();
        param.extend_from_slice(&addr.to_le_bytes());
        param.extend_from_slice(&value.to_le_bytes());
        debug!("[TX] Writing 32-bit value 0x{:08X} to address 0x{:08X}", value, addr);
        self.devctrl(Cmd::SetRegisterValue, Some(&[&param])).await?;
        Ok(())
    }

    async fn get_storage_type(&mut self) -> StorageType {
        self.get_or_detect_storage().await.map_or(StorageType::Unknown, |s| s.kind())
    }

    async fn get_storage(&mut self) -> Option<Arc<dyn Storage>> {
        self.get_or_detect_storage().await
    }
}

impl XFlash {
    async fn send_cmd(&mut self, cmd: Cmd) -> Result<bool> {
        let cmd_bytes = (cmd as u32).to_le_bytes();
        debug!("[TX] Sending Command: 0x{:08X}", cmd as u32);
        self.send(&cmd_bytes[..]).await
    }

    pub fn new(conn: Connection, da: DA, dev_info: DeviceInfo) -> Self {
        XFlash {
            conn,
            da,
            dev_info,
            using_exts: false,
            read_packet_length: None,
            write_packet_length: None,
        }
    }

    // Note: When called with multiple params, this function sends data only and does not read any
    // response. For that, call read_data separately and check status manually.
    // This is to accomodate the protocol, while also not breaking read_data for other operations.
    async fn devctrl(&mut self, cmd: Cmd, params: Option<&[&[u8]]>) -> Result<Vec<u8>> {
        self.send_cmd(Cmd::DeviceCtrl).await?;
        self.send_cmd(cmd).await?;

        if let Some(p) = params {
            self.send_data(p).await?;
            return Ok(Vec::new());
        }

        let read = self.read_data().await;
        status_ok!(self);

        read
    }

    // When called after calling a cmd that returns a status too,
    // call status_ok!() macro manually.
    // This function only reads the data, and cannot be used to read status,
    // or functions like read_flash will fail.
    async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 12];
        self.conn.port.read_exact(&mut hdr).await?;

        let len = self.parse_header(&hdr)?;

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;

        Ok(data)
    }

    async fn upload_stage1(
        &mut self,
        addr: u32,
        length: u32,
        data: Vec<u8>,
        sig_len: u32,
    ) -> Result<bool> {
        info!(
            "[Penumbra] Uploading DA1 region to address 0x{:08X} with length 0x{:X}",
            addr, length
        );

        self.conn.send_da(&data, length, addr, sig_len).await?;
        info!("[Penumbra] Sent DA1, jumping to address 0x{:08X}...", addr);
        self.conn.jump_da(addr).await?;

        let sync_byte = {
            let mut sync_buf = [0u8; 1];
            match self.conn.port.read_exact(&mut sync_buf).await {
                Ok(_) => sync_buf[0],
                Err(e) => return Err(Error::io(e.to_string())),
            }
        };

        info!("[Penumbra] Received sync byte");

        if sync_byte != 0xC0 {
            return Err(Error::proto("Incorrect sync byte received"));
        }

        let hdr = self.generate_header(&[0u8; 4]);
        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SyncSignal as u32).to_le_bytes()).await?;

        let mut env_param = Vec::new();
        env_param.extend_from_slice(&2u32.to_le_bytes()); // da_log_level = 2 (UART)
        env_param.extend_from_slice(&1u32.to_le_bytes()); // log_channel = 1
        env_param.extend_from_slice(&1u32.to_le_bytes()); // system_os = 1 (OS_LINUX)
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ufs_provision = 0
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ...

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SetupEnvironment as u32).to_le_bytes()).await?;
        self.send(&env_param).await?;

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SetupHwInitParams as u32).to_le_bytes()).await?;
        let hw_param = [0x00, 0x00, 0x00, 0x00];
        self.send(&hw_param).await?;

        status_any!(self, Cmd::SyncSignal as u32);

        info!("[Penumbra] Received DA1 sync signal.");
        Ok(true)
    }

    async fn boot_extensions(&mut self) -> Result<bool> {
        if self.using_exts {
            warn!("DA extensions already in use, skipping re-upload");
            return Ok(true);
        }
        info!("Booting DA extensions...");
        self.using_exts = boot_extensions(self).await?;
        Ok(true)
    }

    // This is an internal helper, do not use it directly
    async fn get_or_detect_storage(&mut self) -> Option<Arc<dyn Storage>> {
        if let Some(storage) = self.dev_info.storage().await {
            return Some(storage);
        }

        if let Some(storage) = detect_storage(self).await {
            self.dev_info.set_storage(storage.clone()).await;
            return Some(storage);
        }

        None
    }

    fn generate_header(&self, data: &[u8]) -> [u8; 12] {
        let mut hdr = [0u8; 12];

        // efeeeefe | 010000000 | 04000000 (Data Length)
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!("[TX] Data Header: {:02X?}, Data Length: {}", hdr, data.len());

        hdr
    }

    fn parse_header(&self, hdr: &[u8; 12]) -> Result<u32> {
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

        if magic != Cmd::Magic as u32 {
            return Err(Error::io("Invalid magic"));
        }

        debug!("[RX] Data Length from Header: 0x{:X}", len);

        Ok(len)
    }
}
