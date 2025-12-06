/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::Cursor;
use std::sync::Arc;

use log::{debug, error, info};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::devinfo::DeviceInfo;
use crate::core::seccfg::LockFlag;
use crate::core::storage::{Partition, PartitionKind, Storage, StorageType, parse_gpt};
use crate::da::xflash::cmds::*;
use crate::da::xflash::exts::{read32_ext, write32_ext};
use crate::da::xflash::sec::{parse_seccfg, write_seccfg};
use crate::da::xflash::{flash, patch};
use crate::da::{DA, DAEntryRegion, DAProtocol, XFlash};
use crate::error::{Error, Result, XFlashError};
use crate::exploit::Exploit;
use crate::exploit::carbonara::Carbonara;
use crate::exploit::kamakiri::Kamakiri2;

#[async_trait::async_trait]
impl DAProtocol for XFlash {
    async fn upload_da(&mut self) -> Result<bool> {
        // TODO: Clean up this function
        let mutex_da = Arc::new(Mutex::new(self.da.clone()));
        if self.patch {
            // Try Kamakiri
            let mut kamakiri = Kamakiri2::new(mutex_da.clone());
            if let Ok(result) = kamakiri.run(self).await {
                self.patch = !result;
            }
        }

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

        let da2data = if self.patch {
            let mut carbonara = Carbonara::new(mutex_da.clone());

            match carbonara.run(self).await {
                Ok(_) => match carbonara.get_patched_da2() {
                    Some(patched_da2) => patched_da2.data.clone(),
                    None => da2_original_data,
                },
                Err(_) => da2_original_data,
            }
        } else {
            da2_original_data
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

    async fn upload(
        &mut self,
        part_name: String,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::upload(self, part_name, writer, progress).await
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

    async fn get_partitions(&mut self) -> Vec<Partition> {
        let storage_type = self.get_storage_type().await;

        let mut progress = |_, _| {};
        let mut pgpt_data = Vec::new();
        let mut cursor = Cursor::new(&mut pgpt_data);
        self.upload("PGPT".into(), &mut cursor, &mut progress).await.ok();
        self.send(&[0u8; 4]).await.ok();

        parse_gpt(&pgpt_data, storage_type).unwrap_or_default()
    }

    async fn set_seccfg_lock_state(&mut self, locked: LockFlag) -> Option<Vec<u8>> {
        let seccfg = parse_seccfg(self).await;
        if seccfg.is_none() {
            error!("[Penumbra] Failed to parse seccfg, cannot set lock state");
            return None;
        }

        let mut seccfg = seccfg.unwrap();
        seccfg.set_lock_state(locked);
        write_seccfg(self, &mut seccfg).await
    }

    fn patch_da(&mut self) -> Option<DA> {
        patch::patch_da(self).ok()
    }

    fn patch_da1(&mut self) -> Option<DAEntryRegion> {
        patch::patch_da1(self).ok()
    }

    fn patch_da2(&mut self) -> Option<DAEntryRegion> {
        patch::patch_da2(self).ok()
    }

    fn get_devinfo(&self) -> &DeviceInfo {
        &self.dev_info
    }
}
