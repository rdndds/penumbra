/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::connection::Connection;
use crate::core::auth::{AuthManager, SignData, SignPurpose, SignRequest};
use crate::core::devinfo::DeviceInfo;
use crate::core::emi::extract_emi_settings;
use crate::core::storage::Storage;
use crate::da::xflash::cmds::*;
#[cfg(not(feature = "no_exploits"))]
use crate::da::xflash::exts::boot_extensions;
use crate::da::xflash::storage::detect_storage;
use crate::da::{DA, DAProtocol};
use crate::error::{Error, Result, XFlashError};
use crate::le_u32;

pub struct XFlash {
    pub conn: Connection,
    pub da: DA,
    pub pl: Option<Vec<u8>>,
    pub dev_info: DeviceInfo,
    pub(super) using_exts: bool,
    pub(super) read_packet_length: Option<usize>,
    pub(super) write_packet_length: Option<usize>,
    pub(super) patch: bool,
    pub(super) verbose: bool,
}

impl XFlash {
    pub async fn send_cmd(&mut self, cmd: Cmd) -> Result<bool> {
        let cmd_bytes = (cmd as u32).to_le_bytes();
        debug!("[TX] Sending Command: 0x{:08X}", cmd as u32);
        self.send(&cmd_bytes[..]).await
    }

    pub fn new(
        conn: Connection,
        da: DA,
        dev_info: DeviceInfo,
        pl: Option<Vec<u8>>,
        verbose: bool,
    ) -> Self {
        XFlash {
            conn,
            da,
            pl,
            dev_info,
            using_exts: false,
            read_packet_length: None,
            write_packet_length: None,
            patch: true,
            verbose,
        }
    }

    // Note: When called with multiple params, this function sends data only and does not read any
    // response. For that, call read_data separately and check status manually.
    // This is to accomodate the protocol, while also not breaking read_data for other operations.
    pub async fn devctrl(&mut self, cmd: Cmd, params: Option<&[&[u8]]>) -> Result<Vec<u8>> {
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
    pub async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 12];
        self.conn.read(&mut hdr).await?;

        let len = self.parse_header(&hdr)?;

        let mut data = vec![0u8; len as usize];
        self.conn.read(&mut data).await?;

        Ok(data)
    }

    pub(super) async fn upload_stage1(
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
            match self.conn.read(&mut sync_buf).await {
                Ok(_) => sync_buf[0],
                Err(e) => return Err(Error::io(e.to_string())),
            }
        };

        info!("[Penumbra] Received sync byte");

        if sync_byte != 0xC0 {
            return Err(Error::proto("Incorrect sync byte received"));
        }

        let hdr = self.generate_header(&[0u8; 4]);
        self.conn.write(&hdr).await?;
        self.conn.write(&(Cmd::SyncSignal as u32).to_le_bytes()).await?;

        // We can only set the environment parameters once, and for whatever reason if we set the
        // log level to DEBUG and try to send EMI settings in BROM mode, the DA hangs. This
        // appears to be a MediaTek quirk as usual. As a workaround, we always use INFO
        // level when in BROM mode, even if verbose logging is requested.
        let da_log_level: u32 = if self.verbose
            && self.conn.connection_type != crate::connection::port::ConnectionType::Brom
        {
            1 // DEBUG
        } else {
            2 // INFO
        };

        let env_params: [u32; 5] = [
            da_log_level, // da_log_level
            1,            // log_channel = UART
            1,            // system_os = OS_LINUX
            0,            // ufs_provision
            0,            // reserved
        ];
        let mut env_buf = [0u8; 20];
        for (i, v) in env_params.iter().enumerate() {
            env_buf[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }

        self.send_data(&[&(Cmd::SetupEnvironment as u32).to_le_bytes(), &env_buf]).await?;

        self.send_data(&[&(Cmd::SetupHwInitParams as u32).to_le_bytes(), &[0u8; 4]]).await?;

        status_any!(self, Cmd::SyncSignal as u32);

        info!("[Penumbra] Received DA1 sync signal.");

        self.handle_emi().await?;
        self.devctrl(Cmd::SetChecksumLevel, Some(&[&0u32.to_le_bytes()])).await?;

        Ok(true)
    }

    #[cfg(not(feature = "no_exploits"))]
    pub(super) async fn boot_extensions(&mut self) -> Result<bool> {
        if self.using_exts {
            warn!("DA extensions already in use, skipping re-upload");
            return Ok(true);
        }
        info!("Booting DA extensions...");
        self.using_exts = boot_extensions(self).await?;
        Ok(true)
    }

    // This is an internal helper, do not use it directly
    pub(super) async fn get_or_detect_storage(&mut self) -> Option<Arc<dyn Storage>> {
        if let Some(storage) = self.dev_info.storage().await {
            return Some(storage);
        }

        if let Some(storage) = detect_storage(self).await {
            self.dev_info.set_storage(storage.clone()).await;
            return Some(storage);
        }

        None
    }

    /// Receives data from the device, writing it to the provided writer.
    /// Common loop for `read_flash` and `upload`.
    pub async fn upload_data(
        &mut self,
        size: usize,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        let mut bytes_read = 0;
        progress(0, size);
        loop {
            let chunk = self.read_data().await?;
            if chunk.is_empty() {
                debug!("No data received, breaking.");
                break;
            }

            writer.write_all(&chunk).await?;
            bytes_read += chunk.len();

            self.send(&[0u8; 4]).await?;

            progress(bytes_read, size);

            if bytes_read >= size {
                debug!("Requested size read. Breaking.");
                break;
            }

            debug!("Read {:X}/{:X} bytes...", bytes_read, size);
        }

        Ok(())
    }

    /// Sends data to the device from the provided reader.
    /// Common loop for `write_flash` and `download`.
    ///
    /// If we receive less data than requested from the reader,
    /// we pad the remaining bytes with 0s and send it anyway.
    pub async fn download_data(
        &mut self,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        let chunk_size = self.write_packet_length.unwrap_or(0x8000);
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0;

        progress(0, size);
        loop {
            if bytes_written >= size {
                break;
            }

            // It is mandatory to make data size the same as size, or we will be leaving
            // older data in the partition. Usually, this is not an issue for partitions
            // with an header, like LK (which stores the start and length of the lk image),
            // but for other partitions, this might make the partition unusable.
            // This issue only arises when flashing stuff that is not coming from a dump made
            // with read_flash() or any other tool like mtkclient.
            let remaining = size - bytes_written;
            let to_read = remaining.min(chunk_size);

            let bytes_read = reader.read(&mut buffer[..to_read]).await?;
            let chunk = if bytes_read == 0 {
                &buffer[..to_read]
            } else if bytes_read < to_read {
                buffer[bytes_read..to_read].fill(0);
                &buffer[..to_read]
            } else {
                &buffer[..to_read]
            };

            // DA expects a checksum of the data chunk before the actual data
            // The actual checksum is a additive 16-bit checksum (Good job MTK!!)
            // For whoever is reading this code and has no clue what this is doing:
            // Just sum all bytes then AND with 0xFFFF :D!!!
            let checksum = chunk.iter().fold(0u32, |total, &byte| total + byte as u32) & 0xFFFF;
            self.send_data(&[&0u32.to_le_bytes(), &checksum.to_le_bytes(), chunk]).await?;

            bytes_written += chunk.len();
            progress(bytes_written, size);
            debug!("Written {}/{} bytes...", bytes_written, size);
        }

        status_ok!(self);

        Ok(())
    }

    pub async fn progress_report(
        &mut self,
        size: usize,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        progress(0, size);
        loop {
            let status = self.read_data().await?;
            if le_u32!(status, 0) == 0x40040005 {
                progress(size, size);
                break;
            }

            let status = self.read_data().await?;
            let progress_percent = le_u32!(status, 0);

            // The device doesn't send statuses during erase/format, so we have to send
            // an acknowledgment manually through the port and not through send()
            let ack = [0u8; 4];
            let hdr = self.generate_header(&ack);
            self.conn.write(&hdr).await?;
            self.conn.write(&ack).await?;

            let progress_bytes = (progress_percent as usize * size) / 100;
            progress(progress_bytes, size);
        }

        Ok(())
    }

    pub(super) fn generate_header(&self, data: &[u8]) -> [u8; 12] {
        let mut hdr = [0u8; 12];

        // efeeeefe | 010000000 | 04000000 (Data Length)
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!("[TX] Data Header: {:02X?}, Data Length: {}", hdr, data.len());

        hdr
    }

    pub(super) fn parse_header(&self, hdr: &[u8; 12]) -> Result<u32> {
        let magic = le_u32!(hdr, 0);
        let len = le_u32!(hdr, 8);

        if magic != Cmd::Magic as u32 {
            return Err(Error::io("Invalid magic"));
        }

        debug!("[RX] Data Length from Header: 0x{:X}", len);

        Ok(len)
    }

    async fn handle_emi(&mut self) -> Result<()> {
        let conn_agent = self.devctrl(Cmd::GetConnectionAgent, None).await?;

        // If the connection agent is "preloader", there's no need to upload EMI settings
        if conn_agent == b"preloader" {
            return Ok(());
        }

        let pl = self
            .pl
            .as_ref()
            .ok_or_else(|| Error::penumbra("Device is in BROM but no preloader was provided!"))?;

        let emi = extract_emi_settings(pl)
            .ok_or_else(|| Error::penumbra("Failed to extract EMI settings from preloader!"))?;

        info!("[Penumbra] Uploading EMI settings to device...");
        self.send_cmd(Cmd::InitExtRam).await?;
        self.send_data(&[&(emi.len() as u32).to_le_bytes(), emi.as_slice()]).await?;
        info!("[Penumbra] EMI settings uploaded successfully.");

        Ok(())
    }

    pub(super) async fn handle_sla(&mut self) -> Result<bool> {
        let resp = match self.devctrl(Cmd::SlaEnabledStatus, None).await {
            Ok(r) => r,
            Err(_) => {
                // The CMD might not be supported on some devices, so we just assume SLA is disabled
                return Ok(true);
            }
        };

        let sla_enabled = le_u32!(resp, 0) != 0;

        if !sla_enabled {
            return Ok(true);
        }

        info!("DA SLA is enabled");

        let da2_data = match self.da.get_da2() {
            Some(da2) => da2.data.clone(),
            None => Vec::new(),
        };

        let auth = AuthManager::get();
        if !auth.can_sign(&da2_data) {
            #[cfg(not(feature = "no_exploits"))]
            {
                info!("No available signers for DA SLA, trying dummy signature...");
                let dummy_sig = vec![0u8; 256];
                if self.devctrl(Cmd::SetRemoteSecPolicy, Some(&[&dummy_sig])).await.is_ok() {
                    info!("DA SLA signature accepted (dummy)!");
                    return Ok(true);
                }
            }

            error!("No signer available for DA SLA! Can't proceed.");
            return Err(Error::penumbra(
                "DA SLA is enabled, but no signer is available. Can't continue.",
            ));
        }

        let firmware_info = self.devctrl(Cmd::GetDevFwInfo, None).await?;
        debug!("Firmware Info: {:02X?}", firmware_info);
        let rnd = &firmware_info[4..4 + 0x10];
        let hrid = &firmware_info[4 + 0x10..4 + 0x10 + 16];
        let soc_id = &firmware_info[4 + 0x10 + 16..4 + 0x10 + 16 + 32];

        let sign_data = SignData {
            rnd: rnd.to_vec(),
            hrid: hrid.to_vec(),
            soc_id: soc_id.to_vec(),
            raw: firmware_info.to_vec(),
        };
        let sign_req =
            SignRequest { data: sign_data, purpose: SignPurpose::DaSla, pubk_mod: da2_data };

        info!("Found signer for DA SLA!");
        let signed_rnd = auth.sign(&sign_req).await?;
        info!("Signed DA SLA challenge. Uploading to device...");
        self.devctrl(Cmd::SetRemoteSecPolicy, Some(&[&signed_rnd])).await?;
        info!("DA SLA signature accepted!");
        Ok(true)
    }
}
