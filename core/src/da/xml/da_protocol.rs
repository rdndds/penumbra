/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, error, info};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex;

use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::devinfo::DeviceInfo;
use crate::core::seccfg::LockFlag;
use crate::core::storage::{Partition, PartitionKind, Storage, StorageType, parse_gpt};
use crate::da::protocol::DAProtocol;
use crate::da::xml::cmds::{
    BootTo,
    HOST_CMDS,
    HostSupportedCommands,
    NotifyInitHw,
    XmlCmdLifetime,
};
use crate::da::xml::sec::{parse_seccfg, write_seccfg};
use crate::da::xml::{exts, flash, patch};
use crate::da::{DA, DAEntryRegion, Xml};
use crate::error::{Error, Result};
use crate::exploit::Exploit;
use crate::exploit::carbonara::Carbonara;

#[async_trait]
impl DAProtocol for Xml {
    async fn upload_da(&mut self) -> Result<bool> {
        let mutex_da = Arc::new(Mutex::new(self.da.clone()));

        let (da1addr, da1length, da1data, da1sig_len) = match self.da.get_da1() {
            Some(da1) => (da1.addr, da1.length, da1.data.clone(), da1.sig_len),
            None => return Err(Error::penumbra("DA1 region not found")),
        };

        self.upload_stage1(da1addr, da1length, da1data, da1sig_len)
            .await
            .map_err(|e| Error::proto(format!("Failed to upload XML DA1: {}", e)))?;

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

        info!("Uploading and booting to XML DA2...");
        self.boot_to(da2addr, &da2data)
            .await
            .map_err(|e| Error::proto(format!("Failed to upload and boot to XML DA2: {}", e)))?;

        // This might fail on some devices, but we can ignore the error
        xmlcmd_e!(self, HostSupportedCommands, HOST_CMDS).ok();

        xmlcmd!(self, NotifyInitHw)?;
        let mut mock_progress = |_, _| {};
        self.progress_report(&mut mock_progress).await?;
        self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

        info!("Successfully uploaded and booted to XML DA2");

        self.boot_extensions().await?;

        Ok(true)
    }

    async fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool> {
        xmlcmd!(self, BootTo, addr, addr, 0x0u64, data.len() as u64)?;

        let reader = BufReader::new(Cursor::new(data));
        let mut progress = |_, _| {};
        self.download_file(data.len(), reader, &mut progress).await?;

        self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;
        Ok(true)
    }

    async fn send(&mut self, data: &[u8]) -> Result<bool> {
        self.send_data(&[data]).await
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

        Ok(true)
    }

    /// We don't need it for XML DA
    async fn get_status(&mut self) -> Result<u32> {
        Ok(0)
    }

    async fn read_flash(
        &mut self,
        _addr: u64,
        _size: usize,
        _section: PartitionKind,
        _progress: &mut (dyn FnMut(usize, usize) + Send),
        _writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()> {
        todo!()
    }

    async fn write_flash(
        &mut self,
        _addr: u64,
        _size: usize,
        _reader: &mut (dyn AsyncRead + Unpin + Send),
        _section: PartitionKind,
        _progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        todo!()
    }

    async fn erase_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::erase_flash(self, addr, size, section, progress).await
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
        reader: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::upload(self, part_name, reader, progress).await
    }

    async fn format(
        &mut self,
        part_name: String,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::format(self, part_name, progress).await
    }

    async fn read32(&mut self, _addr: u32) -> Result<u32> {
        todo!()
    }

    async fn write32(&mut self, _addr: u32, _value: u32) -> Result<()> {
        todo!()
    }

    async fn get_usb_speed(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()> {
        self.conn.connection_type = conn_type;
        Ok(())
    }

    async fn get_storage(&mut self) -> Option<Arc<dyn Storage>> {
        self.get_or_detect_storage().await
    }

    async fn get_storage_type(&mut self) -> StorageType {
        self.get_or_detect_storage().await.map_or(StorageType::Unknown, |s| s.kind())
    }

    async fn get_partitions(&mut self) -> Vec<Partition> {
        let storage = match self.get_storage().await {
            Some(s) => s,
            None => {
                error!("[Penumbra] Failed to get storage for partition parsing");
                return Vec::new();
            }
        };

        let storage_type = storage.kind();
        let pl_part1 = storage.get_pl_part1();
        let pl_part2 = storage.get_pl_part2();
        let pl1_size = storage.get_pl1_size() as usize;
        let pl2_size = storage.get_pl2_size() as usize;

        let mut partitions = Vec::<Partition>::new();

        let preloader = Partition::new("preloader", pl1_size, 0, pl_part1);
        let preloader_backup = Partition::new("preloader_backup", pl2_size, 0, pl_part2);
        partitions.push(preloader);
        partitions.push(preloader_backup);

        let mut progress = |_, _| {};
        let mut pgpt_data = Vec::new();
        let mut cursor = Cursor::new(&mut pgpt_data);
        self.upload("PGPT".into(), &mut cursor, &mut progress).await.ok();

        let gpt_parts = parse_gpt(&pgpt_data, storage_type).unwrap_or_default();
        partitions.extend(gpt_parts);

        partitions
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
