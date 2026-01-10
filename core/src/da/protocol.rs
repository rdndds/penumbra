/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use downcast_rs::{DowncastSend, impl_downcast};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::devinfo::DeviceInfo;
use crate::core::seccfg::LockFlag;
use crate::core::storage::{Partition, PartitionKind, Storage, StorageType};
use crate::da::{DA, DAEntryRegion};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Normal,
    HomeScreen,
    Fastboot,
    Test,
    Meta,
}

impl BootMode {
    pub fn to_text(&self) -> Option<&'static str> {
        match self {
            BootMode::Fastboot => Some("FASTBOOT"),
            BootMode::Meta => Some("META"),
            BootMode::Test => Some("ANDROID-TEST-MODE"),
            BootMode::Normal | BootMode::HomeScreen => None,
        }
    }
}

#[async_trait::async_trait]
pub trait DAProtocol: DowncastSend {
    // Main helpers
    async fn upload_da(&mut self) -> Result<bool>;
    async fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool>;
    async fn send(&mut self, data: &[u8]) -> Result<bool>;
    async fn send_data(&mut self, data: &[&[u8]]) -> Result<bool>;
    async fn get_status(&mut self) -> Result<u32>;
    async fn shutdown(&mut self) -> Result<()>;
    async fn reboot(&mut self, bootmode: BootMode) -> Result<()>;
    // FLASH operations
    // fn read_partition(&mut self, name: &str) -> Result<Vec<u8>, Error>;
    async fn read_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()>;

    async fn write_flash(
        &mut self,
        addr: u64,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn erase_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn download(
        &mut self,
        part_name: String,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn upload(
        &mut self,
        part_name: String,
        reader: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn format(
        &mut self,
        part_name: String,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    // Memory
    async fn read32(&mut self, addr: u32) -> Result<u32>;
    async fn write32(&mut self, addr: u32, value: u32) -> Result<()>;

    #[cfg(not(feature = "no_exploits"))]
    async fn peek(
        &mut self,
        addr: u32,
        length: usize,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn get_usb_speed(&mut self) -> Result<u32>;
    // fn set_usb_speed(&mut self, speed: u32) -> Result<(), Error>;

    // Connection
    fn get_connection(&mut self) -> &mut Connection;
    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()>;

    async fn get_storage(&mut self) -> Option<Arc<dyn Storage>>;
    async fn get_storage_type(&mut self) -> StorageType;
    async fn get_partitions(&mut self) -> Vec<Partition>;

    // Sec
    #[cfg(not(feature = "no_exploits"))]
    async fn set_seccfg_lock_state(&mut self, locked: LockFlag) -> Option<Vec<u8>>;

    // DA Patching utils. These *must* be protocol specific, as different protocols
    // have different DA implementations
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da(&mut self) -> Option<DA>;
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da1(&mut self) -> Option<DAEntryRegion>;
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da2(&mut self) -> Option<DAEntryRegion>;

    // DevInfo helpers
    fn get_devinfo(&self) -> &DeviceInfo;
}

impl_downcast!(DAProtocol);
