/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::debug;

use crate::core::storage::Storage;
use crate::core::storage::emmc::EmmcStorage;
use crate::core::storage::ufs::UfsStorage;
use crate::da::DAProtocol;
use crate::da::xflash::{Cmd, XFlash};

// TODO: Avoid repeated logic
pub async fn detect_storage(xflash: &mut XFlash) -> Option<Arc<dyn Storage>> {
    let emmc_response = xflash.devctrl(Cmd::GetEmmcInfo, None).await;
    let _ = xflash.get_status().await;
    let ufs_response = xflash.devctrl(Cmd::GetUfsInfo, None).await;
    let _ = xflash.get_status().await;

    if let Ok(resp) = emmc_response
        && !resp.iter().all(|&b| b == 0) {
            debug!("eMMC storage detected.");
            if let Ok(storage) = EmmcStorage::from_response(&resp) {
                return Some(Arc::new(storage));
            }
        }

    if let Ok(resp) = ufs_response
        && !resp.iter().all(|&b| b == 0) {
            debug!("UFS storage detected.");
            if let Ok(storage) = UfsStorage::from_response(&resp) {
                return Some(Arc::new(storage));
            }
        }

    None
}
