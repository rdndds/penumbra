/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::debug;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::core::storage::Storage;
use crate::core::storage::emmc::EmmcStorage;
use crate::core::storage::ufs::UfsStorage;
use crate::da::xml::Xml;
use crate::da::xml::cmds::{GetHwInfo, XmlCmdLifetime};
use crate::utilities::xml::get_tag;

pub async fn detect_storage(xml: &mut Xml) -> Option<Arc<dyn Storage>> {
    xmlcmd!(xml, GetHwInfo, "0").ok();

    // TODO: Make a macro for this pattern
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    let mut progress = |_, _| {};
    xml.upload_file(&mut writer, &mut progress).await.ok()?;
    writer.flush().await.ok()?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await.ok()?;

    let xml_str = String::from_utf8_lossy(&buffer);
    let storage_str: String = get_tag(&xml_str, "storage").ok()?;

    match storage_str.as_str() {
        "EMMC" => {
            debug!("eMMC storage detected.");
            if let Ok(storage) = EmmcStorage::from_xml_response(&xml_str) {
                return Some(Arc::new(storage));
            }
        }
        "UFS" => {
            debug!("UFS storage detected.");
            if let Ok(storage) = UfsStorage::from_xml_response(&xml_str) {
                return Some(Arc::new(storage));
            }
        }
        _ => {}
    }

    None
}
