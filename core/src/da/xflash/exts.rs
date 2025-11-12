/*
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy

    Derived from:
    https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/DA/xflash/extension/xflash.py
    Original SPDX-License-Identifier: GPL-3.0-or-later
    Original SPDX-FileCopyrightText: 2018–2024 bkerler

    This file remains under the GPL-3.0-or-later license.
    However, as part of a larger project licensed under the AGPL-3.0-or-later,
    the combined work is subject to the networking terms of the AGPL-3.0-or-later,
    as for term 13 of the GPL-3.0-or-later license.
*/
use log::{debug, info};

use crate::da::DAProtocol;
use crate::da::xflash::{Cmd, XFlash};
use crate::error::{Error, Result};
use crate::extract_ptr;
use crate::utilities::patching::{HEX_NOT_FOUND, find_pattern, patch_ptr};

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_x.bin");

pub async fn boot_extensions(xflash: &mut XFlash) -> Result<bool> {
    debug!("Trying booting XFlash extensions...");

    let ext_data = match prepare_extensions(xflash) {
        Some(data) => data,
        None => {
            debug!("Failed to prepare DA extensions");
            return Ok(false);
        }
    };

    let ext_addr = 0x68000000;
    let ext_size = ext_data.len() as u32;

    info!("Uploading DA extensions to {:08X} ({} bytes)", ext_addr, ext_size);
    match xflash.boot_to(ext_addr, &ext_data).await {
        Ok(_) => {}
        // If DA extensions fail to upload, we just return false, not a fatal error
        Err(_) => {
            return Ok(false);
        }
    }
    info!("DA extensions uploaded");

    let ack = xflash.devctrl(Cmd::ExtAck, None).await?;

    // Ack must be 0xA1A2A3A4
    if ack.len() < 4 || ack[0..4] != [0xA4, 0xA3, 0xA2, 0xA1] {
        return Err(Error::proto("DA extensions failed to start (invalid ACK)"));
    } else {
        info!("Received ack: {:02X?}", &ack[0..4]);
    }

    Ok(true)
}

fn prepare_extensions(xflash: &XFlash) -> Option<Vec<u8>> {
    let da2 = &xflash.da.get_da2()?.data;
    let da2address = xflash.da.get_da2()?.addr;

    let mut da_ext_data = DA_EXT.to_vec();

    // This allows to register DA Extensions custom commands (0x0F000X)
    let register_devctrl = find_pattern(da2, "38B505460C20", 0);
    if register_devctrl == HEX_NOT_FOUND {
        return None;
    }

    let mmc_get_card = {
        let pos = find_pattern(da2, "4B4FF43C72", 0);
        if pos != HEX_NOT_FOUND {
            pos.saturating_sub(1)
        } else {
            let pos = find_pattern(da2, "A3EB0013181A02EB0010", 0);
            if pos != HEX_NOT_FOUND {
                pos.saturating_sub(10)
            } else {
                return None;
            }
        }
    };

    let mut mmc_set_part_config = HEX_NOT_FOUND;
    let mut search_offset = 0;

    while search_offset < da2.len() {
        let pos = find_pattern(da2, "C3690A4610B5", search_offset);
        if pos == HEX_NOT_FOUND {
            break;
        }

        if pos + 22 <= da2.len() && da2[pos + 20] == 0xB3 && da2[pos + 21] == 0x21 {
            mmc_set_part_config = pos;
            break;
        }

        search_offset = pos + 1;
    }

    if mmc_set_part_config == HEX_NOT_FOUND {
        mmc_set_part_config = find_pattern(da2, "C36913F00103", 0);
    }

    let mut mmc_rpmb_send_command = find_pattern(da2, "F8B506469DF81850", 0);
    if mmc_rpmb_send_command == HEX_NOT_FOUND {
        mmc_rpmb_send_command = find_pattern(da2, "2DE9F0414FF6FD74", 0);
    }

    let ufs_patterns =
        [("20460BB0BDE8F08300BF", 10), ("20460DB0BDE8F083", 8), ("214602F002FB1BE600BF", 18)];

    let mut g_ufs_hba = 0;

    for (pattern, offset) in ufs_patterns {
        let pos = find_pattern(da2, pattern, 0);
        if pos != HEX_NOT_FOUND && pos + offset + 4 <= da2.len() {
            g_ufs_hba = extract_ptr!(u32, da2, pos + offset);
            break;
        }
    }

    let has_ufs = g_ufs_hba != 0;

    let ufs_tag_pos = if has_ufs { find_pattern(da2, "B52EB190F8", 0) } else { HEX_NOT_FOUND };

    let ufs_queue_pos = if has_ufs { find_pattern(da2, "2DE9F8430127", 0) } else { HEX_NOT_FOUND };

    // Actual patching starts here
    let register_ptr = find_pattern(&da_ext_data, "11111111", 0);
    let mmc_get_card_ptr = find_pattern(&da_ext_data, "22222222", 0);
    let mmc_set_part_config_ptr = find_pattern(&da_ext_data, "33333333", 0);
    let mmc_rpmb_send_command_ptr = find_pattern(&da_ext_data, "44444444", 0);
    let ufshcd_queuecommand_ptr = find_pattern(&da_ext_data, "55555555", 0);
    let ufshcd_get_free_tag_ptr = find_pattern(&da_ext_data, "66666666", 0);
    let ptr_g_ufs_hba_ptr = find_pattern(&da_ext_data, "77777777", 0);
    // let efuse_addr_ptr = find_pattern(&da_ext_data, "88888888", 0);

    let patches = [
        (register_ptr, register_devctrl),
        (mmc_get_card_ptr, mmc_get_card),
        (mmc_set_part_config_ptr, mmc_set_part_config),
        (mmc_rpmb_send_command_ptr, mmc_rpmb_send_command),
        (ufshcd_queuecommand_ptr, ufs_queue_pos),
        (ufshcd_get_free_tag_ptr, ufs_tag_pos),
        (ptr_g_ufs_hba_ptr, g_ufs_hba as usize),
    ];

    for (offset, value) in patches {
        if offset != HEX_NOT_FOUND && value != HEX_NOT_FOUND {
            patch_ptr(&mut da_ext_data, offset, value as u32, da2address, true);
        }
    }

    Some(da_ext_data)
}

pub async fn read32_ext(xflash: &mut XFlash, addr: u32) -> Result<u32> {
    xflash.devctrl(Cmd::ExtReadRegister, Some(&[&addr.to_le_bytes()])).await?;

    let payload = xflash.read_data().await?;
    status_ok!(xflash);

    Ok(u32::from_le_bytes(payload[0..4].try_into().unwrap()))
}

pub async fn write32_ext(xflash: &mut XFlash, addr: u32, value: u32) -> Result<()> {
    let addr_bytes = addr.to_le_bytes();
    let value_bytes = value.to_le_bytes();

    xflash.devctrl(Cmd::ExtWriteRegister, Some(&[&addr_bytes, &value_bytes])).await?;

    Ok(())
}
