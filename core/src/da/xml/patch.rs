/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use log::{info, warn};

use crate::da::{DA, DAEntryRegion, Xml};
use crate::error::Result;
use crate::exploit::get_v6_payload;
use crate::utilities::analysis::{Aarch64Analyzer, ArchAnalyzer, ArmAnalyzer};
use crate::utilities::arm::{encode_bl_arm, force_return as arm_force_return};
use crate::utilities::arm64::{encode_bl as arm64_encode_bl, force_return as arm64_force_return};
use crate::utilities::patching::*;

const SEJ_BASE_PATTERN_ARM64: &str = "0801XX52XX00805208XXXX72";
const SEJ_BASE_PATTERN_ARM64_ALT: &str = "0901XX52XX031faa09XXXX72";
const SEJ_BASE_PATTERN_ARM: &str = "0800XXE30210A0E3XXXX41E3";
const EXTLOADER: &[u8] = include_bytes!("../../../payloads/extloader_v6.bin");

pub fn is_arm64(data: &[u8]) -> bool {
    data.len() > 4 && data[0..4] == [0xC6, 0x01, 0x00, 0x58]
}

fn read_le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

pub fn find_sej_base(data: &[u8]) -> u32 {
    let sej_base = 0x1000A000;

    let is_arm64 = is_arm64(data);
    let offset = if is_arm64 {
        let off = find_pattern(data, SEJ_BASE_PATTERN_ARM64, 0);
        if off == HEX_NOT_FOUND { find_pattern(data, SEJ_BASE_PATTERN_ARM64_ALT, 0) } else { off }
    } else {
        find_pattern(data, SEJ_BASE_PATTERN_ARM, 0)
    };

    if offset != HEX_NOT_FOUND {
        if is_arm64 {
            let mov = read_le32(data, offset);
            let movk = read_le32(data, offset + 8);

            let low = (mov >> 5) & 0xFFFF;
            let high = (movk >> 5) & 0xFFFF;

            let sej_base = ((high << 16) | low) & 0xFFFFF000;
            return sej_base;
        } else {
            let movw = read_le32(data, offset);
            let movt = read_le32(data, offset + 8);

            let low = (((movw >> 16) & 0xF) << 12) | (movw & 0xFFF);
            let high = (((movt >> 16) & 0xF) << 12) | (movt & 0xFFF);

            let sej_base = ((high << 16) | low) & 0xFFFFF000;
            return sej_base;
        }
    }

    warn!("Could not find SEJ base! Defaulting to 0x{:08X}", sej_base);
    sej_base
}

pub fn patch_da(_xml: &mut Xml) -> Result<DA> {
    todo!()
}

pub fn patch_da1(_xml: &mut Xml) -> Result<DAEntryRegion> {
    todo!()
}

pub fn patch_da2(xml: &mut Xml) -> Result<DAEntryRegion> {
    let mut da2 = xml.da.get_da2().cloned().unwrap();

    let is_arm64 = is_arm64(&da2.data);
    let analyzer: Box<dyn ArchAnalyzer> = if is_arm64 {
        Box::new(Aarch64Analyzer::new(da2.data.clone(), da2.addr as u64))
    } else {
        Box::new(ArmAnalyzer::new(da2.data.clone(), da2.addr as u64))
    };

    patch_security(&mut da2, analyzer.as_ref(), is_arm64)?;
    patch_boot_to(&mut da2, analyzer.as_ref(), is_arm64)?;

    Ok(da2)
}

pub fn patch_boot_to(
    da: &mut DAEntryRegion,
    analyzer: &dyn ArchAnalyzer,
    is_arm64: bool,
) -> Result<bool> {
    if find_pattern(&da.data, "434D443A424F4F542D544F00", 0) != HEX_NOT_FOUND {
        return Ok(true);
    }

    let mut extloader = get_v6_payload(EXTLOADER, is_arm64).to_vec();

    let download_function_off = analyzer.find_function_from_string("Download host file:%s");

    if download_function_off.is_none() {
        warn!("Could not find download function to patch Ext-Loader!");
        return Ok(false);
    }

    let payload_pointer = find_pattern(&extloader, "11111111", 0);
    if payload_pointer == HEX_NOT_FOUND {
        warn!("Could not prepare Ext-Loader!");
        return Ok(false);
    }

    let download_addr: u32 = (download_function_off.unwrap() as u32) + da.addr;
    patch(&mut extloader, payload_pointer, &bytes_to_hex(&download_addr.to_le_bytes()))?;

    let rsc_func_off = analyzer.find_function_from_string("RSC file");
    if rsc_func_off.is_none() {
        warn!("Could not find RSC function to inject Ext-Loader!");
        return Ok(false);
    }

    patch(&mut da.data, rsc_func_off.unwrap(), &bytes_to_hex(&extloader))?;
    patch_string(&mut da.data, "CMD:SET-RSC", "CMD:BOOT-TO");

    info!("Injected Ext-Loader to DA2 successfully.");

    Ok(true)
}

fn patch_security(
    da: &mut DAEntryRegion,
    analyzer: &dyn ArchAnalyzer,
    is_arm64: bool,
) -> Result<bool> {
    patch_lock_state(da, analyzer, is_arm64)?;
    patch_sec_policy(da, analyzer, is_arm64)?;
    patch_da_sla(da, analyzer, is_arm64)
}

fn patch_lock_state(
    da: &mut DAEntryRegion,
    analyzer: &dyn ArchAnalyzer,
    is_arm64: bool,
) -> Result<bool> {
    let mut lks_patch = Vec::new();
    if is_arm64 {
        #[rustfmt::skip]
        lks_patch.extend_from_slice(&[
            0x1F, 0x00, 0x00, 0xB9, // str xzr, [x0]
            0x00, 0x00, 0x80, 0xD2, // mov x0, #0
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ]);
    } else {
        #[rustfmt::skip]
        lks_patch.extend_from_slice(&[
            0x00, 0x20, 0xA0, 0xE3, // mov r2, #0
            0x04, 0x00, 0x80, 0xE8, // stmia r0, {r2}
            0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
            0x1E, 0xFF, 0x2F, 0xE1, // bx lr
        ]);
    }

    let off = analyzer.find_function_from_string("[%s] sec_get_seccfg");

    if off.is_none() {
        warn!("Could not patch lock state!");
        return Ok(false);
    }

    patch(&mut da.data, off.unwrap(), &bytes_to_hex(&lks_patch))?;
    info!("Patched DA2 to always report unlocked state.");

    Ok(true)
}

fn patch_sec_policy(
    da: &mut DAEntryRegion,
    analyzer: &dyn ArchAnalyzer,
    is_arm64: bool,
) -> Result<bool> {
    const POLICY_FUNC: &str = "==========security policy==========";

    let Some(part_sec_pol_off) = analyzer.find_function_from_string(POLICY_FUNC) else {
        warn!("Could not find security policy function!");
        return Ok(false);
    };

    // BL policy_index
    // BL hash_binding
    // BL verify_policy
    // BL download_policy
    let Some(policy_idx_bl) = analyzer.get_next_bl_from_off(part_sec_pol_off) else {
        warn!("Could not find policy_idx call");
        return Ok(false);
    };

    let Some(hash_binding_bl) = analyzer.get_next_bl_from_off(policy_idx_bl + 4) else {
        warn!("Could not find hash_binding call");
        return Ok(false);
    };
    let Some(verify_bl) = analyzer.get_next_bl_from_off(hash_binding_bl + 4) else {
        warn!("Could not find verify_policy call");
        return Ok(false);
    };
    let Some(download_bl) = analyzer.get_next_bl_from_off(verify_bl + 4) else {
        warn!("Could not find download_policy call");
        return Ok(false);
    };

    let targets =
        [(hash_binding_bl, "Hash Binding"), (verify_bl, "Verification"), (download_bl, "Download")];

    let mut patched_any = false;

    for (bl_offset, desc) in targets {
        if let Some(func_offset) = analyzer.get_bl_target_offset(bl_offset) {
            if is_arm64 {
                arm64_force_return(&mut da.data, func_offset, 0)?;
            } else {
                arm_force_return(&mut da.data, func_offset, 0, false)?;
            }

            info!("Patched DA2 to skip security policy ({})", desc);
            patched_any = true;
        } else {
            warn!("Failed to resolve target for {}", desc);
        }
    }

    if !patched_any {
        warn!("Could not patch security policy!");
    }

    Ok(patched_any)
}

fn patch_da_sla(
    da: &mut DAEntryRegion,
    analyzer: &dyn ArchAnalyzer,
    is_arm64: bool,
) -> Result<bool> {
    let sla_str_offset = find_pattern(&da.data, "44412E534C4100454E41424C454400", 0);
    if sla_str_offset == HEX_NOT_FOUND {
        return Ok(true);
    }

    let register_all_cmds_off = analyzer.find_function_from_string("CMD:REBOOT");
    if register_all_cmds_off.is_none() {
        warn!("Could not patch DA SLA!");
        return Ok(false);
    }

    let cmd_offset = analyzer.find_string_xref("CMD:SECURITY-GET-DEV-FW-INFO");
    if cmd_offset.is_none() {
        warn!("Could not patch DA SLA!");
        return Ok(false);
    }

    let bl_to_patch_off = analyzer.get_next_bl_from_off(cmd_offset.unwrap());
    let bl_patch = if is_arm64 {
        arm64_encode_bl(
            bl_to_patch_off.unwrap() as u32 + da.addr,
            register_all_cmds_off.unwrap() as u32 + da.addr,
        )?
    } else {
        encode_bl_arm(
            bl_to_patch_off.unwrap() as u32 + da.addr,
            register_all_cmds_off.unwrap() as u32 + da.addr,
        )?
    };

    patch(&mut da.data, bl_to_patch_off.unwrap(), &bytes_to_hex(&bl_patch.to_le_bytes()))?;

    info!("Patched DA2 SLA to be disabled.");

    Ok(true)
}
