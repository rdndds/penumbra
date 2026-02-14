/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::Cursor;

use log::{debug, info};
use tokio::io::AsyncWrite;
use xmlcmd_derive::XmlCommand;

use crate::da::DAProtocol;
use crate::da::xml::Xml;
use crate::da::xml::cmds::{XmlCmdLifetime, XmlCommand};
use crate::da::xml::patch::{detect_arch, find_sej_base, to_arch};
use crate::error::Result;
use crate::exploit::get_v6_payload;
use crate::utilities::analysis::create_analyzer;
use crate::utilities::patching::{bytes_to_hex, patch_pattern_str};
use crate::utilities::xml::get_tag;

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_xml.bin");

#[derive(XmlCommand)]
pub struct ExtAck;

#[derive(XmlCommand)]
pub struct ExtSetSejBase {
    #[xml(tag = "sej_base", fmt = "0x{sej_base:X}")]
    sej_base: u32,
}

#[derive(XmlCommand)]
pub struct ExtReadMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: usize,
}

/*
#[derive(XmlCommand)]
pub struct ExtWriteMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u32,
}
*/

#[derive(XmlCommand)]
pub struct ExtSej {
    #[xml(tag = "encrypt")]
    encrypt: String,
    #[xml(tag = "legacy")]
    legacy: String,
    #[xml(tag = "ac")]
    anti_clone: String,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u32,
}

pub async fn boot_extensions(xml: &mut Xml) -> Result<bool> {
    let ext_data = match prepare_extensions(xml) {
        Some(data) => data,
        None => {
            debug!("Failed to prepare XML extensions. Continuing without.");
            return Ok(false);
        }
    };

    debug!("Trying booting XML extensions...");

    let ext_addr = 0x68000000;
    let ext_size = DA_EXT.len() as u32;

    info!("Uploading XML extensions to 0x{:08X} (0x{:X} bytes)", ext_addr, ext_size);

    let boot_to_resp = xml.boot_to(ext_addr, &ext_data).await.unwrap_or(false);
    if !boot_to_resp {
        info!("Failed to upload XML extensions, continuing without extensions");
        return Ok(false);
    }

    match xmlcmd!(xml, ExtAck) {
        Ok(_) => {}
        Err(_) => {
            info!("Extensions did not reply, continuing without extensions");
            return Ok(false);
        }
    }

    let response = match xml.get_upload_file_resp().await {
        Ok(resp) => resp,
        Err(_) => {
            xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;
            info!("Failed to get extension ack response, continuing without extensions");
            return Ok(false);
        }
    };

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

    let ack: String = get_tag(&response, "status")?;
    if ack != "OK" {
        info!("DA extensions failed to start: {}", ack);
        return Ok(false);
    }

    // Some V6 devices have a different SEJ base, we need to set it here so that SEJ commands work
    let sej_base = find_sej_base(xml.da.get_da2().map_or(&[][..], |da| &da.data[..]));
    xmlcmd_e!(xml, ExtSetSejBase, sej_base)?;

    info!("Successfully booted XML extensions");

    Ok(true)
}

fn prepare_extensions(xml: &Xml) -> Option<Vec<u8>> {
    let da2address = xml.da.get_da2()?.addr;
    let da2data = &xml.da.get_da2()?.data;

    let is_arm64 = detect_arch(da2data);
    let mut da_ext_data = get_v6_payload(DA_EXT, is_arm64).to_vec();

    patch_pattern_str(&mut da_ext_data, "11111111", &bytes_to_hex(&da2address.to_le_bytes()))?;

    let analyzer = create_analyzer(da2data.clone(), da2address as u64, to_arch(is_arm64));

    let download_function_off = analyzer.find_function_from_string("Download host file:%s")?;
    let upload_function_off = analyzer.find_function_from_string("Upload data to host file:%s")?;
    let download_addr = analyzer.offset_to_va(download_function_off)? as u32;
    let upload_addr = analyzer.offset_to_va(upload_function_off)? as u32;

    debug!("Download function at offset 0x{:X}, VA 0x{:X}", download_function_off, download_addr);
    debug!("Upload function at offset 0x{:X}, VA 0x{:X}", upload_function_off, upload_addr);

    let off = analyzer.find_string_xref("CMD:REBOOT")?;
    let bl_off = analyzer.get_next_bl_from_off(off)?;
    let reg_cmd_addr = analyzer.get_bl_target(bl_off)? as u32;

    debug!("Reg CMD function at VA 0x{:X}", reg_cmd_addr);

    let off = analyzer.va_to_offset(reg_cmd_addr as u64)?;
    let bl_off = analyzer.get_next_bl_from_off(off)?;
    let malloc_addr = analyzer.get_bl_target(bl_off)? as u32;

    debug!("Malloc function at VA 0x{:X}", malloc_addr);

    let off = analyzer.find_string_xref("Bad %s")?;
    let bl1 = analyzer.get_next_bl_from_off(off)?;
    let bl2 = analyzer.get_next_bl_from_off(bl1 + 4)?;
    let free_addr = analyzer.get_bl_target(bl2)? as u32;

    debug!("Free function at VA 0x{:X}", free_addr);

    let load_string_off = analyzer.find_function_start_from_off(off)?;
    let load_str_addr = analyzer.offset_to_va(load_string_off)? as u32;

    debug!("mxml_load_string function at VA 0x{:X}", load_str_addr);
    let off = analyzer.find_string_xref("runtime_switchable_config/magic")?;
    let bl_off = analyzer.get_next_bl_from_off(off)?;
    let gettext_addr = analyzer.get_bl_target(bl_off)? as u32;

    debug!("gettext function at VA 0x{:X}", gettext_addr);

    patch_pattern_str(&mut da_ext_data, "22222222", &bytes_to_hex(&reg_cmd_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "33333333", &bytes_to_hex(&download_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "44444444", &bytes_to_hex(&upload_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "55555555", &bytes_to_hex(&malloc_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "66666666", &bytes_to_hex(&free_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "77777777", &bytes_to_hex(&gettext_addr.to_le_bytes()))?;
    patch_pattern_str(&mut da_ext_data, "88888888", &bytes_to_hex(&load_str_addr.to_le_bytes()))?;

    Some(da_ext_data)
}

pub async fn sej(
    xml: &mut Xml,
    data: &[u8],
    encrypt: bool,
    legacy: bool,
    anti_clone: bool,
    _xor: bool,
) -> Result<Vec<u8>> {
    let length = data.len() as u32;

    // yes or no
    let encrypt_str = if encrypt { "yes" } else { "no" }.to_string();
    let legacy_str = if legacy { "yes" } else { "no" }.to_string();
    let anti_clone_str = if anti_clone { "yes" } else { "no" }.to_string();
    xmlcmd!(xml, ExtSej, encrypt_str, legacy_str, anti_clone_str, length)?;

    let mut buf = data.to_vec();
    let mut cursor = Cursor::new(&mut buf);
    let mut progress = |_: usize, _: usize| {};

    xml.download_file(length as usize, &mut cursor, &mut progress).await?;
    cursor.set_position(0);
    xml.upload_file(&mut cursor, &mut progress).await?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

    Ok(buf)
}

pub async fn peek<F>(
    xml: &mut Xml,
    addr: u32,
    length: usize,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    mut progress: F,
) -> Result<()>
where
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, ExtReadMem, addr, length)?;

    xml.upload_file(writer, &mut progress).await?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

    Ok(())
}
