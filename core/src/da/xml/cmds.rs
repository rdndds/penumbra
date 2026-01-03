/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::collections::BTreeMap;

use xmlcmd_derive::XmlCommand;

/// MAGIC value for protocol communication
pub const MAGIC: u32 = 0xFEEEEEEF;
/// Each header contains this, to identify the DataType.
/// V6 doesn't seem to use anything other than this.
pub const DT_PROTOCOL_FLOW: u32 = 0x1;
pub const CMD_START: &[u8] = b"<command>CMD:START</command>";
pub const CMD_END: &[u8] = b"<command>CMD:END</command>";
pub const HOST_CMDS: &str =
    "CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@";

/// Perform a (fake) file system operation
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum FileSystemOp {
    MkDir,
    Exists,
    FileSize,
    RemoveAll,
    Remove,
}

impl FileSystemOp {
    pub fn default(&self) -> &'static str {
        match self {
            FileSystemOp::MkDir => "MKDIR\u{0}",
            FileSystemOp::Exists => "NOT-EXISTS\u{0}", // To avoid more reads
            FileSystemOp::FileSize => "FILE-SIZE\u{0}",
            FileSystemOp::RemoveAll => "REMOVE-ALL\u{0}",
            FileSystemOp::Remove => "REMOVE\u{0}",
        }
    }
}

/// Lifetime of an XML command
#[derive(Clone, Copy)]
pub enum XmlCmdLifetime {
    CmdStart,
    CmdEnd,
}

/// Each XML command should implement this trait, by
/// using the `XmlCommand` derive macro.
pub trait XmlCommand {
    fn cmd_name(&self) -> &'static str;
    fn args(&self) -> Vec<(Option<&'static str>, &'static str, String)>;
    fn version(&self) -> &'static str;
}

#[derive(XmlCommand)]
pub struct BootTo {
    #[xml(tag = "at_address", fmt = "0x{at_addr:x}")]
    at_addr: u64,
    #[xml(tag = "jmp_address", fmt = "0x{jmp_addr:x}")]
    jmp_addr: u64,
    #[xml(tag = "source_file", fmt = "MEM://0x{host_offset:x}:0x{length:x}")]
    host_offset: u64,
    length: u64,
}

#[derive(XmlCommand)]
#[xmlcmd(version = "1.1")]
pub struct SetRuntimeParameter {
    #[xml(tag = "checksum_level")]
    checksum_level: String,
    #[xml(tag = "battery_exist")]
    battery_exist: String,
    #[xml(tag = "da_log_level")]
    da_log_level: String,
    #[xml(tag = "log_channel")]
    log_channel: String,
    #[xml(tag = "system_os")]
    system_os: String,
    #[xml(custom_arg = "adv", tag = "initialize_dram")]
    init_dram: String,
}

#[derive(XmlCommand)]
pub struct HostSupportedCommands {
    #[xml(tag = "host_capability")]
    host_capability: String,
}

#[derive(XmlCommand)]
pub struct NotifyInitHw;

#[derive(XmlCommand)]
pub struct GetHwInfo {
    #[allow(dead_code)]
    #[xml(tag = "target_file", fmt = "MEM://0x0:0x200000")]
    target_file: String,
}

#[derive(XmlCommand)]
pub struct ReadPartition {
    #[xml(tag = "partition")]
    partition: String,
    #[allow(dead_code)]
    #[xml(tag = "target_file", fmt = "{partition}.bin")]
    target_file: String,
}

#[derive(XmlCommand)]
pub struct WritePartition {
    #[xml(tag = "partition")]
    partition: String,
    #[allow(dead_code)]
    #[xml(tag = "source_file", fmt = "{partition}.bin")]
    source_file: String,
}

#[derive(XmlCommand)]
pub struct ErasePartition {
    #[xml(tag = "partition")]
    partition: String,
}

pub fn create_cmd<C: XmlCommand>(cmd: &C) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><da><version>{}</version><command>CMD:{}</command>"#,
        cmd.version(),
        cmd.cmd_name()
    );

    let mut sections: BTreeMap<Option<&str>, Vec<(&str, String)>> = BTreeMap::new();

    for (section, tag, content) in cmd.args() {
        sections.entry(section).or_default().push((tag, content));
    }

    for (section, entries) in sections {
        let tag = section.unwrap_or("arg");
        xml.push_str(&format!("<{}>", tag));
        for (tag_path, content) in entries {
            let parts: Vec<&str> = tag_path.split('/').collect();

            for p in &parts {
                xml.push_str(&format!("<{}>", p));
            }

            xml.push_str(&content);

            for p in parts.iter().rev() {
                xml.push_str(&format!("</{}>", p));
            }
        }
        xml.push_str(&format!("</{}>", tag));
    }

    xml.push_str("</da>");
    xml
}
