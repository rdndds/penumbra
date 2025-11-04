/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use log::debug;

use crate::error::{Error, Result};

/// Protocol used by the DA
/// - Legacy: Old DA, used in old devices
/// - V5 (XFlash): Used mainly in early Dimensity devices and most Helio devices
/// - V6 (XML): Newest protocol, used in most recent Dimensity and Helio devices
#[derive(Debug, Clone, PartialEq)]
pub enum DAType {
    Legacy,
    V5,
    V6,
}

/// Represents a region within a DA entry
/// Usually there are 3 regions:
/// - Region 0: File Info (On XML Region 0 is the same as Region 1)
/// - Region 1: First stage DA (DA1)
/// - Region 2: Second stage DA (DA2)
#[derive(Clone, Debug)]
pub struct DAEntryRegion {
    /// Raw data of the region, including signature if any
    pub data: Vec<u8>,
    /// Offset within the file itself, where the region starts
    pub offset: u32,
    /// Length of the region
    pub length: u32,
    /// Address in which the region will be loaded in the device
    pub addr: u32,
    /// Same as length, minus the signature (offset - sig_len)
    pub region_length: u32,
    /// Length of the signature, if any
    pub sig_len: u32,
}

/// Represents a Download Agent (DA) entry for a specific SoC
#[derive(Clone, Debug)]
pub struct DA {
    /// Type of DA (Legacy, V5, V6)
    pub da_type: DAType,
    /// Regions within the DA entry
    pub regions: Vec<DAEntryRegion>,
    /// Magic number identifying the DA, always 0xDADA
    pub magic: u16,
    /// Hardware code identifying the SoC. On XFlash DA this corresponds
    /// to the "Commercial" name of the SoC (e.g., 0x6768 for Helio G85)
    /// On XML and Legacy DA this corresponds to the actual hw_code
    pub hw_code: u16,
    /// Always seems to be 0xCA00
    pub hw_sub_code: u16,
}

/// Represents a Download Agent (DA) file containing multiple DA entries
pub struct DAFile {
    /// Raw data of the entire DA file
    pub da_raw_data: Vec<u8>,
    pub da_type: DAType,
    /// List of DA entries for different SoCs
    pub das: Vec<DA>,
}

impl DAFile {
    pub fn parse_da(raw_data: &[u8]) -> Result<DAFile> {
        let hdr = &raw_data[..0x6C];

        let da_type = if &hdr[0..2] == b"\xDA\xDA" {
            DAType::Legacy
        } else if hdr.windows(10).any(|w| w == b"MTK_DA_v6") {
            DAType::V6
        } else {
            DAType::V5
        };

        if da_type != DAType::Legacy && !hdr.windows(0x12).any(|w| w == b"MTK_DOWNLOAD_AGENT") {
            return Err(Error::penumbra("Invalid DA file: Missing MTK_DOWNLOAD_AGENT signature"));
        }

        let _da_id = String::from_utf8_lossy(&hdr[0x20..0x60]).trim_end_matches('\0').to_string();
        let _version = u32::from_le_bytes(hdr[0x60..0x64].try_into().unwrap());
        let num_socs = u32::from_le_bytes(hdr[0x68..0x6C].try_into().unwrap());
        let _magic_number = &hdr[0x64..0x68];

        let da_entry_size = match da_type {
            DAType::Legacy => 0xD8,
            _ => 0xDC,
        };

        let mut das = Vec::new();
        for i in 0..num_socs {
            // Each one of this is a DA entry in the header
            let start = 0x6C + (i as usize * da_entry_size);
            let end = start + da_entry_size;
            let da_entry = &raw_data[start..end];

            // For each DA, we parse its header entry
            let magic = u16::from_le_bytes(da_entry[0x00..0x02].try_into().unwrap());
            let hw_code = u16::from_le_bytes(da_entry[0x02..0x04].try_into().unwrap());
            let hw_sub_code = u16::from_le_bytes(da_entry[0x04..0x06].try_into().unwrap());
            let _hw_version = u16::from_le_bytes(da_entry[0x06..0x08].try_into().unwrap());
            let mut regions: Vec<DAEntryRegion> = Vec::new();
            let region_count = u16::from_le_bytes(da_entry[0x12..0x14].try_into().unwrap());
            // Structure of the DA header entry
            // 0x00	magic	u16
            // 0x02	hw_code	u16
            // 0x04	hw_sub_code	u16
            // 0x06	hw_version	u16
            // 0x08	sw_version	u16 (v5 and v6 only, 0 in legacy)
            // 0x0A	...	u16
            // 0x0C	pagesize	u16
            // 0x0E	...	u16
            // 0x10	entry_region_index	u16
            // 0x12	entry_region_count	u16
            // 0x14	region table starts
            let mut current_region_offset = 0x14; // Starting from 0x14 to skip the data we already parsed
            for _ in 0..region_count {
                // Each region entry is 20 bytes
                // 0x00	offset (m_buf)	u32
                // 0x04	length (m_len)	u32
                // 0x08	addr (m_addr)	u32
                // 0x0C	m_region_offset (m_len - m_sig_len)	u32
                // 0x10	sig_len (m_sig_len)	u32
                let region_header_data =
                    &da_entry[current_region_offset..current_region_offset + 20];
                let offset = u32::from_le_bytes(region_header_data[0x00..0x04].try_into().unwrap());
                let length = u32::from_le_bytes(region_header_data[0x04..0x08].try_into().unwrap());
                let addr = u32::from_le_bytes(region_header_data[0x08..0x0C].try_into().unwrap());
                let sig_len =
                    u32::from_le_bytes(region_header_data[0x10..0x14].try_into().unwrap());
                let region_data: Vec<u8> =
                    raw_data[offset as usize..(offset + length) as usize].to_vec();
                debug!(
                    "Region: offset={:08X}, length={:08X}, addr={:08X}, sig_len={:08X}",
                    offset, length, addr, sig_len
                );
                regions.push(DAEntryRegion {
                    data: region_data,
                    offset,
                    length,
                    addr,
                    region_length: length - sig_len,
                    sig_len,
                });
                current_region_offset += 20; // Move to the next region header
            }

            das.push(DA { da_type: da_type.clone(), regions, magic, hw_code, hw_sub_code });
            debug!(
                "Parsed DA entry: hw_code={:04X}, hw_sub_code={:04X}, regions={}",
                hw_code, hw_sub_code, region_count
            );
        }

        Ok(DAFile { da_raw_data: raw_data.to_vec(), da_type, das })
    }

    // TODO: Make an Hashmap, possibly also including other info about a chip
    pub fn get_da_from_hw_code(&self, hw_code: u16) -> Option<DA> {
        let da_code = match hw_code {
            0x279 => 0x6797,
            0x321 => 0x6735,
            0x326 => 0x6755,
            0x335 => 0x6735,
            0x337 => 0x6735,
            0x507 => 0x6758,
            0x551 => 0x6757,
            0x562 => 0x6799,
            0x601 => 0x6755,
            0x633 => 0x6570,
            0x688 => 0x6758,
            0x690 => 0x6763,
            0x699 => 0x6739,
            0x707 => 0x6768,
            0x717 => 0x6761,
            0x725 => 0x6779,
            0x766 => 0x6765,
            0x788 => 0x6771,
            0x813 => 0x6785,
            0x816 => 0x6885,
            0x886 => 0x6873,
            0x908 => 0x8696,
            0x930 => 0x8195,
            0x950 => 0x6893,
            0x959 => 0x6877,
            0x989 => 0x6833,
            0x996 => 0x6853,
            0x1066 => 0x6781,
            0x6583 => 0x6589,
            0x8172 => 0x8173,
            0x8176 => 0x8173,
            _ => hw_code,
        };

        // I did the clone, I'm sorry!
        self.das.iter().find(|da| da.hw_code == da_code).cloned()
    }
}

impl DA {
    pub fn get_da1(&self) -> Option<&DAEntryRegion> {
        if self.regions.len() >= 3 { Some(&self.regions[1]) } else { None }
    }

    pub fn get_da2(&self) -> Option<&DAEntryRegion> {
        if self.regions.len() >= 3 { Some(&self.regions[2]) } else { None }
    }
}
