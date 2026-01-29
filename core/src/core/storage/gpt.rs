/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crc32fast::hash as crc32;

use crate::core::storage::{EmmcPartition, Partition, PartitionKind, StorageType, UfsPartition};
use crate::error::{Error, Result};

const EFI_PART_SIGNATURE: &[u8; 8] = b"EFI PART";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GptType {
    Pgpt,
    Sgpt,
}

#[allow(dead_code)]
#[derive(Debug)]
struct GptHeader {
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    part_entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    header_size: u32,
    header_crc32: u32,
    part_array_crc32: u32,
    sector_size: usize,
}

#[derive(Debug)]
pub struct Gpt {
    #[allow(dead_code)]
    header: GptHeader,
    partitions: Vec<Partition>,
}

impl Gpt {
    pub fn parse(data: &[u8], storage_type: StorageType) -> Result<Self> {
        let part_kind = match storage_type {
            StorageType::Emmc => PartitionKind::Emmc(EmmcPartition::User),
            StorageType::Ufs => PartitionKind::Ufs(UfsPartition::Lu2),
            _ => PartitionKind::Unknown,
        };

        let (gpt_type, header_offset) =
            Self::detect_type(data).ok_or_else(|| Error::penumbra("No valid GPT header found"))?;

        let header = Self::parse_header(data, header_offset)?;

        let entries_data = match gpt_type {
            GptType::Pgpt => {
                let start = header.part_entry_lba as usize * header_offset;
                let len = header.num_entries as usize * header.entry_size as usize;
                if data.len() < start + len {
                    return Err(Error::io("Partition array out of bounds"));
                }
                &data[start..start + len]
            }
            GptType::Sgpt => {
                let len = header.num_entries as usize * header.entry_size as usize;
                if data.len() < header_offset || header_offset < len {
                    return Err(Error::io("SGPT buffer too small for entries"));
                }
                &data[0..len]
            }
        };

        let partitions = Self::parse_partition_entries(entries_data, &header, part_kind)?;

        Ok(Self { header, partitions })
    }

    pub fn partitions(&self) -> Vec<Partition> {
        self.partitions.clone()
    }

    fn parse_header(data: &[u8], offset: usize) -> Result<GptHeader> {
        if offset + 92 > data.len() {
            return Err(Error::io("GPT header out of bounds"));
        }

        let hdr = &data[offset..offset + 92];

        if &hdr[0..8] != EFI_PART_SIGNATURE {
            return Err(Error::penumbra("Invalid GPT signature"));
        }

        let header_size = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
        let stored_crc = u32::from_le_bytes(hdr[16..20].try_into().unwrap());

        if !(92..=512).contains(&header_size) {
            return Err(Error::penumbra("Invalid GPT header size"));
        }
        if offset + header_size > data.len() {
            return Err(Error::io("GPT header out of bounds"));
        }

        let mut crc_buf = data[offset..offset + header_size].to_vec();
        crc_buf[16..20].fill(0);
        let computed_crc = crc32(&crc_buf);

        if computed_crc != stored_crc {
            return Err(Error::penumbra("GPT header CRC mismatch"));
        }

        Ok(GptHeader {
            header_size: header_size as u32,
            header_crc32: stored_crc,
            current_lba: u64::from_le_bytes(hdr[24..32].try_into().unwrap()),
            backup_lba: u64::from_le_bytes(hdr[32..40].try_into().unwrap()),
            first_usable_lba: u64::from_le_bytes(hdr[40..48].try_into().unwrap()),
            last_usable_lba: u64::from_le_bytes(hdr[48..56].try_into().unwrap()),
            part_entry_lba: u64::from_le_bytes(hdr[72..80].try_into().unwrap()),
            num_entries: u32::from_le_bytes(hdr[80..84].try_into().unwrap()),
            entry_size: u32::from_le_bytes(hdr[84..88].try_into().unwrap()),
            part_array_crc32: u32::from_le_bytes(hdr[88..92].try_into().unwrap()),
            sector_size: offset,
        })
    }

    fn validate_parts_crc(entries: &[u8], header: &GptHeader) -> Result<()> {
        let array_len = header.num_entries as usize * header.entry_size as usize;
        if entries.len() < array_len {
            return Err(Error::io("Partition array out of bounds"));
        }

        let computed = crc32(&entries[..array_len]);
        if computed != header.part_array_crc32 {
            return Err(Error::penumbra("Partition array CRC mismatch"));
        }

        Ok(())
    }

    fn parse_partition_entries(
        entries_data: &[u8],
        header: &GptHeader,
        part_kind: PartitionKind,
    ) -> Result<Vec<Partition>> {
        if header.entry_size != 128 {
            return Err(Error::penumbra("Unsupported GPT entry size"));
        }

        Self::validate_parts_crc(entries_data, header)?;

        let mut parts = Vec::new();

        for i in 0..header.num_entries {
            let off = i as usize * header.entry_size as usize;
            if off + header.entry_size as usize > entries_data.len() {
                return Err(Error::io("Partition entry out of bounds"));
            }

            let entry = &entries_data[off..off + header.entry_size as usize];
            if entry[0..16].iter().all(|&b| b == 0) {
                continue;
            }

            let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
            let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
            if last_lba < first_lba {
                return Err(Error::io("Partition last_lba < first_lba"));
            }

            let name = String::from_utf16_lossy(
                &entry[56..128]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect::<Vec<_>>(),
            );

            let sector_size = header.sector_size;
            let size_bytes = (last_lba - first_lba + 1) * sector_size as u64;

            parts.push(Partition::new(
                &name,
                size_bytes as usize,
                first_lba * sector_size as u64,
                part_kind,
            ));
        }

        Ok(parts)
    }

    fn detect_type(data: &[u8]) -> Option<(GptType, usize)> {
        let end = data.len();
        let sector_sizes = [512, 1024, 2048, 4096, 8192];

        for &sector_size in &sector_sizes {
            if end >= sector_size + 8 && &data[end - sector_size..end - sector_size + 8] == EFI_PART_SIGNATURE {
                return Some((GptType::Sgpt, end - sector_size));
            }
        }

        for &sector_size in &sector_sizes {
            if data.len() >= sector_size + 8 && &data[sector_size..sector_size + 8] == EFI_PART_SIGNATURE {
                return Some((GptType::Pgpt, sector_size));
            }
        }

        None
    }
}

impl From<Gpt> for Vec<Partition> {
    fn from(gpt: Gpt) -> Self {
        gpt.partitions
    }
}
