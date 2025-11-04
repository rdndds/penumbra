/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::core::storage::{EmmcPartition, Partition, PartitionKind, StorageType, UfsPartition};
use crate::error::{Error, Result};

pub fn parse_gpt(data: &[u8], storage_type: StorageType) -> Result<Vec<Partition>> {
    let mut sector_size: Option<usize> = None;

    let sector_sizes = [512, 4096, 0x8000, 0x10000, 0x20000];
    for &ss in &sector_sizes {
        if data.len() >= ss + 8 && &data[ss..ss + 8] == b"EFI PART" {
            sector_size = Some(ss);
            break;
        }
    }

    let sector_size = match sector_size {
        Some(size) => size,
        None => {
            return Err(Error::penumbra("No valid GPT header found"));
        }
    };

    let hdr = &data[sector_size..sector_size * 2];
    let partition_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap());

    if entry_size as usize != 128 {
        return Err(Error::penumbra("Unsupported partition entry size"));
    }

    let start_offset = (partition_entry_lba as usize) * sector_size;
    let mut partitions: Vec<Partition> = Vec::new();
    let part_kind = match storage_type {
        StorageType::Emmc => PartitionKind::Emmc(EmmcPartition::User),
        StorageType::Ufs => PartitionKind::Ufs(UfsPartition::Lu2),
        _ => PartitionKind::Unknown,
    };

    for i in 0..num_entries {
        let current_offset = start_offset + (i as usize * entry_size as usize);

        let entry = &data[current_offset..current_offset + entry_size as usize];

        // Yeet empty entries
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }

        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());

        if last_lba < first_lba {
            return Err(Error::io("Partition last_lba < first_lba"));
        }

        let part_size = (last_lba - first_lba + 1) * sector_size as u64;
        let part_addr = first_lba * sector_size as u64;

        let part_name = String::from_utf16_lossy(
            &entry[56..128]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|&c| c != 0)
                .collect::<Vec<u16>>(),
        );

        partitions.push(Partition::new(&part_name, part_size as usize, part_addr, part_kind));
    }

    Ok(partitions)
}
