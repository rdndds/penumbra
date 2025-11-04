/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::error::{Error, Result};
use crate::utilities::arm::to_thumb_addr;

pub const HEX_NOT_FOUND: usize = usize::MAX;
pub type HexPattern = Vec<Option<u8>>;

fn parse_pattern(input: &str) -> Result<HexPattern> {
    let filtered: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '-' && *c != ':')
        .collect();

    if !filtered.len().is_multiple_of(2) {
        return Err(Error::penumbra("Pattern has an odd number of hex digits"));
    }

    (0..filtered.len())
        .step_by(2)
        .map(|i| {
            let pair = &filtered[i..i + 2];
            if pair.eq_ignore_ascii_case("XX") {
                Ok(None)
            } else {
                u8::from_str_radix(pair, 16)
                    .map(Some)
                    .map_err(|_| Error::penumbra(format!("Invalid hex byte in pattern: {}", pair)))
            }
        })
        .collect()
}

fn pattern_matches(window: &[u8], pattern: &HexPattern) -> bool {
    pattern.iter().zip(window).all(|(p, &b)| p.is_none_or(|v| v == b))
}

/// Checks if a data window matches the given pattern, considering wildcards.
pub fn find_pattern(data: &[u8], pattern_str: &str, offset: usize) -> usize {
    let pattern = match parse_pattern(pattern_str) {
        Ok(p) => p,
        Err(_) => return HEX_NOT_FOUND,
    };

    if pattern.is_empty() || offset > data.len().saturating_sub(pattern.len()) {
        return HEX_NOT_FOUND;
    }

    for (i, window) in data.windows(pattern.len()).enumerate().skip(offset) {
        if pattern_matches(window, &pattern) {
            return i;
        }
    }

    HEX_NOT_FOUND
}

/// Applies a patch to the data at the specified offset.
/// The patch string can contain wildcards ('XX') which leave the corresponding byte unchanged.
pub fn patch(data: &mut [u8], offset: usize, patch_str: &str) -> Result<()> {
    let patch = parse_pattern(patch_str)?;

    if offset + patch.len() > data.len() {
        return Err(Error::penumbra("Patch exceeds data bounds"));
    }

    for (i, byte) in patch.into_iter().enumerate() {
        if let Some(b) = byte {
            data[offset + i] = b;
        }
    }

    Ok(())
}

/// Finds a pattern in the data and applies a patch at the found location.
/// Returns the position where the patch was applied, or -1 on failure.
pub fn patch_pattern_str(data: &mut [u8], pattern: &str, patch_str: &str) -> Option<usize> {
    let pos = find_pattern(data, pattern, 0);

    if pos == HEX_NOT_FOUND {
        return None;
    }

    if patch(data, pos, patch_str).is_err() {
        return None;
    }

    Some(pos)
}

pub fn patch_pattern(data: &mut [u8], pattern: &str, patch: u32) -> Option<usize> {
    let patch_str = format!(
        "{:02X}{:02X}{:02X}{:02X}",
        patch & 0xFF,
        (patch >> 8) & 0xFF,
        (patch >> 16) & 0xFF,
        (patch >> 24) & 0xFF
    );

    patch_pattern_str(data, pattern, &patch_str)
}

pub fn patch_ptr(data: &mut [u8], ptr_off: usize, value: u32, base_addr: u32, thumb: bool) {
    if thumb {
        let addr = to_thumb_addr(value as usize, base_addr);
        data[ptr_off..ptr_off + 4].copy_from_slice(&addr.to_le_bytes());
    } else {
        let addr = value + base_addr;
        data[ptr_off..ptr_off + 4].copy_from_slice(&addr.to_le_bytes());
    }
}
