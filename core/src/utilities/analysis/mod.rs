/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

pub mod aarch64;
pub mod arm;

pub use aarch64::Aarch64Analyzer;
pub use arm::ArmAnalyzer;
use downcast_rs::{Downcast, impl_downcast};

/// Architecture-agnostic binary analysis trait.
pub trait ArchAnalyzer: Downcast {
    /// Converts a virtual address to a file offset.
    fn va_to_offset(&self, va: u64) -> Option<usize>;

    /// Converts a file offset to a virtual address.
    fn offset_to_va(&self, offset: usize) -> Option<u64>;

    /// Finds the file offset of the start of a function that references a specific string.
    fn find_function_from_string(&self, s: &str) -> Option<usize>;

    /// Finds a function pointer passed as an argument to a call that follows a string reference.
    fn find_call_arg_from_string(&self, s: &str, arg_idx: u8) -> Option<u64>;

    /// Returns the target address (VA) of a BL instruction at the given offset.
    fn get_bl_target(&self, offset: usize) -> Option<u64>;

    /// Returns the target address (VA) of a B instruction at the given offset.
    fn get_b_target(&self, offset: usize) -> Option<u64>;

    /// Finds the next BL instruction from the given file offset.
    fn get_next_bl_from_off(&self, offset: usize) -> Option<usize>;

    /// Finds the next B instruction from the given file offset.
    fn get_next_b_from_off(&self, offset: usize) -> Option<usize>;

    /// Finds the first reference to the given string, returning the file offset.
    fn find_string_xref(&self, target_str: &str) -> Option<usize>;

    /// Finds the start of a function containing the given offset.
    fn find_function_start_from_off(&self, offset: usize) -> Option<usize>;

    /// Returns the file offset target of a BL instruction.
    fn get_bl_target_offset(&self, offset: usize) -> Option<usize> {
        let va = self.get_bl_target(offset)?;
        self.va_to_offset(va)
    }

    fn data(&self) -> &[u8];
}

impl_downcast!(ArchAnalyzer);
