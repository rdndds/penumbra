pub mod aarch64;
pub mod arm;

pub use aarch64::Aarch64Analyzer;
pub use arm::ArmAnalyzer;

pub trait ArchAnalyzer {
    /// Finds the file offset of the start of a function that references a specific string.
    fn find_function_from_string(&self, s: &str) -> Option<usize>;

    /// Finds a function pointer passed as an argument to a call that follows a string reference.
    fn find_call_arg_from_string(&self, s: &str, arg_idx: u8) -> Option<u64>;

    /// Converts a Virtual Address to a File Offset
    fn va_to_offset(&self, va: u64) -> Option<usize>;
    fn offset_to_va(&self, offset: usize) -> Option<u64>;

    /// Returns the target address (VA) of a BL
    fn get_bl_target(&self, offset: usize) -> Option<u64>;
    /// Finds the next BL instruction from the given file offset
    fn get_next_bl_from_off(&self, offset: usize) -> Option<usize>;
    /// Finds the first reference to the given string, returning the file offset of the ref
    fn find_string_xref(&self, target_str: &str) -> Option<usize>;

    /// Returns the file offset target of a BL instruction
    fn get_bl_target_offset(&self, offset: usize) -> Option<usize> {
        let va = self.get_bl_target(offset)?;
        self.va_to_offset(va)
    }

    fn find_function_start_from_off(&self, offset: usize) -> Option<usize>;
}
