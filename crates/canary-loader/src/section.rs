//! Section representation.

use std::ops::Range;

/// Flags for a binary section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SectionFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Classification of a binary section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Executable code.
    Code,
    /// Read-only data (strings, jump tables).
    ReadOnlyData,
    /// Initialized writable data.
    Data,
    /// Uninitialized data (BSS).
    Bss,
    /// Debug information.
    Debug,
    /// Other / unknown.
    Other,
}

/// A single section of a loaded binary.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (e.g., `.text`, `.data`).
    pub name: String,
    /// Virtual address range in the loaded image.
    pub virtual_range: Range<u64>,
    /// Raw bytes of the section (empty for BSS).
    pub data: Vec<u8>,
    pub flags: SectionFlags,
    pub kind: SectionKind,
}

impl Section {
    /// Returns the size of the section in bytes.
    pub fn size(&self) -> u64 {
        self.virtual_range.end - self.virtual_range.start
    }

    /// Returns the bytes at a given virtual address range within this section,
    /// or `None` if the range is out of bounds.
    pub fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let base = self.virtual_range.start;
        if addr < base || addr + len as u64 > self.virtual_range.end {
            return None;
        }
        let offset = (addr - base) as usize;
        self.data.get(offset..offset + len)
    }

    /// Returns `true` if `addr` falls within this section's virtual range.
    pub fn contains(&self, addr: u64) -> bool {
        self.virtual_range.contains(&addr)
    }
}
