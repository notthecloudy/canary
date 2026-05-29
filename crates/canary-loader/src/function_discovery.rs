//! Function discovery heuristics.
//!
//! Beyond named exports and symbols, we use heuristics to discover
//! additional function entry points in stripped binaries.

use crate::binary::LoadedBinary;

/// Patterns that suggest a new function starts at an offset.
const FUNCTION_PROLOGUE_X64: &[&[u8]] = &[
    &[0x55, 0x48, 0x89, 0xE5], // push rbp; mov rbp, rsp
    &[0x55, 0x41, 0x57],       // push rbp; push r15
    &[0x53, 0x48, 0x83, 0xEC], // push rbx; sub rsp, ...
];

/// Scans executable sections for function prologues and returns candidate addresses.
pub fn discover_by_prologue(binary: &LoadedBinary) -> Vec<u64> {
    let mut candidates = Vec::new();
    for section in binary.code_sections() {
        let data = &section.data;
        let base = section.virtual_range.start;
        for (offset, window) in data.windows(8).enumerate() {
            for pattern in FUNCTION_PROLOGUE_X64 {
                if window.starts_with(pattern) {
                    candidates.push(base + offset as u64);
                    break;
                }
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}
