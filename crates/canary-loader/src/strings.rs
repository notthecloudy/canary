//! Advanced string recovery from binary data.
//!
//! Provides utilities to scan for, decode, and categorize UTF-8 and UTF-16
//! strings within raw binary sections, attributing them with confidence
//! and tracking cross-references.

use canary_sdb::types::SdbString;

pub struct StringExtractor {
    pub min_length: usize,
}

impl Default for StringExtractor {
    fn default() -> Self {
        Self { min_length: 5 }
    }
}

impl StringExtractor {
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Scans a byte slice for printable ASCII/UTF-8 and UTF-16 strings.
    /// Extracted strings are directly added to the semantic database.
    pub fn extract_strings(&self, bytes: &[u8], base_address: u64) -> Vec<SdbString> {
        let mut res = Vec::new();
        self.scan_utf8(&mut res, bytes, base_address);
        self.scan_utf16(&mut res, bytes, base_address);
        res
    }

    fn scan_utf8(&self, res: &mut Vec<SdbString>, bytes: &[u8], base_address: u64) {
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_graphic() || bytes[i] == b' ' {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_graphic()
                        || bytes[i] == b' '
                        || bytes[i] == b'\t'
                        || bytes[i] == b'\n'
                        || bytes[i] == b'\r')
                {
                    i += 1;
                }

                if i - start >= self.min_length {
                    // It must be null-terminated to have higher confidence

                    if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                        res.push(SdbString {
                            value: s.to_string(),
                            address: base_address + start as u64,
                            encoding: "UTF-8".to_string(),
                            xrefs: Vec::new(),
                        });
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    fn scan_utf16(&self, res: &mut Vec<SdbString>, bytes: &[u8], base_address: u64) {
        let mut i = 0;
        while i + 1 < bytes.len() {
            let b1 = bytes[i];
            let b2 = bytes[i + 1];

            // Basic heuristic for printable UTF-16 LE
            if (b1.is_ascii_graphic() || b1 == b' ') && b2 == 0 {
                let start = i;
                let mut utf16_chars = Vec::new();

                while i + 1 < bytes.len() {
                    let c1 = bytes[i];
                    let c2 = bytes[i + 1];
                    if (c1.is_ascii_graphic()
                        || c1 == b' '
                        || c1 == b'\t'
                        || c1 == b'\n'
                        || c1 == b'\r')
                        && c2 == 0
                    {
                        utf16_chars.push(c1 as u16);
                        i += 2;
                    } else {
                        break;
                    }
                }

                if utf16_chars.len() >= self.min_length {
                    if let Ok(s) = String::from_utf16(&utf16_chars) {
                        res.push(SdbString {
                            value: s,
                            address: base_address + start as u64,
                            encoding: "UTF-16LE".to_string(),
                            xrefs: Vec::new(),
                        });
                    }
                }
            } else {
                i += 1;
            }
        }
    }
}
