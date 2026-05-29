//! Incremental Analysis and Caching Module
//!
//! Provides function-level and module-level caching capabilities.
//! Hashes raw byte regions and avoids re-lifting or re-analyzing if unmodified.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Represents the cached artifacts for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCacheEntry {
    /// Hash of the original binary bytes of this function.
    pub byte_hash: u64,
    /// Serialized representation of the lifted CFG, SSA, or MLIL.
    /// (Mocked as a byte blob for this phase).
    pub ir_blob: Vec<u8>,
}

/// The top-level analysis cache that can be serialized to disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnalysisCache {
    /// Map from function entry address to its cached artifacts.
    pub functions: HashMap<u64, FunctionCacheEntry>,
    /// Map from module/section name to its byte hash for coarse invalidation.
    pub modules: HashMap<String, u64>,
}

impl AnalysisCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a function is present in the cache and its hash matches.
    pub fn get_valid_function(&self, addr: u64, current_hash: u64) -> Option<&FunctionCacheEntry> {
        if let Some(entry) = self.functions.get(&addr) {
            if entry.byte_hash == current_hash {
                return Some(entry);
            }
        }
        None
    }

    /// Save the cache to disk using JSON serialization.
    pub fn save_to_disk(&self, path: &Path) -> Result<(), std::io::Error> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)
    }

    /// Load the cache from disk.
    pub fn load_from_disk(path: &Path) -> Result<Self, std::io::Error> {
        let data = fs::read_to_string(path)?;
        let cache = serde_json::from_str(&data)?;
        Ok(cache)
    }
}
