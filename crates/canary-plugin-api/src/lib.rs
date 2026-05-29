//! `canary-plugin-api` — Stable plugin interface for Wasm-sandboxed plugins.
//!
//! This crate defines the data types that cross the host↔plugin boundary.
//! All types must be serializable (serde + JSON for Phase 1;
//! Cap'n Proto will be introduced in Phase 4 for zero-copy performance).
//!
//! # Design Law
//!
//! **Core owns truth. Plugins own hypotheses.**
//!
//! Plugins receive read-only IR snapshots and return typed proposals.
//! The core engine validates every proposal before committing it.

use serde::{Deserialize, Serialize};

/// Capabilities that a plugin may declare it needs.
///
/// The plugin runtime grants only declared capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read-only access to IR snapshots.
    ReadIr,
    /// May return type hypotheses for variables.
    SuggestTypes,
    /// May return name candidates for symbols.
    SuggestNames,
    /// May propose bounded local subgraph rewrites.
    ProposeLocalRewrite,
    /// May register a new pattern matcher.
    RegisterPatternMatcher,
}

/// Plugin metadata declared in `plugin.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// Capabilities this plugin requires.
    pub capabilities: Vec<Capability>,
    /// IR dialects this plugin can consume.
    pub input_dialects: Vec<String>,
    /// IR facts this plugin produces (for scheduling).
    pub provides: Vec<String>,
    /// IR facts this plugin requires to be present (for scheduling).
    pub requires: Vec<String>,
}

/// A suggestion returned by a plugin — one entry in a proposal payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Suggestion {
    /// Rename a symbol (variable, function, type).
    RenameSym {
        /// The current synthetic name (e.g., `var_8`, `sub_401000`).
        current_name: String,
        /// The proposed new name.
        proposed_name: String,
        /// Confidence score in [0.0, 1.0].
        confidence: f32,
        /// Human-readable rationale.
        rationale: String,
    },

    /// Suggest a type for a variable.
    SuggestType {
        /// Synthetic variable name.
        var_name: String,
        /// Proposed type in a C-like notation.
        proposed_type: String,
        confidence: f32,
        rationale: String,
    },

    /// Propose replacing a subgraph of instructions with a named intrinsic.
    ProposeIdiom {
        /// The first address in the matched instruction sequence.
        start_addr: u64,
        /// The last address (inclusive).
        end_addr: u64,
        /// The high-level intrinsic name (e.g., `std::vector::push_back`).
        intrinsic: String,
        confidence: f32,
        rationale: String,
    },

    /// Add a comment to a specific address.
    AddComment { addr: u64, text: String },
}

/// The complete proposal returned by a plugin for one analysis unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginProposal {
    /// The plugin that generated this proposal.
    pub plugin_name: String,
    /// SHA-256 hash of the function's CFG bytes (for cache keying).
    pub cfg_hash: String,
    /// The suggestions in this proposal.
    pub suggestions: Vec<Suggestion>,
}

/// Validation result for a single suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub suggestion_index: usize,
    pub accepted: bool,
    /// If rejected, the reason why.
    pub rejection_reason: Option<String>,
}
