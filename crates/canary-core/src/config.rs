//! Global configuration for the Canary Reconstruction Engine
//!
//! Contains recovery modes and heuristic tunings.

use serde::{Deserialize, Serialize};

/// Defines the overall aggressiveness of the reconstruction heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    /// Strict evidence only. Only proven structs and exact cross-reference names are emitted.
    /// Emits heavily guarded, raw representations if ambiguous.
    Conservative,

    /// Emits classes and inheritance using standard memory layout assumptions.
    /// Prefers semantic structural models over raw types.
    Structural,

    /// High-heuristic naming. Infers names from API calls and string usages.
    /// Will generate "ShowMessageDialog" instead of `sub_x1234` when evidence aligns.
    Readable,

    /// Maximum verbosity and confidence annotations. Emits all alternatives in comments.
    Research,

    /// The highest priority is making the emitted C++ code immediately compilable,
    /// even if some structs need to be padded with dummy data.
    Rebuildable,
}

impl Default for RecoveryMode {
    fn default() -> Self {
        RecoveryMode::Readable
    }
}

/// Global settings for a reconstruction workspace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub recovery_mode: RecoveryMode,

    /// If true, XAML/UI recovery will synthesize dynamic MVVM data bindings.
    pub emit_ui_bindings: bool,

    /// If true, automatically group functions into `Subsystems` based on call graphs.
    pub cluster_subsystems: bool,
}
