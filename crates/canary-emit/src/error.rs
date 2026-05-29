//! Emit errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("Unsupported IR node in {language} emitter: {node}")]
    UnsupportedNode {
        language: &'static str,
        node: String,
    },

    #[error("Emit failed: {reason}")]
    Failed { reason: String },
}
