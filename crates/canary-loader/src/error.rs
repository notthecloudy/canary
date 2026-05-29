//! Binary loading errors.

use thiserror::Error;

/// Errors that can occur during binary loading.
#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsupported binary format")]
    UnsupportedFormat,

    #[error("Malformed binary: {reason}")]
    Malformed { reason: String },

    #[error("Section not found: {name}")]
    SectionNotFound { name: String },

    #[error("Address out of range: {addr:#x}")]
    AddressOutOfRange { addr: u64 },

    #[error("Parse error: {0}")]
    Parse(String),
}
