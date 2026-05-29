//! `canary-loader` — Binary loader for PE, ELF, and Mach-O files.
//!
//! The loader is responsible for:
//! - Parsing binary file headers and section tables
//! - Mapping sections into a virtual address layout
//! - Discovering function entry points (via exports, symbols, or heuristics)
//! - Providing raw bytes for disassembly by architecture lifters

pub mod binary;
pub mod error;
pub mod function_discovery;
pub mod pri;
pub mod section;
pub mod strings;
pub mod winmd;
pub mod xbf;
pub mod xbf_framework_types;

pub use binary::{Binary, BinaryFormat, LoadedBinary};
pub use error::LoaderError;
pub use pri::{PriAsset, PriParser, PriResources, PriString, PriXbf};
pub use section::{Section, SectionFlags, SectionKind};
pub use winmd::{
    WinMdParser, WinRtClass, WinRtInterface, WinRtMetadata, WinRtMethod, WinRtParam, WinRtProperty,
};
pub use xbf::{XbfDecoder, XbfNode};
