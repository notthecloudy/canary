//! Dialect system — MLIR-style progressive semantic raising.
//!
//! Dialects represent different abstraction levels in the Canary IR.
//! Analysis passes raise operations from lower dialects to higher ones.
//!
//! # Dialect Hierarchy
//!
//! ```text
//! x86 Dialect       → Raw register/flag operations
//!     ↓
//! Core Dialect      → SSA variables, arithmetic, control flow
//!     ↓
//! Memory Dialect    → Explicit heap/stack, pointers, array accesses
//!     ↓
//! OO Dialect        → Classes, vtables, inheritance, this-pointers
//!     ↓
//! HighLevel Dialect → Iterators, closures, maps, option types
//! ```
//!
//! Operations that cannot be raised remain at their current dialect level.
//! Emitters handle all dialects, falling back gracefully.

/// The abstraction level of a dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DialectLevel {
    /// Raw architecture-specific operations.
    Arch = 0,
    /// Architecture-agnostic SSA variables and arithmetic.
    Core = 1,
    /// Explicit memory model (heap, stack, pointers).
    Memory = 2,
    /// Object-oriented constructs (classes, vtables, RTTI).
    ObjectOriented = 3,
    /// High-level language constructs (iterators, closures, algebraic types).
    HighLevel = 4,
}

impl std::fmt::Display for DialectLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialectLevel::Arch => write!(f, "arch"),
            DialectLevel::Core => write!(f, "core"),
            DialectLevel::Memory => write!(f, "memory"),
            DialectLevel::ObjectOriented => write!(f, "oo"),
            DialectLevel::HighLevel => write!(f, "hl"),
        }
    }
}

/// A trait for IR nodes that belong to a dialect.
pub trait Dialectal {
    fn dialect(&self) -> DialectLevel;
}

impl Dialectal for crate::llil::LlilExpr {
    fn dialect(&self) -> DialectLevel {
        DialectLevel::Arch
    }
}

impl Dialectal for crate::llil::LlilInstr {
    fn dialect(&self) -> DialectLevel {
        DialectLevel::Arch
    }
}

impl Dialectal for crate::ssa::SsaExpr {
    fn dialect(&self) -> DialectLevel {
        DialectLevel::Core
    }
}

impl Dialectal for crate::ssa::SsaInstr {
    fn dialect(&self) -> DialectLevel {
        DialectLevel::Core
    }
}

impl Dialectal for crate::mlil::MlilExpr {
    fn dialect(&self) -> DialectLevel {
        match self {
            crate::mlil::MlilExpr::Load { .. } | crate::mlil::MlilExpr::AddressOf(_) => {
                DialectLevel::Memory
            }
            _ => DialectLevel::Core,
        }
    }
}

impl Dialectal for crate::mlil::MlilInstr {
    fn dialect(&self) -> DialectLevel {
        match self {
            crate::mlil::MlilInstr::Store { .. } => DialectLevel::Memory,
            _ => DialectLevel::Core,
        }
    }
}

impl Dialectal for crate::semantic::SemanticInstr {
    fn dialect(&self) -> DialectLevel {
        DialectLevel::HighLevel
    }
}
