//! IR type system.
//!
//! Types in the IR evolve as analysis progresses:
//!
//! - Initially: `Unknown` or `BitWidth` (we know the size, not the meaning)
//! - After type inference: `Pointer`, `Struct`, `Function`, etc.
//! - After semantic raising: `StdVector`, `StdString`, `Class` with full layout

use crate::arena::{Arena, NodeId};

use canary_sdb::{ConfidenceVector, StableId};

#[derive(Debug, Clone, PartialEq)]
pub struct ConfidenceTag {
    pub score: ConfidenceVector,
    pub origin: String,
    pub evidence_ids: Vec<StableId>,
}

impl Default for ConfidenceTag {
    fn default() -> Self {
        Self {
            score: ConfidenceVector::base(1.0),
            origin: "exact".to_string(),
            evidence_ids: Vec::new(),
        }
    }
}

/// A stable identifier for a type in the [`TypeArena`].
pub type TypeId = NodeId<IrType>;

/// Calling conventions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallingConvention {
    SysV64,
    Win64Fastcall,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
    Unknown,
}

/// An IR type — evolves from coarse to fine as analysis progresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrType {
    /// Unknown type — size may or may not be known.
    Unknown { bit_width: Option<u8> },

    /// A boolean (1-bit) value.
    Bool,

    /// A signed integer of the given bit width.
    Int { bit_width: u8, signed: bool },

    /// A floating-point value.
    Float { bit_width: u8 },

    /// A pointer to another type.
    Pointer {
        target: TypeId,
        /// If `None`, assumed to be the native pointer width.
        bit_width: Option<u8>,
    },

    /// A fixed-size array.
    Array { element: TypeId, count: u64 },

    /// A structure with named fields.
    Struct {
        name: Option<String>,
        fields: Vec<StructField>,
    },

    /// A function type.
    Function {
        return_type: TypeId,
        params: Vec<TypeId>,
        variadic: bool,
        calling_convention: CallingConvention,
    },

    /// A void type (used for function returns with no value).
    Void,
}

/// A single field in a [`IrType::Struct`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    /// Byte offset of this field from the start of the struct.
    pub offset: u64,
    /// Name of the field (initially synthetic, e.g. `field_0x8`).
    pub name: String,
    /// Type of the field.
    pub ty: TypeId,
}

impl IrType {
    /// Returns the bit width of the type if known.
    pub fn bit_width(&self) -> Option<u32> {
        match self {
            IrType::Unknown { bit_width } => bit_width.map(|w| w as u32),
            IrType::Bool => Some(1),
            IrType::Int { bit_width, .. } => Some(*bit_width as u32),
            IrType::Float { bit_width } => Some(*bit_width as u32),
            IrType::Pointer { bit_width, .. } => bit_width.map(|w| w as u32).or(Some(64)),
            _ => None,
        }
    }
}

/// An arena for storing [`IrType`] nodes.
pub type TypeArena = Arena<IrType>;

/// Monotonic type lattice for interprocedural type propagation.
///
/// Enforces a strict partial ordering:
/// `Top <= Union <= Struct <= Primitive <= Bottom`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeLattice {
    /// Most general (Totally unconstrained)
    Top,
    /// Primitive (Int, Float, Bool)
    Primitive(IrType),
    /// Pointer to another lattice type
    Pointer(Box<TypeLattice>),
    /// Structure with fields
    Struct {
        name: String,
        fields: std::collections::BTreeMap<i64, TypeLattice>,
    },
    /// Uncertainty merge node (prevents early collapse to Bottom)
    Union(Vec<TypeLattice>),
    /// Conflict / Invalid (Overconstrained)
    Bottom,
}

impl TypeLattice {
    /// Least Upper Bound (LUB) merge operation that preserves monotonicity.
    pub fn merge(self, other: TypeLattice) -> TypeLattice {
        use TypeLattice::*;
        match (self, other) {
            (Top, t) | (t, Top) => t,
            (Bottom, _) | (_, Bottom) => Bottom,
            (a, b) if a == b => a,
            (Pointer(a), Pointer(b)) => Pointer(Box::new(a.merge(*b))),
            (a, b) => {
                let mut merged = Vec::new();
                if let Union(mut av) = a {
                    merged.append(&mut av);
                } else {
                    merged.push(a);
                }

                if let Union(mut bv) = b {
                    merged.append(&mut bv);
                } else {
                    merged.push(b);
                }

                // Deduplicate
                let mut unique = Vec::new();
                for m in merged {
                    if !unique.contains(&m) {
                        unique.push(m);
                    }
                }

                if unique.len() == 1 {
                    unique.pop().unwrap()
                } else if unique.len() > 4 {
                    // Cap union size to prevent explosion
                    Bottom
                } else {
                    Union(unique)
                }
            }
        }
    }
}
