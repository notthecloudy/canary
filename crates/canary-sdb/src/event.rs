#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TypeHint {
    Unknown,
    Int,
    Float,
    Bool,
    Pointer,
    FunctionPtr,
    Struct(u64),
}

impl Default for TypeHint {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Clone, Debug)]
pub enum NegativeKind {
    ConflictingType(TypeHint),
    UnstableAlias,
    DeadAccess,
    VtableMismatch,
}

#[derive(Clone, Debug)]
pub enum SemanticEvent {
    VTableHit {
        vtable_addr: u64,
        methods: Vec<u64>,
    },
    MemoryRead {
        site: u64,
        this_ptr: u64,
        offset: i64,
        value_hint: TypeHint,
    },
    MemoryWrite {
        site: u64,
        this_ptr: u64,
        offset: i64,
        value_hint: TypeHint,
    },
    CallSite {
        site: u64,
        callee: u64,
        this_ptr: Option<u64>,
    },
    ObjectLifetimeMarker {
        ptr: u64,
    },
    NegativeEvidence {
        site: u64,
        class_id: Option<u64>,
        this_ptr: Option<u64>,
        offset: Option<i64>,
        kind: NegativeKind,
    },
}

impl SemanticEvent {
    pub fn is_memory(&self) -> bool {
        matches!(self, Self::MemoryRead { .. } | Self::MemoryWrite { .. })
    }
}
