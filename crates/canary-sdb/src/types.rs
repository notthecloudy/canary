use crate::{SdbEntry, SdbParam};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticUnit {
    Class,
    Module,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKind {
    UserCode,
    Intrinsic,
    ExternalStub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrState {
    None,
    Lifted,
    OptimizedSSA,
}

#[derive(Debug, Clone)]
pub struct SemanticDecision {
    pub unit: SemanticUnit,
    pub confidence: f32,
    pub evidence: f32,
}
#[derive(Debug, Clone)]
pub struct StructField {
    pub offset: i64,
    pub name: Option<String>,
    pub size: usize,
    pub ty_hint: Option<String>,
    pub bit_mask: Option<u64>,
    pub bit_shift: Option<u8>,
    pub bit_width: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct SdbStruct {
    pub name: String,
    pub fields: Vec<StructField>,
    pub total_size: usize,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub discriminant: i64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct SdbEnum {
    pub name: String,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, Clone)]
pub struct SdbArray {
    pub element_ty: String,
    pub stride: usize,
    pub count_hint: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SdbFunctionType {
    pub name: String,
    pub params: Vec<SdbParam>,
    pub return_ty: String,
    pub calling_conv: String,
}

#[derive(Debug, Clone)]
pub struct SdbVtable {
    pub addr: u64,
    pub entries: Vec<u64>,
    pub class_name: Option<String>,
    pub base_vtable: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SdbInheritance {
    pub derived_vtable: u64,
    pub base_vtables: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct SdbMethod {
    pub fn_addr: u64,
    pub class_vtable: u64,
    pub is_virtual: bool,
    pub slot: Option<usize>,
    pub is_ctor: bool,
    pub is_dtor: bool,
}

#[derive(Debug, Clone)]
pub struct SdbClass {
    pub name: String,
    pub vtables: Vec<u64>,
    pub methods: Vec<SdbMethod>,
    pub bases: Vec<String>,
}

#[derive(Default)]
pub struct TypesNamespace {
    pub structs: Vec<SdbEntry<SdbStruct>>,
    pub enums: Vec<SdbEntry<SdbEnum>>,
    pub arrays: Vec<SdbEntry<SdbArray>>,
    pub function_types: Vec<SdbEntry<SdbFunctionType>>,
    pub vtables: Vec<SdbEntry<SdbVtable>>,
    pub inheritance: Vec<SdbEntry<SdbInheritance>>,
    pub methods: Vec<SdbEntry<SdbMethod>>,
    pub classes: Vec<SdbEntry<SdbClass>>,
    pub strings: Vec<SdbEntry<SdbString>>,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceBundle {
    pub rtti_score: f32,
    pub vtable_score: f32,
    pub callgraph_score: f32,
    pub this_usage_score: f32,
}

#[derive(Debug, Clone)]
pub struct ClassHypothesis {
    pub vtable_addr: u64,
    pub methods: Vec<u64>,
    pub confidence: f32,
    pub evidence: EvidenceBundle,
    pub cluster_id: u64,
}

#[derive(Debug, Clone)]
pub struct FieldModel {
    pub class_vtable: u64,
    pub offset: i64,
    pub reads: u32,
    pub writes: u32,
    pub methods_touching: u32,
    pub read_entropy: f32,
    pub write_entropy: f32,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub struct FieldAccessEvent {
    pub class_vtable: u64,
    pub function_addr: u64,
    pub offset: i64,
    pub kind: AccessKind,
}

#[derive(Debug, Clone)]
pub struct TypeModel {
    pub id: u64,
    pub confidence: f32,
    pub origin_fields: Vec<(u64, i64)>, // class_id + offset
}

#[derive(Debug, Clone)]
pub struct SdbString {
    pub value: String,
    pub address: u64,
    pub encoding: String,
    pub xrefs: Vec<u64>,
}
