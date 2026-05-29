use indexmap::IndexMap;

#[derive(Default, Debug)]
pub struct Index {
    pub vtable_to_class: IndexMap<u64, u64>,
    pub fn_to_class: IndexMap<u64, u64>,
    pub ptr_to_class: IndexMap<u64, u64>,
}
