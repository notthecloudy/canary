use crate::{
    class::{ClassNode, FieldNode},
    event::{SemanticEvent, TypeHint},
    index::Index,
};
use indexmap::IndexMap;

#[derive(Default, Debug)]
pub struct SemanticEngine {
    pub classes: IndexMap<u64, ClassNode>,
    pub fields: IndexMap<(u64, i64), FieldNode>,
    pub index: Index,
    pub tick: u64,
    next_class_id: u64,
}

impl SemanticEngine {
    pub fn new() -> Self {
        Self {
            classes: IndexMap::new(),
            fields: IndexMap::new(),
            index: Index::default(),
            tick: 0,
            next_class_id: 1,
        }
    }

    pub fn push_event(&mut self, event: SemanticEvent) {
        self.tick += 1;

        match event {
            SemanticEvent::VTableHit {
                vtable_addr,
                methods,
            } => self.handle_vtable(vtable_addr, methods),
            SemanticEvent::MemoryRead {
                site,
                this_ptr,
                offset,
                value_hint,
            } => self.handle_memory(site, this_ptr, offset, value_hint, false),
            SemanticEvent::MemoryWrite {
                site,
                this_ptr,
                offset,
                value_hint,
            } => self.handle_memory(site, this_ptr, offset, value_hint, true),
            SemanticEvent::CallSite {
                site,
                callee,
                this_ptr,
            } => self.handle_call(site, callee, this_ptr),
            SemanticEvent::ObjectLifetimeMarker { ptr } => {
                if let Some(class_id) = self.resolve_class_for_ptr(ptr) {
                    if let Some(class) = self.classes.get_mut(&class_id) {
                        class.this_ptrs.insert(ptr);
                        class.note_positive(0.02, self.tick);
                    }
                }
            }
            SemanticEvent::NegativeEvidence {
                class_id,
                this_ptr,
                offset,
                ..
            } => {
                self.handle_negative(class_id, this_ptr, offset);
            }
        }
    }

    pub fn resolve_class_for_fn(&self, fn_addr: u64) -> Option<u64> {
        self.index.fn_to_class.get(&fn_addr).copied()
    }

    pub fn resolve_class_for_site(&self, site: u64) -> Option<u64> {
        self.resolve_class_for_fn(site)
    }

    pub fn resolve_class_for_ptr(&self, ptr: u64) -> Option<u64> {
        self.index.ptr_to_class.get(&ptr).copied()
    }

    fn new_class(&mut self, vtable: Option<u64>) -> u64 {
        let id = self.next_class_id;
        self.next_class_id += 1;
        self.classes
            .insert(id, ClassNode::new(id, vtable, self.tick));
        id
    }

    fn handle_vtable(&mut self, vtable_addr: u64, methods: Vec<u64>) {
        let class_id = if let Some(id) = self.index.vtable_to_class.get(&vtable_addr).copied() {
            id
        } else {
            let id = self.new_class(Some(vtable_addr));
            self.index.vtable_to_class.insert(vtable_addr, id);
            id
        };

        if let Some(class) = self.classes.get_mut(&class_id) {
            class.vtable = Some(vtable_addr);
            class.note_positive(0.22, self.tick);
            class.methods.extend(methods.iter().copied());
        }

        for m in methods {
            self.index.fn_to_class.insert(m, class_id);
        }
    }

    fn handle_call(&mut self, site: u64, callee: u64, this_ptr: Option<u64>) {
        let mut class_id = self
            .resolve_class_for_fn(callee)
            .or_else(|| self.resolve_class_for_site(site));

        if class_id.is_none() {
            if let Some(ptr) = this_ptr {
                class_id = self.resolve_class_for_ptr(ptr);
            }
        }

        if let Some(cid) = class_id {
            self.index.fn_to_class.entry(site).or_insert(cid);

            if let Some(ptr) = this_ptr {
                self.index.ptr_to_class.insert(ptr, cid);
                if let Some(class) = self.classes.get_mut(&cid) {
                    class.this_ptrs.insert(ptr);
                }
            }

            if let Some(class) = self.classes.get_mut(&cid) {
                class.methods.insert(site);
                class.note_positive(0.08, self.tick);
            }
        }
    }

    fn handle_memory(
        &mut self,
        site: u64,
        this_ptr: u64,
        offset: i64,
        hint: TypeHint,
        is_write: bool,
    ) {
        let class_id = self
            .resolve_class_for_site(site)
            .or_else(|| self.resolve_class_for_ptr(this_ptr));

        let Some(cid) = class_id else { return };

        self.index.ptr_to_class.insert(this_ptr, cid);
        self.index.fn_to_class.entry(site).or_insert(cid);

        if let Some(class) = self.classes.get_mut(&cid) {
            class.this_ptrs.insert(this_ptr);
            class.note_positive(if is_write { 0.05 } else { 0.03 }, self.tick);
        }

        let field = self
            .fields
            .entry((cid, offset))
            .or_insert_with(|| FieldNode::new(cid, offset, self.tick));
        field.touch(site, is_write, hint, self.tick);

        if let Some(class) = self.classes.get_mut(&cid) {
            class.note_positive(0.03, self.tick);
        }
    }

    fn handle_negative(
        &mut self,
        class_id: Option<u64>,
        this_ptr: Option<u64>,
        offset: Option<i64>,
    ) {
        let cid = class_id.or_else(|| this_ptr.and_then(|p| self.resolve_class_for_ptr(p)));

        if let Some(cid) = cid {
            if let Some(class) = self.classes.get_mut(&cid) {
                class.note_negative(0.10, self.tick);
            }

            if let Some(off) = offset {
                if let Some(field) = self.fields.get_mut(&(cid, off)) {
                    field.negatives += 1;
                    field.confidence = (field.confidence - 0.08).max(0.0);
                }
            }
        }
    }
}
