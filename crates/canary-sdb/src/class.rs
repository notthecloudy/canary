use crate::event::TypeHint;
use indexmap::{IndexMap, IndexSet};

#[derive(Clone, Debug)]
pub struct ClassNode {
    pub id: u64,
    pub vtable: Option<u64>,
    pub methods: IndexSet<u64>,
    pub this_ptrs: IndexSet<u64>,
    pub confidence: f32,
    pub evidence: u32,
    pub positives: u32,
    pub negatives: u32,
    pub last_tick: u64,
}

impl ClassNode {
    pub fn new(id: u64, vtable: Option<u64>, tick: u64) -> Self {
        Self {
            id,
            vtable,
            methods: IndexSet::new(),
            this_ptrs: IndexSet::new(),
            confidence: 0.10,
            evidence: 0,
            positives: 0,
            negatives: 0,
            last_tick: tick,
        }
    }

    pub fn note_positive(&mut self, delta: f32, tick: u64) {
        self.evidence += 1;
        self.positives += 1;
        self.last_tick = tick;
        self.confidence = (self.confidence + delta).min(0.99);
    }

    pub fn note_negative(&mut self, delta: f32, tick: u64) {
        self.evidence += 1;
        self.negatives += 1;
        self.last_tick = tick;
        self.confidence = (self.confidence - delta).max(0.0);
    }

    pub fn contradiction_rate(&self) -> f32 {
        let seen = self.positives + self.negatives;
        if seen == 0 {
            return 1.0;
        }
        self.negatives as f32 / seen as f32
    }
}

#[derive(Clone, Debug)]
pub struct FieldNode {
    pub class_id: u64,
    pub offset: i64,
    pub reads: u32,
    pub writes: u32,
    pub sites: IndexSet<u64>,
    pub confidence: f32,
    pub negatives: u32,
    pub type_votes: IndexMap<TypeHint, f32>,
    pub last_tick: u64,
}

impl FieldNode {
    pub fn new(class_id: u64, offset: i64, tick: u64) -> Self {
        Self {
            class_id,
            offset,
            reads: 0,
            writes: 0,
            sites: IndexSet::new(),
            confidence: 0.05,
            negatives: 0,
            type_votes: IndexMap::new(),
            last_tick: tick,
        }
    }

    pub fn touch(&mut self, site: u64, is_write: bool, hint: TypeHint, tick: u64) {
        self.sites.insert(site);
        self.last_tick = tick;

        if is_write {
            self.writes += 1;
            self.confidence = (self.confidence + 0.06).min(0.99);
        } else {
            self.reads += 1;
            self.confidence = (self.confidence + 0.04).min(0.99);
        }

        *self.type_votes.entry(hint.clone()).or_insert(0.0) += 1.0;

        let dominant = self.dominant_type();
        if dominant != TypeHint::Unknown && dominant != hint && hint != TypeHint::Unknown {
            self.negatives += 1;
            self.confidence = (self.confidence - 0.03).max(0.0);
        }
    }

    pub fn dominant_type(&self) -> TypeHint {
        self.type_votes
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone())
            .unwrap_or(TypeHint::Unknown)
    }

    pub fn support(&self) -> u32 {
        self.reads + self.writes
    }

    pub fn contradiction_rate(&self) -> f32 {
        let seen = self.support() + self.negatives;
        if seen == 0 {
            return 1.0;
        }
        self.negatives as f32 / seen as f32
    }
}
