use crate::event::TypeHint;
use indexmap::{IndexMap, IndexSet};

#[derive(Clone, Debug)]
pub struct SdbClass {
    pub class_id: u64,
    pub vtable: Option<u64>,
    pub methods: IndexSet<u64>,
    pub confidence: f32,
}

#[derive(Clone, Debug)]
pub struct SdbField {
    pub class_id: u64,
    pub offset: i64,
    pub reads: u32,
    pub writes: u32,
    pub confidence: f32,
    pub dominant_type: TypeHint,
}

#[derive(Clone, Debug)]
pub struct SdbClassCandidate {
    pub class_id: u64,
    pub vtable: Option<u64>,
    pub methods: IndexSet<u64>,
    pub max_confidence: f32,
    pub evidence_sources: u32,
    pub contradiction_score: f32,
}

#[derive(Clone, Debug)]
pub struct SdbFieldCandidate {
    pub class_id: u64,
    pub offset: i64,
    pub reads: u32,
    pub writes: u32,
    pub max_confidence: f32,
    pub dominant_type: TypeHint,
    pub evidence_sources: u32,
    pub contradiction_score: f32,
}

#[derive(Default, Debug)]
pub struct CandidateLedger {
    pub classes: IndexMap<u64, SdbClassCandidate>,
    pub fields: IndexMap<(u64, i64), SdbFieldCandidate>,
}

#[derive(Default, Debug)]
pub struct LiveDatabase {
    pub classes: IndexMap<u64, SdbClass>,
    pub fields: IndexMap<(u64, i64), SdbField>,
    pub ledger: CandidateLedger,
}

impl LiveDatabase {
    pub fn upsert_class(
        &mut self,
        class_id: u64,
        vtable: Option<u64>,
        methods: impl IntoIterator<Item = u64>,
        confidence: f32,
    ) {
        let entry = self
            .ledger
            .classes
            .entry(class_id)
            .or_insert_with(|| SdbClassCandidate {
                class_id,
                vtable,
                methods: IndexSet::new(),
                max_confidence: 0.0,
                evidence_sources: 0,
                contradiction_score: 0.0,
            });

        if entry.vtable.is_none() {
            entry.vtable = vtable;
        } else if vtable.is_some() && entry.vtable != vtable {
            entry.contradiction_score += 1.0;
        }

        entry.max_confidence = entry.max_confidence.max(confidence);
        entry.evidence_sources += 1;
        entry.methods.extend(methods);
    }

    pub fn upsert_field(
        &mut self,
        class_id: u64,
        offset: i64,
        reads: u32,
        writes: u32,
        confidence: f32,
        dominant_type: TypeHint,
    ) {
        let entry = self
            .ledger
            .fields
            .entry((class_id, offset))
            .or_insert_with(|| SdbFieldCandidate {
                class_id,
                offset,
                reads: 0,
                writes: 0,
                max_confidence: 0.0,
                dominant_type: TypeHint::Unknown,
                evidence_sources: 0,
                contradiction_score: 0.0,
            });

        entry.reads = entry.reads.saturating_add(reads);
        entry.writes = entry.writes.saturating_add(writes);
        entry.max_confidence = entry.max_confidence.max(confidence);
        entry.evidence_sources += 1;

        if dominant_type != TypeHint::Unknown {
            if entry.dominant_type != TypeHint::Unknown && entry.dominant_type != dominant_type {
                entry.contradiction_score += 0.5; // Type collision
            } else {
                entry.dominant_type = dominant_type;
            }
        }
    }

    pub fn commit_truths(&mut self) {
        for (id, cand) in &self.ledger.classes {
            if cand.max_confidence > 0.65
                && cand.evidence_sources >= 3
                && cand.contradiction_score < 1.0
            {
                self.classes.insert(
                    *id,
                    SdbClass {
                        class_id: cand.class_id,
                        vtable: cand.vtable,
                        methods: cand.methods.clone(),
                        confidence: cand.max_confidence,
                    },
                );
            }
        }

        for (k, cand) in &self.ledger.fields {
            if cand.max_confidence > 0.5
                && cand.evidence_sources >= 3
                && cand.contradiction_score < 1.0
            {
                self.fields.insert(
                    *k,
                    SdbField {
                        class_id: cand.class_id,
                        offset: cand.offset,
                        reads: cand.reads,
                        writes: cand.writes,
                        confidence: cand.max_confidence,
                        dominant_type: cand.dominant_type.clone(),
                    },
                );
            }
        }
    }
}
