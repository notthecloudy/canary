use crate::{
    class::{ClassNode, FieldNode},
    engine::SemanticEngine,
    event::{NegativeKind, SemanticEvent},
};
use indexmap::IndexMap;

#[derive(Clone, Debug, Default)]
pub struct VoteWindow {
    pub first_tick: u64,
    pub last_tick: u64,
    pub seen: u32,
    pub positive: u32,
    pub negative: u32,
}

impl VoteWindow {
    pub fn record(&mut self, tick: u64, positive: bool) {
        if self.seen == 0 {
            self.first_tick = tick;
        }
        self.last_tick = tick;
        self.seen += 1;
        if positive {
            self.positive += 1;
        } else {
            self.negative += 1;
        }
    }

    pub fn stability_window(&self) -> u64 {
        self.last_tick.saturating_sub(self.first_tick) + 1
    }

    pub fn contradiction_rate(&self) -> f32 {
        if self.seen == 0 {
            return 1.0;
        }
        self.negative as f32 / self.seen as f32
    }
}

#[derive(Default, Debug)]
pub struct CandidateLedger {
    pub class_votes: IndexMap<u64, VoteWindow>,
    pub field_votes: IndexMap<(u64, i64), VoteWindow>,
    pub min_class_seen: u32,
    pub min_field_seen: u32,
    pub min_window: u64,
}

impl CandidateLedger {
    pub fn observe_event(&mut self, tick: u64, event: &SemanticEvent, engine: &SemanticEngine) {
        match event {
            SemanticEvent::VTableHit { vtable_addr, .. } => {
                if let Some(class_id) = engine.index.vtable_to_class.get(vtable_addr) {
                    self.class_votes
                        .entry(*class_id)
                        .or_default()
                        .record(tick, true);
                }
            }
            SemanticEvent::MemoryRead {
                site,
                this_ptr,
                offset,
                ..
            }
            | SemanticEvent::MemoryWrite {
                site,
                this_ptr,
                offset,
                ..
            } => {
                if let Some(class_id) = engine
                    .resolve_class_for_site(*site)
                    .or_else(|| engine.resolve_class_for_ptr(*this_ptr))
                {
                    self.class_votes
                        .entry(class_id)
                        .or_default()
                        .record(tick, true);
                    self.field_votes
                        .entry((class_id, *offset))
                        .or_default()
                        .record(tick, true);
                }
            }
            SemanticEvent::CallSite {
                site,
                callee,
                this_ptr,
            } => {
                if let Some(class_id) = engine
                    .resolve_class_for_site(*site)
                    .or_else(|| engine.resolve_class_for_fn(*callee))
                    .or_else(|| this_ptr.and_then(|p| engine.resolve_class_for_ptr(p)))
                {
                    self.class_votes
                        .entry(class_id)
                        .or_default()
                        .record(tick, true);
                }
            }
            SemanticEvent::NegativeEvidence {
                class_id,
                this_ptr,
                offset,
                kind,
                ..
            } => {
                let resolved =
                    (*class_id).or_else(|| this_ptr.and_then(|p| engine.resolve_class_for_ptr(p)));

                if let Some(cid) = resolved {
                    self.class_votes.entry(cid).or_default().record(tick, false);

                    if let Some(off) = offset {
                        self.field_votes
                            .entry((cid, *off))
                            .or_default()
                            .record(tick, false);
                    }

                    match kind {
                        NegativeKind::ConflictingType(_) => {}
                        NegativeKind::UnstableAlias => {}
                        NegativeKind::DeadAccess => {}
                        NegativeKind::VtableMismatch => {}
                    }
                }
            }
            SemanticEvent::ObjectLifetimeMarker { .. } => {}
        }
    }

    pub fn class_ready(&self, class_id: u64, class: &ClassNode) -> bool {
        let vote = match self.class_votes.get(&class_id) {
            Some(v) => v,
            None => return false,
        };

        vote.seen >= self.min_class_seen
            && vote.stability_window() >= self.min_window
            && vote.contradiction_rate() < 0.35
            && class.confidence >= 0.55
            && class.contradiction_rate() < 0.35
    }

    pub fn field_ready(&self, class_id: u64, offset: i64, field: &FieldNode) -> bool {
        let vote = match self.field_votes.get(&(class_id, offset)) {
            Some(v) => v,
            None => return false,
        };

        vote.seen >= self.min_field_seen
            && vote.stability_window() >= self.min_window
            && vote.contradiction_rate() < 0.25
            && field.confidence >= 0.45
            && field.contradiction_rate() < 0.35
            && field.support() >= self.min_field_seen
    }
}
