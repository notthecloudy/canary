use crate::{
    database::LiveDatabase, engine::SemanticEngine, event::SemanticEvent, ledger::CandidateLedger,
};

#[derive(Debug)]
pub struct SdbBridge {
    pub engine: SemanticEngine,
    pub ledger: CandidateLedger,
    pub sdb: LiveDatabase,
}

impl Default for SdbBridge {
    fn default() -> Self {
        let mut ledger = CandidateLedger::default();
        ledger.min_class_seen = 4;
        ledger.min_field_seen = 3;
        ledger.min_window = 2;

        Self {
            engine: SemanticEngine::new(),
            ledger,
            sdb: LiveDatabase::default(),
        }
    }
}

impl SdbBridge {
    pub fn ingest_event(&mut self, event: SemanticEvent) {
        self.engine.push_event(event.clone());
        self.ledger
            .observe_event(self.engine.tick, &event, &self.engine);
        self.sync_event_to_sdb(&event);
    }

    fn sync_event_to_sdb(&mut self, event: &SemanticEvent) {
        match event {
            SemanticEvent::VTableHit {
                vtable_addr,
                methods,
            } => {
                if let Some(class_id) = self.engine.index.vtable_to_class.get(vtable_addr).copied()
                {
                    let class = self.engine.classes.get(&class_id).unwrap();
                    if self.ledger.class_ready(class_id, class) {
                        self.sdb.upsert_class(
                            class_id,
                            Some(*vtable_addr),
                            methods.iter().copied().chain(class.methods.iter().copied()),
                            class.confidence,
                        );
                    }
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
                let class_id = self
                    .engine
                    .resolve_class_for_site(*site)
                    .or_else(|| self.engine.resolve_class_for_ptr(*this_ptr));

                let Some(cid) = class_id else { return };

                let Some(field) = self.engine.fields.get(&(cid, *offset)) else {
                    return;
                };
                let Some(class) = self.engine.classes.get(&cid) else {
                    return;
                };

                if self.ledger.class_ready(cid, class)
                    && self.ledger.field_ready(cid, *offset, field)
                {
                    self.sdb.upsert_class(
                        cid,
                        class.vtable,
                        class.methods.iter().copied(),
                        class.confidence,
                    );
                    self.sdb.upsert_field(
                        cid,
                        *offset,
                        field.reads,
                        field.writes,
                        field.confidence,
                        field.dominant_type(),
                    );
                }
            }

            SemanticEvent::CallSite {
                site,
                callee,
                this_ptr,
            } => {
                let class_id = self
                    .engine
                    .resolve_class_for_site(*site)
                    .or_else(|| self.engine.resolve_class_for_fn(*callee))
                    .or_else(|| this_ptr.and_then(|p| self.engine.resolve_class_for_ptr(p)));

                let Some(cid) = class_id else { return };
                let Some(class) = self.engine.classes.get(&cid) else {
                    return;
                };

                if self.ledger.class_ready(cid, class) {
                    self.sdb.upsert_class(
                        cid,
                        class.vtable,
                        class.methods.iter().copied(),
                        class.confidence,
                    );
                }
            }

            SemanticEvent::NegativeEvidence { .. } | SemanticEvent::ObjectLifetimeMarker { .. } => {
            }
        }
    }
}
