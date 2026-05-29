//! Constraint and Belief Revision Core.
//!
//! This engine manages competing hypotheses and incorporates new evidence
//! to invalidate prior conclusions or elevate confidence scores.

use canary_sdb::{Evidence, Hypothesis, StableId};
use indexmap::IndexMap;

#[derive(Debug, Clone)]
pub struct BeliefState {
    pub current_hypothesis: Hypothesis,
    pub alternatives: Vec<Hypothesis>,
    /// Ambiguity preservation: if true, no single hypothesis has sufficiently high
    /// margin over others to be treated as conclusive.
    pub is_ambiguous: bool,
}

pub struct ConstraintEngine {
    /// Maps a stable ID (e.g. an object, function, or type) to its current belief state.
    pub beliefs: IndexMap<StableId, BeliefState>,
}

impl Default for ConstraintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintEngine {
    pub fn new() -> Self {
        Self {
            beliefs: IndexMap::new(),
        }
    }

    /// Introduce a new hypothesis for a given ID.
    pub fn add_hypothesis(&mut self, id: StableId, hypothesis: Hypothesis) {
        if let Some(state) = self.beliefs.get_mut(&id) {
            state.alternatives.push(hypothesis);
            self.evaluate_ambiguity(id);
        } else {
            self.beliefs.insert(
                id,
                BeliefState {
                    current_hypothesis: hypothesis,
                    alternatives: Vec::new(),
                    is_ambiguous: false,
                },
            );
        }
    }

    /// Reconcile new evidence against existing beliefs.
    /// This may invalidate the `current_hypothesis` and promote an alternative.
    pub fn reconcile(&mut self, id: StableId, new_evidence: Evidence) {
        if let Some(state) = self.beliefs.get_mut(&id) {
            // Re-weight the current and alternatives based on the new evidence.
            // For MVP: we just attach the evidence to the current hypothesis if it aligns,
            // or we might create a competing hypothesis if it contradicts.
            state.current_hypothesis.evidence.push(new_evidence);

            // Trigger a re-evaluation of ambiguity and confidence
            self.evaluate_ambiguity(id);
        }
    }

    /// Evaluates whether the margin between the top hypothesis and others
    /// is large enough to discard ambiguity.
    fn evaluate_ambiguity(&mut self, id: StableId) {
        if let Some(state) = self.beliefs.get_mut(&id) {
            if state.alternatives.is_empty() {
                state.is_ambiguous = false;
                return;
            }

            let mut all_hyps = vec![state.current_hypothesis.clone()];
            all_hyps.extend(state.alternatives.iter().cloned());

            // Sort descending by composite confidence score
            all_hyps.sort_by(|a, b| {
                b.confidence
                    .composite()
                    .partial_cmp(&a.confidence.composite())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            let top = &all_hyps[0];
            let runner_up = &all_hyps[1];

            // If the top score isn't significantly higher than the runner up, it remains ambiguous.
            let margin = top.confidence.composite() - runner_up.confidence.composite();
            state.is_ambiguous = margin < 0.2; // 20% margin required for certainty

            state.current_hypothesis = all_hyps.remove(0);
            state.alternatives = all_hyps;
        }
    }
}
