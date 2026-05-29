//! Confidence propagation engine.
//!
//! Handles updating the confidence scores of facts based on inference rules and
//! evidence accumulation.

use crate::SemanticDatabase;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ConfidenceEngine {
    // Engine configuration or rules could go here
}

pub struct ConfidenceReport {
    pub average_structural: f32,
    pub average_semantic: f32,
    pub high_confidence_count: usize,
    pub low_confidence_count: usize,
}

impl ConfidenceEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Propagates confidence scores across the database, updating facts where evidence
    /// or derived conclusions change.
    pub fn propagate(&mut self, db: &mut SemanticDatabase) {
        for (_, sdb_func) in db.interpretations.functions.functions.iter_mut() {
            let evidence_count = sdb_func.provenance.evidence.len()
                + sdb_func.hypotheses.iter().map(|h| h.evidence.len()).sum::<usize>();

            if evidence_count > 0 {
                let evidence_score = (0.45 + (evidence_count as f32 * 0.1)).min(1.0);
                sdb_func.confidence.provenance = sdb_func.confidence.provenance.max(evidence_score);
            }

            let mut semantic_components = Vec::new();
            if let Some(signature) = &sdb_func.value.call_signature {
                semantic_components.push(signature.confidence.semantic);
            }
            if let Some(semantic) = &sdb_func.value.semantic {
                semantic_components.push(semantic.confidence.semantic);
            }
            if let Some(provenance) = &sdb_func.value.pointer_provenance {
                semantic_components.push(provenance.confidence.semantic);
            }
            if !semantic_components.is_empty() {
                sdb_func.confidence.semantic = semantic_components.iter().sum::<f32>() / semantic_components.len() as f32;
            }
        }
    }

    /// Calibrates confidence scores based on validation outcomes and rebuild test results.
    pub fn calibrate(
        &mut self,
        db: &mut SemanticDatabase,
        over_normalization_risk: f32,
        under_recovery_risk: f32,
        subsystems_failed: &HashMap<String, usize>,
        failed_functions: &[String],
    ) -> ConfidenceReport {
        let mut total_structural = 0.0;
        let mut total_semantic = 0.0;
        let mut high_count = 0;
        let mut low_count = 0;
        let count = db.interpretations.functions.functions.len();

        for (_, sdb_func) in db.interpretations.functions.functions.iter_mut() {
            // Apply calibration penalty if risks are high
            if over_normalization_risk > 0.5 {
                sdb_func.confidence.structural *= 0.9;
            }
            if under_recovery_risk > 0.5 {
                sdb_func.confidence.semantic *= 0.8;
            }
            
            if let Some(name) = &sdb_func.name {
                if failed_functions.contains(name) {
                    sdb_func.confidence.semantic *= 0.5; // Heavy penalty for failing rebuild
                }
            }
            
            // Subsystem penalties
            if subsystems_failed.get("ControlFlowRecovery").copied().unwrap_or(0) > 10 {
                sdb_func.confidence.structural *= 0.85;
            }

            let composite = sdb_func.confidence.composite();
            if composite > 0.8 {
                high_count += 1;
            } else {
                low_count += 1;
            }

            total_structural += sdb_func.confidence.structural;
            total_semantic += sdb_func.confidence.semantic;
        }

        ConfidenceReport {
            average_structural: if count > 0 { total_structural / count as f32 } else { 0.0 },
            average_semantic: if count > 0 { total_semantic / count as f32 } else { 0.0 },
            high_confidence_count: high_count,
            low_confidence_count: low_count,
        }
    }
}
