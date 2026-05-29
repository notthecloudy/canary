//! Semantic IR Layer
//!
//! Represents high-level state transitions, object lifecycles, and component interactions.

use crate::types::ConfidenceTag;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum StateTransition {
    AcquireResource(u64),
    ReleaseResource(u64),
    UpdateState(u64, String), // e.g. state variable changed to 'Initialized'
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticInstr {
    pub id: usize,
    pub address: u64,
    pub transition: StateTransition,
    pub confidence: ConfidenceTag,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SemanticBlock {
    pub instrs: Vec<SemanticInstr>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SemanticFunction {
    pub blocks: BTreeMap<usize, SemanticBlock>,
}
