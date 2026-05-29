use crate::SdbEntry;

#[derive(Debug, Clone)]
pub enum RefinementAction {
    RenameSymbol {
        address: u64,
        old_name: String,
        new_name: String,
    },
    UpdateSignature {
        address: u64,
        param_count: usize,
        param_types: Vec<String>,
    },
    UpdateVariableType {
        fn_address: u64,
        var_name: String,
        new_type: String,
    },
}

#[derive(Debug, Clone)]
pub struct FeedbackEntry {
    pub description: String,
    pub action: RefinementAction,
}

#[derive(Default)]
pub struct FeedbackNamespace {
    pub feedback_queue: Vec<SdbEntry<FeedbackEntry>>,
}
