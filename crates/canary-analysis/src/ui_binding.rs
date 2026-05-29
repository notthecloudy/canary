//! UI Behavior Graph (UBG) & Bayesian Binding Inference Engine
//!
//! Reconstructs dynamic UI control layouts and VM data-bindings universally
//! from native assembly semantics, memory offsets, and metadata without relying on raw XAML files.

use indexmap::{IndexMap, IndexSet};

/// Supported UWP control types recovered from runtime patterns or class metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UiNodeType {
    TextBox,
    Button,
    Label,
    ListView,
    CheckBox,
    Custom(String),
}

/// Dynamic value types held by UI nodes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UiValue {
    Text(String),
    Boolean(bool),
    Integer(i64),
    Float(String),
}

/// Abstract representation of a recovered UI control.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UiNode {
    pub id: u64,
    pub node_type: UiNodeType,
    pub name: String,
    pub properties: IndexMap<String, UiValue>,
}

/// Dynamic relationships connecting controls to event handlers or properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UiRelation {
    EventHandler,  // e.g. click -> triggers native function call
    DataBinding,   // e.g. text <- synchronized with VM property
    TemplateChild, // e.g. nested hierarchy
    FocusChain,    // e.g. tab order
}

/// Directed edge representing dynamic control-to-control or control-to-VM boundaries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UiEdge {
    pub from: u64,
    pub to: u64,
    pub relation: UiRelation,
    pub property_name: Option<String>,
}

/// UI Behavior Graph (UBG) — stores recovered visual nodes and dynamic edges.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UiBehaviorGraph {
    pub nodes: IndexMap<u64, UiNode>,
    pub edges: Vec<UiEdge>,
}

impl UiBehaviorGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: UiNode) {
        self.nodes.insert(node.id, node);
    }

    pub fn add_edge(&mut self, edge: UiEdge) {
        self.edges.push(edge);
    }
}

/// Behavioral evidence supporting a recovered VM dynamic binding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BindingEvidence {
    StringConstant(String), // Found wide string matching property name (e.g. "Expression")
    PropertyAccessPattern,  // Code uses direct get_/set_ pattern on vtable slot
    VtableSlotIndex(usize), // Slot matches unstripped WinRT signature slot
    RuntimeActivationTrace(u64), // Runtime traced constructor factory allocation address
}

impl BindingEvidence {
    /// Returns the prior probability score for this evidence signal family.
    pub fn prior_score(&self) -> f32 {
        match self {
            Self::RuntimeActivationTrace(_) => 0.95,
            Self::StringConstant(_) => 0.75,
            Self::PropertyAccessPattern => 0.65,
            Self::VtableSlotIndex(_) => 0.60,
        }
    }
}

/// Probabilistic dynamic binding mapping a control property to a ViewModel property.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BindingEdge {
    pub control_id: u64,
    pub control_name: String,
    pub control_property: String,
    pub target_viewmodel: String,
    pub target_property: String,
    pub confidence: f32,
    pub evidence: Vec<BindingEvidence>,
}

/// Bayesian Binding Inference Engine.
/// Converges on dynamic binding facts using independent evidence signals without XAML files.
pub struct BindingInferenceEngine;

impl BindingInferenceEngine {
    /// Infers all dynamic bindings by fusing the UBG and the Semantic Database.
    pub fn infer_bindings(
        &self,
        ubg: &UiBehaviorGraph,
        sdb: &canary_sdb::SemanticDatabase,
    ) -> Vec<BindingEdge> {
        let mut inferred = Vec::new();

        // 1. Map VM properties dynamically by querying SDB function table
        let mut vm_properties = IndexMap::new();
        for class_entry in &sdb.interpretations.types.classes {
            let class = &class_entry.value;
            let mut props = IndexSet::new();
            for method in &class.methods {
                if let Some(f_entry) = sdb.interpretations.functions.functions.get(&method.fn_addr)
                {
                    if let Some(ref m_name) = f_entry.value.name {
                        if m_name.starts_with("get_") || m_name.starts_with("set_") {
                            let prop = m_name[4..].to_string();
                            props.insert(prop);
                        }
                    }
                }
            }
            if !props.is_empty() {
                vm_properties.insert(class.name.clone(), props);
            }
        }

        // 2. Iterate through UI nodes to search for dynamic correlation signals
        for (&node_id, node) in &ubg.nodes {
            let control_prop = match node.node_type {
                UiNodeType::TextBox => "Text".to_string(),
                UiNodeType::Button => "Command".to_string(),
                UiNodeType::Label => "Content".to_string(),
                _ => "Value".to_string(),
            };

            for (vm_name, props) in &vm_properties {
                for prop in props {
                    let mut evidence = Vec::new();

                    // Signal A: String match on control names or properties
                    if node.name.to_lowercase().contains(&prop.to_lowercase()) {
                        evidence.push(BindingEvidence::StringConstant(prop.clone()));
                    }

                    // Signal B: Check direct vtable slots mapped in the SDB
                    if let Some(class_entry) = sdb
                        .interpretations
                        .types
                        .classes
                        .iter()
                        .find(|c| c.value.name == *vm_name)
                    {
                        for method in &class_entry.value.methods {
                            if let Some(f_entry) =
                                sdb.interpretations.functions.functions.get(&method.fn_addr)
                            {
                                if let Some(ref m_name) = f_entry.value.name {
                                    if m_name.contains(prop) {
                                        evidence.push(BindingEvidence::PropertyAccessPattern);
                                        if let Some(slot) = method.slot {
                                            evidence.push(BindingEvidence::VtableSlotIndex(slot));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Signal C: Event handler target function tracking
                    for edge in &ubg.edges {
                        if edge.from == node_id && edge.relation == UiRelation::EventHandler {
                            evidence.push(BindingEvidence::RuntimeActivationTrace(edge.to));
                        }
                    }

                    if !evidence.is_empty() {
                        // Compute Bayesian fused score: P(Binding) = 1 - Prod(1 - S_i)
                        let mut product = 1.0;
                        for ev in &evidence {
                            product *= 1.0 - ev.prior_score();
                        }
                        let confidence = 1.0 - product;

                        inferred.push(BindingEdge {
                            control_id: node_id,
                            control_name: node.name.clone(),
                            control_property: control_prop.clone(),
                            target_viewmodel: vm_name.clone(),
                            target_property: prop.clone(),
                            confidence,
                            evidence,
                        });
                    }
                }
            }
        }

        // Sort by confidence descending
        inferred.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        inferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::functions::{SdbCallSignature, SdbFunction};
    use canary_sdb::types::{SdbClass, SdbMethod};
    use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

    #[test]
    fn test_headless_binding_inference() {
        let mut ubg = UiBehaviorGraph::new();

        // 1. Add textbox UI control
        let mut properties = IndexMap::new();
        properties.insert(
            "Text".to_string(),
            UiValue::Text("Invalid input".to_string()),
        );
        ubg.add_node(UiNode {
            id: 101,
            node_type: UiNodeType::TextBox,
            name: "DisplayValueTextBox".to_string(),
            properties,
        });

        // 2. Add dynamic event handler edge
        ubg.add_edge(UiEdge {
            from: 101,
            to: 0x180005020,
            relation: UiRelation::EventHandler,
            property_name: Some("OnClick".to_string()),
        });

        // 3. Create mock Semantic Database
        let mut sdb = SemanticDatabase::new();

        // Add recovered class
        let class = SdbClass {
            name: "CalculatorApp.ViewModel.StandardCalculatorViewModel".to_string(),
            vtables: vec![0x180100000],
            methods: vec![SdbMethod {
                fn_addr: 0x180005020,
                class_vtable: 0x180100000,
                is_virtual: true,
                slot: Some(8),
                is_ctor: false,
                is_dtor: false,
            }],
            bases: vec!["IInspectable".to_string()],
        };
        sdb.interpretations.types.classes.push(SdbEntry::new(
            class,
            canary_sdb::ConfidenceVector::base(0.95),
            RecoveryOrigin::Exact,
        ));

        // Add method to SDB functions
        let func = SdbFunction {
            entry_addr: 0x180005020,
            name: Some("get_DisplayValue".to_string()),
            size: None,
            cfg_blocks: vec![],
            ssa: None,
            vsa: None,
            stack_frame: None,
            call_signature: Some(SdbEntry::new(
                SdbCallSignature {
                    return_ty: "winrt::hstring".to_string(),
                    params: vec![],
                    calling_conv: "win64 thiscall".to_string(),
                    is_variadic: false,
                    noreturn: false,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            )),
            high_level_cfg: None,
            xrefs_out: vec![],
            inferred_call_targets: vec![],
            mlil_complete: true,
            ..Default::default()
        };
        sdb.interpretations.functions.functions.insert(
            0x180005020,
            SdbEntry::new(
                func,
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );

        // 4. Run Bayesian Inference Engine
        let engine = BindingInferenceEngine;
        let bindings = engine.infer_bindings(&ubg, &sdb);

        assert!(!bindings.is_empty());
        let best_match = &bindings[0];

        assert_eq!(best_match.control_name, "DisplayValueTextBox");
        assert_eq!(
            best_match.target_viewmodel,
            "CalculatorApp.ViewModel.StandardCalculatorViewModel"
        );
        assert_eq!(best_match.target_property, "DisplayValue");

        // Verify Bayesian score fusion is greater than any individual prior
        assert!(best_match.confidence > 0.95);
        println!(
            "Headless UI Binding inferred successfully! Confidence: {:.4}",
            best_match.confidence
        );
    }
}
