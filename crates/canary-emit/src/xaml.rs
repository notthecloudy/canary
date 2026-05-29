//! Hierarchical XAML Tree Synthesizer & Namespace Normalizer
//!
//! Reconstructs hierarchical visual DOM trees from flat XBF node streams
//! and integrates dynamic probabilistic data-bindings into standard XML markup.

use crate::error::EmitError;
use canary_analysis::ui_binding::BindingEdge;
use canary_loader::xbf::XbfNode;
use indexmap::IndexMap;

/// In-memory DOM-like representation of a XAML UI element.
#[derive(Debug, Clone)]
pub struct XamlElement {
    pub name: String,
    pub namespace_uri: Option<String>,
    pub attributes: IndexMap<String, String>,
    pub children: Vec<XamlElement>,
    pub text_content: Option<String>,
}

impl XamlElement {
    pub fn new(name: String, namespace_uri: Option<String>) -> Self {
        Self {
            name,
            namespace_uri,
            attributes: IndexMap::new(),
            children: Vec::new(),
            text_content: None,
        }
    }
}

pub struct XamlSynthesizer;

impl XamlSynthesizer {
    /// Validates if the Semantic Database meets all confidence thresholds to safely proceed with binding projection.
    pub fn check_stabilization_gate(sdb: &canary_sdb::SemanticDatabase) -> bool {
        // ViewModel Class Confidence >= 0.85
        let max_class_confidence = sdb
            .interpretations
            .types
            .classes
            .iter()
            .map(|c| c.confidence.composite())
            .fold(0.0f32, f32::max);

        // Call Graph Stability Score >= 0.90
        let total_discovered = sdb.interpretations.functions.functions.len();
        let total_analyzed = sdb
            .interpretations
            .functions
            .functions
            .iter()
            .filter(|(_, f)| f.value.mlil_complete)
            .count();
        let stability_score = if total_discovered > 0 {
            total_analyzed as f32 / total_discovered as f32
        } else {
            1.0
        };

        // Vtable/RTTI Target Alignment >= 0.80
        let mut total_methods = 0;
        let mut aligned_methods = 0;
        for class_entry in &sdb.interpretations.types.classes {
            for method in &class_entry.value.methods {
                total_methods += 1;
                if method.slot.is_some() {
                    aligned_methods += 1;
                }
            }
        }
        let alignment_score = if total_methods > 0 {
            aligned_methods as f32 / total_methods as f32
        } else {
            1.0
        };

        tracing::info!(
            "Semantic Stabilization Gate check: MaxClassConfidence={:.2} (threshold 0.85), StabilityScore={:.2} (threshold 0.90), AlignmentScore={:.2} (threshold 0.80)",
            max_class_confidence, stability_score, alignment_score
        );

        max_class_confidence >= 0.85 && stability_score >= 0.90 && alignment_score >= 0.80
    }

    /// Builds a hierarchical XamlElement DOM tree from a flat sequence of XbfNode tokens.
    pub fn build_tree(nodes: &[XbfNode]) -> Result<XamlElement, EmitError> {
        let mut stack: Vec<XamlElement> = Vec::new();
        let mut root: Option<XamlElement> = None;
        let mut namespace_declarations = Vec::new();

        for node in nodes {
            match node {
                XbfNode::NamespaceDeclaration { prefix, uri } => {
                    namespace_declarations.push((prefix.clone(), uri.clone()));
                }
                XbfNode::ElementStart {
                    type_name,
                    namespace_uri,
                } => {
                    let element = XamlElement::new(type_name.clone(), namespace_uri.clone());
                    stack.push(element);
                }
                XbfNode::ElementEnd => {
                    if let Some(mut completed) = stack.pop() {
                        // Apply accumulated namespace declarations to the root element
                        if stack.is_empty() {
                            for (prefix, uri) in &namespace_declarations {
                                let attr_name = if prefix.is_empty() {
                                    "xmlns".to_string()
                                } else {
                                    format!("xmlns:{}", prefix)
                                };
                                completed.attributes.insert(attr_name, uri.clone());
                            }
                            root = Some(completed);
                        } else {
                            // Append as child to parent
                            let parent_idx = stack.len() - 1;
                            stack[parent_idx].children.push(completed);
                        }
                    } else {
                        return Err(EmitError::Failed {
                            reason: "Unexpected ElementEnd opcode without matching Start"
                                .to_string(),
                        });
                    }
                }
                XbfNode::AddProperty { name, value, .. } => {
                    if let Some(top) = stack.last_mut() {
                        top.attributes.insert(name.clone(), value.clone());
                    } else {
                        return Err(EmitError::Failed {
                            reason: format!(
                                "Orphaned property '{}={}' encountered outside element scope",
                                name, value
                            ),
                        });
                    }
                }
                XbfNode::Text(val) => {
                    if let Some(top) = stack.last_mut() {
                        top.text_content = Some(val.clone());
                    } else {
                        return Err(EmitError::Failed {
                            reason: format!(
                                "Orphaned text content '{}' encountered outside element scope",
                                val
                            ),
                        });
                    }
                }
            }
        }

        root.ok_or_else(|| EmitError::Failed {
            reason: "No root element found in XBF node stream".to_string(),
        })
    }

    /// Emits a standard XML formatted XAML string, enriching elements with inferred data bindings.
    pub fn synthesize(root: &XamlElement, bindings: &[BindingEdge]) -> Result<String, EmitError> {
        let mut xaml = String::new();
        Self::emit_element(root, &mut xaml, 0, bindings)?;
        Ok(xaml)
    }

    fn emit_element(
        element: &XamlElement,
        writer: &mut String,
        indent_level: usize,
        bindings: &[BindingEdge],
    ) -> Result<(), EmitError> {
        let indent = "  ".repeat(indent_level);
        writer.push_str(&indent);
        writer.push('<');
        writer.push_str(&element.name);

        // Map and enrich dynamic data bindings based on control names
        let mut attributes = element.attributes.clone();
        let control_name = attributes
            .get("x:Name")
            .or_else(|| attributes.get("Name"))
            .cloned();

        if let Some(ref name) = control_name {
            // Check if we have inferred bindings targeting this control
            for binding in bindings {
                if binding.control_name == *name {
                    // Enrich element with data-binding attributes
                    let binding_expression = format!("{{x:Bind {}}}", binding.target_property);
                    attributes.insert(binding.control_property.clone(), binding_expression);
                }
            }
        }

        // Format and sort attributes for standard clean ordering:
        // x:Class/xmlns declarations first, then Names, then Properties/Bindings
        let mut sorted_attrs: Vec<(&String, &String)> = attributes.iter().collect();
        sorted_attrs.sort_by(|a, b| {
            let is_ns_a = a.0.starts_with("xmlns") || a.0 == "x:Class";
            let is_ns_b = b.0.starts_with("xmlns") || b.0 == "x:Class";
            if is_ns_a && !is_ns_b {
                std::cmp::Ordering::Less
            } else if !is_ns_a && is_ns_b {
                std::cmp::Ordering::Greater
            } else {
                a.0.cmp(b.0)
            }
        });

        for (name, val) in sorted_attrs {
            writer.push(' ');
            writer.push_str(name);
            writer.push_str("=\"");
            writer.push_str(&escape_xml_value(val));
            writer.push('"');
        }

        if element.children.is_empty() && element.text_content.is_none() {
            writer.push_str(" />\n");
        } else {
            writer.push_str(">\n");

            if let Some(ref text) = element.text_content {
                let text_indent = "  ".repeat(indent_level + 1);
                writer.push_str(&text_indent);
                writer.push_str(&escape_xml_value(text));
                writer.push('\n');
            }

            for child in &element.children {
                Self::emit_element(child, writer, indent_level + 1, bindings)?;
            }

            writer.push_str(&indent);
            writer.push_str("</");
            writer.push_str(&element.name);
            writer.push_str(">\n");
        }

        Ok(())
    }
}

fn escape_xml_value(val: &str) -> String {
    val.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_analysis::ui_binding::BindingEvidence;

    #[test]
    fn test_xaml_synthesis_flow() {
        // 1. Build flat mock XBF node stream
        let nodes = vec![
            XbfNode::NamespaceDeclaration {
                prefix: "".to_string(),
                uri: "http://schemas.microsoft.com/winfx/2006/xaml/presentation".to_string(),
            },
            XbfNode::NamespaceDeclaration {
                prefix: "x".to_string(),
                uri: "http://schemas.microsoft.com/winfx/2006/xaml".to_string(),
            },
            XbfNode::ElementStart {
                type_name: "Page".to_string(),
                namespace_uri: None,
            },
            XbfNode::AddProperty {
                name: "x:Class".to_string(),
                value: "CalculatorApp.MainPage".to_string(),
                namespace_uri: None,
            },
            XbfNode::ElementStart {
                type_name: "Grid".to_string(),
                namespace_uri: None,
            },
            XbfNode::ElementStart {
                type_name: "Button".to_string(),
                namespace_uri: None,
            },
            XbfNode::AddProperty {
                name: "x:Name".to_string(),
                value: "NumberPadButton".to_string(),
                namespace_uri: None,
            },
            XbfNode::AddProperty {
                name: "Content".to_string(),
                value: "7".to_string(),
                namespace_uri: None,
            },
            XbfNode::ElementEnd, // Button
            XbfNode::ElementStart {
                type_name: "TextBlock".to_string(),
                namespace_uri: None,
            },
            XbfNode::AddProperty {
                name: "x:Name".to_string(),
                value: "DisplayValueTextBox".to_string(),
                namespace_uri: None,
            },
            XbfNode::Text("Result text".to_string()),
            XbfNode::ElementEnd, // TextBlock
            XbfNode::ElementEnd, // Grid
            XbfNode::ElementEnd, // Page
        ];

        // 2. Build DOM visual tree
        let root = XamlSynthesizer::build_tree(&nodes).expect("Failed to build XamlElement tree");
        assert_eq!(root.name, "Page");
        assert_eq!(root.children.len(), 1); // Grid
        assert_eq!(root.children[0].children.len(), 2); // Button and TextBlock

        // 3. Inject mock inferred bindings
        let bindings = vec![
            BindingEdge {
                control_id: 101,
                control_name: "DisplayValueTextBox".to_string(),
                control_property: "Text".to_string(),
                target_viewmodel: "StandardCalculatorViewModel".to_string(),
                target_property: "DisplayValue".to_string(),
                confidence: 0.98,
                evidence: vec![BindingEvidence::StringConstant("DisplayValue".to_string())],
            },
            BindingEdge {
                control_id: 102,
                control_name: "NumberPadButton".to_string(),
                control_property: "Command".to_string(),
                target_viewmodel: "StandardCalculatorViewModel".to_string(),
                target_property: "OnNumberClick".to_string(),
                confidence: 0.96,
                evidence: vec![BindingEvidence::PropertyAccessPattern],
            },
        ];

        // 4. Synthesize final clean XAML string
        let xaml =
            XamlSynthesizer::synthesize(&root, &bindings).expect("Failed to synthesize XAML");
        println!("Synthesized XML:\n{}", xaml);

        // Verify well-formed XML elements
        assert!(xaml.contains("<Page x:Class=\"CalculatorApp.MainPage\" xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\">"));
        assert!(xaml.contains("<Button Command=\"{x:Bind OnNumberClick}\" Content=\"7\" x:Name=\"NumberPadButton\" />"));
        assert!(xaml
            .contains("<TextBlock Text=\"{x:Bind DisplayValue}\" x:Name=\"DisplayValueTextBox\">"));
        assert!(xaml.contains("Result text"));
    }

    #[test]
    fn test_semantic_stabilization_gate() {
        use canary_sdb::functions::SdbFunction;
        use canary_sdb::types::{SdbClass, SdbMethod};
        use canary_sdb::{RecoveryOrigin, SdbEntry, SemanticDatabase};

        // Case 1: Empty SDB (should fail because max class confidence is 0.0)
        let empty_sdb = SemanticDatabase::new();
        assert!(!XamlSynthesizer::check_stabilization_gate(&empty_sdb));

        // Case 2: High-confidence ViewModel and stable CallGraph / Vtable alignment (should pass)
        let mut sdb = SemanticDatabase::new();

        // 1. Add class with high confidence 0.95
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
            bases: vec![],
        };
        sdb.interpretations.types.classes.push(SdbEntry::new(
            class,
            canary_sdb::ConfidenceVector::base(0.95),
            RecoveryOrigin::Exact,
        ));

        // 2. Add stable function with mlil_complete = true
        let mut func = SdbFunction {
            entry_addr: 0x180005020,
            ..Default::default()
        };
        func.mlil_complete = true;
        sdb.interpretations.functions.functions.insert(
            0x180005020,
            SdbEntry::new(
                func,
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ),
        );

        assert!(XamlSynthesizer::check_stabilization_gate(&sdb));
    }
}
