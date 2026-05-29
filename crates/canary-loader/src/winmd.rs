//! CLI Metadata (.winmd) Parser
//!
//! Parses WinRT metadata files using the `windows-metadata` crate.

use crate::error::LoaderError;
use windows_metadata::reader::{File, TypeIndex};

#[derive(Debug, Clone)]
pub struct WinRtParam {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct WinRtMethod {
    pub name: String,
    pub params: Vec<WinRtParam>,
    pub return_ty: String,
}

#[derive(Debug, Clone)]
pub struct WinRtProperty {
    pub name: String,
    pub ty: String,
    pub has_getter: bool,
    pub has_setter: bool,
}

#[derive(Debug, Clone)]
pub struct WinRtClass {
    pub namespace: String,
    pub name: String,
    pub methods: Vec<WinRtMethod>,
    pub properties: Vec<WinRtProperty>,
}

#[derive(Debug, Clone)]
pub struct WinRtInterface {
    pub namespace: String,
    pub name: String,
    pub methods: Vec<WinRtMethod>,
    pub parent_interface: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WinRtMetadata {
    pub classes: Vec<WinRtClass>,
    pub interfaces: Vec<WinRtInterface>,
}

pub struct WinMdParser;

impl WinMdParser {
    pub fn parse(bytes: &[u8]) -> Result<WinRtMetadata, LoaderError> {
        let file = File::new(bytes.to_vec())
            .ok_or_else(|| LoaderError::Parse("Failed to load WinMD file bytes".to_string()))?;
        let index = TypeIndex::new(vec![file]);

        let mut classes = Vec::new();
        let mut interfaces = Vec::new();

        for def in index.types() {
            let namespace = def.namespace().to_string();
            let name = def.name().to_string();

            // Check extends
            let extends = def.extends();

            let mut methods = Vec::new();
            for method in def.methods() {
                let m_name = method.name().to_string();
                let sig = method.signature(&[]);

                let mut params = Vec::new();
                let method_params: Vec<_> = method.params().collect();

                // Pair parameters with their types from the signature
                for (i, param) in method_params.iter().enumerate() {
                    let p_name = param.name().to_string();
                    let p_ty = if i < sig.types.len() {
                        format!("{:?}", sig.types[i])
                    } else {
                        "unknown".to_string()
                    };
                    params.push(WinRtParam {
                        name: p_name,
                        ty: p_ty,
                    });
                }

                let return_ty = format!("{:?}", sig.return_type);

                methods.push(WinRtMethod {
                    name: m_name,
                    params,
                    return_ty,
                });
            }

            // A simple interface check: if extends is None, or contains "Interface"
            // Typically interfaces extend nothing or extend IInspectable/IUnknown (extends is null in TypeDef).
            // Classes usually extend some other class (like System.Object or Windows.UI.Xaml.DependencyObject).
            let is_interface = extends.is_none();

            if is_interface {
                interfaces.push(WinRtInterface {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    methods,
                    parent_interface: None,
                });
            } else {
                classes.push(WinRtClass {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    methods,
                    properties: Vec::new(),
                });
            }
        }

        Ok(WinRtMetadata {
            classes,
            interfaces,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_winmd() {
        let bytes = fs::read("../../CalculatorApp.ViewModel.winmd").expect("Failed to read winmd");
        let metadata = WinMdParser::parse(&bytes).expect("Failed to parse winmd");
        println!(
            "Loaded metadata: {} classes, {} interfaces",
            metadata.classes.len(),
            metadata.interfaces.len()
        );

        // Print out standard view model to verify
        if let Some(vm) = metadata
            .classes
            .iter()
            .find(|c| c.name == "StandardCalculatorViewModel")
        {
            println!("Class: {}.{}", vm.namespace, vm.name);
            for m in &vm.methods {
                println!("  Method: {} -> {}", m.name, m.return_ty);
                for p in &m.params {
                    println!("    Param: {}: {}", p.name, p.ty);
                }
            }
        }
    }
}
