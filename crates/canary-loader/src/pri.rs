//! Package Resource Index (.pri) Parser
//!
//! Universally extracts strings, assets, and compiled XBF UI trees from
//! UWP resources.pri files using official MakePri tooling and high-fidelity parsing.

use crate::error::LoaderError;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriString {
    pub name: String,
    pub value: String,
    pub language: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriAsset {
    pub name: String,
    pub path: String,
    pub qualifiers: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriXbf {
    pub name: String,
    pub base64_data: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriResources {
    pub strings: Vec<PriString>,
    pub assets: Vec<PriAsset>,
    pub xbfs: Vec<PriXbf>,
}

pub struct PriParser;

impl PriParser {
    /// Attempts to dynamically resolve MakePri.exe in the standard PATH or standard Windows SDK directories.
    pub fn find_makepri() -> Option<PathBuf> {
        // 1. Try standard system path first
        if let Ok(output) = Command::new("makepri.exe").arg("/?").output() {
            if output.status.success() {
                return Some(PathBuf::from("makepri.exe"));
            }
        }

        // 2. Scan typical Windows Kits SDK installation directories
        let kits_base = Path::new("C:\\Program Files (x86)\\Windows Kits\\10\\bin");
        if kits_base.exists() {
            if let Ok(entries) = fs::read_dir(kits_base) {
                // Find directories corresponding to SDK versions (e.g. 10.0.26100.0)
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let path = entry.path();
                        // Search architecture directories
                        for arch in &["x64", "arm64", "x86"] {
                            let makepri_path = path.join(arch).join("makepri.exe");
                            if makepri_path.exists() {
                                return Some(makepri_path);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub fn dump_pri(pri_path: &Path, xml_path: &Path) -> Result<(), LoaderError> {
        let makepri = match Self::find_makepri() {
            Some(path) => path,
            None => {
                eprintln!("\n⚠️  WARNING: MakePri.exe was not found!");
                eprintln!("This SDK utility is required to decompile and reconstruct the UWP Package Resource Index (resources.pri).");
                eprintln!("\n💡 How and where to get it:");
                eprintln!("1. Download the official Microsoft Windows 10/11 SDK:");
                eprintln!(
                    "   👉 https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
                );
                eprintln!("2. During SDK installation, ensure you check 'Windows SDK Signing Tools for Desktop Apps'");
                eprintln!("   and 'Windows Software Development Kit' options.");
                eprintln!("3. MakePri.exe will be installed under: C:\\Program Files (x86)\\Windows Kits\\10\\bin\\<version>\\x64\\makepri.exe");

                eprintln!("\n❓ Would you like to proceed in fallback mode (skipping resources/XAML extraction)?");
                eprint!("👉 Continue with fallback? [y/N]: ");
                use std::io::{self, Write};
                let _ = io::stderr().flush();

                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_ok() {
                    let ans = input.trim().to_lowercase();
                    if ans == "y" || ans == "yes" {
                        eprintln!("Proceeding in fallback mode. Resource maps and UI layouts will be empty.");
                        let empty_skeleton = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<PriInfo>
  <ResourceMap name="Fallback" version="1.0" primary="true">
  </ResourceMap>
</PriInfo>"#;
                        if fs::write(xml_path, empty_skeleton).is_ok() {
                            return Ok(());
                        }
                    }
                }

                return Err(LoaderError::Parse(
                    "MakePri.exe is missing and required for resource recovery.".to_string(),
                ));
            }
        };

        let output = Command::new(&makepri)
            .arg("dump")
            .arg("/if")
            .arg(pri_path)
            .arg("/of")
            .arg(xml_path)
            .arg("/dt")
            .arg("Detailed")
            .arg("/o") // Overwrite output file if it exists
            .output()
            .map_err(|e| LoaderError::Parse(format!("Failed to execute MakePri.exe: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LoaderError::Parse(format!(
                "MakePri.exe failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr
            )));
        }

        Ok(())
    }

    /// Parses the XML output generated by MakePri.exe to recover strings, assets, and XBF layouts.
    pub fn parse_xml(xml_path: &Path) -> Result<PriResources, LoaderError> {
        let content = fs::read_to_string(xml_path).map_err(|e| {
            LoaderError::Parse(format!("Failed to read temporary PRI XML file: {}", e))
        })?;

        let mut strings = Vec::new();
        let mut assets = Vec::new();
        let mut xbfs = Vec::new();

        let mut current_subtree = String::new();
        let mut current_resource_name = String::new();
        let mut current_resource_uri = String::new();

        // High-performance parser state
        let mut in_named_resource = false;
        let mut in_candidate = false;
        let mut candidate_qualifiers = String::new();
        let mut candidate_is_default = false;
        let mut candidate_type = String::new();

        let mut in_value = false;
        let mut in_base64_value = false;

        let mut value_buffer = String::new();
        let mut base64_buffer = String::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("<ResourceMapSubtree name=\"") {
                if let Some(name) = extract_attribute(trimmed, "name") {
                    current_subtree = name;
                }
            } else if trimmed.starts_with("</ResourceMapSubtree>") {
                current_subtree.clear();
            } else if trimmed.starts_with("<NamedResource name=\"") {
                if let Some(name) = extract_attribute(trimmed, "name") {
                    current_resource_name = name;
                }
                if let Some(uri) = extract_attribute(trimmed, "uri") {
                    current_resource_uri = uri;
                }
                in_named_resource = true;
            } else if trimmed.starts_with("</NamedResource>") {
                current_resource_name.clear();
                current_resource_uri.clear();
                in_named_resource = false;
            } else if trimmed.starts_with("<Candidate ") && in_named_resource {
                candidate_qualifiers = extract_attribute(trimmed, "qualifiers").unwrap_or_default();
                candidate_is_default = extract_attribute(trimmed, "isDefault")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                candidate_type = extract_attribute(trimmed, "type").unwrap_or_default();
                in_candidate = !trimmed.ends_with("/>");
            } else if trimmed.starts_with("</Candidate>") {
                in_candidate = false;
            } else if trimmed.starts_with("<Qualifier ") && in_candidate {
                if let (Some(q_name), Some(q_val)) = (
                    extract_attribute(trimmed, "name"),
                    extract_attribute(trimmed, "value"),
                ) {
                    if !candidate_qualifiers.is_empty() {
                        candidate_qualifiers.push(',');
                    }
                    candidate_qualifiers.push_str(&format!("{}-{}", q_name, q_val));
                }
            } else if trimmed.starts_with("<Value>") {
                in_value = true;
                value_buffer.clear();
                if trimmed.ends_with("</Value>") {
                    let inside = trimmed
                        .strip_prefix("<Value>")
                        .unwrap()
                        .strip_suffix("</Value>")
                        .unwrap();
                    value_buffer.push_str(inside);
                    in_value = false;
                    self::process_candidate(
                        &current_subtree,
                        &current_resource_name,
                        &current_resource_uri,
                        &candidate_type,
                        &candidate_qualifiers,
                        candidate_is_default,
                        &value_buffer,
                        &mut strings,
                        &mut assets,
                    );
                }
            } else if trimmed.starts_with("<Base64Value>") {
                in_base64_value = true;
                base64_buffer.clear();
                if trimmed.ends_with("</Base64Value>") {
                    let inside = trimmed
                        .strip_prefix("<Base64Value>")
                        .unwrap()
                        .strip_suffix("</Base64Value>")
                        .unwrap();
                    base64_buffer.push_str(inside);
                    in_base64_value = false;

                    if current_resource_name.ends_with(".xbf") {
                        xbfs.push(PriXbf {
                            name: current_resource_name.clone(),
                            base64_data: base64_buffer.clone(),
                        });
                    }
                }
            } else if trimmed.starts_with("</Value>") {
                in_value = false;
                self::process_candidate(
                    &current_subtree,
                    &current_resource_name,
                    &current_resource_uri,
                    &candidate_type,
                    &candidate_qualifiers,
                    candidate_is_default,
                    &value_buffer,
                    &mut strings,
                    &mut assets,
                );
            } else if trimmed.starts_with("</Base64Value>") {
                in_base64_value = false;
                if current_resource_name.ends_with(".xbf") {
                    xbfs.push(PriXbf {
                        name: current_resource_name.clone(),
                        base64_data: base64_buffer.clone(),
                    });
                }
            } else {
                // Buffer accumulation for multi-line values
                if in_value {
                    if !value_buffer.is_empty() {
                        value_buffer.push('\n');
                    }
                    value_buffer.push_str(trimmed);
                } else if in_base64_value {
                    base64_buffer.push_str(trimmed);
                }
            }
        }

        Ok(PriResources {
            strings,
            assets,
            xbfs,
        })
    }

    /// Synthesizes standard Microsoft UWP localized resource tables (.resw) for each language.
    pub fn write_resw_files(
        resources: &PriResources,
        output_dir: &Path,
    ) -> Result<Vec<PathBuf>, LoaderError> {
        let mut language_groups = indexmap::IndexMap::new();

        for item in &resources.strings {
            let lang = if item.language.is_empty() {
                "en-US".to_string()
            } else {
                item.language.to_uppercase()
            };
            language_groups
                .entry(lang)
                .or_insert_with(Vec::new)
                .push(item);
        }

        let mut generated = Vec::new();

        for (lang, items) in language_groups {
            let lang_dir = output_dir.join(&lang);
            fs::create_dir_all(&lang_dir).map_err(|e| {
                LoaderError::Parse(format!(
                    "Failed to create directory {}: {}",
                    lang_dir.display(),
                    e
                ))
            })?;

            let resw_path = lang_dir.join("Resources.resw");
            let mut xml = String::new();
            xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
            xml.push_str("<root>\n");
            xml.push_str("  <xsd:schema id=\"root\" xmlns=\"\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\">\n");
            xml.push_str("    <xsd:import namespace=\"http://www.w3.org/XML/1998/namespace\" />\n");
            xml.push_str("    <xsd:element name=\"root\" msdata:IsDataSet=\"true\">\n");
            xml.push_str("      <xsd:complexType>\n");
            xml.push_str("        <xsd:choice maxOccurs=\"unbounded\">\n");
            xml.push_str("          <xsd:element name=\"metadata\">\n");
            xml.push_str("            <xsd:complexType>\n");
            xml.push_str("              <xsd:sequence>\n");
            xml.push_str("                <xsd:element name=\"value\" type=\"xsd:string\" minOccurs=\"0\" />\n");
            xml.push_str("              </xsd:sequence>\n");
            xml.push_str("              <xsd:attribute name=\"name\" use=\"required\" type=\"xsd:string\" />\n");
            xml.push_str("              <xsd:attribute name=\"type\" type=\"xsd:string\" />\n");
            xml.push_str("              <xsd:attribute name=\"mimetype\" type=\"xsd:string\" />\n");
            xml.push_str("              <xsd:attribute ref=\"xml:space\" />\n");
            xml.push_str("            </xsd:complexType>\n");
            xml.push_str("          </xsd:element>\n");
            xml.push_str("          <xsd:element name=\"assembly\">\n");
            xml.push_str("            <xsd:complexType>\n");
            xml.push_str("              <xsd:attribute name=\"alias\" type=\"xsd:string\" />\n");
            xml.push_str("              <xsd:attribute name=\"name\" type=\"xsd:string\" />\n");
            xml.push_str("            </xsd:complexType>\n");
            xml.push_str("          </xsd:element>\n");
            xml.push_str("          <xsd:element name=\"data\">\n");
            xml.push_str("            <xsd:complexType>\n");
            xml.push_str("              <xsd:sequence>\n");
            xml.push_str("                <xsd:element name=\"value\" type=\"xsd:string\" minOccurs=\"0\" msdata:Ordinal=\"0\" />\n");
            xml.push_str("                <xsd:element name=\"comment\" type=\"xsd:string\" minOccurs=\"0\" msdata:Ordinal=\"1\" />\n");
            xml.push_str("              </xsd:sequence>\n");
            xml.push_str("              <xsd:attribute name=\"name\" type=\"xsd:string\" use=\"required\" msdata:Ordinal=\"1\" />\n");
            xml.push_str("              <xsd:attribute name=\"type\" type=\"xsd:string\" msdata:Ordinal=\"3\" />\n");
            xml.push_str("              <xsd:attribute name=\"mimetype\" type=\"xsd:string\" msdata:Ordinal=\"4\" />\n");
            xml.push_str("              <xsd:attribute ref=\"xml:space\" />\n");
            xml.push_str("            </xsd:complexType>\n");
            xml.push_str("          </xsd:element>\n");
            xml.push_str("          <xsd:element name=\"resheader\">\n");
            xml.push_str("            <xsd:complexType>\n");
            xml.push_str("              <xsd:sequence>\n");
            xml.push_str("                <xsd:element name=\"value\" type=\"xsd:string\" minOccurs=\"0\" msdata:Ordinal=\"0\" />\n");
            xml.push_str("              </xsd:sequence>\n");
            xml.push_str("              <xsd:attribute name=\"name\" type=\"xsd:string\" use=\"required\" />\n");
            xml.push_str("            </xsd:complexType>\n");
            xml.push_str("          </xsd:element>\n");
            xml.push_str("        </xsd:choice>\n");
            xml.push_str("      </xsd:complexType>\n");
            xml.push_str("    </xsd:element>\n");
            xml.push_str("  </xsd:schema>\n");
            xml.push_str("  <resheader name=\"resmimetype\">\n");
            xml.push_str("    <value>text/microsoft-resx</value>\n");
            xml.push_str("  </resheader>\n");
            xml.push_str("  <resheader name=\"version\">\n");
            xml.push_str("    <value>2.0</value>\n");
            xml.push_str("  </resheader>\n");
            xml.push_str("  <resheader name=\"reader\">\n");
            xml.push_str("    <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>\n");
            xml.push_str("  </resheader>\n");
            xml.push_str("  <resheader name=\"writer\">\n");
            xml.push_str("    <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>\n");
            xml.push_str("  </resheader>\n");

            for item in items {
                let encoded_val = escape_xml(&item.value);
                xml.push_str(&format!(
                    "  <data name=\"{}\" xml:space=\"preserve\">\n    <value>{}</value>\n  </data>\n",
                    item.name, encoded_val
                ));
            }

            xml.push_str("</root>\n");

            fs::write(&resw_path, xml).map_err(|e| {
                LoaderError::Parse(format!(
                    "Failed to write Resw file {}: {}",
                    resw_path.display(),
                    e
                ))
            })?;

            generated.push(resw_path);
        }

        Ok(generated)
    }
}

fn process_candidate(
    subtree: &str,
    name: &str,
    _uri: &str,
    candidate_type: &str,
    qualifiers: &str,
    is_default: bool,
    value: &str,
    strings: &mut Vec<PriString>,
    assets: &mut Vec<PriAsset>,
) {
    let decoded_val = decode_xml_entities(value);

    if candidate_type == "String" {
        // Parse language qualifier if available (e.g. Language-EN-US or Language-en)
        let mut language = String::new();
        for qual in qualifiers.split(',') {
            if qual.to_lowercase().starts_with("language-") {
                language = qual[9..].to_string();
                break;
            }
        }

        let full_name = if subtree.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", subtree, name)
        };

        strings.push(PriString {
            name: full_name,
            value: decoded_val,
            language,
            is_default,
        });
    } else if candidate_type == "Path" {
        assets.push(PriAsset {
            name: name.to_string(),
            path: decoded_val,
            qualifiers: qualifiers.to_string(),
            is_default,
        });
    }
}

fn extract_attribute(tag: &str, attr: &str) -> Option<String> {
    let search = format!("{}=\"", attr);
    if let Some(start) = tag.find(&search) {
        let after_attr = &tag[start + search.len()..];
        if let Some(end) = after_attr.find('"') {
            return Some(after_attr[..end].to_string());
        }
    }
    None
}

fn decode_xml_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn escape_xml(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_find_makepri() {
        let path = PriParser::find_makepri();
        assert!(path.is_some(), "MakePri.exe must be installed for testing!");
        println!("Resolved MakePri.exe at: {:?}", path.unwrap());
    }

    #[test]
    fn test_parse_pri_flow() {
        let pri_path = Path::new("../../resources.pri");
        let xml_path = Path::new("../../temp_resources.xml");

        if pri_path.exists() {
            PriParser::dump_pri(pri_path, xml_path).expect("Failed to dump PRI to XML");
            assert!(xml_path.exists());

            let resources = PriParser::parse_xml(xml_path).expect("Failed to parse XML resources");
            assert!(
                !resources.strings.is_empty(),
                "Strings should not be empty!"
            );
            assert!(
                !resources.xbfs.is_empty(),
                "XBF visual trees should not be empty!"
            );

            println!(
                "Successfully extracted: {} strings, {} assets, {} XBF visual layouts",
                resources.strings.len(),
                resources.assets.len(),
                resources.xbfs.len()
            );

            // Verify a few key string keys from Calculator
            let has_error_str = resources
                .strings
                .iter()
                .any(|s| s.name.contains("Invalid input") || s.value == "Invalid input");
            assert!(has_error_str, "Should extract standard engine strings!");

            // Test .resw output synthesis
            let output_resw_dir = Path::new("../../temp_resw_output");
            let resw_files = PriParser::write_resw_files(&resources, output_resw_dir)
                .expect("Failed to write RESW files");
            assert!(!resw_files.is_empty());
            println!("Generated .resw files: {:?}", resw_files);

            // Clean up temporary resources
            let _ = fs::remove_file(xml_path);
            let _ = fs::remove_dir_all(output_resw_dir);
        }
    }
}
