//! XBF (XAML Binary Format) Bytecode Decoder
//!
//! Universally parses and decodes compiled XBF binary UI layout streams.

#![allow(dead_code)]

use crate::error::LoaderError;
use crate::xbf_framework_types::{self, PROPERTY_NAMES, TYPE_NAMES};
use indexmap::IndexMap;

/// Node types emitted during flat XBF stream traversal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum XbfNode {
    ElementStart {
        type_name: String,
        namespace_uri: Option<String>,
    },
    ElementEnd,
    AddProperty {
        name: String,
        value: String,
        namespace_uri: Option<String>,
    },
    Text(String),
    NamespaceDeclaration {
        prefix: String,
        uri: String,
    },
}

/// A parsed XBF type reference.
#[derive(Debug, Clone)]
pub struct XbfType {
    pub name: String,
    pub namespace_uri: Option<String>,
}

/// A parsed XBF property reference.
#[derive(Debug, Clone)]
pub struct XbfProperty {
    pub name: String,
    pub namespace_uri: Option<String>,
}

/// Represents an assembly reference within the XBF file.
#[derive(Debug, Clone)]
struct AssemblyEntry {
    kind: u32,
    name_string_idx: u32,
}

/// Represents a type namespace declaration mapping to an assembly.
#[derive(Debug, Clone)]
struct TypeNamespaceEntry {
    assembly_idx: u32,
    name_string_idx: u32,
}

/// Represents a type declaration, potentially with a specific namespace.
#[derive(Debug, Clone)]
struct TypeEntry {
    flags: u32,
    namespace_idx: u32,
    name_string_idx: u32,
}

/// Represents a property declaration linking a name to its parent type.
#[derive(Debug, Clone)]
struct PropertyEntry {
    flags: u32,
    type_idx: u32,
    name_string_idx: u32,
}

/// Represents a positional offset section for the XBF node stream.
#[derive(Debug, Clone)]
struct NodeSectionEntry {
    node_offset: i32,
    positional_offset: i32,
}

/// Intermediate representation of an object decoded from the XBF stream.
#[derive(Debug, Clone)]
struct XbfObject {
    type_name: String,
    name: Option<String>,
    uid: Option<String>,
    key: Option<String>,
    connection_id: Option<i32>,
    properties: Vec<XbfObjectProperty>,
    children: Vec<usize>,
}

/// Represents an evaluated property assigned to an XBF object.
#[derive(Debug, Clone)]
struct XbfObjectProperty {
    name: String,
    value: XbfPropertyValue,
}

/// Encapsulates the varying types of values a property can hold.
#[derive(Debug, Clone)]
enum XbfPropertyValue {
    String(String),
    Object(usize),
    Collection(Vec<usize>),
}

/// Represents a reference context when adding to a collection.
#[derive(Debug, Clone)]
enum CollectionRef {
    Children(usize),
    Property(usize, String),
}

/// Robust, universal XBF decoder.
pub struct XbfDecoder;

impl XbfDecoder {
    /// Decodes a raw binary XBF byte stream into a flat sequence of layout nodes.
    pub fn decode(bytes: &[u8]) -> Result<Vec<XbfNode>, LoaderError> {
        if bytes.len() < 12 {
            return Err(LoaderError::Parse("XBF payload is too short".to_string()));
        }

        // 1. Verify magic signature
        if &bytes[0..3] != b"XBF" {
            return Err(LoaderError::Parse(format!(
                "Invalid XBF magic: {:?}",
                &bytes[0..3]
            )));
        }

        let _magic_version = bytes[3];

        if bytes.len() < 100 {
            return Err(LoaderError::Parse(
                "XBF payload is too short for headers".to_string(),
            ));
        }

        let major_version = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let minor_version = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        tracing::info!("Decoding XBF version {}.{}", major_version, minor_version);

        if major_version < 2 {
            return Err(LoaderError::Parse(format!(
                "Unsupported XBF version: {}.{}",
                major_version, minor_version
            )));
        }

        let metadata_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let _node_size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;

        let string_table_offset = u64::from_le_bytes([
            bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27],
        ]) as usize;
        let assembly_table_offset = u64::from_le_bytes([
            bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35],
        ]) as usize;
        let type_namespace_table_offset = u64::from_le_bytes([
            bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43],
        ]) as usize;
        let type_table_offset = u64::from_le_bytes([
            bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
        ]) as usize;
        let property_table_offset = u64::from_le_bytes([
            bytes[52], bytes[53], bytes[54], bytes[55], bytes[56], bytes[57], bytes[58], bytes[59],
        ]) as usize;
        let xml_namespace_table_offset = u64::from_le_bytes([
            bytes[60], bytes[61], bytes[62], bytes[63], bytes[64], bytes[65], bytes[66], bytes[67],
        ]) as usize;

        let metadata_offset = 12;
        let abs_string_table = metadata_offset + string_table_offset;
        let abs_assembly_table = metadata_offset + assembly_table_offset;
        let abs_type_namespace_table = metadata_offset + type_namespace_table_offset;
        let abs_type_table = metadata_offset + type_table_offset;
        let abs_property_table = metadata_offset + property_table_offset;
        let abs_xml_namespace_table = metadata_offset + xml_namespace_table_offset;

        // Parse String Table
        let mut string_table = Vec::new();
        let mut cursor = abs_string_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse("String table truncated".to_string()));
                }
                let length = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]) as usize;
                cursor += 4;
                if cursor + length * 2 > bytes.len() {
                    return Err(LoaderError::Parse("String data truncated".to_string()));
                }

                let mut utf16_chars = Vec::with_capacity(length);
                for i in 0..length {
                    let b1 = bytes[cursor + i * 2];
                    let b2 = bytes[cursor + i * 2 + 1];
                    utf16_chars.push(u16::from_le_bytes([b1, b2]));
                }
                cursor += length * 2;

                // Read null terminator (2 bytes)
                if cursor + 2 <= bytes.len() {
                    cursor += 2;
                }

                let s = String::from_utf16(&utf16_chars).map_err(|e| {
                    LoaderError::Parse(format!("Invalid UTF-16 in string table: {}", e))
                })?;
                string_table.push(s);
            }
        }

        // Parse Assembly Table
        let mut assembly_table = Vec::new();
        let mut cursor = abs_assembly_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 8 > bytes.len() {
                    return Err(LoaderError::Parse("Assembly table truncated".to_string()));
                }
                let kind = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                let name_string_idx = u32::from_le_bytes([
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                cursor += 8;
                assembly_table.push(AssemblyEntry {
                    kind,
                    name_string_idx,
                });
            }
        }

        // Parse Type Namespace Table
        let mut type_namespace_table = Vec::new();
        let mut cursor = abs_type_namespace_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 8 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Type namespace table truncated".to_string(),
                    ));
                }
                let assembly_idx = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                let name_string_idx = u32::from_le_bytes([
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                cursor += 8;
                type_namespace_table.push(TypeNamespaceEntry {
                    assembly_idx,
                    name_string_idx,
                });
            }
        }

        // Parse Type Table
        let mut type_table = Vec::new();
        let mut cursor = abs_type_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 12 > bytes.len() {
                    return Err(LoaderError::Parse("Type table truncated".to_string()));
                }
                let flags = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                let namespace_idx = u32::from_le_bytes([
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                let name_string_idx = u32::from_le_bytes([
                    bytes[cursor + 8],
                    bytes[cursor + 9],
                    bytes[cursor + 10],
                    bytes[cursor + 11],
                ]);
                cursor += 12;
                type_table.push(TypeEntry {
                    flags,
                    namespace_idx,
                    name_string_idx,
                });
            }
        }

        // Parse Property Table
        let mut property_table = Vec::new();
        let mut cursor = abs_property_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 12 > bytes.len() {
                    return Err(LoaderError::Parse("Property table truncated".to_string()));
                }
                let flags = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                let type_idx = u32::from_le_bytes([
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                let name_string_idx = u32::from_le_bytes([
                    bytes[cursor + 8],
                    bytes[cursor + 9],
                    bytes[cursor + 10],
                    bytes[cursor + 11],
                ]);
                cursor += 12;
                property_table.push(PropertyEntry {
                    flags,
                    type_idx,
                    name_string_idx,
                });
            }
        }

        // Parse XML Namespace Table
        let mut xml_namespace_table = Vec::new();
        let mut cursor = abs_xml_namespace_table;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "XML namespace table truncated".to_string(),
                    ));
                }
                let string_idx = u32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                cursor += 4;
                xml_namespace_table.push(string_idx);
            }
        }

        // Parse Node Section Table
        let mut node_section_table = Vec::new();
        let mut cursor = 12 + metadata_size;
        if cursor + 4 <= bytes.len() {
            let count = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            for _ in 0..count {
                if cursor + 8 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Node section table truncated".to_string(),
                    ));
                }
                let node_offset = i32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                let positional_offset = i32::from_le_bytes([
                    bytes[cursor + 4],
                    bytes[cursor + 5],
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                ]);
                cursor += 8;
                node_section_table.push(NodeSectionEntry {
                    node_offset,
                    positional_offset,
                });
            }
        }

        let first_node_section_pos = cursor;

        if node_section_table.is_empty() {
            return Err(LoaderError::Parse(
                "No node sections found in XBF".to_string(),
            ));
        }

        let start_pos = first_node_section_pos + node_section_table[0].node_offset as usize;
        let end_pos = first_node_section_pos + node_section_table[0].positional_offset as usize;

        let mut cursor = start_pos;

        let mut arena = Vec::new();
        let mut object_stack = Vec::new();
        let mut collection_stack = Vec::new();
        let mut root_object_stack = Vec::new();
        let mut namespace_prefixes = IndexMap::new();

        let _ = read_root(
            &mut cursor,
            end_pos,
            bytes,
            &mut arena,
            &mut object_stack,
            &mut collection_stack,
            &mut root_object_stack,
            &node_section_table,
            first_node_section_pos,
            &type_table,
            &type_namespace_table,
            &property_table,
            &xml_namespace_table,
            &string_table,
            &mut namespace_prefixes,
        )?;

        let mut nodes = Vec::new();

        // Collect all XML namespace declarations and emit them first
        let mut sorted_prefixes = namespace_prefixes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<(String, String)>>();
        sorted_prefixes.sort_by(|a, b| a.1.cmp(&b.1));
        for (uri, prefix) in sorted_prefixes {
            nodes.push(XbfNode::NamespaceDeclaration {
                prefix: prefix.clone(),
                uri: uri.clone(),
            });
        }

        if !arena.is_empty() {
            flatten_object(&arena, 0, "", &mut nodes);
        }

        Ok(nodes)
    }
}

fn get_type_name(
    id: u16,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    string_table: &[String],
    namespace_prefixes: &IndexMap<String, String>,
) -> String {
    if (id & 0x8000) != 0 {
        let clean_id = (id & 0x7FFF) as usize;
        if clean_id > 0 && clean_id - 1 < TYPE_NAMES.len() {
            if let Some(name) = TYPE_NAMES[clean_id - 1] {
                return name.to_string();
            }
        }
        return format!("UnknownType0x{:04X}", id);
    }

    let idx = id as usize;
    if idx < type_table.len() {
        let type_entry = &type_table[idx];
        let name = if (type_entry.name_string_idx as usize) < string_table.len() {
            &string_table[type_entry.name_string_idx as usize]
        } else {
            "UnknownType"
        };

        let ns_idx = type_entry.namespace_idx as usize;
        if ns_idx < type_namespace_table.len() {
            let ns_entry = &type_namespace_table[ns_idx];
            let ns_name = if (ns_entry.name_string_idx as usize) < string_table.len() {
                &string_table[ns_entry.name_string_idx as usize]
            } else {
                ""
            };

            let namespace_key = format!("using:{}", ns_name);
            if let Some(prefix) = namespace_prefixes.get(&namespace_key) {
                let prefix: &String = prefix;
                if !prefix.is_empty() {
                    return format!("{}:{}", prefix, name);
                }
            }
        }
        return name.to_string();
    }

    format!("UnknownType0x{:04X}", id)
}

fn get_property_name(id: u16, property_table: &[PropertyEntry], string_table: &[String]) -> String {
    if (id & 0x8000) != 0 {
        let clean_id = (id & 0x7FFF) as usize;
        if clean_id > 0 && clean_id - 1 < PROPERTY_NAMES.len() {
            if let Some(name) = PROPERTY_NAMES[clean_id - 1] {
                return name.to_string();
            }
        }
        return format!("UnknownProperty0x{:04X}", id);
    }

    let idx = id as usize;
    if idx < property_table.len() {
        let prop_entry = &property_table[idx];
        if (prop_entry.name_string_idx as usize) < string_table.len() {
            return string_table[prop_entry.name_string_idx as usize].clone();
        }
    }

    format!("UnknownProperty0x{:04X}", id)
}

fn get_enumeration_value(enum_id: u16, value: i32) -> String {
    if let Some(name) = xbf_framework_types::get_enum_value_name(enum_id as u32, value) {
        name.to_string()
    } else {
        let mut flags = Vec::new();
        let mut remaining = value;
        for bit in 0..31 {
            let bit_val = 1 << bit;
            if (remaining & bit_val) == bit_val {
                if let Some(name) =
                    xbf_framework_types::get_enum_value_name(enum_id as u32, bit_val)
                {
                    flags.push(name);
                    remaining &= !bit_val;
                }
            }
        }
        if !flags.is_empty() && remaining == 0 {
            flags.join(",")
        } else {
            format!("{}", value)
        }
    }
}

fn read_root(
    cursor: &mut usize,
    end_pos: usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<usize, LoaderError> {
    let root_idx = arena.len();
    arena.push(XbfObject {
        type_name: "PendingRoot".to_string(),
        name: None,
        uid: None,
        key: None,
        connection_id: None,
        properties: Vec::new(),
        children: Vec::new(),
    });

    object_stack.push(root_idx);
    root_object_stack.push(root_idx);
    collection_stack.push(CollectionRef::Children(root_idx));

    read_nodes(
        cursor,
        end_pos,
        false,
        false,
        bytes,
        arena,
        object_stack,
        collection_stack,
        root_object_stack,
        node_section_table,
        first_node_section_pos,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;

    collection_stack.pop();
    object_stack.pop();
    root_object_stack.pop();

    if !collection_stack.is_empty() {
        add_object_to_current_collection(root_idx, collection_stack, arena);
    }

    Ok(root_idx)
}

fn read_string(cursor: &mut usize, bytes: &[u8]) -> Result<String, LoaderError> {
    if *cursor + 4 > bytes.len() {
        return Err(LoaderError::Parse("Truncated string length".to_string()));
    }
    let len = u32::from_le_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]) as usize;
    *cursor += 4;
    if *cursor + len * 2 > bytes.len() {
        return Err(LoaderError::Parse("Truncated string data".to_string()));
    }
    let mut utf16_chars = Vec::with_capacity(len);
    for i in 0..len {
        let b1 = bytes[*cursor + i * 2];
        let b2 = bytes[*cursor + i * 2 + 1];
        utf16_chars.push(u16::from_le_bytes([b1, b2]));
    }
    *cursor += len * 2;
    String::from_utf16(&utf16_chars)
        .map_err(|e| LoaderError::Parse(format!("Invalid UTF-16 string: {}", e)))
}

fn read_7bit_encoded_int(cursor: &mut usize, bytes: &[u8]) -> Result<i32, LoaderError> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        if *cursor >= bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated 7-bit encoded int".to_string(),
            ));
        }
        let b = bytes[*cursor];
        *cursor += 1;
        result |= ((b & 0x7F) as i32) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return Err(LoaderError::Parse("Invalid 7-bit encoded int".to_string()));
        }
    }
    Ok(result)
}

fn read_property_value(
    cursor: &mut usize,
    bytes: &[u8],
    string_table: &[String],
) -> Result<String, LoaderError> {
    if *cursor >= bytes.len() {
        return Err(LoaderError::Parse(
            "Truncated property value type".to_string(),
        ));
    }
    let value_type = bytes[*cursor];
    *cursor += 1;

    match value_type {
        0x01 => Ok("false".to_string()),
        0x02 => Ok("true".to_string()),
        0x03 => {
            if *cursor + 4 > bytes.len() {
                return Err(LoaderError::Parse("Truncated float value".to_string()));
            }
            let val = f32::from_le_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]);
            *cursor += 4;
            Ok(format!("{}", val))
        }
        0x04 => {
            if *cursor + 4 > bytes.len() {
                return Err(LoaderError::Parse("Truncated int value".to_string()));
            }
            let val = i32::from_le_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]);
            *cursor += 4;
            Ok(format!("{}", val))
        }
        0x05 => {
            if *cursor + 2 > bytes.len() {
                return Err(LoaderError::Parse("Truncated string index".to_string()));
            }
            let idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
            *cursor += 2;
            if idx < string_table.len() {
                Ok(string_table[idx].clone())
            } else {
                Ok(format!("RawString_{}", idx))
            }
        }
        0x06 => {
            if *cursor + 16 > bytes.len() {
                return Err(LoaderError::Parse("Truncated Thickness value".to_string()));
            }
            let left = f32::from_le_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]);
            let top = f32::from_le_bytes([
                bytes[*cursor + 4],
                bytes[*cursor + 5],
                bytes[*cursor + 6],
                bytes[*cursor + 7],
            ]);
            let right = f32::from_le_bytes([
                bytes[*cursor + 8],
                bytes[*cursor + 9],
                bytes[*cursor + 10],
                bytes[*cursor + 11],
            ]);
            let bottom = f32::from_le_bytes([
                bytes[*cursor + 12],
                bytes[*cursor + 13],
                bytes[*cursor + 14],
                bytes[*cursor + 15],
            ]);
            *cursor += 16;
            if left == right && top == bottom {
                if left == top {
                    Ok(format!("{}", left))
                } else {
                    Ok(format!("{},{}", left, top))
                }
            } else {
                Ok(format!("{},{},{},{}", left, top, right, bottom))
            }
        }
        0x07 => {
            if *cursor + 8 > bytes.len() {
                return Err(LoaderError::Parse("Truncated GridLength value".to_string()));
            }
            let gl_type = i32::from_le_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]);
            let gl_val = f32::from_le_bytes([
                bytes[*cursor + 4],
                bytes[*cursor + 5],
                bytes[*cursor + 6],
                bytes[*cursor + 7],
            ]);
            *cursor += 8;
            match gl_type {
                0 => Ok("Auto".to_string()),
                1 => Ok(format!("{}", gl_val)),
                2 => {
                    if gl_val == 1.0 {
                        Ok("*".to_string())
                    } else {
                        Ok(format!("{}*", gl_val))
                    }
                }
                _ => Err(LoaderError::Parse(format!(
                    "Unexpected GridLength type: {}",
                    gl_type
                ))),
            }
        }
        0x08 => {
            if *cursor + 4 > bytes.len() {
                return Err(LoaderError::Parse("Truncated Color value".to_string()));
            }
            let b = bytes[*cursor];
            let g = bytes[*cursor + 1];
            let r = bytes[*cursor + 2];
            let a = bytes[*cursor + 3];
            *cursor += 4;
            Ok(format!("#{:02X}{:02X}{:02X}{:02X}", a, r, g, b))
        }
        0x09 => {
            if *cursor + 4 > bytes.len() {
                return Err(LoaderError::Parse(
                    "Truncated Duration string length".to_string(),
                ));
            }
            let len = u32::from_le_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]) as usize;
            *cursor += 4;
            if *cursor + len * 2 > bytes.len() {
                return Err(LoaderError::Parse(
                    "Truncated Duration string data".to_string(),
                ));
            }
            let mut utf16_chars = Vec::with_capacity(len);
            for i in 0..len {
                utf16_chars.push(u16::from_le_bytes([
                    bytes[*cursor + i * 2],
                    bytes[*cursor + i * 2 + 1],
                ]));
            }
            *cursor += len * 2;
            let s = String::from_utf16(&utf16_chars).map_err(|e| {
                LoaderError::Parse(format!("Invalid UTF-16 in Duration string: {}", e))
            })?;
            Ok(s)
        }
        0x0B => {
            if *cursor + 6 > bytes.len() {
                return Err(LoaderError::Parse(
                    "Truncated Enumeration value".to_string(),
                ));
            }
            let enum_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
            let enum_val = i32::from_le_bytes([
                bytes[*cursor + 2],
                bytes[*cursor + 3],
                bytes[*cursor + 4],
                bytes[*cursor + 5],
            ]);
            *cursor += 6;
            Ok(get_enumeration_value(enum_id, enum_val))
        }
        _ => Err(LoaderError::Parse(format!(
            "Unrecognized value type 0x{:02X}",
            value_type
        ))),
    }
}

fn add_object_to_current_collection(
    obj_idx: usize,
    collection_stack: &mut [CollectionRef],
    arena: &mut [XbfObject],
) {
    if let Some(col_ref) = collection_stack.last() {
        match col_ref {
            CollectionRef::Children(parent_idx) => {
                arena[*parent_idx].children.push(obj_idx);
            }
            CollectionRef::Property(parent_idx, prop_name) => {
                let mut found = false;
                for prop in &mut arena[*parent_idx].properties {
                    if prop.name == *prop_name {
                        if let XbfPropertyValue::Collection(ref mut list) = prop.value {
                            list.push(obj_idx);
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    arena[*parent_idx].properties.push(XbfObjectProperty {
                        name: prop_name.clone(),
                        value: XbfPropertyValue::Collection(vec![obj_idx]),
                    });
                }
            }
        }
    }
}

fn read_object_in_node_section(
    node_section_idx: usize,
    offset: usize,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    _root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<usize, LoaderError> {
    let section = &node_section_table[node_section_idx];
    let new_pos = first_node_section_pos + section.node_offset as usize + offset;
    let mut temp_cursor = new_pos;

    let mut temp_object_stack = Vec::new();
    let mut temp_collection_stack = Vec::new();
    let mut temp_root_object_stack = Vec::new();

    let root_idx = read_root(
        &mut temp_cursor,
        usize::MAX,
        bytes,
        arena,
        &mut temp_object_stack,
        &mut temp_collection_stack,
        &mut temp_root_object_stack,
        node_section_table,
        first_node_section_pos,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;

    Ok(root_idx)
}

fn read_node_in_node_section(
    node_section_idx: usize,
    offset: usize,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let section = &node_section_table[node_section_idx];
    let new_pos = first_node_section_pos + section.node_offset as usize + offset;
    let mut temp_cursor = new_pos;

    let object_stack_len_before = object_stack.len();
    let collection_stack_len_before = collection_stack.len();

    read_nodes(
        &mut temp_cursor,
        usize::MAX,
        false,
        true,
        bytes,
        arena,
        object_stack,
        collection_stack,
        root_object_stack,
        node_section_table,
        first_node_section_pos,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;

    if object_stack.len() != object_stack_len_before {
        return Err(LoaderError::Parse(
            "Object stack corrupted in read_node_in_node_section".to_string(),
        ));
    }
    if collection_stack.len() != collection_stack_len_before {
        return Err(LoaderError::Parse(
            "Collection stack corrupted in read_node_in_node_section".to_string(),
        ));
    }
    Ok(())
}

fn read_node_section(
    _cursor: &mut usize,
    node_section_idx: usize,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let section = &node_section_table[node_section_idx];
    let new_pos = first_node_section_pos + section.node_offset as usize;
    let new_end = first_node_section_pos + section.positional_offset as usize;

    let mut temp_cursor = new_pos;
    read_nodes(
        &mut temp_cursor,
        new_end,
        false,
        false,
        bytes,
        arena,
        object_stack,
        collection_stack,
        root_object_stack,
        node_section_table,
        first_node_section_pos,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;
    Ok(())
}

fn read_node_section_reference(
    cursor: &mut usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let node_section_idx = read_7bit_encoded_int(cursor, bytes)? as usize;
    if node_section_idx >= node_section_table.len() {
        return Err(LoaderError::Parse(format!(
            "Invalid node section index: {}",
            node_section_idx
        )));
    }

    if *cursor + 2 > bytes.len() {
        return Err(LoaderError::Parse(
            "Truncated node section reference".to_string(),
        ));
    }
    let val = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    if val != 0 {
        return Err(LoaderError::Parse(format!(
            "Unexpected value in node section reference: {}",
            val
        )));
    }

    let type_val = read_7bit_encoded_int(cursor, bytes)?;
    match type_val {
        2 | 8 => {
            read_style(
                cursor,
                bytes,
                node_section_idx,
                node_section_table,
                first_node_section_pos,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        7 | 10 => {
            read_resource_dictionary(
                cursor,
                bytes,
                node_section_idx,
                false,
                node_section_table,
                first_node_section_pos,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        9 => {
            read_node_section(
                cursor,
                node_section_idx,
                node_section_table,
                first_node_section_pos,
                bytes,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        371 => {
            read_resource_dictionary(
                cursor,
                bytes,
                node_section_idx,
                true,
                node_section_table,
                first_node_section_pos,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        5 => {
            skip_visual_state_bytes(cursor, bytes, string_table, arena)?;
            read_node_section(
                cursor,
                node_section_idx,
                node_section_table,
                first_node_section_pos,
                bytes,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        6 => {
            read_deferred_element(
                cursor,
                bytes,
                node_section_idx,
                true,
                node_section_table,
                first_node_section_pos,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        746 => {
            read_deferred_element(
                cursor,
                bytes,
                node_section_idx,
                false,
                node_section_table,
                first_node_section_pos,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
        }
        _ => {
            return Err(LoaderError::Parse(format!(
                "Unknown node type {} while parsing referenced code section",
                type_val
            )));
        }
    }

    Ok(())
}

fn read_data_template(
    cursor: &mut usize,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    if *cursor + 2 > bytes.len() {
        return Err(LoaderError::Parse(
            "Truncated DataTemplate property_id".to_string(),
        ));
    }
    let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    let prop_name = get_property_name(property_id, property_table, string_table);

    let node_section_idx = read_7bit_encoded_int(cursor, bytes)? as usize;
    if node_section_idx >= node_section_table.len() {
        return Err(LoaderError::Parse(format!(
            "Invalid node section index in DataTemplate: {}",
            node_section_idx
        )));
    }

    let static_resource_count = read_7bit_encoded_int(cursor, bytes)?;
    let theme_resource_count = read_7bit_encoded_int(cursor, bytes)?;

    for _ in 0..static_resource_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated static resource ref".to_string(),
            ));
        }
        let _ref_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;
    }

    for _ in 0..theme_resource_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated theme resource ref".to_string(),
            ));
        }
        let _ref_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;
    }

    let parent_idx = *object_stack.last().unwrap();
    let template_obj_idx = arena.len();
    arena.push(XbfObject {
        type_name: "Template".to_string(),
        name: None,
        uid: None,
        key: None,
        connection_id: None,
        properties: Vec::new(),
        children: Vec::new(),
    });

    arena[parent_idx].properties.push(XbfObjectProperty {
        name: prop_name,
        value: XbfPropertyValue::Object(template_obj_idx),
    });

    object_stack.push(template_obj_idx);
    collection_stack.push(CollectionRef::Children(template_obj_idx));

    read_node_section(
        cursor,
        node_section_idx,
        node_section_table,
        first_node_section_pos,
        bytes,
        arena,
        object_stack,
        collection_stack,
        root_object_stack,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;

    collection_stack.pop();
    object_stack.pop();

    Ok(())
}

fn read_style(
    cursor: &mut usize,
    bytes: &[u8],
    node_section_idx: usize,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let setter_count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..setter_count {
        if *cursor >= bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated Setter value type".to_string(),
            ));
        }
        let value_type = bytes[*cursor];
        *cursor += 1;

        let mut property_name = None;
        let mut _type_name = None;
        let mut property_value = None;
        let mut value_offset = 0;

        match value_type {
            0x01 | 0x02 | 0x08 => {
                if *cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated Setter metadata".to_string()));
                }
                let prop_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
                let type_idx = u16::from_le_bytes([bytes[*cursor + 2], bytes[*cursor + 3]]);
                *cursor += 4;
                if prop_idx < string_table.len() {
                    property_name = Some(string_table[prop_idx].clone());
                }
                _type_name = Some(get_type_name(
                    type_idx,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                ));
                value_offset = read_7bit_encoded_int(cursor, bytes)? as usize;
            }
            0x11 | 0x12 | 0x18 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated Setter metadata".to_string()));
                }
                let prop_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                property_name = Some(get_property_name(prop_id, property_table, string_table));
                value_offset = read_7bit_encoded_int(cursor, bytes)? as usize;
            }
            0x20 => {
                if *cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated Setter metadata".to_string()));
                }
                let prop_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
                let type_idx = u16::from_le_bytes([bytes[*cursor + 2], bytes[*cursor + 3]]);
                *cursor += 4;
                if prop_idx < string_table.len() {
                    property_name = Some(string_table[prop_idx].clone());
                }
                _type_name = Some(get_type_name(
                    type_idx,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                ));
                property_value = Some(read_property_value(cursor, bytes, string_table)?);
            }
            0x30 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated Setter metadata".to_string()));
                }
                let prop_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                property_name = Some(get_property_name(prop_id, property_table, string_table));
                property_value = Some(read_property_value(cursor, bytes, string_table)?);
            }
            _ => {
                return Err(LoaderError::Parse(format!(
                    "Unexpected value type in Setter: {}",
                    value_type
                )));
            }
        }

        if value_type == 0x08 || value_type == 0x18 {
            let child_obj_idx = read_object_in_node_section(
                node_section_idx,
                value_offset,
                node_section_table,
                first_node_section_pos,
                bytes,
                arena,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
            let setter_idx = arena.len();
            arena.push(XbfObject {
                type_name: "Setter".to_string(),
                name: None,
                uid: None,
                key: None,
                connection_id: None,
                properties: vec![
                    XbfObjectProperty {
                        name: "Property".to_string(),
                        value: XbfPropertyValue::String(property_name.unwrap_or_default()),
                    },
                    XbfObjectProperty {
                        name: "Value".to_string(),
                        value: XbfPropertyValue::Object(child_obj_idx),
                    },
                ],
                children: Vec::new(),
            });
            add_object_to_current_collection(setter_idx, collection_stack, arena);
        } else if property_value.is_some() {
            let setter_idx = arena.len();
            arena.push(XbfObject {
                type_name: "Setter".to_string(),
                name: None,
                uid: None,
                key: None,
                connection_id: None,
                properties: vec![
                    XbfObjectProperty {
                        name: "Property".to_string(),
                        value: XbfPropertyValue::String(property_name.unwrap_or_default()),
                    },
                    XbfObjectProperty {
                        name: "Value".to_string(),
                        value: XbfPropertyValue::String(property_value.unwrap()),
                    },
                ],
                children: Vec::new(),
            });
            add_object_to_current_collection(setter_idx, collection_stack, arena);
        } else {
            let setter_idx = arena.len();
            arena.push(XbfObject {
                type_name: "Setter".to_string(),
                name: None,
                uid: None,
                key: None,
                connection_id: None,
                properties: vec![XbfObjectProperty {
                    name: "Property".to_string(),
                    value: XbfPropertyValue::String(property_name.unwrap_or_default()),
                }],
                children: Vec::new(),
            });
            add_object_to_current_collection(setter_idx, collection_stack, arena);

            object_stack.push(setter_idx);
            read_node_in_node_section(
                node_section_idx,
                value_offset,
                node_section_table,
                first_node_section_pos,
                bytes,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
            object_stack.pop();
        }
    }
    Ok(())
}

fn read_deferred_element(
    cursor: &mut usize,
    bytes: &[u8],
    node_section_idx: usize,
    extended: bool,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    if *cursor + 2 > bytes.len() {
        return Err(LoaderError::Parse(
            "Truncated DeferredElement name".to_string(),
        ));
    }
    let _name_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    *cursor += 2;

    if extended {
        let count = read_7bit_encoded_int(cursor, bytes)?;
        for _ in 0..count {
            if *cursor + 2 > bytes.len() {
                return Err(LoaderError::Parse(
                    "Truncated DeferredElement property".to_string(),
                ));
            }
            let _prop_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
            *cursor += 2;
            let _val = read_property_value(cursor, bytes, string_table)?;
        }
    }

    read_node_section(
        cursor,
        node_section_idx,
        node_section_table,
        first_node_section_pos,
        bytes,
        arena,
        object_stack,
        collection_stack,
        root_object_stack,
        type_table,
        type_namespace_table,
        property_table,
        xml_namespace_table,
        string_table,
        namespace_prefixes,
    )?;

    let child_idx = object_stack
        .pop()
        .ok_or_else(|| LoaderError::Parse("DeferredElement stack empty".to_string()))?;

    if let Some(col_ref) = collection_stack.last() {
        match col_ref {
            CollectionRef::Children(parent_idx) => {
                arena[*parent_idx].children.push(child_idx);
            }
            _ => {
                arena[0].children.push(child_idx);
            }
        }
    } else {
        arena[0].children.push(child_idx);
    }

    Ok(())
}

fn read_resource_dictionary(
    cursor: &mut usize,
    bytes: &[u8],
    node_section_idx: usize,
    extended: bool,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    arena: &mut Vec<XbfObject>,
    _object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let resources_count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..resources_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated ResourceDictionary key".to_string(),
            ));
        }
        let key_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;

        let position = read_7bit_encoded_int(cursor, bytes)? as usize;
        let key_str = if key_idx < string_table.len() {
            string_table[key_idx].clone()
        } else {
            "".to_string()
        };

        let child_obj_idx = read_object_in_node_section(
            node_section_idx,
            position,
            node_section_table,
            first_node_section_pos,
            bytes,
            arena,
            root_object_stack,
            type_table,
            type_namespace_table,
            property_table,
            xml_namespace_table,
            string_table,
            namespace_prefixes,
        )?;

        arena[child_obj_idx].key = Some(key_str);
        add_object_to_current_collection(child_obj_idx, collection_stack, arena);
    }

    let count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated ResourceDictionary repeated key".to_string(),
            ));
        }
        *cursor += 2;
    }

    let style_count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..style_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse("Truncated Style TargetType".to_string()));
        }
        let _target_type_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;

        let position = read_7bit_encoded_int(cursor, bytes)? as usize;
        let child_obj_idx = read_object_in_node_section(
            node_section_idx,
            position,
            node_section_table,
            first_node_section_pos,
            bytes,
            arena,
            root_object_stack,
            type_table,
            type_namespace_table,
            property_table,
            xml_namespace_table,
            string_table,
            namespace_prefixes,
        )?;
        add_object_to_current_collection(child_obj_idx, collection_stack, arena);
    }

    if extended {
        let val = read_7bit_encoded_int(cursor, bytes)?;
        if val != 0 {
            return Err(LoaderError::Parse(format!(
                "Unexpected value in extended ResourceDictionary: {}",
                val
            )));
        }
    }

    let count2 = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..count2 {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated ResourceDictionary repeated target type".to_string(),
            ));
        }
        *cursor += 2;
    }

    Ok(())
}

fn skip_visual_state_bytes(
    cursor: &mut usize,
    bytes: &[u8],
    string_table: &[String],
    arena: &mut Vec<XbfObject>,
) -> Result<(), LoaderError> {
    let visual_state_count = read_7bit_encoded_int(cursor, bytes)?;
    let mut visual_state_group_memberships = Vec::with_capacity(visual_state_count as usize);
    for _ in 0..visual_state_count {
        visual_state_group_memberships.push(read_7bit_encoded_int(cursor, bytes)?);
    }

    let visual_state_count2 = read_7bit_encoded_int(cursor, bytes)?;
    if visual_state_count != visual_state_count2 {
        return Err(LoaderError::Parse(format!(
            "Visual state count mismatch: {} vs {}",
            visual_state_count, visual_state_count2
        )));
    }

    let mut visual_states = Vec::with_capacity(visual_state_count2 as usize);
    for _ in 0..visual_state_count2 {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated VisualState name id".to_string(),
            ));
        }
        let name_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;

        read_7bit_encoded_int(cursor, bytes)?;
        read_7bit_encoded_int(cursor, bytes)?;

        let setter_count = read_7bit_encoded_int(cursor, bytes)?;
        for _ in 0..setter_count {
            read_7bit_encoded_int(cursor, bytes)?;
        }

        let adaptive_trigger_count = read_7bit_encoded_int(cursor, bytes)?;
        for _ in 0..adaptive_trigger_count {
            let count = read_7bit_encoded_int(cursor, bytes)?;
            for _ in 0..count {
                read_7bit_encoded_int(cursor, bytes)?;
            }
        }

        let state_trigger_count = read_7bit_encoded_int(cursor, bytes)?;
        for _ in 0..state_trigger_count {
            read_7bit_encoded_int(cursor, bytes)?;
        }

        let offset_count = read_7bit_encoded_int(cursor, bytes)?;
        for _ in 0..offset_count {
            read_7bit_encoded_int(cursor, bytes)?;
        }

        read_7bit_encoded_int(cursor, bytes)?;

        let vs_name = if name_idx < string_table.len() {
            string_table[name_idx].clone()
        } else {
            "".to_string()
        };

        let vs_idx = arena.len();
        arena.push(XbfObject {
            type_name: "VisualState".to_string(),
            name: Some(vs_name),
            uid: None,
            key: None,
            connection_id: None,
            properties: Vec::new(),
            children: Vec::new(),
        });
        visual_states.push(vs_idx);
    }

    let visual_state_group_count = read_7bit_encoded_int(cursor, bytes)?;
    for i in 0..visual_state_group_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated VisualStateGroup name id".to_string(),
            ));
        }
        let name_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
        *cursor += 2;

        read_7bit_encoded_int(cursor, bytes)?;
        let _object_offset = read_7bit_encoded_int(cursor, bytes)?;

        let _vsg_name = if name_idx < string_table.len() {
            string_table[name_idx].clone()
        } else {
            "".to_string()
        };

        let mut _group_states = Vec::new();
        for j in 0..visual_state_group_memberships.len() {
            if visual_state_group_memberships[j] == i {
                _group_states.push(visual_states[j]);
            }
        }
    }

    let visual_transition_count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..visual_transition_count {
        if *cursor + 4 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated VisualTransition states".to_string(),
            ));
        }
        *cursor += 4;
        read_7bit_encoded_int(cursor, bytes)?;
    }

    read_7bit_encoded_int(cursor, bytes)?;

    let count2 = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..count2 {
        read_7bit_encoded_int(cursor, bytes)?;
        read_7bit_encoded_int(cursor, bytes)?;
        read_7bit_encoded_int(cursor, bytes)?;
    }

    let count3 = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..count3 {
        read_7bit_encoded_int(cursor, bytes)?;
    }

    read_7bit_encoded_int(cursor, bytes)?;

    let string_count = read_7bit_encoded_int(cursor, bytes)?;
    for _ in 0..string_count {
        if *cursor + 2 > bytes.len() {
            return Err(LoaderError::Parse(
                "Truncated visual state transition strings".to_string(),
            ));
        }
        *cursor += 2;
    }

    Ok(())
}

fn read_nodes(
    cursor: &mut usize,
    end_pos: usize,
    read_single_object: bool,
    read_single_node: bool,
    bytes: &[u8],
    arena: &mut Vec<XbfObject>,
    object_stack: &mut Vec<usize>,
    collection_stack: &mut Vec<CollectionRef>,
    root_object_stack: &mut Vec<usize>,
    node_section_table: &[NodeSectionEntry],
    first_node_section_pos: usize,
    type_table: &[TypeEntry],
    type_namespace_table: &[TypeNamespaceEntry],
    property_table: &[PropertyEntry],
    xml_namespace_table: &[u32],
    string_table: &[String],
    namespace_prefixes: &mut IndexMap<String, String>,
) -> Result<(), LoaderError> {
    let mut single_object_idx = None;
    let mut unknown_opcode_count = 0u32;
    let mut first_unknown_opcode = 0u8;

    while *cursor < bytes.len() && *cursor < end_pos {
        let opcode = bytes[*cursor];
        *cursor += 1;

        let is_nested = if let Some(&curr_root_idx) = root_object_stack.last() {
            arena[curr_root_idx].type_name != "PendingRoot"
        } else {
            false
        };

        if is_nested && (opcode == 0x03 || opcode == 0x0B || opcode == 0x12 || opcode == 0x17) {
            *cursor -= 1;
            read_root(
                cursor,
                end_pos,
                bytes,
                arena,
                object_stack,
                collection_stack,
                root_object_stack,
                node_section_table,
                first_node_section_pos,
                type_table,
                type_namespace_table,
                property_table,
                xml_namespace_table,
                string_table,
                namespace_prefixes,
            )?;
            if read_single_node {
                break;
            }
            continue;
        }

        match opcode {
            0x01 => {}
            0x02 => {
                collection_stack.pop();
            }
            0x04 => {
                let value = read_property_value(cursor, bytes, string_table)?;
                let mut is_verbatim = true;
                if let Some(CollectionRef::Children(parent_idx)) = collection_stack.last() {
                    if object_stack.last() == Some(parent_idx) {
                        is_verbatim = false; // Event handler / class modifier, ignore
                    }
                }

                if is_verbatim {
                    let verbatim_idx = arena.len();
                    arena.push(XbfObject {
                        type_name: "Verbatim".to_string(),
                        name: None,
                        uid: None,
                        key: None,
                        connection_id: None,
                        properties: vec![XbfObjectProperty {
                            name: "Value".to_string(),
                            value: XbfPropertyValue::String(value),
                        }],
                        children: Vec::new(),
                    });
                    object_stack.push(verbatim_idx);
                }
            }
            0x07 | 0x20 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated property id".to_string()));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let prop_name = get_property_name(property_id, property_table, string_table);

                let sub_obj_idx = object_stack
                    .pop()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x07".to_string()))?;
                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Parent stack empty on 0x07".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::Object(sub_obj_idx),
                });
            }
            0x08 | 0x09 => {
                let obj_idx = object_stack
                    .pop()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x08".to_string()))?;
                add_object_to_current_collection(obj_idx, collection_stack, arena);
            }
            0x0A => {
                let obj_idx = object_stack
                    .pop()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x0A".to_string()))?;
                let key_str = read_property_value(cursor, bytes, string_table)?;
                arena[obj_idx].key = Some(key_str);
                add_object_to_current_collection(obj_idx, collection_stack, arena);
            }
            0x0B => {
                let class_name = read_string(cursor, bytes)?;
                let root_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x0B".to_string()))?;
                arena[root_idx].properties.push(XbfObjectProperty {
                    name: "x:Class".to_string(),
                    value: XbfPropertyValue::String(class_name),
                });
            }
            0x0C => {
                let conn_val = read_property_value(cursor, bytes, string_table)?;
                let conn_id = conn_val.parse::<i32>().unwrap_or(0);
                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x0C".to_string()))?;
                arena[parent_idx].connection_id = Some(conn_id);
            }
            0x0D => {
                let name = read_property_value(cursor, bytes, string_table)?;
                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x0D".to_string()))?;
                arena[parent_idx].name = Some(name);
            }
            0x0E => {
                let uid = read_property_value(cursor, bytes, string_table)?;
                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x0E".to_string()))?;
                arena[parent_idx].uid = Some(uid);
            }
            0x0F => {
                read_node_section_reference(
                    cursor,
                    bytes,
                    arena,
                    object_stack,
                    collection_stack,
                    root_object_stack,
                    node_section_table,
                    first_node_section_pos,
                    type_table,
                    type_namespace_table,
                    property_table,
                    xml_namespace_table,
                    string_table,
                    namespace_prefixes,
                )?;
            }
            0x11 => {
                read_data_template(
                    cursor,
                    bytes,
                    arena,
                    object_stack,
                    collection_stack,
                    root_object_stack,
                    node_section_table,
                    first_node_section_pos,
                    type_table,
                    type_namespace_table,
                    property_table,
                    xml_namespace_table,
                    string_table,
                    namespace_prefixes,
                )?;
            }
            0x03 | 0x12 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated XML namespace index".to_string(),
                    ));
                }
                let ns_idx = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
                *cursor += 2;
                let ns_uri = if ns_idx < xml_namespace_table.len() {
                    let str_idx = xml_namespace_table[ns_idx] as usize;
                    if str_idx < string_table.len() {
                        string_table[str_idx].clone()
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                let prefix = read_string(cursor, bytes)?;
                namespace_prefixes.insert(ns_uri.clone(), prefix.clone());

                let root_idx = *object_stack.last().ok_or_else(|| {
                    LoaderError::Parse("Stack empty on namespace declaration".to_string())
                })?;
                let xmlns_key = if prefix.is_empty() {
                    "xmlns".to_string()
                } else {
                    format!("xmlns:{}", prefix)
                };
                arena[root_idx].properties.push(XbfObjectProperty {
                    name: xmlns_key,
                    value: XbfPropertyValue::String(ns_uri),
                });
            }
            0x13 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated collection property id".to_string(),
                    ));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x13".to_string()))?;
                collection_stack.push(CollectionRef::Property(parent_idx, prop_name));
            }
            0x14 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated type id in 0x14".to_string()));
                }
                let type_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let type_name = get_type_name(
                    type_id,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                );

                let child_idx = arena.len();
                arena.push(XbfObject {
                    type_name,
                    name: None,
                    uid: None,
                    key: None,
                    connection_id: None,
                    properties: Vec::new(),
                    children: Vec::new(),
                });

                object_stack.push(child_idx);
                collection_stack.push(CollectionRef::Children(child_idx));

                if read_single_object && single_object_idx.is_none() {
                    single_object_idx = Some(child_idx);
                }
            }
            0x15 | 0x16 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated type id in 0x15/0x16".to_string(),
                    ));
                }
                let type_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let type_name = get_type_name(
                    type_id,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                );

                let value = read_property_value(cursor, bytes, string_table)?;
                let child_idx = arena.len();
                arena.push(XbfObject {
                    type_name,
                    name: None,
                    uid: None,
                    key: None,
                    connection_id: None,
                    properties: vec![XbfObjectProperty {
                        name: "Value".to_string(),
                        value: XbfPropertyValue::String(value),
                    }],
                    children: Vec::new(),
                });

                object_stack.push(child_idx);

                if read_single_object && single_object_idx.is_none() {
                    single_object_idx = Some(child_idx);
                }
            }
            0x17 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated root type id".to_string()));
                }
                let type_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let root_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x17".to_string()))?;
                arena[root_idx].type_name = get_type_name(
                    type_id,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                );
            }
            0x18 | 0x19 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated type id in 0x18/0x19".to_string(),
                    ));
                }
                let type_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let type_name = get_type_name(
                    type_id,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                );
                let argument = read_property_value(cursor, bytes, string_table)?;

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x18/0x19".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: "x:Class".to_string(),
                    value: XbfPropertyValue::String(type_name),
                });
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: "x:Arguments".to_string(),
                    value: XbfPropertyValue::String(argument),
                });
            }
            0x1A | 0x1B => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse("Truncated property id".to_string()));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let value = read_property_value(cursor, bytes, string_table)?;

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x1A/0x1B".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::String(value),
                });
            }
            0x1D => {
                if *cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated TargetType style metadata".to_string(),
                    ));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                let type_id = u16::from_le_bytes([bytes[*cursor + 2], bytes[*cursor + 3]]);
                *cursor += 4;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let type_name = get_type_name(
                    type_id,
                    type_table,
                    type_namespace_table,
                    string_table,
                    namespace_prefixes,
                );

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x1D".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::String(type_name),
                });
            }
            0x1E => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated StaticResource property id".to_string(),
                    ));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let value = read_property_value(cursor, bytes, string_table)?;

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x1E".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::String(format!("{{StaticResource {}}}", value)),
                });
            }
            0x1F => {
                if *cursor + 4 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated TemplateBinding metadata".to_string(),
                    ));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                let binding_path_id = u16::from_le_bytes([bytes[*cursor + 2], bytes[*cursor + 3]]);
                *cursor += 4;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let binding_path = get_property_name(binding_path_id, property_table, string_table);

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x1F".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::String(format!(
                        "{{TemplateBinding {}}}",
                        binding_path
                    )),
                });
            }
            0x24 => {
                if *cursor + 2 > bytes.len() {
                    return Err(LoaderError::Parse(
                        "Truncated ThemeResource property id".to_string(),
                    ));
                }
                let property_id = u16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
                *cursor += 2;
                let prop_name = get_property_name(property_id, property_table, string_table);
                let value = read_property_value(cursor, bytes, string_table)?;

                let parent_idx = *object_stack
                    .last()
                    .ok_or_else(|| LoaderError::Parse("Stack empty on 0x24".to_string()))?;
                arena[parent_idx].properties.push(XbfObjectProperty {
                    name: prop_name,
                    value: XbfPropertyValue::String(format!("{{ThemeResource {}}}", value)),
                });
            }
            0x21 => {
                if !collection_stack.is_empty()
                    && matches!(collection_stack.last().unwrap(), CollectionRef::Children(idx) if *idx == *object_stack.last().unwrap())
                {
                    collection_stack.pop();
                }

                if read_single_object && object_stack.last().cloned() == single_object_idx {
                    return Ok(());
                }

                if object_stack.last() == Some(&0) {
                    return Ok(());
                }

                if let (Some(&obj_top), Some(&root_top)) =
                    (object_stack.last(), root_object_stack.last())
                {
                    if obj_top == root_top {
                        return Ok(());
                    }
                }
            }
            0x22 => {
                let value = read_property_value(cursor, bytes, string_table)?;
                let child_idx = arena.len();
                arena.push(XbfObject {
                    type_name: "StaticResource".to_string(),
                    name: None,
                    uid: None,
                    key: None,
                    connection_id: None,
                    properties: vec![XbfObjectProperty {
                        name: "ResourceKey".to_string(),
                        value: XbfPropertyValue::String(value),
                    }],
                    children: Vec::new(),
                });

                object_stack.push(child_idx);

                if read_single_object && single_object_idx.is_none() {
                    single_object_idx = Some(child_idx);
                }
            }
            0x23 => {
                let value = read_property_value(cursor, bytes, string_table)?;
                let child_idx = arena.len();
                arena.push(XbfObject {
                    type_name: "ThemeResource".to_string(),
                    name: None,
                    uid: None,
                    key: None,
                    connection_id: None,
                    properties: vec![XbfObjectProperty {
                        name: "ResourceKey".to_string(),
                        value: XbfPropertyValue::String(value),
                    }],
                    children: Vec::new(),
                });

                object_stack.push(child_idx);

                if read_single_object && single_object_idx.is_none() {
                    single_object_idx = Some(child_idx);
                }
            }
            0x8B => {
                object_stack.pop();
            }
            0x00 => {
                // NUL padding byte — silently skip
            }
            _ => {
                // Downgraded from warn! to trace! to avoid flooding the log.
                // We accumulate a count and emit a single summary warning instead.
                tracing::trace!(
                    "Unknown XBF opcode: 0x{:02x} at offset {}",
                    opcode,
                    *cursor - 1
                );
                if unknown_opcode_count == 0 {
                    first_unknown_opcode = opcode;
                }
                unknown_opcode_count += 1;
            }
        }

        if read_single_node {
            break;
        }
    }

    if unknown_opcode_count > 0 {
        tracing::warn!(
            "XBF: skipped {} unknown opcode(s) (first: 0x{:02x})",
            unknown_opcode_count,
            first_unknown_opcode
        );
    }

    Ok(())
}

fn flatten_object(arena: &[XbfObject], idx: usize, _parent_type: &str, nodes: &mut Vec<XbfNode>) {
    let obj = &arena[idx];

    if obj.type_name == "Verbatim" {
        if let Some(prop) = obj.properties.first() {
            if let XbfPropertyValue::String(text) = &prop.value {
                nodes.push(XbfNode::Text(text.clone()));
            }
        }
        return;
    }

    nodes.push(XbfNode::ElementStart {
        type_name: obj.type_name.clone(),
        namespace_uri: None,
    });

    if let Some(ref name) = obj.name {
        nodes.push(XbfNode::AddProperty {
            name: "x:Name".to_string(),
            value: name.clone(),
            namespace_uri: None,
        });
    }
    if let Some(ref uid) = obj.uid {
        nodes.push(XbfNode::AddProperty {
            name: "x:Uid".to_string(),
            value: uid.clone(),
            namespace_uri: None,
        });
    }
    if let Some(ref key) = obj.key {
        nodes.push(XbfNode::AddProperty {
            name: "x:Key".to_string(),
            value: key.clone(),
            namespace_uri: None,
        });
    }
    if let Some(conn_id) = obj.connection_id {
        nodes.push(XbfNode::AddProperty {
            name: "ConnectionId".to_string(),
            value: format!("{}", conn_id),
            namespace_uri: None,
        });
    }

    for prop in &obj.properties {
        if prop.name == "xmlns" || prop.name.starts_with("xmlns:") {
            continue;
        }

        match &prop.value {
            XbfPropertyValue::String(val_str) => {
                nodes.push(XbfNode::AddProperty {
                    name: prop.name.clone(),
                    value: val_str.clone(),
                    namespace_uri: None,
                });
            }
            XbfPropertyValue::Object(child_idx) => {
                let prop_tag = format!("{}.{}", obj.type_name, prop.name);
                nodes.push(XbfNode::ElementStart {
                    type_name: prop_tag.clone(),
                    namespace_uri: None,
                });
                flatten_object(arena, *child_idx, &prop_tag, nodes);
                nodes.push(XbfNode::ElementEnd);
            }
            XbfPropertyValue::Collection(items) => {
                let prop_tag = format!("{}.{}", obj.type_name, prop.name);
                nodes.push(XbfNode::ElementStart {
                    type_name: prop_tag.clone(),
                    namespace_uri: None,
                });
                for item_idx in items {
                    flatten_object(arena, *item_idx, &prop_tag, nodes);
                }
                nodes.push(XbfNode::ElementEnd);
            }
        }
    }

    for child_idx in &obj.children {
        let child = &arena[*child_idx];
        if child.type_name == "Verbatim" {
            if let Some(prop) = child.properties.first() {
                if let XbfPropertyValue::String(text) = &prop.value {
                    nodes.push(XbfNode::Text(text.clone()));
                }
            }
        } else {
            flatten_object(arena, *child_idx, &obj.type_name, nodes);
        }
    }

    nodes.push(XbfNode::ElementEnd);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xbf_decoder_resilient_header() {
        let empty_payload = vec![0u8; 10];
        let result = XbfDecoder::decode(&empty_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_xbf_decode_flow() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"XBF\x00"); // Magic
        payload.extend_from_slice(&0u32.to_le_bytes()); // Metadata size placeholder
        payload.extend_from_slice(&0u32.to_le_bytes()); // Node size placeholder

        let metadata_start = payload.len();
        payload.extend_from_slice(&2u32.to_le_bytes()); // Major
        payload.extend_from_slice(&1u32.to_le_bytes()); // Minor

        let offsets_pos = payload.len();
        for _ in 0..6 {
            payload.extend_from_slice(&0u64.to_le_bytes());
        }
        payload.extend_from_slice(&[0u8; 32]); // Hash

        let string_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&5u32.to_le_bytes()); // Count: 5
        let strings = vec![
            "MyCustomPage",
            "Expression",
            "x",
            "http://schemas.microsoft.com/winfx/2006/xaml",
            "using:CalculatorApp",
        ];
        for s in strings {
            payload.extend_from_slice(&(s.len() as u32).to_le_bytes());
            for c in s.encode_utf16() {
                payload.extend_from_slice(&c.to_le_bytes());
            }
            payload.extend_from_slice(&0u16.to_le_bytes());
        }

        let assembly_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&0u32.to_le_bytes());

        let type_namespace_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&0u32.to_le_bytes());

        let type_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&0u32.to_le_bytes());

        let property_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&0u32.to_le_bytes());

        let xml_namespace_table_rel = (payload.len() - metadata_start) as u64;
        payload.extend_from_slice(&5u32.to_le_bytes());
        for i in 0..5u32 {
            payload.extend_from_slice(&i.to_le_bytes());
        }

        let metadata_size = (payload.len() - metadata_start) as u32;
        payload[4..8].copy_from_slice(&metadata_size.to_le_bytes());

        payload[offsets_pos..offsets_pos + 8].copy_from_slice(&string_table_rel.to_le_bytes());
        payload[offsets_pos + 8..offsets_pos + 16]
            .copy_from_slice(&assembly_table_rel.to_le_bytes());
        payload[offsets_pos + 16..offsets_pos + 24]
            .copy_from_slice(&type_namespace_table_rel.to_le_bytes());
        payload[offsets_pos + 24..offsets_pos + 32].copy_from_slice(&type_table_rel.to_le_bytes());
        payload[offsets_pos + 32..offsets_pos + 40]
            .copy_from_slice(&property_table_rel.to_le_bytes());
        payload[offsets_pos + 40..offsets_pos + 48]
            .copy_from_slice(&xml_namespace_table_rel.to_le_bytes());

        let node_start = payload.len();
        payload.extend_from_slice(&1u32.to_le_bytes()); // Count: 1

        let node_sec_offsets_pos = payload.len();
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes());

        let first_node_section_pos = payload.len();

        // 1. NamespaceDeclaration (0x03)
        payload.push(0x03);
        payload.extend_from_slice(&3u16.to_le_bytes());
        let prefix = "x";
        payload.extend_from_slice(&(prefix.len() as u32).to_le_bytes());
        for c in prefix.encode_utf16() {
            payload.extend_from_slice(&c.to_le_bytes());
        }

        // 2. ElementStart (0x17) - Page (ID: 33293)
        payload.push(0x17);
        payload.extend_from_slice(&33293u16.to_le_bytes());

        // 3. AddProperty (0x1A) - Text (ID: 33568), value "Expression"
        payload.push(0x1A);
        payload.extend_from_slice(&33568u16.to_le_bytes());
        payload.push(0x05);
        payload.extend_from_slice(&1u16.to_le_bytes());

        // 4. Collection start (0x13) - Text (ID: 33568)
        payload.push(0x13);
        payload.extend_from_slice(&33568u16.to_le_bytes());

        // 5. Verbatim Text (0x04) - "MyCustomPage"
        payload.push(0x04);
        payload.push(0x05);
        payload.extend_from_slice(&0u16.to_le_bytes());

        // 6. Add to list (0x08)
        payload.push(0x08);

        // 7. End of collection (0x02)
        payload.push(0x02);

        // 8. ElementEnd (0x21)
        payload.push(0x21);

        let node_size = (payload.len() - node_start) as u32;
        payload[8..12].copy_from_slice(&node_size.to_le_bytes());

        let node_offset_bytes = 0i32.to_le_bytes();
        let positional_offset_bytes =
            ((payload.len() - first_node_section_pos) as i32).to_le_bytes();
        payload[node_sec_offsets_pos..node_sec_offsets_pos + 4].copy_from_slice(&node_offset_bytes);
        payload[node_sec_offsets_pos + 4..node_sec_offsets_pos + 8]
            .copy_from_slice(&positional_offset_bytes);

        let nodes = XbfDecoder::decode(&payload).expect("Failed to parse mock XBF");
        println!("DECODED NODES: {:#?}", nodes);

        // Output elements are NamespaceDeclaration, Page (start), Text, ElementEnd, ElementEnd
        // Wait, why Page and Text, and two ElementEnds?
        // - Page start (XbfNode::ElementStart Page)
        // - Text property -> flat text node or attribute?
        //   Text is added as a child verbatim object, which flattens to:
        //   - XbfNode::ElementStart Page
        //   - AddProperty Text="Expression"
        //   - XbfNode::Text("MyCustomPage")
        //   - XbfNode::ElementEnd
        // In the namespace declaration:
        // - XbfNode::NamespaceDeclaration prefix "x" uri "http://schemas.microsoft.com/winfx/2006/xaml"

        assert!(nodes
            .iter()
            .any(|n| matches!(n, XbfNode::NamespaceDeclaration { prefix, .. } if prefix == "x")));
        assert!(nodes
            .iter()
            .any(|n| matches!(n, XbfNode::ElementStart { type_name, .. } if type_name == "Page")));
        assert!(nodes.iter().any(|n| matches!(n, XbfNode::AddProperty { name, value, .. } if name == "Text" && value == "Expression")));
        assert!(nodes
            .iter()
            .any(|n| matches!(n, XbfNode::Text(val) if val == "MyCustomPage")));
    }

    #[test]
    fn test_decode_settings_card() {
        let path = "tests/fixtures/SettingsCard.xbf";
        if std::path::Path::new(path).exists() {
            let bytes = std::fs::read(path).unwrap();
            match XbfDecoder::decode(&bytes) {
                Ok(nodes) => {
                    println!(
                        "Successfully decoded SettingsCard.xbf: {} nodes",
                        nodes.len()
                    );
                }
                Err(e) => {
                    panic!("Failed to decode SettingsCard.xbf: {:?}", e);
                }
            }
        }
    }
}
