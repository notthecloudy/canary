use crate::SdbEntry;
use indexmap::IndexMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Header,
    Source,
    Build,
    Doc,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub file_type: FileType,
    pub content: String,
    pub includes: Vec<String>,
    pub symbol_addresses: Vec<u64>,
}

#[derive(Default, Debug, Clone)]
pub struct ProjectLayout {
    pub files: IndexMap<String, FileEntry>,
}

#[derive(Default)]
pub struct ProjectNamespace {
    pub layout: Option<SdbEntry<ProjectLayout>>,
}
