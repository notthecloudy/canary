use crate::SdbEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetType {
    Png,
    Jpeg,
    Wav,
    Lua,
    Xml,
    Json,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SdbAsset {
    pub address: u64,
    pub size: usize,
    pub detected_type: AssetType,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct AssetsNamespace {
    pub assets: Vec<SdbEntry<SdbAsset>>,
}
