use crate::workspace::Workspace;
use canary_loader::binary::Binary;
use canary_sdb::{AssetType, RecoveryOrigin, SdbAsset, SdbEntry};

pub fn extract_assets(workspace: &mut Workspace) {
    let mut assets = Vec::new();

    if let Ok(loaded) = Binary::load(&workspace.binary_bytes) {
        for section in &loaded.sections {
            let bytes = &section.data;
            let mut i = 0;
            while i + 8 <= bytes.len() {
                // PNG detection
                if bytes[i..i + 8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                    let mut found_iend = None;
                    if bytes.len() >= 8 {
                        for j in i + 8..bytes.len() - 4 {
                            if bytes[j..j + 4] == [0x49, 0x45, 0x4E, 0x44] {
                                found_iend = Some(j);
                                break;
                            }
                        }
                    }
                    if let Some(iend_idx) = found_iend {
                        let size = (iend_idx - i) + 8;
                        let asset_bytes = bytes[i..i + size].to_vec();
                        let address = section.virtual_range.start + i as u64;
                        let path = format!("assets/img_{:x}.png", address);
                        assets.push(SdbEntry::new(
                            SdbAsset {
                                address,
                                size,
                                detected_type: AssetType::Png,
                                path,
                                bytes: asset_bytes,
                            },
                            canary_sdb::ConfidenceVector::base(0.95),
                            RecoveryOrigin::Pattern,
                        ));
                        i += size;
                        continue;
                    }
                }

                // JPEG detection
                if i + 3 <= bytes.len() && bytes[i..i + 3] == [0xFF, 0xD8, 0xFF] {
                    let mut found_eoi = None;
                    for j in i + 3..bytes.len() - 2 {
                        if bytes[j..j + 2] == [0xFF, 0xD9] {
                            found_eoi = Some(j);
                            break;
                        }
                    }
                    if let Some(eoi_idx) = found_eoi {
                        let size = (eoi_idx - i) + 2;
                        let asset_bytes = bytes[i..i + size].to_vec();
                        let address = section.virtual_range.start + i as u64;
                        let path = format!("assets/img_{:x}.jpg", address);
                        assets.push(SdbEntry::new(
                            SdbAsset {
                                address,
                                size,
                                detected_type: AssetType::Jpeg,
                                path,
                                bytes: asset_bytes,
                            },
                            canary_sdb::ConfidenceVector::base(0.95),
                            RecoveryOrigin::Pattern,
                        ));
                        i += size;
                        continue;
                    }
                }

                // WAV detection
                if i + 12 <= bytes.len()
                    && &bytes[i..i + 4] == b"RIFF"
                    && &bytes[i + 8..i + 12] == b"WAVE"
                {
                    let chunk_size =
                        u32::from_le_bytes(bytes[i + 4..i + 8].try_into().unwrap_or([0; 4]))
                            as usize;
                    let size = chunk_size + 8;
                    if i + size <= bytes.len() {
                        let asset_bytes = bytes[i..i + size].to_vec();
                        let address = section.virtual_range.start + i as u64;
                        let path = format!("assets/audio_{:x}.wav", address);
                        assets.push(SdbEntry::new(
                            SdbAsset {
                                address,
                                size,
                                detected_type: AssetType::Wav,
                                path,
                                bytes: asset_bytes,
                            },
                            canary_sdb::ConfidenceVector::base(0.95),
                            RecoveryOrigin::Pattern,
                        ));
                        i += size;
                        continue;
                    }
                }

                // LUA bytecode detection
                if i + 4 <= bytes.len() && bytes[i..i + 4] == [0x1B, 0x4C, 0x75, 0x61] {
                    let mut size = 1024;
                    for j in i + 4..bytes.len() - 16 {
                        if bytes[j..j + 16] == [0; 16] {
                            size = j - i;
                            break;
                        }
                    }
                    if i + size <= bytes.len() {
                        let asset_bytes = bytes[i..i + size].to_vec();
                        let address = section.virtual_range.start + i as u64;
                        let path = format!("assets/script_{:x}.luac", address);
                        assets.push(SdbEntry::new(
                            SdbAsset {
                                address,
                                size,
                                detected_type: AssetType::Lua,
                                path,
                                bytes: asset_bytes,
                            },
                            canary_sdb::ConfidenceVector::base(0.8),
                            RecoveryOrigin::Pattern,
                        ));
                        i += size;
                        continue;
                    }
                }

                i += 1;
            }
        }
    } else {
        // Fallback for flat binaries or unrecognized formats
        let bytes = &workspace.binary_bytes;
        let mut i = 0;
        while i + 8 <= bytes.len() {
            if bytes[i..i + 8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                let mut found_iend = None;
                if bytes.len() >= 8 {
                    for j in i + 8..bytes.len() - 4 {
                        if bytes[j..j + 4] == [0x49, 0x45, 0x4E, 0x44] {
                            found_iend = Some(j);
                            break;
                        }
                    }
                }
                if let Some(iend_idx) = found_iend {
                    let size = (iend_idx - i) + 8;
                    let asset_bytes = bytes[i..i + size].to_vec();
                    let address = i as u64;
                    let path = format!("assets/img_{:x}.png", address);
                    assets.push(SdbEntry::new(
                        SdbAsset {
                            address,
                            size,
                            detected_type: AssetType::Png,
                            path,
                            bytes: asset_bytes,
                        },
                        canary_sdb::ConfidenceVector::base(0.95),
                        RecoveryOrigin::Pattern,
                    ));
                    i += size;
                    continue;
                }
            }
            i += 1;
        }
    }

    workspace.sdb.facts.assets.assets = assets;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_detection() {
        let mut workspace = Workspace::new(
            "dummy",
            vec![
                0, 0, 0, 0, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00,
                0x49, 0x45, 0x4E, 0x44, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        extract_assets(&mut workspace);
        assert_eq!(workspace.sdb.facts.assets.assets.len(), 1);
        let asset = &workspace.sdb.facts.assets.assets[0].value;
        assert_eq!(asset.detected_type, AssetType::Png);
        assert_eq!(asset.address, 4);
        assert_eq!(asset.size, 20);
    }
}
