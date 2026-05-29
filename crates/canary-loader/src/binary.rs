//! Binary loading — pluggable platform loaders for PE, ELF, and Mach-O formats.

use crate::error::LoaderError;
use crate::section::{Section, SectionFlags, SectionKind};
use goblin::Object;
use tracing::{debug, info};

/// The format of a loaded binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
}

/// A named entry point discovered in the binary.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub addr: u64,
    pub name: Option<String>,
}

/// The result of loading a binary — sections, entry points, and metadata.
#[derive(Debug, Clone)]
pub struct LoadedBinary {
    pub format: BinaryFormat,
    pub arch_name: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub named_functions: Vec<EntryPoint>,
    pub imports: Vec<canary_sdb::Import>,
    pub exports: Vec<canary_sdb::Export>,
    pub relocations: Vec<canary_sdb::Relocation>,
    pub debug_info: Vec<canary_sdb::DebugInfo>,
    pub toolchain: Vec<canary_sdb::ToolchainInfo>,
    pub resources: Vec<canary_sdb::ResourceBlob>,
    pub packers: Vec<canary_sdb::PackerInfo>,
    pub eh_frames: Vec<canary_sdb::EhFrame>,
    pub tls_callbacks: Vec<canary_sdb::TlsCallback>,
    pub delay_imports: Vec<canary_sdb::DelayImport>,
    pub strings: Vec<canary_sdb::types::SdbString>,
    pub com_descriptors: Vec<canary_sdb::ComDescriptor>,
    pub rich_header_data: Vec<canary_sdb::RichHeaderData>,
    pub exception_tables: Vec<canary_sdb::ExceptionTable>,
}

impl LoadedBinary {
    /// Returns a reference to the section containing `addr`, if any.
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(addr))
    }

    /// Returns the raw bytes at `addr` with the given `len`.
    pub fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        self.section_at(addr)?.bytes_at(addr, len)
    }

    /// Returns all executable sections.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.flags.executable)
    }

    /// Converts the LoadedBinary into a Semantic Database BinaryNamespace.
    pub fn to_sdb(&self) -> canary_sdb::BinaryNamespace {
        use canary_sdb::{MappedSection, MappedSegment, NamedFunction, RecoveryOrigin, SdbEntry};

        let format_str = match self.format {
            BinaryFormat::Elf => "ELF",
            BinaryFormat::Pe => "PE",
            BinaryFormat::MachO => "Mach-O",
        }
        .to_string();

        let mut ns = canary_sdb::BinaryNamespace {
            format: format_str,
            arch: self.arch_name.clone(),
            image_base: self.image_base,
            entry_point: self.entry_point,
            ..Default::default()
        };

        for section in &self.sections {
            ns.sections.push(SdbEntry::new(
                MappedSection {
                    name: section.name.clone(),
                    address: section.virtual_range.start,
                    size: section.data.len(),
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));

            ns.segments.push(SdbEntry::new(
                MappedSegment {
                    address: section.virtual_range.start,
                    size: section.data.len(),
                    is_read: section.flags.readable,
                    is_write: section.flags.writable,
                    is_exec: section.flags.executable,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for func in &self.named_functions {
            let name = func
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", func.addr));
            ns.named_functions.push(SdbEntry::new(
                NamedFunction {
                    address: func.addr,
                    name,
                },
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for imp in &self.imports {
            ns.imports.push(SdbEntry::new(
                imp.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for exp in &self.exports {
            ns.exports.push(SdbEntry::new(
                exp.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for rel in &self.relocations {
            ns.relocations.push(SdbEntry::new(
                rel.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for dbg in &self.debug_info {
            ns.debug_info.push(SdbEntry::new(
                dbg.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for tool in &self.toolchain {
            ns.toolchain.push(SdbEntry::new(
                tool.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Heuristic,
            ));
        }

        for res in &self.resources {
            ns.resources.push(SdbEntry::new(
                res.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for pack in &self.packers {
            ns.packers.push(SdbEntry::new(
                pack.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Pattern,
            ));
        }

        for com in &self.com_descriptors {
            ns.com_descriptors.push(SdbEntry::new(
                com.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for rh in &self.rich_header_data {
            ns.rich_header_data.push(SdbEntry::new(
                rh.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        for et in &self.exception_tables {
            ns.exception_tables.push(SdbEntry::new(
                et.clone(),
                canary_sdb::ConfidenceVector::base(1.0),
                RecoveryOrigin::Exact,
            ));
        }

        ns
    }
}

/// A pluggable binary loader trait that defines can_load and load interface for platform loaders.
pub trait BinaryLoader {
    /// Returns true if this loader supports the binary data.
    fn can_load(&self, bytes: &[u8]) -> bool;
    /// Parses the raw binary and returns a LoadedBinary payload.
    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary, LoaderError>;
}

/// Standard PE Loader plugin.
pub struct PeLoader;

impl BinaryLoader for PeLoader {
    fn can_load(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[b'M', b'Z'])
    }

    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
        if let Ok(Object::PE(pe)) = Object::parse(bytes) {
            info!("Loaded PE binary");
            return load_pe(&pe, bytes);
        }
        Err(LoaderError::UnsupportedFormat)
    }
}

/// Standard ELF Loader plugin.
pub struct ElfLoader;

impl BinaryLoader for ElfLoader {
    fn can_load(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[0x7f, b'E', b'L', b'F'])
    }

    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
        if let Ok(Object::Elf(elf)) = Object::parse(bytes) {
            info!("Loaded ELF binary");
            return load_elf(&elf, bytes);
        }
        Err(LoaderError::UnsupportedFormat)
    }
}

/// Standard Mach-O Loader plugin.
pub struct MachOLoader;

impl BinaryLoader for MachOLoader {
    fn can_load(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        let magic = &bytes[0..4];
        magic == &[0xfe, 0xed, 0xfa, 0xce]
            || magic == &[0xce, 0xfa, 0xed, 0xfe]
            || magic == &[0xfe, 0xed, 0xfa, 0xcf]
            || magic == &[0xcf, 0xfa, 0xed, 0xfe]
            || magic == &[0xca, 0xfe, 0xba, 0xbe]
            || magic == &[0xbe, 0xba, 0xfe, 0xca]
    }

    fn load(&self, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
        if let Ok(Object::Mach(mach)) = Object::parse(bytes) {
            info!("Loaded Mach-O binary");
            return load_macho(&mach, bytes);
        }
        Err(LoaderError::UnsupportedFormat)
    }
}

/// Top-level binary loading entry point dispatcher.
pub struct Binary;

impl Binary {
    /// Loads a binary from raw bytes by dynamically matching against registered platform loaders.
    pub fn load(bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
        let loaders: &[&dyn BinaryLoader] = &[&PeLoader, &ElfLoader, &MachOLoader];

        for loader in loaders {
            if loader.can_load(bytes) {
                return loader.load(bytes);
            }
        }

        Err(LoaderError::UnsupportedFormat)
    }
}

// ── ELF Loader Internals ───────────────────────────────────────────────────

fn load_elf(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
    let arch_name = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_386 => "x86",
        _ => "unknown",
    }
    .to_string();

    debug!("ELF arch: {arch_name}");

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_size == 0 {
            continue;
        }
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("?")
            .to_string();

        let executable = sh.is_executable();
        let writable = sh.is_writable();
        let kind = if executable {
            SectionKind::Code
        } else if writable {
            SectionKind::Data
        } else {
            SectionKind::ReadOnlyData
        };

        let data = if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            vec![]
        } else {
            let off = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            bytes.get(off..off + size).unwrap_or(&[]).to_vec()
        };

        sections.push(Section {
            name,
            virtual_range: sh.sh_addr..sh.sh_addr + sh.sh_size,
            data,
            flags: SectionFlags {
                readable: true,
                writable,
                executable,
            },
            kind,
        });
    }

    // Collect exported/symbol functions
    let mut named_functions: Vec<EntryPoint> = elf
        .syms
        .iter()
        .filter(|sym| sym.is_function() && sym.st_value != 0)
        .map(|sym| EntryPoint {
            addr: sym.st_value,
            name: elf.strtab.get_at(sym.st_name).map(|s| s.to_string()),
        })
        .collect();

    // Also add the ELF entry point
    if elf.header.e_entry != 0 {
        named_functions.push(EntryPoint {
            addr: elf.header.e_entry,
            name: Some("_start".to_string()),
        });
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut relocations = Vec::new();

    for dyn_sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(dyn_sym.st_name) {
            if dyn_sym.st_value == 0 {
                imports.push(canary_sdb::Import {
                    lib_name: "unknown".to_string(),
                    symbol_name: name.to_string(),
                    address: 0,
                });
            } else {
                exports.push(canary_sdb::Export {
                    symbol_name: name.to_string(),
                    address: dyn_sym.st_value,
                    ordinal: None,
                });
            }
        }
    }

    for rel in elf.dynrelas.iter().chain(
        elf.shdr_relocs
            .iter()
            .flat_map(|(_, rels)| rels.into_iter()),
    ) {
        relocations.push(canary_sdb::Relocation {
            address: rel.r_offset,
            target: rel.r_addend.unwrap_or(0) as u64,
            rel_type: rel.r_type,
        });
    }

    let mut debug_info = Vec::new();
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name.starts_with(".debug") {
                debug_info.push(canary_sdb::DebugInfo {
                    info_type: "DWARF".to_string(),
                    path: None,
                    guid: None,
                });
                break;
            }
        }
    }

    let mut toolchain = Vec::new();
    let mut packers = Vec::new();
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name.starts_with(".upx") || name.starts_with(".UPX") {
                packers.push(canary_sdb::PackerInfo {
                    name: "UPX".to_string(),
                    description: "UPX executable packer".to_string(),
                });
            }
            if name == ".comment" {
                toolchain.push(canary_sdb::ToolchainInfo {
                    compiler: Some("GCC/Clang".to_string()),
                    runtime: None,
                    version: None,
                });
            }
        }
    }
    let resources = Vec::new();

    let strings =
        crate::strings::StringExtractor::default().extract_strings(bytes, elf.header.e_entry);

    Ok(LoadedBinary {
        format: BinaryFormat::Elf,
        arch_name,
        image_base: 0,
        entry_point: elf.header.e_entry,
        sections,
        named_functions,
        imports,
        exports,
        relocations,
        debug_info,
        toolchain,
        resources,
        packers,
        eh_frames: Vec::new(),
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        strings: strings,
        com_descriptors: Vec::new(),
        rich_header_data: Vec::new(),
        exception_tables: Vec::new(),
    })
}

// ── PE Loader Internals ────────────────────────────────────────────────────

fn load_pe(pe: &goblin::pe::PE, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
    let arch_name = if pe.is_64 { "x86_64" } else { "x86" }.to_string();
    let image_base = pe.image_base as u64;

    let mut sections = Vec::new();
    for section in &pe.sections {
        let name = std::str::from_utf8(&section.name)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string();

        let va = image_base + section.virtual_address as u64;
        let vsize = section.virtual_size as u64;
        let raw_off = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let data = bytes
            .get(raw_off..raw_off + raw_size)
            .unwrap_or(&[])
            .to_vec();

        use goblin::pe::section_table::*;
        let chars = section.characteristics;
        let executable = chars & IMAGE_SCN_MEM_EXECUTE != 0;
        let writable = chars & IMAGE_SCN_MEM_WRITE != 0;
        let readable = chars & IMAGE_SCN_MEM_READ != 0;

        let kind = if executable {
            SectionKind::Code
        } else if writable {
            SectionKind::Data
        } else {
            SectionKind::ReadOnlyData
        };

        sections.push(Section {
            name,
            virtual_range: va..va + vsize,
            data,
            flags: SectionFlags {
                readable,
                writable,
                executable,
            },
            kind,
        });
    }

    let entry_rva = pe.entry as u64;
    let entry_point = image_base + entry_rva;

    let mut named_functions: Vec<EntryPoint> = pe
        .exports
        .iter()
        .filter(|exp| exp.rva != 0)
        .map(|exp| EntryPoint {
            addr: image_base + exp.rva as u64,
            name: exp.name.map(|n| n.to_string()),
        })
        .collect();

    named_functions.push(EntryPoint {
        addr: entry_point,
        name: Some("entry".to_string()),
    });

    let mut imports = Vec::new();
    for imp in &pe.imports {
        imports.push(canary_sdb::Import {
            lib_name: imp.dll.to_string(),
            symbol_name: imp.name.to_string(),
            address: imp.offset as u64,
        });
    }

    let mut exports = Vec::new();
    for exp in &pe.exports {
        if exp.rva != 0 {
            exports.push(canary_sdb::Export {
                symbol_name: exp.name.unwrap_or("").to_string(),
                address: image_base + exp.rva as u64,
                ordinal: exp.offset.map(|o| o as u16),
            });
        }
    }

    let mut relocations: Vec<canary_sdb::Relocation> = Vec::new();
    for section in &pe.sections {
        if let Ok(name) = std::str::from_utf8(&section.name) {
            if name.trim_end_matches('\0') == ".reloc" {
                let raw_off = section.pointer_to_raw_data as usize;
                let raw_size = section.size_of_raw_data as usize;
                if let Some(reloc_data) = bytes.get(raw_off..raw_off + raw_size) {
                    let mut i = 0usize;
                    while i + 8 <= reloc_data.len() {
                        let page_rva =
                            u32::from_le_bytes(reloc_data[i..i + 4].try_into().unwrap_or([0; 4]))
                                as u64;
                        let block_size = u32::from_le_bytes(
                            reloc_data[i + 4..i + 8].try_into().unwrap_or([0; 4]),
                        ) as usize;
                        if block_size < 8 || i + block_size > reloc_data.len() {
                            break;
                        }
                        let num_entries = (block_size - 8) / 2;
                        for j in 0..num_entries {
                            let entry = u16::from_le_bytes(
                                reloc_data[i + 8 + j * 2..i + 8 + j * 2 + 2]
                                    .try_into()
                                    .unwrap_or([0; 2]),
                            );
                            let rel_type = (entry >> 12) as u32;
                            let offset = (entry & 0x0FFF) as u64;
                            if rel_type != 0 {
                                relocations.push(canary_sdb::Relocation {
                                    address: image_base + page_rva + offset,
                                    target: 0,
                                    rel_type,
                                });
                            }
                        }
                        i += block_size;
                    }
                }
                break;
            }
        }
    }

    let mut debug_info = Vec::new();
    if let Some(dbg) = &pe.debug_data {
        if let Some(codeview) = &dbg.codeview_pdb70_debug_info {
            debug_info.push(canary_sdb::DebugInfo {
                info_type: "PDB".to_string(),
                path: Some(String::from_utf8_lossy(codeview.filename).into_owned()),
                guid: Some(format!("{:?}", codeview.signature)),
            });
        }
    }

    let mut packers = Vec::new();
    for section in &pe.sections {
        if let Ok(name) = std::str::from_utf8(&section.name) {
            if name.starts_with(".UPX") || name.starts_with(".upx") {
                packers.push(canary_sdb::PackerInfo {
                    name: "UPX".to_string(),
                    description: "UPX executable packer".to_string(),
                });
            }
        }
    }

    let mut toolchain = Vec::new();
    for imp in &pe.imports {
        if imp.dll.to_lowercase().contains("msvcr") || imp.dll.to_lowercase().contains("ucrt") {
            toolchain.push(canary_sdb::ToolchainInfo {
                compiler: Some("MSVC".to_string()),
                runtime: Some(imp.dll.to_string()),
                version: None,
            });
            break;
        }
    }

    let mut resources = Vec::new();
    for section in &pe.sections {
        if let Ok(name) = std::str::from_utf8(&section.name) {
            if name.starts_with(".rsrc") {
                let raw_off = section.pointer_to_raw_data as usize;
                let raw_size = section.size_of_raw_data as usize;
                let res_data = bytes.get(raw_off..raw_off + raw_size).unwrap_or(&[]);

                // Heuristic mock for resource types
                let has_icon = res_data.windows(4).any(|w| w == b"Icon");
                let has_manifest = res_data.windows(8).any(|w| b"assembly" == w);
                let has_version = res_data.windows(12).any(|w| b"VS_VERSION_I" == w);

                if has_icon {
                    resources.push(canary_sdb::ResourceBlob {
                        res_type: "Icon".into(),
                        name: Some("AppIcon".into()),
                        size: 1024,
                    });
                }
                if has_manifest {
                    resources.push(canary_sdb::ResourceBlob {
                        res_type: "Manifest".into(),
                        name: Some("AppManifest".into()),
                        size: 2048,
                    });
                }
                if has_version {
                    resources.push(canary_sdb::ResourceBlob {
                        res_type: "VersionInfo".into(),
                        name: None,
                        size: 512,
                    });
                }

                resources.push(canary_sdb::ResourceBlob {
                    res_type: "PE_RSRC".to_string(),
                    name: None,
                    size: section.size_of_raw_data as usize,
                });
            }
        }
    }

    let mut exception_tables = Vec::new();
    let mut eh_frames = Vec::new();
    if let Some(exc_data) = &pe.exception_data {
        for func in exc_data.functions() {
            if let Ok(f) = func {
                eh_frames.push(canary_sdb::EhFrame {
                    address: image_base + f.begin_address as u64,
                    size: (f.end_address - f.begin_address) as usize,
                });
                exception_tables.push(canary_sdb::ExceptionTable {
                    address: image_base + f.begin_address as u64,
                    size: (f.end_address - f.begin_address) as usize,
                });
            }
        }
    }

    let mut com_descriptors = Vec::new();
    if let Some(opt) = &pe.header.optional_header {
        if let Some(clr_dir) = opt.data_directories.get_clr_runtime_header() {
            if clr_dir.virtual_address != 0 {
                com_descriptors.push(canary_sdb::ComDescriptor {
                    address: image_base + clr_dir.virtual_address as u64,
                    size: clr_dir.size as usize,
                });
            }
        }
    }

    // Rich header is typically found between DOS stub and PE header, often starting with "DanS" XOR key
    // For this implementation, we just mock extraction of a single typical rich header signature
    let mut rich_header_data = Vec::new();
    if bytes.windows(4).any(|w| w == b"Rich") {
        rich_header_data.push(canary_sdb::RichHeaderData {
            comp_id: 1,
            count: 1,
        });
    }

    let strings = crate::strings::StringExtractor::default().extract_strings(bytes, image_base);

    Ok(LoadedBinary {
        format: BinaryFormat::Pe,
        arch_name,
        image_base,
        entry_point,
        sections,
        named_functions,
        imports,
        exports,
        relocations,
        debug_info,
        toolchain,
        resources,
        packers,
        eh_frames,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        strings,
        com_descriptors,
        rich_header_data,
        exception_tables,
    })
}

// ── Mach-O Loader Internals ────────────────────────────────────────────────

fn load_macho(mach: &goblin::mach::Mach, bytes: &[u8]) -> Result<LoadedBinary, LoaderError> {
    match mach {
        goblin::mach::Mach::Binary(macho) => load_macho_object(macho, bytes),
        goblin::mach::Mach::Fat(fat) => {
            match fat.get(0).map_err(|e| LoaderError::Parse(e.to_string()))? {
                goblin::mach::SingleArch::MachO(macho) => load_macho_object(&macho, bytes),
                goblin::mach::SingleArch::Archive(_) => Err(LoaderError::Parse(
                    "Fat binary slice is an archive, not a MachO".into(),
                )),
            }
        }
    }
}

fn load_macho_object(
    macho: &goblin::mach::MachO,
    _bytes: &[u8],
) -> Result<LoadedBinary, LoaderError> {
    let arch_name = match macho.header.cputype {
        goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
        goblin::mach::cputype::CPU_TYPE_ARM64 => "aarch64",
        goblin::mach::cputype::CPU_TYPE_X86 => "x86",
        _ => "unknown",
    }
    .to_string();

    let image_base = 0u64;
    let entry_point = macho.entry as u64;

    let mut sections = Vec::new();
    for segment in macho.segments.iter() {
        for section_result in segment
            .sections()
            .map_err(|e: goblin::error::Error| LoaderError::Parse(e.to_string()))?
        {
            let (sec, sec_data) = section_result;
            let seg_name = std::str::from_utf8(&sec.segname)
                .unwrap_or("?")
                .trim_end_matches('\0');
            let sec_name_raw = std::str::from_utf8(&sec.sectname)
                .unwrap_or("?")
                .trim_end_matches('\0');
            let full_name = format!("{},{}", seg_name, sec_name_raw);

            let va = sec.addr;
            let size = sec.size;

            let executable = (sec.flags & goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS) != 0
                || (sec.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS) != 0;
            let writable = seg_name == "__DATA";
            let readable = true;
            let kind = if executable {
                SectionKind::Code
            } else if writable {
                SectionKind::Data
            } else {
                SectionKind::ReadOnlyData
            };

            sections.push(Section {
                name: full_name,
                virtual_range: va..va + size,
                data: sec_data.to_vec(),
                flags: SectionFlags {
                    readable,
                    writable,
                    executable,
                },
                kind,
            });
        }
    }

    let mut named_functions: Vec<EntryPoint> = vec![EntryPoint {
        addr: entry_point,
        name: Some("_main".to_string()),
    }];
    if let Some(syms) = macho.symbols.as_ref() {
        for sym in syms.iter() {
            if let Ok((name, nlist)) = sym {
                if nlist.is_global() && !nlist.is_undefined() && nlist.n_value != 0 {
                    named_functions.push(EntryPoint {
                        addr: nlist.n_value,
                        name: Some(name.trim_start_matches('_').to_string()),
                    });
                }
            }
        }
    }

    let mut imports: Vec<canary_sdb::Import> = Vec::new();
    for import in macho
        .imports()
        .map_err(|e: goblin::error::Error| LoaderError::Parse(e.to_string()))?
    {
        imports.push(canary_sdb::Import {
            lib_name: import.dylib.to_string(),
            symbol_name: import.name.trim_start_matches('_').to_string(),
            address: import.address,
        });
    }

    Ok(LoadedBinary {
        format: BinaryFormat::MachO,
        arch_name,
        image_base,
        entry_point,
        sections,
        named_functions,
        imports,
        exports: vec![],
        relocations: vec![],
        debug_info: vec![],
        toolchain: vec![],
        resources: vec![],
        packers: vec![],
        eh_frames: vec![],
        tls_callbacks: vec![],
        delay_imports: vec![],
        strings: vec![],
        com_descriptors: vec![],
        rich_header_data: vec![],
        exception_tables: vec![],
    })
}
