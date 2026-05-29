use canary_loader::binary::LoadedBinary;
use indexmap::IndexSet;

/// Scans executable sections for common x86_64 function prologues
/// to bypass CFG obfuscation (e.g. Byfron/Hyperion) which hides direct calls.
pub fn scan_for_prologues(loaded: &LoadedBinary) -> IndexSet<u64> {
    let mut found = IndexSet::new();

    for section in &loaded.sections {
        // Only scan sections flagged as executable code.
        // Data sections (.rdata, .data, etc.) frequently contain byte sequences that match
        // prologue patterns by coincidence, generating thousands of false-positive candidates.
        if !section.flags.executable
            || section.data.is_empty()
            || section.name.starts_with(".rsrc")
            || section.name.starts_with(".pdata")
        {
            continue;
        }

        let data = &section.data;
        let base = section.virtual_range.start;

        let mut i = 0;
        while i < data.len() {
            // Common x64 prologues

            // 1. push rbp; mov rbp, rsp (55 48 89 E5)
            if i + 3 < data.len()
                && data[i] == 0x55
                && data[i + 1] == 0x48
                && data[i + 2] == 0x89
                && data[i + 3] == 0xE5
            {
                found.insert(base + i as u64);
                i += 4;
                continue;
            }

            // 2. sub rsp, XX (48 83 EC XX)
            if i + 3 < data.len() && data[i] == 0x48 && data[i + 1] == 0x83 && data[i + 2] == 0xEC {
                found.insert(base + i as u64);
                i += 4;
                continue;
            }

            // 3. push rbx (40 53) or push r12 (41 54) or push r13 (41 55) or push r14 (41 56) or push r15 (41 57)
            if i + 1 < data.len() {
                if data[i] == 0x40 && data[i + 1] == 0x53 {
                    found.insert(base + i as u64);
                    i += 2;
                    continue;
                }
                if data[i] == 0x41 && data[i + 1] >= 0x54 && data[i + 1] <= 0x57 {
                    found.insert(base + i as u64);
                    i += 2;
                    continue;
                }
            }

            // 4. mov [rsp+xx], rbx/rsi/rdi (48 89 5C 24 XX)
            if i + 4 < data.len() && data[i] == 0x48 && data[i + 1] == 0x89 {
                if (data[i + 2] == 0x5C || data[i + 2] == 0x74 || data[i + 2] == 0x7C)
                    && data[i + 3] == 0x24
                {
                    found.insert(base + i as u64);
                    i += 5;
                    continue;
                }
            }

            i += 1;
        }
    }

    found
}
