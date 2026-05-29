# Guide: Adding a New Architecture

This guide explains how to add support for a new CPU architecture (e.g., ARM64, MIPS, RISC-V).

---

## Overview

Architecture support in Canary is implemented as a crate that implements the `ArchLifter` trait
from `canary-arch`. The lifter is responsible for:

1. Disassembling raw bytes into `NativeInstr` structs
2. Lifting each native instruction to a sequence of `LlilInstr` operations
3. Building a `ControlFlowGraph` via recursive descent

---

## Step 1: Create the Crate

```bash
# From the workspace root:
mkdir -p crates/canary-arch-arm64/src
```

Create `crates/canary-arch-arm64/Cargo.toml`:

```toml
[package]
name = "canary-arch-arm64"
description = "Canary ARM64/AArch64 architecture lifter"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
canary-ir = { path = "../canary-ir" }
canary-arch = { path = "../canary-arch" }
capstone.workspace = true
thiserror.workspace = true
tracing.workspace = true
```

Add it to the workspace `Cargo.toml`:

```toml
members = [
    # ... existing crates ...
    "crates/canary-arch-arm64",
]
```

---

## Step 2: Implement the Lifter

```rust
// src/lib.rs
use canary_arch::{ArchLifter, LiftError, NativeInstr};
use canary_ir::llil::{LlilInstr, LlilExpr, OperandSize};
use capstone::prelude::*;

pub struct Arm64Lifter {
    cs: Capstone,
}

impl Arm64Lifter {
    pub fn new() -> Result<Self, LiftError> {
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| LiftError::Disassembly { addr: 0, reason: e.to_string() })?;
        Ok(Self { cs })
    }
}

impl ArchLifter for Arm64Lifter {
    fn name(&self) -> &'static str { "aarch64" }
    
    fn supports(&self, arch_name: &str) -> bool {
        matches!(arch_name, "aarch64" | "arm64")
    }
    
    fn disassemble(&self, bytes: &[u8], start_addr: u64)
        -> Result<Vec<NativeInstr>, LiftError>
    {
        // ... similar to X86_64Lifter
    }
    
    fn lift_instr(&self, instr: &NativeInstr) -> Result<Vec<LlilInstr>, LiftError> {
        // Map ARM64 mnemonics to LlilInstr
        match instr.mnemonic.as_str() {
            "ldr" => { /* ... */ }
            "str" => { /* ... */ }
            "b"   => { /* Goto */ }
            "bl"  => { /* Call */ }
            "ret" => Ok(vec![LlilInstr::Return { value: None }]),
            _     => Ok(vec![LlilInstr::Undef { bytes: instr.bytes.clone() }]),
        }
    }
}
```

---

## Step 3: Add Fixture Binaries

Add test binaries compiled for your architecture:

```
tests/fixtures/
  arm64/
    hello_world.elf      # Simple test binary
    README.md            # Document how each fixture was compiled
```

Document in `README.md`:
```
hello_world.elf — compiled with:
  aarch64-linux-gnu-gcc -O0 -o hello_world hello_world.c
  Compiler: GCC 13.2
```

---

## Step 4: Add Integration Tests

```rust
// tests/integration/arm64.rs
use canary_arch::ArchLifter;
use canary_arch_arm64::Arm64Lifter;

#[test]
fn disassemble_arm64_hello_world() {
    let bytes = include_bytes!("../../tests/fixtures/arm64/hello_world.elf");
    let loaded = canary_loader::binary::Binary::load(bytes).unwrap();
    let lifter = Arm64Lifter::new().unwrap();
    
    // Verify we can disassemble the entry point
    let ep = loaded.entry_point;
    let bytes_at = loaded.bytes_at(ep, 64).unwrap();
    let instrs = lifter.disassemble(bytes_at, ep).unwrap();
    assert!(!instrs.is_empty());
}
```

---

## Step 5: Document Coverage

Add a `crates/canary-arch-arm64/README.md` documenting:
- Which instruction classes are lifted
- Which are stubbed as `Undef` (and in which milestone they'll be completed)
- Any architecture-specific quirks (e.g., THUMB interworking, IT blocks)

---

## Instruction Coverage Checklist (ARM64)

| Category | Instructions | Status |
|----------|-------------|--------|
| Data processing (reg) | ADD, SUB, AND, ORR, EOR, ... | Phase 1 |
| Load/Store | LDR, STR, LDP, STP, ... | Phase 1 |
| Branches | B, BL, CBZ, CBNZ, ... | Phase 1 |
| SIMD/FP | FADD, FMUL, ... | Phase 2 |
| System | MRS, MSR, SVC | Phase 2 |
| Crypto | AES*, SHA* | Phase 3+ |
