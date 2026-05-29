# Getting Started with Canary

This guide walks through building Canary from source and running your first analysis.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.78+ | `rustup update stable` |
| Git | Any | System package manager |
| Capstone libraries | 5.x | See below |

### Capstone on Windows

The `capstone` Rust crate bundles Capstone and builds it via the C compiler.
Ensure you have a C toolchain:

```powershell
# Install Visual Studio Build Tools or use MSYS2 with GCC
winget install Microsoft.VisualStudio.2022.BuildTools
```

### Capstone on Linux

```bash
# Ubuntu/Debian
sudo apt install libclang-dev

# Arch
sudo pacman -S clang
```

---

## Build

```bash
git clone https://github.com/notthecloudy/canary.git
cd canary
cargo build --workspace
```

First build downloads and compiles all dependencies (~2–4 min on a fresh machine).
Subsequent builds are incremental.

---

## Run

### Binary information

```bash
cargo run -p canary-cli -- info path/to/binary.exe
```

Output:
```
═══════════════════════════════════════
  🐦 Canary Binary Info
═══════════════════════════════════════
  File:         binary.exe
  Format:       Pe
  Architecture: x86_64
  Image Base:   0x140000000
  Entry Point:  0x14001a3b0
  Sections:     6

  Sections:
    .text        0x140001000 – 0x140023000    139 KB  Code
    .rdata       0x140023000 – 0x14002c000     36 KB  ReadOnlyData
    .data        0x14002c000 – 0x140030000     16 KB  Data
    ...
```

### List functions

```bash
cargo run -p canary-cli -- list-functions path/to/binary.exe
```

Add `--heuristics` to also run prologue pattern matching for stripped binaries:

```bash
cargo run -p canary-cli -- list-functions path/to/binary.exe --heuristics
```

### Decompile a function

```bash
cargo run -p canary-cli -- decompile path/to/binary.exe --function main --lang c
```

> **Note:** Decompilation runs Phase 1 & 2 (VSA, MLIL, and semantic reconstruction) and outputs C pseudocode.

### Dump Control Flow Graph (CFG)

```bash
cargo run -p canary-cli -- cfg-dump path/to/binary.exe --function main --format dot > main_cfg.dot
```

### Dump C++ Headers

```bash
cargo run -p canary-cli -- dump-headers path/to/binary.exe > recovered_classes.h
```

### Export SDB State

Export the Semantic Database (SDB) state to JSON for external analysis:
```bash
cargo run -p canary-cli -- export path/to/binary.exe --format json > sdb_state.json
```

---

## Running Tests

```bash
# All tests
cargo test --workspace

# A specific crate
cargo test -p canary-ir

# A specific test
cargo test -p canary-analysis dominators
```

---

## Enabling Logs

Canary uses the `tracing` crate. Control log levels with `RUST_LOG`:

```bash
RUST_LOG=debug cargo run -p canary-cli -- info binary.exe
RUST_LOG=canary_loader=trace cargo run -p canary-cli -- list-functions binary.exe
```

---

## Next Steps

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — how to contribute code
- [Writing a Plugin](./writing-a-plugin.md) — building a Wasm plugin
- [Architecture Decision Records](../architecture/README.md) — why we made key decisions
