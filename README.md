<div align="center">

# 🐦 Canary

**Progressive Semantic Raising for Binary Analysis**

_We don't un-compile. We recover intent._

[![Build Status](https://img.shields.io/github/actions/workflow/status/notthecloudy/canary/ci.yml?branch=main&style=flat-square)](https://github.com/notthecloudy/canary/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/notthecloudy/canary/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange?style=flat-square)](https://www.rust-lang.org/)

> ⚠️ **Early Development** — Core functionality is still under active development. APIs are experimental, unstable, and subject to change.

</div>

---

## The Problem with Decompilers

Every mainstream decompiler answers the same question: _what instructions are these?_ The output is C-like pseudocode — technically accurate, but written in a dialect no human would ever produce. You get `v3 = *(int32_t *)(v1 + 0x28)` when the original was `player.health`.

Canary answers a different question: _what was the programmer trying to do?_

It treats decompilation as **semantic reconstruction** — a pipeline of progressive raising passes that elevate binary representations through increasingly abstract intermediate forms until the original _intent_ of the code can be expressed in idiomatic, maintainable source. The goal is not pseudocode, but semantically reconstructed code that is readable, maintainable, and structurally close to what a human may have originally written.

---

## How It Works

```
Binary ELF/PE/Mach-O
    │
    ▼  Loader + Disassembler
    │  (PE/COFF/ELF, x86_64, ARM64)
    │
    ▼  Low-Level IR (LLIL)
    │  Architecture-agnostic register transfer language
    │
    ▼  SSA Transformation
    │  φ-functions, def-use chains, dominance frontiers
    │
    ▼  Mid-Level IR (MLIL)
    │  Stack slots → named variables, calling conventions resolved
    │
    ▼  Semantic Raising Passes
    │  Dialects: Memory → OO → HighLevel
    │  Patterns:  vtables, STL idioms, closures, iterators
    │
    ▼  Intent Graph
    │  Language-agnostic representation of programmer intent
    │
    ▼  Language Emitters
       C  │  C++  │  Rust  │  Go
```

Each stage is a standalone pass. A pass that cannot raise cleanly falls back to its lower-level output. When a pass cannot recover a fact confidently, Canary falls back to a lower-level representation and marks uncertainty explicitly. The pipeline degrades gracefully, prioritizing best-effort semantic recovery with explicit uncertainty.

---

## Non-Goals

To maintain a focused scope and set realistic expectations, Canary explicitly does **not** attempt to:

- Recover all original variable or function names (unless debug symbols are present).
- Restore original source code comments or documentation.
- Guarantee the exact formatting, macro usage, or layout of the original source.
- Automatically resolve all forms of aggressive, deliberate obfuscation.

---

## Design Principles

### 1. Progressive Semantic Raising

There is no monolithic translation step. A series of targeted raising passes elevates the representation one abstraction layer at a time. Each pass has a narrow job and a defined fallback. Composing small, verified transformations is more robust than one large one.

### 2. Core Owns Truth, Plugins Own Hypotheses

The core engine is the authoritative source of semantic facts: SSA form, alias analysis, memory versioning, CFG validity. External plugins — including first-party ones — interact through a narrow, validated API. They may _suggest_. The core decides.

### 3. AI as Advisor, Not Authority

Language models are good at naming, idiomatic style, and pattern recognition. They are not reliable for control-flow analysis or mathematical reasoning. Canary's AI integration follows the **Advisory Board** pattern: the deterministic pipeline produces a sound AST; AI annotates it; the core validates every annotation before commit. AI outputs are strictly annotative, never authoritative, and AI is never allowed to alter control-flow semantics directly. AI suggestions are cached by CFG hash — if the binary hasn't changed, the model isn't queried again.

### 4. Intent Graph, Not Syntax Tree

The high-level IR is converted to an **Intent Graph** — a language-agnostic representation of what the code _does_, not how any particular language would say it. Language emitters are visitors over this graph:

| Intent Node           | Rust                     | C                           | Go                         |
| --------------------- | ------------------------ | --------------------------- | -------------------------- |
| `Iterate(Collection)` | `for item in col.iter()` | `for (i = 0; i < len; i++)` | `for _, item := range col` |
| `Option(T)`           | `Option<T>`              | `nullable pointer`          | `(T, bool)`                |
| `OwnedString`         | `String`                 | `char *`                    | `string`                   |

Semantic content is captured once. Syntax is generated per target.

**Example Reconstruction:**
* **Input IR (MLIL):** `v1 = rcx; v2 = [v1 + 8]; if (v2 != 0) { call v2(v1); }`
* **Intent Node:** `VirtualMethodCall(Instance: v1, Offset: 8, Args: [])`
* **Emitted Code (C++):** `instance->method();`

### 5. Wasm-Sandboxed Plugins

Community plugins are compiled to WebAssembly and executed inside a Wasmtime sandbox. They cannot corrupt the IR graph, access the filesystem arbitrarily, or interfere with analysis. Plugins declare explicit capability requirements (`ReadIR`, `SuggestTypes`, `ProposeLocalRewrite`) and are granted only what they declare.

### 6. Explicit Uncertainty Model

When evidence is incomplete, Canary does not guess blindly. It maintains a confidence model for all facts:
- **Certain:** Derived mathematically (e.g., control flow, definite aliases).
- **Inferred:** Derived heuristically (e.g., struct bounds from access patterns).
- **Speculative:** Suggested by AI or weak heuristics.

Uncertainty is explicitly marked in the UI and exported in the final output, allowing the user to distinguish verified facts from guesses.

---

## Architecture

### Crate Map

| Crate               | Role                                                       |
| ------------------- | ---------------------------------------------------------- |
| `canary-core`       | Pass scheduler, incremental database, commit/validate loop |
| `canary-ir`         | IR node types (core dialects), SSA, arena storage          |
| `canary-loader`     | PE/ELF/Mach-O binary parsers                               |
| `canary-arch`       | Architecture lifting trait definitions                     |
| `canary-arch-x86`   | x86/x64 instruction lifting to LLIL                        |
| `canary-analysis`   | CFG, dominators, VSA, alias analysis, symbolic reasoning   |
| `canary-emit`       | Syntax and formatting/layout emission for target languages |
| `canary-plugin-api` | Stable Wasm plugin interface                               |
| `canary-cli`        | Command-line interface                                     |

### Dialect System

Raising passes target transitions between dialects, modelled after MLIR's dialect infrastructure — but inverted: Canary raises rather than lowers.

```
x86 Dialect       →  Raw register/flag operations
    ↓
Core Dialect      →  SSA variables, arithmetic, control flow
    ↓
Memory Dialect    →  Heap/stack layout, pointer arithmetic, array accesses
    ↓
OO Dialect        →  Classes, vtables, virtual dispatch, this-ptr
    ↓
HighLevel Dialect →  Iterators, closures, algebraic types, RAII
```

Emitters target the highest available dialect and fall back gracefully if a pass didn't fire.

---

## Getting Started

### Prerequisites

- Rust 1.78+ — install via `rustup update stable`
- Cargo (included with Rust)

### Build

```bash
git clone https://github.com/notthecloudy/canary.git
cd canary
cargo build --workspace
```

### UI & Visual Output

*(UI screenshots and workflow graphics will be added here as UI development progresses. The goal is to provide a side-by-side view of the binary, Intent Graph, and raised code, highlighting speculative facts dynamically.)*

### Usage

```bash
# List functions discovered in a binary
cargo run -p canary-cli -- list-functions path/to/binary.exe

# Decompile a function (Phase 1 & 2: VSA, MLIL, and semantic reconstruction)
cargo run -p canary-cli -- decompile path/to/binary.exe --function main

# Decompile with verbose IR dumps (useful for debugging passes)
cargo run -p canary-cli -- decompile path/to/binary.exe --function main --dump-ir
```

> Phase 1 output is intentionally conservative — the goal is correctness, not beauty. Higher dialect output arrives in later phases.

---

## Roadmap

| Phase       | Target  | Focus                                                              |
| ----------- | ------- | ------------------------------------------------------------------ |
| **Phase 1** | `v0.1`  | Foundation: loader, x64 lifting, CFG/SSA, basic C emission         |
| **Phase 2** | `v0.2`  | Recovery: VSA, MLIL, struct layout, control-flow unflattening      |
| **Phase 3** | `v0.3`  | Raising: dialects, vtable/RTTI recovery, C++ emission              |
| **Phase 4** | `v0.4`  | Extensibility: Wasm plugins, AI advisory layer, Rust emitter       |
| **Phase 5** | `v1.0+` | Expansion: Go, Rust lifetime inference, collaborative RE           |

Detailed technical decisions live in [Architecture Decision Records](./docs/architecture/). Significant changes go through the [RFC process](./docs/rfcs/).

---

## Prior Art & Differences

Canary is built on a well-understood foundation and borrows ideas from across the RE ecosystem. Where it diverges:

| Tool                 | What Canary learns from it                                | Where Canary differs                                                    |
| -------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- |
| **Binary Ninja**     | Tiered IR (LLIL/MLIL/HLIL), fast interactive analysis     | Canary targets multi-language emission and the Intent Graph abstraction |
| **Ghidra**           | P-Code lifting, SLEIGH specs, open ecosystem              | Canary prioritises idiomatic output over complete instruction coverage  |
| **MLIR**             | Dialect infrastructure, progressive transformation passes | Canary inverts the direction: raising instead of lowering               |
| **angr**             | Symbolic execution for de-obfuscation                     | Canary borrows targeted VSA ideas rather than full symbolic reasoning   |
| **remill**           | Architecture-agnostic instruction semantics               | Informs the LLIL lifting layer design                                   |
| **Capstone / Zydis** | Disassembly engines                                       | Used directly as lifting primitives                                     |

---

## Contributing

Canary welcomes contributors at all levels. The codebase is deliberately modular — you can add a new architecture lifter, language emitter, or analysis pass without touching the core.

Read [CONTRIBUTING.md](./CONTRIBUTING.md) for:

- Development setup and workflow
- Code style and review standards
- The RFC process for significant changes
- How to add a new architecture lifter or language emitter
- How to write a Wasm plugin

For questions, join the [Discord](https://discord.gg/canary) or open a Discussion.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/notthecloudy/canary/blob/main/LICENSE) for details.

---

<div align="center">
<sub>Correctness first. Intent always.</sub>
</div>
