# ADR-0001: Rust as Core Language

**Status:** Accepted
**Date:** 2026-05-21
**Author:** Canary Core Team

---

## Context

Canary is a long-horizon (5–10 year) binary analysis framework. The core IR engine will:
- Process untrusted binary inputs
- Maintain a complex, mutable graph of IR nodes
- Execute analysis passes concurrently across functions
- Host a sandboxed plugin runtime (WebAssembly)
- Run as a long-lived background process

Language choice has permanent consequences for architecture, performance, hiring, and ecosystem integration.

The principal candidates were **Rust** and **C++**.

## Decision

**Rust is the primary language for the Canary core engine.**

C++ is permitted for:
- FFI bindings to existing binary analysis libraries (Capstone, Zydis, remill)
- Extremely hot micro-optimized components when profiling proves necessary

## Rationale

### Correctness Under Concurrency

The engine requires:
- Work-stealing analysis of functions in parallel
- Background re-analysis on incremental changes
- Shared IR database with concurrent readers
- Live UI updates from a background analysis thread

In C++, achieving this safely requires discipline that is not enforced by the language. Canary's IR is a complex, mutable graph; use-after-free and data races would be extremely difficult to eliminate over a 10-year codebase.

In Rust:
- Ownership is explicit and enforced at compile time
- `Send + Sync` guarantees are structural, not conventional
- Data races are compile-time errors, not runtime surprises

### IR Safety

Decompiler IRs are not normal compiler IRs. They contain:
- Partially known types
- Speculative facts
- Invalid states during lifting
- Graph rewrites mid-analysis
- Cyclic structures during SSA construction

Rust's ownership model catches:
- Stale references to invalidated IR nodes
- Shared mutable access during parallel reads
- Memory leaks in complex ownership chains

### Wasm Ecosystem Alignment

Canary's plugin ecosystem is built on WebAssembly. Rust has first-class support for:
- Compiling to `wasm32-wasi`
- The WASI component model
- Wasmtime (the chosen Wasm runtime) — itself written in Rust

### Long-Term Maintainability

For a 10-year codebase:
- Rust APIs become stricter over time (ownership encodes invariants in types)
- Refactors are safer (the compiler catches broken invariants)
- The trait system provides clean pass abstractions

## Consequences

- Higher initial development velocity cost (Rust learning curve, borrow checker friction)
- Compile times must be managed (workspace splitting, judicious use of generics)
- C++ FFI requires careful `unsafe` blocks with `// SAFETY:` justification

## Alternatives Considered

### C++
- **Pro:** Mature ecosystem, existing RE library integration, large hiring pool of RE engineers
- **Con:** Manual memory safety, race condition risk in concurrent IR manipulation, no language-level ownership guarantees

### Go
- **Pro:** Fast compile times, simple concurrency model
- **Con:** GC pauses unacceptable for real-time analysis, poor Wasm integration, no zero-cost abstractions for hot analysis paths

### Python
- Rejected immediately. Performance requirements preclude Python for the core engine.
