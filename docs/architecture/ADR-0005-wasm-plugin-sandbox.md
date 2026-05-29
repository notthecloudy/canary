# ADR-0005: Wasm Plugin Sandbox

**Status:** Accepted
**Date:** 2026-05-21

---

## Decision

**Community plugins are compiled to WebAssembly and run inside a Wasmtime sandbox.**

## Rationale

Binary analysis is a security-sensitive domain. Users regularly analyze malware.
Community plugins are untrusted code. Arbitrary code execution from a plugin must
be impossible.

WebAssembly provides memory isolation by construction:
- Plugins operate on their own linear memory
- Host memory is inaccessible unless explicitly shared via capability buffers
- System calls are mediated through WASI, not arbitrary syscalls

## Plugin Interface (Phase 1)

- JSON over shared memory buffers (serde_json)
- Phase 4: Cap'n Proto for zero-copy performance

## Capability Model

Plugins declare capabilities in `plugin.toml`. The runtime grants only declared capabilities.
A plugin without `ProposeLocalRewrite` cannot call the rewrite API — enforced at the ABI boundary,
not just by convention.

## Target

Plugins are compiled to `wasm32-wasi`.

Languages supported: Rust (first-class), C/C++ (via wasi-sdk), Go (via TinyGo), Python (via Wasm).
