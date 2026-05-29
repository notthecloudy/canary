# Developer Guide: Writing a Plugin

This guide walks through creating a Canary plugin from scratch.
Plugins are compiled to WebAssembly and run inside a Wasmtime sandbox.

---

## Overview

Plugins interact with Canary through the `canary-plugin-api` crate.
They receive read-only IR snapshots and return typed proposals.

**Remember:** Core owns truth. Plugins own hypotheses.
The core engine validates every proposal before committing it.

---

## Prerequisites

```bash
# Install the wasm32-wasi target
rustup target add wasm32-wasi

# Install wasm-pack (optional, for testing)
cargo install wasm-pack
```

---

## Step 1: Create a Plugin Crate

```bash
cargo new --lib my-canary-plugin
cd my-canary-plugin
```

In `Cargo.toml`:

```toml
[package]
name = "my-canary-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
canary-plugin-api = "0.1"
serde_json = "1"
```

---

## Step 2: Declare Plugin Metadata

Create `plugin.toml` at the crate root:

```toml
name = "my-canary-plugin"
version = "0.1.0"
description = "Example plugin: suggests names for XOR-based functions"
author = "Your Name"
capabilities = ["read_ir", "suggest_names"]
input_dialects = ["core", "memory"]
provides = ["xor_name_hints"]
requires = ["ssa_form"]
```

---

## Step 3: Implement the Plugin

```rust
// src/lib.rs
use canary_plugin_api::{PluginProposal, Suggestion};

/// Entry point called by the Canary plugin runtime.
///
/// # Safety
/// `input_ptr` and `input_len` point to a JSON-encoded IR snapshot
/// in the plugin's linear memory. The caller (Canary core) ensures
/// the buffer is valid for the duration of this call.
#[no_mangle]
pub extern "C" fn analyze(input_ptr: *const u8, input_len: usize) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    let snapshot: serde_json::Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return encode_error("invalid JSON"),
    };

    let mut suggestions = Vec::new();

    // Look for functions that contain XOR instructions
    if let Some(functions) = snapshot["functions"].as_array() {
        for func in functions {
            if contains_xor_loop(func) {
                suggestions.push(Suggestion::SuggestType {
                    var_name: func["name"].as_str().unwrap_or("").to_string(),
                    proposed_type: "decrypt_fn".to_string(),
                    confidence: 0.75,
                    rationale: "Function contains XOR loop over buffer — likely decryption".to_string(),
                });
            }
        }
    }

    let proposal = PluginProposal {
        plugin_name: "my-canary-plugin".to_string(),
        cfg_hash: snapshot["cfg_hash"].as_str().unwrap_or("").to_string(),
        suggestions,
    };

    write_output(&serde_json::to_vec(&proposal).unwrap())
}

fn contains_xor_loop(func: &serde_json::Value) -> bool {
    // Simplified: check if any block contains XOR operations
    func["blocks"]
        .as_array()
        .map(|blocks| {
            blocks.iter().any(|block| {
                block["instrs"]
                    .as_array()
                    .map(|instrs| instrs.iter().any(|i| i["op"].as_str() == Some("Xor")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

// Output buffer helpers (simplified — full SDK provides these)
static mut OUTPUT: Vec<u8> = Vec::new();

fn write_output(data: &[u8]) -> u64 {
    unsafe {
        OUTPUT = data.to_vec();
        let ptr = OUTPUT.as_ptr() as u64;
        let len = OUTPUT.len() as u64;
        (len << 32) | ptr
    }
}

fn encode_error(msg: &str) -> u64 {
    write_output(msg.as_bytes())
}
```

---

## Step 4: Build

```bash
cargo build --target wasm32-wasi --release
# Output: target/wasm32-wasi/release/my_canary_plugin.wasm
```

---

## Step 5: Test

```bash
# Register and test against a binary
canary plugin test ./target/wasm32-wasi/release/my_canary_plugin.wasm \
  --binary path/to/test.exe
```

---

## Capability Reference

| Capability | What it allows |
|-----------|---------------|
| `read_ir` | Read IR snapshots |
| `suggest_names` | Return `RenameSym` suggestions |
| `suggest_types` | Return `SuggestType` suggestions |
| `propose_local_rewrite` | Return `ProposeIdiom` suggestions |
| `register_pattern_matcher` | Register a named pattern |

Undeclared capabilities are refused at the ABI boundary —
requesting them returns an error, not a permission escalation.

---

## Best Practices

1. **Return low-confidence suggestions rather than nothing.** The core uses confidence scores for prioritization.
2. **Always populate `rationale`.** Users see this in the UI when reviewing suggestions.
3. **Cache within a session.** Your plugin may be called many times. Cache expensive computations keyed by `cfg_hash`.
4. **Don't try to alter control flow.** `ProposeIdiom` suggestions that modify CFG structure are rejected by the validator.
5. **Handle unknown IR gracefully.** The IR schema evolves. Use `serde_json::Value` and ignore unknown fields.
