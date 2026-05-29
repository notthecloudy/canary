# Phase 1 Milestone Tracker

**Goal:** A working CLI that can load a PE/ELF binary, lift x64 to LLIL, construct a CFG with basic SSA, and emit valid C pseudocode.

**Status:** 🟡 Foundation complete — lifting pipeline integration in progress

---

## Milestone M1.1 — Binary Loading ✅

**Complete.**

- PE loader: sections, exports, entry point
- ELF loader: sections, symbols, entry point
- Mach-O: stub (Phase 3)
- Function discovery: named exports + prologue heuristics
- CLI: `canary info`, `canary list-functions`

**Crates:** `canary-loader`, `canary-cli`

---

## Milestone M1.2 — Disassembly & Basic Block Discovery 🟡

**In Progress.**

Tasks:
- [x] Capstone integration in `canary-arch-x86`
- [x] Linear disassembly via `disassemble()`
- [ ] Recursive descent with split-on-branch
- [ ] Jump table detection (Phase 2)
- [ ] Inline data skipping

---

## Milestone M1.3 — CFG Construction 🟡

**Partial.** Stub recursive descent exists in `build_cfg_x86`.

Tasks:
- [x] Basic block allocation
- [x] Entry block registration
- [ ] Full edge wiring (successor/predecessor links)
- [ ] Back edge detection (loop identification)
- [ ] CFG validation (all blocks reachable from entry)
- [ ] Dominance computation (Cooper et al. implemented in `canary-analysis`)

---

## Milestone M1.4 — LLIL Lifting 🟡

**Partial stub.** Common instructions are stubbed; full lifting pending.

Tasks:
- [x] MOV, ADD, SUB (stub)
- [x] JMP, JE, JNE, RET, CALL (stub)
- [ ] Full MOV variants (MOVZX, MOVSX, MOVSXD, MOVSS, MOVSD)
- [ ] LEA
- [ ] PUSH/POP
- [ ] CMP, TEST (flag expressions)
- [ ] Full conditional branch set (JG, JL, JGE, JLE, JA, JB, ...)
- [ ] MUL, IMUL, DIV, IDIV
- [ ] Bitwise: AND, OR, XOR, SHL, SHR, SAR, ROL, ROR
- [ ] Memory operands (complex addressing modes: `[rbp - 0x8]`)
- [ ] SIMD subset (for common patterns: MOVAPS, MOVDQU)

---

## Milestone M1.5 — SSA Transformation 🔴

**Not started** (infrastructure complete, integration pending).

Tasks:
- [ ] Collect all `Reg` definitions per function
- [ ] Compute dominance frontiers (algorithm implemented)
- [ ] Insert φ-nodes at join points
- [ ] Rename pass (dominator tree walk)
- [ ] Validate SSA: every use has exactly one definition
- [ ] Unit tests with known SSA shapes

---

## Milestone M1.6 — Basic C Emission 🟡

**C emitter implemented.** Integration with lifted functions pending.

Tasks:
- [x] `Emitter` trait
- [x] `CEmitter` for LLIL → C
- [ ] Wire emitter to a fully lifted function
- [ ] Integration test: compile known C → decompile → verify structure
- [ ] CLI: `canary decompile --lang c` produces valid C output

---

## Milestone M1.7 — CLI Completion 🟡

**Partial.** `info` and `list-functions` complete. `decompile` is a stub.

Tasks:
- [x] `canary info <binary>`
- [x] `canary list-functions <binary>`
- [x] `canary list-functions --heuristics`
- [ ] `canary decompile <binary> --function <name|addr>`
- [ ] Output to file: `--output path.c`
- [ ] JSON output mode: `--format json`

---

## Current Sprint Focus

**Priority: M1.3 CFG edge wiring and M1.4 instruction coverage**

The `build_cfg_x86` function's second pass (edge wiring) needs to be completed.
Once we have a properly connected CFG, the dominator computation and SSA builder
can be integrated end-to-end.

See [feature/ssa-construction](https://github.com/notthecloudy/canary/tree/feature/ssa-construction) branch.
