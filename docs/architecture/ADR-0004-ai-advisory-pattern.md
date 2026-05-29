# ADR-0004: AI as Advisory Board

**Status:** Accepted
**Date:** 2026-05-21

---

## Decision

**AI/LLMs are never on the critical path of semantic validity.**

AI integration follows the "Advisory Board" pattern:
1. The deterministic pipeline produces a sound HLIL/AST (95%+ of work)
2. AI acts as an **Analysis Pass** — consuming the AST and returning typed suggestions
3. The core validator accepts or rejects each suggestion
4. AI outputs are **cached by `hash(function_cfg)`** — unchanged binary → no re-query

## Where AI Adds Value

- **Naming & Symbol Recovery:** `decrypt_and_encode_payload` instead of `sub_401000`
- **Idiom Recognition:** Recognizing bespoke logging frameworks or custom thread pools
- **Style Formatting:** Making mathematically correct but ugly AST output idiomatic

## Where AI Is Forbidden

- Rewriting control flow
- Removing bounds checks or safety checks
- Modifying data-flow (def-use relationships)
- Any operation that changes the CFG dominator tree

## Rationale

LLMs hallucinate control flow and arithmetic. They are probabilistic. Decompilation
correctness requires determinism. The AI must be an annotator, not an author.

The caching strategy is critical for reproducibility: if the same binary is analyzed
twice with the same AI model, identical suggestions are produced without API calls.
