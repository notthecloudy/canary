//! `canary-core` — Core engine: pass scheduler, incremental database, and commit/validate.
//!
//! The core engine is the **authoritative** source of all semantic facts about a binary.
//! It owns the IR graph, orchestrates analysis passes, and validates proposals from plugins.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                   Core Engine                        │
//! │                                                      │
//! │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
//! │  │ IR Graph  │  │ Pass     │  │ Proposal Validator  │ │
//! │  │ (Arena)  │  │ Scheduler│  │                    │ │
//! │  └──────────┘  └──────────┘  └────────────────────┘ │
//! │                                                      │
//! │  Plugin proposals → Validator → Commit or Reject     │
//! └──────────────────────────────────────────────────────┘
//! ```

pub mod assets;
pub mod class_emit;
pub mod clustering;
pub mod codegen;
pub mod config;
pub mod discovery;
pub mod engine;
pub mod linear_sweep;
pub mod naming;
pub mod program_db;
pub mod program_emit;
pub mod project_layout;
pub mod refinement;
pub mod scheduler;
pub mod validator;
pub mod workspace;

pub use engine::Engine;
pub use program_db::ProgramDatabase;
pub use workspace::Workspace;

pub mod cache;
pub mod diff;
pub mod export;
pub mod rebuild_test;
pub mod verify;
