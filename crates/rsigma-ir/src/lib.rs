//! # rsigma-ir
//!
//! Intermediate representation for Sigma rules — a shared canonical form
//! between evaluation and conversion backends.
//!
//! The IR lives between the parser AST (rsigma-parser) and the eval engine
//! and convert backends:
//!
//! ```text
//! YAML ─► parser(AST) ─► pipeline(AST transformations) ─► lower(HIR) ─► compile(CompiledRule)
//!                                                              │
//!                                                          convert(Backend queries)
//! ```
//!
//! The HIR captures modifier resolution, selector collapse, and array-scope
//! detections in a serializable form.  Compiled matchers (`Regex`, `IpNet`)
//! are elided from the IR; they are materialised in the compile step.
//!
//! ## Architecture
//!
//! - **`IrRule`** — the top-level shape, a superset of `SigmaRule` metadata
//!   with a resolution-free detection tree (`IrDetection`) and conditions
//!   (`IrCondition`) that carry no `Selector` variant.
//!
//! - **`IrMatcher`** — modifier-resolved matchers.  Each field modifier that
//!   changes comparison (contains, startswith, endswith, cidr, re, numeric
//!   operators, exists, fieldref, timestamp parts) produces an explicit enum
//!   variant rather than being encoded as a combination of raw values and an
//!   opaque `Modifiers` bitfield.
//!
//! - **`IrDetection`** — mirrors the compiler's `CompiledDetection` at the
//!   semantic level: `AllOf`, `AnyOf`, `Keywords`, `ArrayMatch`, `And`, and
//!   `Conditional`.  Array-scope quantifiers (`any`/`all`/`all-or-empty`/`none`)
//!   are preserved.
//!
//! - **`SurfaceSpec`** — optional sidecar on `IrDetectionItem` that records the
//!   original field name, modifiers, and values.  Eval ignores it; convert
//!   backends use it when they need the modifier spelling for idiomatic query
//!   emission.
//!
//! ## Constraints
//!
//! - Sync-only.  No tokio, reqwest, or other async-runtime dependencies.
//!   Dynamic source resolution (Phase 6b, `DynamicSourceRef`) lives in
//!   `rsigma-runtime::specialize_ir`, not here.
//!
//! - Serializable.  `IrRule`, `IrCorrelation`, and `IrFilter` derive serde.
//!   Postcard and JSON are the wire formats; Phase 4 is the first serialization
//!   gate.
//!
//! ## Phases
//!
//! | Phase | What | Gate |
//! |-------|------|------|
//! | 0.0 | Baseline fixtures under `tests/` | Legacy match/compile oracles + expected-HIR stubs + correlation/filter/keywords |
//! | 0.1 | HIR types in [`hir`] | Types compile (in progress alongside 0.0) |
//! | 0.2 | `lower_rule`, … in [`lower`] | Fixtures pass through IR lowering |
//! | 0.3 | Corpus differential | match/no-match + `EvaluationResult` wire-shape parity |

pub mod error;
pub mod hir;
pub mod lower;

pub use error::IrError;
pub use hir::*;