//! Lowering: parser AST → HIR.
//!
//! Module placeholder — Phase 0.2 will populate this file with the full

//! lowering implementation:
//! - `lower_rule` — walk metadata, detections, conditions
//! - `lower_detection` — walk `AllOf` / `AnyOf` / `Keywords` / `ArrayMatch` / `And` / `Conditional`
//! - `lower_detection_item` — absorb `ModCtx` + `compile_value` + `validate_modifiers`
//! - `lower_condition` — collapse `Selector` into identifiers + and/or/not
//! - `lower_correlation` / `lower_filter` — parallel walkers

use rsigma_parser::SigmaRule;

use crate::error::IrError;
use crate::{IrCondition, IrDetection, IrFilter, IrRule};

/// Options controlling the lowering strictness.
pub struct LowerOptions {
    /// Reject rules containing `${source.*}` placeholders (strict mode, the
    /// default for Phases 0–5 and 6a).  Phase 6b enables this and preserves
    /// them as `IrValue::DynamicSourceRef`.
    pub permissive_placeholders: bool,
}

impl Default for LowerOptions {
    fn default() -> Self {
        Self {
            permissive_placeholders: false,
        }
    }
}

/// Lower a single parsed `SigmaRule` into its HIR form.
///
/// **Phase 0.2 placeholder** — returns `IrError::Lowering` for now.
/// The real implementation will walk the rule's metadata, detections, and
/// conditions through `lower_*` functions, resolving modifiers and selectors.
pub fn lower_rule(rule: &SigmaRule, _opts: &LowerOptions) -> Result<IrRule, IrError> {
    Err(IrError::Lowering(format!(
        "lower_rule not yet implemented: {}",
        rule.title
    )))
}

/// Lower a parsed detection into `IrDetection`.
pub fn lower_detection(_det: &rsigma_parser::Detection) -> Result<IrDetection, IrError> {
    Err(IrError::Lowering("lower_detection not yet implemented".into()))
}

/// Lower a detection item — absorbs modifier interpretation.
pub fn lower_detection_item(_item: &rsigma_parser::DetectionItem) -> Result<crate::IrDetectionItem, IrError> {
    Err(IrError::Lowering("lower_detection_item not yet implemented".into()))
}

/// Lower a condition expression tree — collapses selectors into identifiers.
pub fn lower_condition(_expr: &rsigma_parser::ConditionExpr) -> Result<IrCondition, IrError> {
    Err(IrError::Lowering("lower_condition not yet implemented".into()))
}

/// Lower a correlation rule into `IrCorrelation`.
pub fn lower_correlation(
    _corr: &rsigma_parser::CorrelationRule,
) -> Result<crate::IrCorrelation, IrError> {
    Err(IrError::Lowering("lower_correlation not yet implemented".into()))
}

/// Lower a filter rule into `IrFilter`.
pub fn lower_filter(_filter: &rsigma_parser::FilterRule) -> Result<IrFilter, IrError> {
    Err(IrError::Lowering("lower_filter not yet implemented".into()))
}
