//! Per-use-case validation overlay on [`Validator::interop_strict()`].

use std::collections::HashSet;

use rstix::validate::{Diagnostic, DiagnosticCode, Leniency, Severity, ValidationReport};

/// Overlay policy layered on the global interop strict validator.
#[derive(Clone, Debug)]
pub struct InteropOverlay {
    downgraded_codes: HashSet<DiagnosticCode>,
}

impl InteropOverlay {
    pub fn apply_overlay(&self, report: ValidationReport) -> OverlayReport {
        let mut kept = Vec::new();
        let mut downgraded = Vec::new();

        for diagnostic in report.diagnostics() {
            if self.should_downgrade(diagnostic) {
                downgraded.push(diagnostic.clone());
            } else {
                kept.push(diagnostic.clone());
            }
        }

        OverlayReport {
            kept,
            downgraded,
            base_leniency: report.leniency(),
        }
    }

    fn should_downgrade(&self, diagnostic: &Diagnostic) -> bool {
        self.downgraded_codes.contains(&diagnostic.code) || diagnostic.code == DiagnosticCode::I0002
    }
}

/// Validation output after applying the interop overlay.
#[derive(Clone, Debug)]
pub struct OverlayReport {
    kept: Vec<Diagnostic>,
    downgraded: Vec<Diagnostic>,
    base_leniency: Leniency,
}

impl OverlayReport {
    pub fn is_valid(&self) -> bool {
        !self
            .kept
            .iter()
            .any(|d| self.base_leniency.fails_validation(d.severity))
    }

    pub fn downgraded(&self) -> impl Iterator<Item = &Diagnostic> {
        self.downgraded.iter()
    }
}

impl Default for InteropOverlay {
    fn default() -> Self {
        Self {
            downgraded_codes: HashSet::from([DiagnosticCode::I0002]),
        }
    }
}

/// SHOULD-level downgrade for relationship matrix warnings (`STIX-I0002`).
pub fn assert_i0002_downgraded() {
    let overlay = InteropOverlay::default();
    let diagnostic = Diagnostic::new(DiagnosticCode::I0002, "relationship endpoint matrix");
    let mut report = ValidationReport::with_leniency(Leniency::Zero);
    report.push(diagnostic);
    let overlay_report = overlay.apply_overlay(report);
    assert!(overlay_report.is_valid());
    assert_eq!(overlay_report.downgraded().count(), 1);
    assert_eq!(
        overlay_report.downgraded().next().unwrap().severity,
        Severity::Warning
    );
}
