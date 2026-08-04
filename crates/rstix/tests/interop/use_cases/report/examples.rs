//! §3.16.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Campaign, Malware, Report};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_CAMPAIGN: &str = "examples/report/ex-3.16.4.1-campaign-report.json";
pub const EXAMPLE_MALWARE: &str = "examples/report/ex-3.16.4.2-malware-analysis-report.json";

pub fn assert_campaign_report() {
    let fixture = load_fixture(EXAMPLE_CAMPAIGN);
    assert_eq!(fixture.provenance.source_section, "3.16.4.1");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 16)
    );
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let id = StixId::parse("report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcbd").unwrap();
    let report = bundle.get_typed::<Report>(&id).unwrap();
    assert_eq!(report.name, "Glass Gazelle Campaign");
    assert!(
        bundle
            .get_typed::<Campaign>(
                &StixId::parse("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c").unwrap()
            )
            .is_some()
    );
}

pub fn assert_malware_analysis_report() {
    let fixture = load_fixture(EXAMPLE_MALWARE);
    assert_eq!(fixture.provenance.source_section, "3.16.4.2");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 16)
    );
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let id = StixId::parse("report--980275a5-4423-46c6-bb79-235654096f8a").unwrap();
    let report = bundle.get_typed::<Report>(&id).unwrap();
    assert_eq!(report.name, "Malware Analysis Report");
    assert!(
        bundle
            .get_typed::<Malware>(
                &StixId::parse("malware--bb4ca8dd-1248-5fef-8828-9bd2d935fa58").unwrap()
            )
            .is_some()
    );
}

interop_test!(
    "REQ-3.16-EX-4.1",
    "use_cases::report::examples::campaign_report",
    campaign_report,
    {
        assert_campaign_report();
    }
);
interop_test!(
    "REQ-3.16-EX-4.2",
    "use_cases::report::examples::malware_analysis_report",
    malware_analysis_report,
    {
        assert_malware_analysis_report();
    }
);
