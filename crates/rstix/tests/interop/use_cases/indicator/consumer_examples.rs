//! §3.7.7 Consumer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Identity, Indicator};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.7.7.1 non-normative Consumer example (TIP / compromised IPv4).
pub const EXAMPLE_TIP: &str = "examples/indicator/ex-3.7.7.1-tip-indicator-consumer.json";
/// OASIS §3.7.7.2 non-normative Consumer example (TMS / SHA-256 file hash).
pub const EXAMPLE_TMS: &str = "examples/indicator/ex-3.7.7.2-tms-indicator-consumer.json";
/// OASIS §3.7.7.3 non-normative Consumer example (TDS / anomalous FQDN).
pub const EXAMPLE_TDS: &str = "examples/indicator/ex-3.7.7.3-tds-indicator-consumer.json";
/// OASIS §3.7.7.4 non-normative Consumer example (SXC / anomalous IPv6).
pub const EXAMPLE_SXC: &str = "examples/indicator/ex-3.7.7.4-sxc-indicator-consumer.json";
/// OASIS §3.7.7.5 non-normative Consumer example (SIEM / malicious URL).
pub const EXAMPLE_SIEM: &str = "examples/indicator/ex-3.7.7.5-siem-indicator-consumer.json";

/// REQ-3.7-EX-7.1 — Consumer ingests TIP persona Indicator example (§3.7.7.1).
pub fn assert_tip_indicator_consumer() {
    let fixture = load_fixture(EXAMPLE_TIP);
    assert_eq!(fixture.provenance.source_section, "3.7.7.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.7.1 example must parse and pass interop gate");

    let identity_id =
        StixId::parse("identity--f6e43aa5-76cc-45ca-9b06-be2d65f26bfb").expect("identity id");
    let identity = bundle
        .get_typed::<Identity>(&identity_id)
        .expect("ACME Corp Sighting Identity");
    assert_eq!(identity.name, "ACME Corp Sighting, Inc.");

    let indicator_id =
        StixId::parse("indicator--a5b23aa5-76cc-45ca-9b06-be2d65defabc").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("TIP example Indicator");
    assert_eq!(indicator.indicator_types, vec!["compromised"]);
    assert_eq!(
        indicator.pattern.raw(),
        "[ipv4-addr:value = '198.51.100.1']"
    );
}

/// REQ-3.7-EX-7.2 — Consumer ingests TMS persona Indicator example (§3.7.7.2).
pub fn assert_tms_indicator_consumer() {
    let fixture = load_fixture(EXAMPLE_TMS);
    assert_eq!(fixture.provenance.source_section, "3.7.7.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.7.2 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--aaabbbcc-cddd-eeef-fff6-be2d65defabc").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("TMS example Indicator");
    assert_eq!(indicator.indicator_types, vec!["malicious-activity"]);
    assert!(
        indicator
            .pattern
            .raw()
            .contains("file:hashes.'SHA-256'"),
        "TMS example must carry SHA-256 file hash pattern"
    );
}

/// REQ-3.7-EX-7.3 — Consumer ingests TDS persona Indicator example (§3.7.7.3).
pub fn assert_tds_indicator_consumer() {
    let fixture = load_fixture(EXAMPLE_TDS);
    assert_eq!(fixture.provenance.source_section, "3.7.7.3");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.7.3 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--abcabcab-cdef-defd-ef12-342d65defabc").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("TDS example Indicator");
    assert_eq!(indicator.indicator_types, vec!["anomalous-activity"]);
    assert_eq!(
        indicator.pattern.raw(),
        "[domain-name:value = 'www.fake-acme-corp.info']"
    );
}

/// REQ-3.7-EX-7.4 — Consumer ingests SXC persona Indicator example (§3.7.7.4).
pub fn assert_sxc_indicator_consumer() {
    let fixture = load_fixture(EXAMPLE_SXC);
    assert_eq!(fixture.provenance.source_section, "3.7.7.4");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.7.4 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--baeabcaa-cdef-defd-ef12-342d65defabc").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("SXC example Indicator");
    assert_eq!(indicator.indicator_types, vec!["anomalous-activity"]);
    assert!(
        indicator.pattern.raw().contains("ipv6-addr:value"),
        "SXC example must carry IPv6 pattern"
    );
}

/// REQ-3.7-EX-7.5 — Consumer ingests SIEM persona Indicator example (§3.7.7.5).
pub fn assert_siem_indicator_consumer() {
    let fixture = load_fixture(EXAMPLE_SIEM);
    assert_eq!(fixture.provenance.source_section, "3.7.7.5");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.7.5 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--baeabcaa-cdef-defd-ef12-342d65defabc").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("SIEM example Indicator");
    assert_eq!(indicator.indicator_types, vec!["malicious-activity"]);
    assert_eq!(
        indicator.pattern.raw(),
        "[url:value = 'https://www.evilsite.info/foo']"
    );
}

interop_test!(
    "REQ-3.7-EX-7.1",
    "use_cases::indicator::consumer_examples::tip_indicator_consumer",
    tip_indicator_consumer,
    {
        assert_tip_indicator_consumer();
    }
);

interop_test!(
    "REQ-3.7-EX-7.2",
    "use_cases::indicator::consumer_examples::tms_indicator_consumer",
    tms_indicator_consumer,
    {
        assert_tms_indicator_consumer();
    }
);

interop_test!(
    "REQ-3.7-EX-7.3",
    "use_cases::indicator::consumer_examples::tds_indicator_consumer",
    tds_indicator_consumer,
    {
        assert_tds_indicator_consumer();
    }
);

interop_test!(
    "REQ-3.7-EX-7.4",
    "use_cases::indicator::consumer_examples::sxc_indicator_consumer",
    sxc_indicator_consumer,
    {
        assert_sxc_indicator_consumer();
    }
);

interop_test!(
    "REQ-3.7-EX-7.5",
    "use_cases::indicator::consumer_examples::siem_indicator_consumer",
    siem_indicator_consumer,
    {
        assert_siem_indicator_consumer();
    }
);
