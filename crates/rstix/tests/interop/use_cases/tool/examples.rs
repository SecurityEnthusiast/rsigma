//! §3.19.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Malware, Tool};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.19.4.1 non-normative example.
pub const EXAMPLE_DROPS_MALWARE: &str =
    "examples/tool/ex-3.19.4.1-tool-drops-malware.json";

/// REQ-3.19-EX-4.1 — §3.19.4.1 loads and passes the interop gate; Tool `drops` Malware.
pub fn assert_tool_drops_malware() {
    let fixture = load_fixture(EXAMPLE_DROPS_MALWARE);
    assert_eq!(fixture.provenance.source_section, "3.19.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.19.4.1 example must parse and pass interop gate");

    let tool_id =
        StixId::parse("tool--44322d2b-ffd4-b1bf-123f-008e46b3cd12").expect("tool id");
    let tool = bundle
        .get_typed::<Tool>(&tool_id)
        .expect("ftp remote access Tool");
    assert_eq!(tool.name, "ftp");
    assert_eq!(tool.tool_types, vec!["remote-access".to_string()]);

    let malware_id =
        StixId::parse("malware--bbb757e7-9bf9-3364-bf88-29dc0644d1e9").expect("malware id");
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "drops");
    assert_eq!(relationships[0].source_ref, tool_id);
    assert_eq!(relationships[0].target_ref, malware_id);
}

interop_test!(
    "REQ-3.19-EX-4.1",
    "use_cases::tool::examples::tool_drops_malware",
    tool_drops_malware,
    {
        assert_tool_drops_malware();
    }
);
