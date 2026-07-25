//! Integration tests for bundle semantic validation (`Bundle::validate`).

#![cfg(feature = "serde")]

#[path = "support/fixtures_root.rs"]
mod fixtures_root;
#[path = "support/fixtures_spec.rs"]
mod fixtures_spec;

use fixtures_root::load_fixture;
use fixtures_spec::load_spec_fixture;
use rstix::model::sdo::{ObservedData, ObservedDataEmbeddedObject, ObservedDataForm};
use rstix::model::{Bundle, ValidationCode};
use rstix::parse_bundle;

#[test]
fn bad_capec_parses_and_warns_on_validate() {
    let bundle = parse_bundle(&load_fixture("validation/bundle-bad-capec.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::InvalidCapecExternalReference)
            .next()
            .is_some()
    );
}

#[test]
fn bad_cve_parses_and_warns_on_validate() {
    let bundle = parse_bundle(&load_fixture("validation/bundle-bad-cve.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::InvalidCveExternalReference)
            .next()
            .is_some()
    );
}

#[test]
fn relationship_matrix_invalid_parses_and_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-relationship-matrix-invalid.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::RelationshipEndpointMatrixInvalid)
            .next()
            .is_some()
    );
}

#[test]
fn bad_encryption_algorithm_rejects_at_parse() {
    let err = parse_bundle(&load_fixture("validation/bundle-bad-encryption.json")).unwrap_err();
    assert!(
        err.to_string().contains("encryption"),
        "expected encryption parse error, got: {err}"
    );
}

#[test]
fn granular_selector_semantic_invalid_rejects_at_parse() {
    let err = parse_bundle(&load_fixture(
        "validation/bundle-granular-selector-invalid.json",
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("does not resolve"),
        "expected granular selector parse error, got: {err}"
    );
}

#[test]
fn location_bad_country_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-location-bad-country.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LocationCountryNotIso3166)
            .next()
            .is_some()
    );
}

#[test]
fn observed_data_deprecated_objects_accepts_embedded_sro() {
    let raw = load_fixture("validation/observed-data-objects-with-sro.json");
    let observed: ObservedData = serde_json::from_str(&raw).expect("deserialize");
    match &observed.form {
        ObservedDataForm::DeprecatedObjects(objects) => {
            assert_eq!(objects.len(), 2);
            assert!(matches!(
                objects.get("0"),
                Some(ObservedDataEmbeddedObject::Sco(_))
            ));
            assert!(matches!(
                objects.get("1"),
                Some(ObservedDataEmbeddedObject::Sro(_))
            ));
        }
        ObservedDataForm::ObjectRefs(_) => panic!("expected deprecated objects form"),
    }
}

#[test]
fn location_bad_region_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-location-bad-region.json")).expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LocationRegionNotInOpenVocab)
            .next()
            .is_some()
    );
}

#[test]
fn language_content_list_length_mismatch_rejects_at_parse() {
    let err = parse_bundle(&load_fixture(
        "validation/bundle-language-content-list-length.json",
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("does not mirror"),
        "expected language-content parse error, got: {err}"
    );
}

#[test]
fn language_content_type_mismatch_rejects_at_parse() {
    let err = parse_bundle(&load_fixture(
        "validation/bundle-language-content-type-mismatch.json",
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("does not mirror"),
        "expected language-content parse error, got: {err}"
    );
}

#[test]
fn sco_deterministic_id_mismatch_warns() {
    let bundle = parse_bundle(&load_fixture(
        "validation/bundle-sco-deterministic-id-mismatch.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::ScoDeterministicIdMismatch)
            .next()
            .is_some()
    );
}

#[test]
fn language_content_unknown_field_is_ignored() {
    let bundle = parse_bundle(&load_fixture(
        "validation/language-content-unknown-field-ignored.json",
    ))
    .expect("parse");
    let report = bundle.validate();
    assert!(
        report
            .warnings_with_code(ValidationCode::LanguageContentValueMismatch)
            .next()
            .is_none(),
        "unknown target fields must be ignored per §7.1.1"
    );
}

#[test]
fn language_content_object_modified_mismatch_rejects_at_parse() {
    let err = parse_bundle(&load_fixture(
        "validation/bundle-language-content-object-modified-mismatch.json",
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("object_modified"),
        "expected object_modified parse error, got: {err}"
    );
}

#[test]
fn tlp1_object_marking_ref_warns() {
    let bundle =
        parse_bundle(&load_fixture("validation/bundle-tlp1-marking-ref.json")).expect("parse");
    let report = bundle.validate();
    let warnings: Vec<_> = report
        .warnings_with_code(ValidationCode::StixW0031TlpV1Encoding)
        .collect();
    assert_eq!(warnings.len(), 1);
    assert_eq!(
        warnings[0].object_id.as_deref(),
        Some("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
    );
}

#[test]
fn validate_is_clean_for_minimal_bundle() {
    let raw = load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = Bundle::parse(&raw).expect("parse");
    assert!(bundle.validate().is_clean());
}

#[cfg(feature = "validate")]
#[test]
fn open_vocab_custom_values_pass_interop_strict() {
    use rstix::{DiagnosticCode, Validator};

    let json = load_fixture("validation/bundle-location-bad-region.json");
    let report = Validator::interop_strict().validate_json_str(&json);
    assert!(
        report.is_valid(),
        "custom location.region is spec-legal open-vocab (STIX §2.14) and must pass interop_strict"
    );
    assert!(
        report.with_code(DiagnosticCode::I0001).next().is_some(),
        "expected STIX-I0001 info for custom location.region"
    );
}
