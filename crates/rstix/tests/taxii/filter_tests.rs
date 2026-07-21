use rstix::core::TaxiiTimestamp;
use rstix::taxii::TaxiiFilter;

#[test]
fn added_after_serializes_six_digits() {
    let filter =
        TaxiiFilter::new().added_after(TaxiiTimestamp::parse("2024-01-01T00:00:00Z").unwrap());
    let pairs = filter.to_query_pairs().unwrap();
    assert!(pairs.contains(&(
        "added_after".to_owned(),
        "2024-01-01T00:00:00.000000Z".to_owned()
    )));
}

#[test]
fn encodes_match_type_or_values() {
    let filter = TaxiiFilter::new()
        .object_type("indicator")
        .object_type("malware");
    let pairs = filter.to_query_pairs().unwrap();
    assert_eq!(
        pairs
            .iter()
            .find(|(k, _)| k == "match[type]")
            .map(|(_, v)| v.as_str()),
        Some("indicator,malware")
    );
}
