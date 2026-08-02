//! RFC 3339 millisecond checks shared by use-case producer tests.

/// Interop millisecond timestamps: exactly three fractional digits before `Z`.
pub fn assert_millisecond_rfc3339(label: &str, value: &str) {
    let Some((_, frac_and_z)) = value.rsplit_once('.') else {
        panic!("{label} must include fractional seconds: {value}");
    };
    assert!(
        frac_and_z.ends_with('Z'),
        "{label} must end with Z: {value}"
    );
    let digits = &frac_and_z[..frac_and_z.len() - 1];
    assert_eq!(
        digits.len(),
        3,
        "{label} must have exactly three subsecond digits: {value}"
    );
    assert!(
        digits.chars().all(|c| c.is_ascii_digit()),
        "{label} fractional part must be digits: {value}"
    );
}
