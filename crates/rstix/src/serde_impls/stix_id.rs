//! [`StixId`](crate::core::StixId) JSON string serialization.
//!
//! Deserialize failures are tagged so [`crate::ParseError`] can recover
//! [`StixIdError`](crate::core::StixIdError) without Display-string matching
//! (same approach as [`crate::model::serde_error`] for `ModelError`). The tagged
//! payload carries the rejected id, so recovery replays [`StixId::parse`] and
//! reproduces the original error, including the `uuid` crate's detail.

use crate::core::{StixId, StixIdError};

/// Prefix embedded in serde custom messages.
const TAG: &str = "\u{001e}rstix-stix-id\u{001e}";

/// Longest rejected id echoed into the tagged payload. Ids that fail
/// [`StixId::parse`] are short in practice, and the cap keeps a hostile document
/// from inflating error strings by the length of its own input. Longer ids fall
/// back to an untagged message and surface as [`crate::ParseError::Json`].
const MAX_TAGGED_ID_LEN: usize = 256;

fn encode_for_serde(raw: &str, err: &StixIdError) -> String {
    if raw.len() > MAX_TAGGED_ID_LEN {
        return err.to_string();
    }
    let payload = serde_json::to_string(raw).expect("json string encoding cannot fail");
    format!("{TAG}{payload}{TAG}{err}")
}

fn decode_from_serde(message: &str) -> Option<StixIdError> {
    let rest = message.strip_prefix(TAG)?;
    let json_end = rest.find(TAG)?;
    let raw: String = serde_json::from_str(&rest[..json_end]).ok()?;
    StixId::parse(&raw).err()
}

/// Recover a [`StixIdError`] from a serde/`serde_json` error message when tagged.
pub(crate) fn stix_id_error_from_serde_message(message: &str) -> Option<StixIdError> {
    decode_from_serde(message)
}

impl serde::Serialize for StixId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for StixId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|err| serde::de::Error::custom(encode_for_serde(&raw, &err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_error(raw: &str) -> StixIdError {
        StixId::parse(raw).expect_err("id must be rejected")
    }

    #[test]
    fn tagged_roundtrip_reproduces_the_original_error() {
        for raw in [
            "malware--deadbeef",
            "malware--1121ffbc-364f-857a-9987-92fbcff24ab",
            "no-delimiter",
            "--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        ] {
            let err = parse_error(raw);
            let recovered =
                decode_from_serde(&encode_for_serde(raw, &err)).expect("tagged message decodes");
            assert_eq!(recovered, err, "recovered error must match original: {raw}");
            assert_eq!(
                recovered.to_string(),
                err.to_string(),
                "recovered detail must match original: {raw}"
            );
        }
    }

    #[test]
    fn recovered_uuid_detail_describes_the_rejected_id() {
        let short = parse_error("malware--deadbeef");
        let truncated = parse_error("malware--1121ffbc-364f-857a-9987-92fbcff24ab");
        // A fixed stand-in cannot describe either id: recovery must not substitute one.
        let stand_in = parse_error("x--not-a-uuid");
        assert_ne!(
            short.to_string(),
            truncated.to_string(),
            "distinct malformed ids must yield distinct detail"
        );
        assert_ne!(stand_in.to_string(), truncated.to_string());
        assert_ne!(stand_in.to_string(), short.to_string());
        let recovered = decode_from_serde(&encode_for_serde(
            "malware--1121ffbc-364f-857a-9987-92fbcff24ab",
            &truncated,
        ))
        .expect("tagged message decodes");
        assert_eq!(recovered.to_string(), truncated.to_string());
    }

    #[test]
    fn deserialize_invalid_uuid_is_recoverable_from_serde_message() {
        let err = serde_json::from_str::<StixId>("\"malware--deadbeef\"").expect_err("must fail");
        let recovered = stix_id_error_from_serde_message(&err.to_string()).expect("tagged");
        assert_eq!(recovered, parse_error("malware--deadbeef"));
    }

    #[test]
    fn oversized_id_is_not_tagged() {
        let raw = format!("malware--{}", "a".repeat(MAX_TAGGED_ID_LEN));
        let err = parse_error(&raw);
        let message = encode_for_serde(&raw, &err);
        assert!(!message.starts_with(TAG), "oversized id must not be tagged");
        assert_eq!(decode_from_serde(&message), None);
    }

    #[test]
    fn untagged_or_forged_messages_do_not_recover() {
        let forged = format!("invalid type: string {TAG}\"malware--deadbeef\"{TAG}forged");
        for message in [
            "invalid type: string".to_owned(),
            String::new(),
            TAG.to_owned(),
            forged,
            format!("{TAG}\"malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061\"{TAG}valid id"),
            format!("{TAG}not-json{TAG}bad payload"),
        ] {
            assert_eq!(
                decode_from_serde(&message),
                None,
                "must not recover from: {message}"
            );
        }
    }
}
