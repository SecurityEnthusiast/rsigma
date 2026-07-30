//! [`StixId`](crate::core::StixId) JSON string serialization.
//!
//! Deserialize failures are tagged so [`crate::ParseError`] can recover
//! [`StixIdError`](crate::core::StixIdError) without Display-string matching
//! (same approach as [`crate::model::serde_error`] for `ModelError`).

use serde::{Deserialize, Serialize};

use crate::core::{StixId, StixIdError};

/// Prefix embedded in serde custom messages.
const TAG: &str = "\u{001e}rstix-stix-id\u{001e}";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StixIdErrorWire {
    MissingDelimiter,
    EmptyTypeName,
    InvalidUuid { detail: String },
    TypeMismatch { expected: String, found: String },
}

impl From<&StixIdError> for StixIdErrorWire {
    fn from(err: &StixIdError) -> Self {
        match err {
            StixIdError::MissingDelimiter => Self::MissingDelimiter,
            StixIdError::EmptyTypeName => Self::EmptyTypeName,
            StixIdError::InvalidUuid(inner) => Self::InvalidUuid {
                detail: inner.to_string(),
            },
            StixIdError::TypeMismatch { expected, found } => Self::TypeMismatch {
                expected: (*expected).to_owned(),
                found: found.clone(),
            },
        }
    }
}

fn encode_for_serde(err: &StixIdError) -> String {
    let payload =
        serde_json::to_string(&StixIdErrorWire::from(err)).expect("stix id error wire json");
    format!("{TAG}{payload}{TAG}{err}")
}

fn decode_from_serde(message: &str) -> Option<StixIdError> {
    let rest = message.strip_prefix(TAG)?;
    let json_end = rest.find(TAG)?;
    let json = &rest[..json_end];
    let wire: StixIdErrorWire = serde_json::from_str(json).ok()?;
    Some(match wire {
        StixIdErrorWire::MissingDelimiter => StixIdError::MissingDelimiter,
        StixIdErrorWire::EmptyTypeName => StixIdError::EmptyTypeName,
        StixIdErrorWire::InvalidUuid { .. } => match StixId::parse("x--not-a-uuid") {
            Err(err @ StixIdError::InvalidUuid(_)) => err,
            other => panic!("expected InvalidUuid placeholder, got {other:?}"),
        },
        StixIdErrorWire::TypeMismatch { expected, found } => StixIdError::TypeMismatch {
            expected: Box::leak(expected.into_boxed_str()),
            found,
        },
    })
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
        Self::parse(&raw).map_err(|err| serde::de::Error::custom(encode_for_serde(&err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_roundtrip_preserves_invalid_uuid_variant() {
        let err = match StixId::parse("malware--deadbeef") {
            Err(e @ StixIdError::InvalidUuid(_)) => e,
            other => panic!("expected InvalidUuid, got {other:?}"),
        };
        let message = encode_for_serde(&err);
        let recovered = decode_from_serde(&message).expect("decode");
        assert!(matches!(recovered, StixIdError::InvalidUuid(_)));
    }

    #[test]
    fn deserialize_invalid_uuid_is_recoverable_from_serde_message() {
        let err = serde_json::from_str::<StixId>("\"malware--deadbeef\"").expect_err("must fail");
        let recovered = stix_id_error_from_serde_message(&err.to_string()).expect("tagged");
        assert!(matches!(recovered, StixIdError::InvalidUuid(_)));
    }
}
