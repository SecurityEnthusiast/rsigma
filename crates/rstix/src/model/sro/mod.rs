//! STIX Relationship Objects (`relationship`, `sighting`).

mod relationship;
mod sighting;

pub use relationship::Relationship;
pub use sighting::{SIGHTING_COUNT_MAX, Sighting, WhereSightedRef};

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};

/// STIX SRO enum (2 variants).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum SroObject {
    /// A relationship between two STIX objects.
    Relationship(Relationship),
    /// A sighting of an SDO.
    Sighting(Sighting),
}

impl SroObject {
    /// Delegate to the wrapped object's STIX type name.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Relationship(_) => Relationship::TYPE_NAME,
            Self::Sighting(_) => Sighting::TYPE_NAME,
        }
    }
}

impl QueryableStixObject for SroObject {
    fn id(&self) -> &StixId {
        match self {
            Self::Relationship(inner) => inner.id(),
            Self::Sighting(inner) => inner.id(),
        }
    }

    fn type_name(&self) -> &'static str {
        self.type_name()
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::Relationship(inner) => inner.spec_version(),
            Self::Sighting(inner) => inner.spec_version(),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Relationship(inner) => inner.created(),
            Self::Sighting(inner) => inner.created(),
        }
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Relationship(inner) => inner.modified(),
            Self::Sighting(inner) => inner.modified(),
        }
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::Relationship(inner) => inner.get_field(path),
            Self::Sighting(inner) => inner.get_field(path),
        }
    }
}
