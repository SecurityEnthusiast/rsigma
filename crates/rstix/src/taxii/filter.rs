//! TAXII query filters (spec section 3.4).

use crate::core::{StixId, StixTimestamp, TaxiiTimestamp};

use super::TaxiiError;

/// Keyword values for `match[version]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionKeyword {
    /// Latest version (`last`).
    Last,
    /// Earliest version (`first`).
    First,
    /// All versions (`all`; must not combine with other selectors).
    All,
}

/// Selector entry for combined `match[version]` values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionSelector {
    /// Keyword selector.
    Keyword(VersionKeyword),
    /// Specific version string.
    Value(ObjectVersion),
}

/// Object version selector for `match[version]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VersionFilter {
    /// Latest version (default when omitted).
    #[default]
    Last,
    /// Earliest version.
    First,
    /// All versions (`all` must not combine with other version values).
    All,
    /// Specific version strings (STIX modified/created timestamps or opaque server values).
    Specific(Vec<ObjectVersion>),
    /// Combined selectors such as `last,first` or mixed keywords and timestamps.
    Selectors(Vec<VersionSelector>),
}

/// A single object version value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectVersion {
    /// STIX object version timestamp.
    Stix(StixTimestamp),
    /// Opaque server-generated version string.
    Raw(String),
}

impl ObjectVersion {
    pub(crate) fn to_query_value(&self) -> String {
        match self {
            Self::Stix(ts) => ts.to_rfc3339(),
            Self::Raw(raw) => raw.clone(),
        }
    }

    pub(crate) fn from_wire(value: &str) -> Self {
        StixTimestamp::parse(value)
            .map(Self::Stix)
            .unwrap_or_else(|_| Self::Raw(value.to_owned()))
    }
}

impl VersionFilter {
    /// Encode `match[version]` or return None when the default (`last`) applies.
    pub fn encode_match_version(&self) -> Result<Option<String>, TaxiiError> {
        match self {
            Self::Last => Ok(None),
            Self::First => Ok(Some("first".to_owned())),
            Self::All => Ok(Some("all".to_owned())),
            Self::Specific(values) => {
                if values.is_empty() {
                    return Err(TaxiiError::InvalidFilter {
                        reason: "match[version] specific list is empty".to_owned(),
                    });
                }
                Ok(Some(
                    values
                        .iter()
                        .map(ObjectVersion::to_query_value)
                        .collect::<Vec<_>>()
                        .join(","),
                ))
            }
            Self::Selectors(selectors) => {
                if selectors.is_empty() {
                    return Err(TaxiiError::InvalidFilter {
                        reason: "match[version] selector list is empty".to_owned(),
                    });
                }
                validate_version_selectors(selectors)?;
                Ok(Some(
                    selectors
                        .iter()
                        .map(|selector| match selector {
                            VersionSelector::Keyword(VersionKeyword::Last) => "last".to_owned(),
                            VersionSelector::Keyword(VersionKeyword::First) => "first".to_owned(),
                            VersionSelector::Keyword(VersionKeyword::All) => "all".to_owned(),
                            VersionSelector::Value(value) => value.to_query_value(),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                ))
            }
        }
    }
}

fn validate_version_selectors(selectors: &[VersionSelector]) -> Result<(), TaxiiError> {
    let mut saw_all = false;
    let mut last_count = 0;
    let mut first_count = 0;
    for selector in selectors {
        match selector {
            VersionSelector::Keyword(VersionKeyword::All) => saw_all = true,
            VersionSelector::Keyword(VersionKeyword::Last) => last_count += 1,
            VersionSelector::Keyword(VersionKeyword::First) => first_count += 1,
            VersionSelector::Value(_) => {}
        }
    }
    if saw_all && selectors.len() > 1 {
        return Err(TaxiiError::InvalidFilter {
            reason: "match[version]=all must not combine with other version values".to_owned(),
        });
    }
    if last_count > 1 || first_count > 1 {
        return Err(TaxiiError::InvalidFilter {
            reason: "duplicate match[version] keywords".to_owned(),
        });
    }
    Ok(())
}

fn validate_limit(limit: Option<usize>) -> Result<(), TaxiiError> {
    if let Some(limit) = limit
        && limit == 0
    {
        return Err(TaxiiError::InvalidFilter {
            reason: "limit must be a positive integer greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn append_pagination(
    pairs: &mut Vec<(String, String)>,
    added_after: Option<TaxiiTimestamp>,
    limit: Option<usize>,
    next: Option<&str>,
) -> Result<(), TaxiiError> {
    validate_limit(limit)?;
    if let Some(ts) = added_after {
        pairs.push(("added_after".to_owned(), ts.to_rfc3339()));
    }
    if let Some(limit) = limit {
        pairs.push(("limit".to_owned(), limit.to_string()));
    }
    if let Some(next) = next {
        pairs.push(("next".to_owned(), next.to_owned()));
    }
    Ok(())
}

fn append_spec_versions(pairs: &mut Vec<(String, String)>, spec_versions: &[String]) {
    if !spec_versions.is_empty() {
        pairs.push(("match[spec_version]".to_owned(), spec_versions.join(",")));
    }
}

/// TAXII object/manifest query filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaxiiFilter {
    /// `match[type]` values (OR within the parameter).
    pub object_types: Vec<String>,
    /// `match[id]` values (OR within the parameter).
    pub object_ids: Vec<StixId>,
    /// `match[spec_version]` values.
    pub spec_versions: Vec<String>,
    /// `match[version]` selector.
    pub version: VersionFilter,
    /// `added_after` transport timestamp (six fractional digits on the wire).
    pub added_after: Option<TaxiiTimestamp>,
    /// Page size hint (`limit`).
    pub limit: Option<usize>,
    /// Opaque pagination cursor (`next`).
    pub next: Option<String>,
}

impl TaxiiFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to STIX types (builder).
    pub fn object_type(mut self, ty: impl Into<String>) -> Self {
        self.object_types.push(ty.into());
        self
    }

    /// Restrict to object ids (builder).
    pub fn object_id(mut self, id: StixId) -> Self {
        self.object_ids.push(id);
        self
    }

    /// Restrict to spec versions (builder).
    pub fn spec_version(mut self, version: impl Into<String>) -> Self {
        self.spec_versions.push(version.into());
        self
    }

    /// Set `added_after` (builder).
    pub fn added_after(mut self, ts: TaxiiTimestamp) -> Self {
        self.added_after = Some(ts);
        self
    }

    /// Set page size hint (builder).
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set opaque pagination cursor (builder).
    pub fn next(mut self, cursor: impl Into<String>) -> Self {
        self.next = Some(cursor.into());
        self
    }

    /// Encode filter parameters for a GET request.
    pub fn to_query_pairs(&self) -> Result<Vec<(String, String)>, TaxiiError> {
        let mut pairs = Vec::new();
        if !self.object_types.is_empty() {
            pairs.push(("match[type]".to_owned(), self.object_types.join(",")));
        }
        if !self.object_ids.is_empty() {
            pairs.push((
                "match[id]".to_owned(),
                self.object_ids
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        append_spec_versions(&mut pairs, &self.spec_versions);
        if let Some(value) = self.version.encode_match_version()? {
            pairs.push(("match[version]".to_owned(), value));
        }
        append_pagination(
            &mut pairs,
            self.added_after.clone(),
            self.limit,
            self.next.as_deref(),
        )?;
        Ok(pairs)
    }
}

/// Query filter for GET object-by-id (spec section 5.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectByIdFilter {
    /// `match[version]` selector.
    pub version: VersionFilter,
    /// `match[spec_version]` values.
    pub spec_versions: Vec<String>,
    /// `added_after` transport timestamp.
    pub added_after: Option<TaxiiTimestamp>,
    /// Page size hint.
    pub limit: Option<usize>,
    /// Opaque pagination cursor.
    pub next: Option<String>,
}

impl ObjectByIdFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `match[version]` (builder).
    pub fn version(mut self, version: VersionFilter) -> Self {
        self.version = version;
        self
    }

    /// Restrict to spec versions (builder).
    pub fn spec_version(mut self, version: impl Into<String>) -> Self {
        self.spec_versions.push(version.into());
        self
    }

    /// Set `added_after` (builder).
    pub fn added_after(mut self, ts: TaxiiTimestamp) -> Self {
        self.added_after = Some(ts);
        self
    }

    /// Set page size hint (builder).
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set opaque pagination cursor (builder).
    pub fn next(mut self, cursor: impl Into<String>) -> Self {
        self.next = Some(cursor.into());
        self
    }

    /// Encode query parameters for GET object-by-id.
    pub fn to_query_pairs(&self) -> Result<Vec<(String, String)>, TaxiiError> {
        let mut pairs = Vec::new();
        append_spec_versions(&mut pairs, &self.spec_versions);
        if let Some(value) = self.version.encode_match_version()? {
            pairs.push(("match[version]".to_owned(), value));
        }
        append_pagination(
            &mut pairs,
            self.added_after.clone(),
            self.limit,
            self.next.as_deref(),
        )?;
        Ok(pairs)
    }
}

/// Query filter for GET versions (spec section 5.8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionsQueryFilter {
    /// `match[spec_version]` values.
    pub spec_versions: Vec<String>,
    /// `added_after` transport timestamp.
    pub added_after: Option<TaxiiTimestamp>,
    /// Page size hint.
    pub limit: Option<usize>,
    /// Opaque pagination cursor.
    pub next: Option<String>,
}

impl VersionsQueryFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to spec versions (builder).
    pub fn spec_version(mut self, version: impl Into<String>) -> Self {
        self.spec_versions.push(version.into());
        self
    }

    /// Set `added_after` (builder).
    pub fn added_after(mut self, ts: TaxiiTimestamp) -> Self {
        self.added_after = Some(ts);
        self
    }

    /// Set page size hint (builder).
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set opaque pagination cursor (builder).
    pub fn next(mut self, cursor: impl Into<String>) -> Self {
        self.next = Some(cursor.into());
        self
    }

    /// Encode query parameters for GET versions.
    pub fn to_query_pairs(&self) -> Result<Vec<(String, String)>, TaxiiError> {
        let mut pairs = Vec::new();
        append_spec_versions(&mut pairs, &self.spec_versions);
        append_pagination(
            &mut pairs,
            self.added_after.clone(),
            self.limit,
            self.next.as_deref(),
        )?;
        Ok(pairs)
    }
}

/// Query filter for DELETE object (spec section 5.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteObjectFilter {
    /// `match[version]` selector.
    pub version: VersionFilter,
    /// `match[spec_version]` values.
    pub spec_versions: Vec<String>,
}

impl DeleteObjectFilter {
    /// Create an empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `match[version]` (builder).
    pub fn version(mut self, version: VersionFilter) -> Self {
        self.version = version;
        self
    }

    /// Restrict to spec versions (builder).
    pub fn spec_version(mut self, version: impl Into<String>) -> Self {
        self.spec_versions.push(version.into());
        self
    }

    /// Encode query parameters for DELETE object.
    pub fn to_query_pairs(&self) -> Result<Vec<(String, String)>, TaxiiError> {
        let mut pairs = Vec::new();
        append_spec_versions(&mut pairs, &self.spec_versions);
        if let Some(value) = self.version.encode_match_version()? {
            pairs.push(("match[version]".to_owned(), value));
        }
        Ok(pairs)
    }
}

impl From<VersionFilter> for DeleteObjectFilter {
    fn from(version: VersionFilter) -> Self {
        Self {
            version,
            ..Self::default()
        }
    }
}

impl From<Option<VersionFilter>> for DeleteObjectFilter {
    fn from(version: Option<VersionFilter>) -> Self {
        Self {
            version: version.unwrap_or_default(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_type_or_and_added_after_precision() {
        let filter = TaxiiFilter::new()
            .object_type("indicator")
            .object_type("malware")
            .added_after(TaxiiTimestamp::parse("2024-01-01T00:00:00.000Z").unwrap());
        let pairs = filter.to_query_pairs().unwrap();
        assert!(pairs.contains(&("match[type]".to_owned(), "indicator,malware".to_owned())));
        assert!(pairs.contains(&(
            "added_after".to_owned(),
            "2024-01-01T00:00:00.000000Z".to_owned()
        )));
    }

    #[test]
    fn rejects_zero_limit() {
        let err = TaxiiFilter::new().limit(0).to_query_pairs().unwrap_err();
        assert!(matches!(err, TaxiiError::InvalidFilter { .. }));
    }

    #[test]
    fn rejects_all_with_other_version_selectors() {
        let filter = VersionFilter::Selectors(vec![
            VersionSelector::Keyword(VersionKeyword::All),
            VersionSelector::Keyword(VersionKeyword::Last),
        ]);
        assert!(filter.encode_match_version().is_err());
    }

    #[test]
    fn encodes_last_and_first_together() {
        let filter = VersionFilter::Selectors(vec![
            VersionSelector::Keyword(VersionKeyword::Last),
            VersionSelector::Keyword(VersionKeyword::First),
        ]);
        assert_eq!(
            filter.encode_match_version().unwrap(),
            Some("last,first".to_owned())
        );
    }
}
