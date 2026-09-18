//! Import TAXII collection objects into a [`StixStore`](crate::store::StixStore).
//!
//! Requires **`taxii`** and **`store`** features (or the `taxii-store` meta-feature).
//! Optional validation before import requires the **`validate`** feature and
//! [`IngestOptions::validator`](IngestOptions::validator).

use crate::core::StixId;
use crate::model::Bundle;
use crate::store::{ImportReport, StixStore, StoreError, audit_unresolved_refs};
#[cfg(feature = "validate")]
use crate::validate::{ValidationReport, Validator};

use super::envelope::TaxiiEnvelope;
use super::headers::TaxiiPageHeaders;
use super::pagination::{advance_more_page, recover_from_range_not_satisfiable};
use super::{TaxiiClient, TaxiiError, TaxiiFilter};

/// Synthetic bundle id for [`ingest_collection`] when no custom id is supplied.
pub const DEFAULT_INGEST_BUNDLE_ID: &str = "bundle--00000000-0000-0000-0000-000000000001";

/// Options controlling TAXII collection ingest.
#[derive(Clone, Debug)]
pub struct IngestOptions {
    /// When set, each page is validated as a synthetic bundle before import.
    #[cfg(feature = "validate")]
    pub validator: Option<Validator>,
    /// Skip store import for pages that fail validation (default: `true`).
    #[cfg(feature = "validate")]
    pub reject_invalid_pages: bool,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            #[cfg(feature = "validate")]
            validator: None,
            #[cfg(feature = "validate")]
            reject_invalid_pages: true,
        }
    }
}

#[cfg(feature = "validate")]
impl IngestOptions {
    /// Validate each page with [`Validator::interop_strict`] and reject invalid pages.
    pub fn interop_strict() -> Self {
        Self {
            validator: Some(Validator::interop_strict()),
            reject_invalid_pages: true,
        }
    }

    /// Attach a custom validator profile.
    pub fn with_validator(validator: Validator) -> Self {
        Self {
            validator: Some(validator),
            reject_invalid_pages: true,
        }
    }

    /// Import pages even when validation fails (diagnostics still recorded).
    pub fn allow_invalid_pages(mut self) -> Self {
        self.reject_invalid_pages = false;
        self
    }
}

/// Validation outcome for one rejected TAXII page.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(feature = "validate")]
pub struct IngestValidationFailure {
    /// Zero-based page index in fetch order.
    pub page: usize,
    /// Objects on the page that were not imported.
    pub object_count: usize,
    /// Pipeline diagnostics for the synthetic bundle built from the page.
    pub report: ValidationReport,
}

/// Aggregated validation results for an ingest run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg(feature = "validate")]
pub struct IngestValidationReport {
    /// Pages validated (validator configured and page non-empty).
    pub pages_validated: usize,
    /// Pages skipped because validation failed and [`IngestOptions::reject_invalid_pages`] was set.
    pub pages_rejected: usize,
    /// Objects not imported due to page rejection.
    pub rejected_object_count: usize,
    /// Per-page failure details.
    pub failures: Vec<IngestValidationFailure>,
}

#[cfg(feature = "validate")]
impl IngestValidationReport {
    /// True when no page was rejected.
    pub fn is_valid(&self) -> bool {
        self.pages_rejected == 0
    }
}

/// Result of TAXII collection ingest (import + optional validation summary).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Store import counters and unresolved reference audit.
    pub import: ImportReport,
    /// Present when the `validate` feature is enabled.
    #[cfg(feature = "validate")]
    pub validation: IngestValidationReport,
}

impl IngestReport {
    /// Import counters (convenience for callers that only need store stats).
    pub fn import(&self) -> &ImportReport {
        &self.import
    }
}

/// Errors from TAXII collection ingest into a store.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// HTTP / TAXII client failure while fetching objects.
    #[error(transparent)]
    Taxii(#[from] TaxiiError),
    /// Store import failure.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Fetch all objects from a TAXII collection (paginated) and import them into `store`.
///
/// Each TAXII response page is upserted via [`StixStore::import_objects`] so memory stays
/// bounded by page size. After the full collection is imported, references are audited once
/// against the store.
///
/// Uses [`DEFAULT_INGEST_BUNDLE_ID`] as the conventional wrapper id when exporting the store
/// with [`StixStore::export_bundle`]. For a custom id, call
/// [`ingest_collection_with_bundle_id`].
pub async fn ingest_collection(
    client: &TaxiiClient,
    store: &impl StixStore,
    api_root_url: &str,
    collection_id: &str,
    filter: TaxiiFilter,
) -> Result<IngestReport, IngestError> {
    ingest_collection_with_bundle_id(
        client,
        store,
        api_root_url,
        collection_id,
        filter,
        StixId::parse(DEFAULT_INGEST_BUNDLE_ID).expect("valid default ingest bundle id"),
        IngestOptions::default(),
    )
    .await
}

/// Like [`ingest_collection`], recording `bundle_id` for callers that export with
/// [`StixStore::export_bundle`]. Ingest does not materialize a STIX bundle on the wire.
pub async fn ingest_collection_with_bundle_id(
    client: &TaxiiClient,
    store: &impl StixStore,
    api_root_url: &str,
    collection_id: &str,
    filter: TaxiiFilter,
    bundle_id: StixId,
    options: IngestOptions,
) -> Result<IngestReport, IngestError> {
    let baseline_added_after = filter.added_after.clone();
    let mut filter = filter;
    let mut finished = false;
    let mut report = IngestReport::default();
    let mut ingested_ids = Vec::new();
    let mut page_index = 0usize;

    while !finished {
        match client
            .fetch_objects_page(api_root_url, collection_id, &filter)
            .await
        {
            Ok((envelope, response)) => {
                let date_added_last = TaxiiPageHeaders::from_response(&response).date_added_last;
                let more = envelope.more;
                let next = envelope.next.clone();
                let page_empty = envelope.objects.is_empty();
                import_page(
                    store,
                    envelope,
                    bundle_id.clone(),
                    &options,
                    page_index,
                    &mut report,
                    &mut ingested_ids,
                )?;
                page_index += 1;
                finished = if page_empty && more {
                    true
                } else {
                    advance_more_page(&mut filter, more, next, date_added_last, false)?
                };
            }
            Err(TaxiiError::RequestedRangeNotSatisfiable { .. }) => {
                recover_from_range_not_satisfiable(&mut filter, baseline_added_after.clone());
            }
            Err(err) => return Err(err.into()),
        }
    }

    report.import.unresolved_references = audit_unresolved_refs(store, &ingested_ids)?;
    Ok(report)
}

fn import_page(
    store: &impl StixStore,
    envelope: TaxiiEnvelope,
    bundle_id: StixId,
    options: &IngestOptions,
    page_index: usize,
    report: &mut IngestReport,
    ingested_ids: &mut Vec<StixId>,
) -> Result<(), IngestError> {
    if envelope.objects.is_empty() {
        return Ok(());
    }

    #[cfg(not(feature = "validate"))]
    let _ = &bundle_id;

    #[cfg(feature = "validate")]
    if let Some(validator) = &options.validator {
        report.validation.pages_validated += 1;
        let bundle = Bundle::from_objects(bundle_id.clone(), envelope.objects.clone());
        let validation = validator.validate_bundle(&bundle);
        if !validation.is_valid() {
            if options.reject_invalid_pages {
                report.validation.pages_rejected += 1;
                report.validation.rejected_object_count += envelope.objects.len();
                report.validation.failures.push(IngestValidationFailure {
                    page: page_index,
                    object_count: envelope.objects.len(),
                    report: validation,
                });
                return Ok(());
            }
            report.validation.failures.push(IngestValidationFailure {
                page: page_index,
                object_count: envelope.objects.len(),
                report: validation,
            });
        }
    }

    for object in &envelope.objects {
        ingested_ids.push(object.id().clone());
    }
    merge_import_report(&mut report.import, store.import_objects(&envelope.objects)?);
    Ok(())
}

fn merge_import_report(into: &mut ImportReport, page: ImportReport) {
    into.objects_added += page.objects_added;
    into.objects_updated += page.objects_updated;
    into.objects_deduplicated += page.objects_deduplicated;
    into.fingerprint_conflicts
        .extend(page.fingerprint_conflicts);
}
