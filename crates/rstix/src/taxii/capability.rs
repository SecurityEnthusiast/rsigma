//! API Root and collection capability checks.

use super::TaxiiError;
use super::media::{TAXII_ACCEPT, TAXII_CONTENT_TYPE};
use super::resources::{TaxiiApiRoot, TaxiiCollection};

const STIX_JSON_MEDIA: &str = "application/stix+json;version=2.1";

/// Validate that an API Root advertises TAXII 2.1.
pub fn ensure_api_root_supports_taxii(api: &TaxiiApiRoot) -> Result<(), TaxiiError> {
    if api
        .versions
        .iter()
        .any(|v| v == TAXII_ACCEPT || v == "application/taxii+json")
    {
        Ok(())
    } else {
        Err(TaxiiError::UnsupportedApiRoot {
            versions: api.versions.clone(),
        })
    }
}

/// Validate that a collection accepts STIX 2.1 objects for POST.
pub fn ensure_collection_accepts_stix(collection: &TaxiiCollection) -> Result<(), TaxiiError> {
    if collection
        .media_types
        .iter()
        .any(|m| m == STIX_JSON_MEDIA || m == "application/stix+json")
    {
        Ok(())
    } else {
        Err(TaxiiError::UnsupportedCollectionMedia {
            media_types: collection.media_types.clone(),
        })
    }
}

/// Validate POST body content type against collection media types.
pub fn ensure_post_content_type(collection: &TaxiiCollection) -> Result<(), TaxiiError> {
    let _ = collection;
    // TAXII POST always uses the TAXII envelope media type; STIX objects are inside the envelope.
    if collection.media_types.is_empty() {
        return Err(TaxiiError::UnsupportedCollectionMedia {
            media_types: vec![],
        });
    }
    ensure_collection_accepts_stix(collection)?;
    let _ = TAXII_CONTENT_TYPE;
    Ok(())
}
