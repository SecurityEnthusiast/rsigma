//! TAXII pagination response headers (spec section 3.2).

use crate::core::TaxiiTimestamp;

use super::request::TaxiiResponse;

/// `X-TAXII-Date-Added-*` headers from a paginated GET response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaxiiPageHeaders {
    /// `X-TAXII-Date-Added-First` when present.
    pub date_added_first: Option<TaxiiTimestamp>,
    /// `X-TAXII-Date-Added-Last` when present.
    pub date_added_last: Option<TaxiiTimestamp>,
}

impl TaxiiPageHeaders {
    /// Parse pagination headers from `response`.
    pub(crate) fn from_response(response: &TaxiiResponse) -> Self {
        Self {
            date_added_first: header_timestamp(response, "x-taxii-date-added-first"),
            date_added_last: header_timestamp(response, "x-taxii-date-added-last"),
        }
    }
}

/// A TAXII resource plus its pagination headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxiiPaged<T> {
    /// Parsed response body.
    pub value: T,
    /// Observed pagination headers.
    pub headers: TaxiiPageHeaders,
}

impl<T> TaxiiPaged<T> {
    pub(crate) fn new(value: T, response: &TaxiiResponse) -> Self {
        Self {
            value,
            headers: TaxiiPageHeaders::from_response(response),
        }
    }
}

fn header_timestamp(response: &TaxiiResponse, name: &str) -> Option<TaxiiTimestamp> {
    response
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| TaxiiTimestamp::parse(s).ok())
}
