//! Bundle reference-closure suite-wide checks (REQ-2.3-X-01/02/03/04).

use crate::harness::closure::tlp_exempt_ids;

/// REQ-2.3-X-04 — predefined TLP ids are exempt from closure requirements.
pub fn assert_tlp_exemption_whitelist() {
    let exempt = tlp_exempt_ids();
    assert_eq!(exempt.len(), 9, "nine predefined TLP marking ids");
    assert!(exempt.contains("marking-definition--94868c89-73b8-4b43-b99e-6a4f9d6ded18"));
}
