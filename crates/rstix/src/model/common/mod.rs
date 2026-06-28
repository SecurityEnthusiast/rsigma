//! Common property structures shared across STIX object families.

mod extension;
mod external_ref;
mod granular;
mod kill_chain;
mod sco;
mod sdo_sro;

pub use extension::{ExtensionEntry, ExtensionMap, ExtensionType};
pub use external_ref::ExternalReference;
pub use granular::GranularMarking;
pub use kill_chain::KillChainPhase;
pub use sco::ScoCommonProps;
pub use sdo_sro::SdoSroCommonProps;
