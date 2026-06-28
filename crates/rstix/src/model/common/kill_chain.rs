//! STIX kill-chain phase (STIX §2.5.3).

use crate::model::ModelError;

/// A kill-chain phase reference (STIX §2.5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KillChainPhase {
    /// Name of the kill chain (for example `mitre-attack`).
    pub kill_chain_name: String,
    /// Phase name within the kill chain (for example `initial-access`).
    pub phase_name: String,
}

impl KillChainPhase {
    /// Rejects empty `kill_chain_name` or `phase_name`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.kill_chain_name.is_empty() {
            return Err(ModelError::KillChainPhaseEmptyKillChainName);
        }
        if self.phase_name.is_empty() {
            return Err(ModelError::KillChainPhaseEmptyPhaseName);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fixture() {
        let json =
            include_str!("../../../tests/fixtures/spec/common/kill-chain-phase-minimal.json");
        let phase: KillChainPhase = serde_json::from_str(json).expect("parse");
        phase.validate().expect("valid");
        let value = serde_json::to_value(&phase).expect("serialize");
        let reparsed: KillChainPhase = serde_json::from_value(value).expect("reparse");
        assert_eq!(phase, reparsed);
    }

    #[test]
    fn rejects_empty_kill_chain_name() {
        let json =
            include_str!("../../../tests/fixtures/spec/common/kill-chain-phase-empty-name.json");
        let phase: KillChainPhase = serde_json::from_str(json).expect("parse");
        assert_eq!(
            phase.validate(),
            Err(ModelError::KillChainPhaseEmptyKillChainName)
        );
    }
}
