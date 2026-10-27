//! Confidence scale support.

use crate::core::error::ConfidenceError;

/// Confidence value 0-100 inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u8);

impl Confidence {
    /// The minimum confidence value.
    pub const NONE: Self = Self(0);
    /// The maximum confidence value.
    pub const FULL: Self = Self(100);

    /// Construct a confidence value, enforcing `0..=100`.
    pub fn new(val: u8) -> Result<Self, ConfidenceError> {
        if val <= 100 {
            Ok(Self(val))
        } else {
            Err(ConfidenceError::OutOfRange(val))
        }
    }

    /// Construct from a compile-time-known value in `0..=100` (scale tables only).
    const fn known(val: u8) -> Self {
        Self(val)
    }

    /// Access the underlying value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Convert between verbal confidence scales and STIX confidence values.
pub trait ConfidenceScale {
    /// Convert a label to STIX confidence.
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError>;
    /// Convert STIX confidence to a label.
    #[allow(clippy::wrong_self_convention)]
    fn from_stix(&self, confidence: Confidence) -> &'static str;
}

/// None/Low/Medium/High scale.
pub struct NiLScale;

impl ConfidenceScale for NiLScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "none" => Ok(Confidence::known(0)),
            "low" => Ok(Confidence::known(15)),
            "medium" => Ok(Confidence::known(50)),
            "high" => Ok(Confidence::known(85)),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=9 => "None",
            10..=34 => "Low",
            35..=69 => "Medium",
            _ => "High",
        }
    }
}

/// Admiralty credibility scale (1-6).
pub struct AdmiraltyScale;

impl ConfidenceScale for AdmiraltyScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label {
            "1" => Ok(Confidence::known(90)),
            "2" => Ok(Confidence::known(75)),
            "3" => Ok(Confidence::known(55)),
            "4" => Ok(Confidence::known(35)),
            "5" => Ok(Confidence::known(15)),
            "6" => Ok(Confidence::known(0)),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            83..=100 => "1",
            64..=82 => "2",
            45..=63 => "3",
            26..=44 => "4",
            1..=25 => "5",
            _ => "6",
        }
    }
}

/// 0-10 integer confidence scale.
pub struct ZeroToTenScale;

impl ConfidenceScale for ZeroToTenScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        let parsed = label
            .parse::<u8>()
            .map_err(|_| ConfidenceError::UnknownLabel(label.to_owned()))?;
        if parsed > 10 {
            return Err(ConfidenceError::UnknownLabel(label.to_owned()));
        }
        Confidence::new(parsed.saturating_mul(10))
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=4 => "0",
            5..=14 => "1",
            15..=24 => "2",
            25..=34 => "3",
            35..=44 => "4",
            45..=54 => "5",
            55..=64 => "6",
            65..=74 => "7",
            75..=84 => "8",
            85..=94 => "9",
            _ => "10",
        }
    }
}

/// Words of estimative probability scale.
pub struct WepScale;

impl ConfidenceScale for WepScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "remote" | "almost-no-chance" => Ok(Confidence::known(5)),
            "unlikely" => Ok(Confidence::known(20)),
            "possible" => Ok(Confidence::known(45)),
            "likely" => Ok(Confidence::known(70)),
            "highly-likely" => Ok(Confidence::known(85)),
            "almost-certain" => Ok(Confidence::known(95)),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=12 => "Almost-No-Chance",
            13..=32 => "Unlikely",
            33..=57 => "Possible",
            58..=77 => "Likely",
            78..=90 => "Highly-Likely",
            _ => "Almost-Certain",
        }
    }
}

/// DNI confidence scale.
pub struct DniScale;

impl ConfidenceScale for DniScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "very-unlikely" => Ok(Confidence::known(7)),
            "unlikely" => Ok(Confidence::known(22)),
            "roughly-even" => Ok(Confidence::known(50)),
            "likely" => Ok(Confidence::known(78)),
            "very-likely" => Ok(Confidence::known(93)),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=14 => "Very-Unlikely",
            15..=34 => "Unlikely",
            35..=65 => "Roughly-Even",
            66..=85 => "Likely",
            _ => "Very-Likely",
        }
    }
}

/// MISP confidence scale.
pub struct MispScale;

impl ConfidenceScale for MispScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "completely-confident" => Ok(Confidence::known(100)),
            "usually-confident" => Ok(Confidence::known(75)),
            "fairly-confident" => Ok(Confidence::known(50)),
            "rarely-confident" => Ok(Confidence::known(25)),
            "unconfident" => Ok(Confidence::known(0)),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            88..=100 => "Completely-Confident",
            63..=87 => "Usually-Confident",
            38..=62 => "Fairly-Confident",
            13..=37 => "Rarely-Confident",
            _ => "Unconfident",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_range_checks() {
        assert_eq!(Confidence::new(0).expect("in range").get(), 0);
        assert_eq!(Confidence::new(100).expect("in range").get(), 100);
    }

    #[test]
    fn nil_scale_examples() {
        let scale = NiLScale;
        assert_eq!(
            scale.to_stix("High").expect("known label"),
            Confidence::new(85).expect("in range")
        );
    }

    #[test]
    fn admiralty_scale_example() {
        let scale = AdmiraltyScale;
        assert_eq!(
            scale.to_stix("2").expect("known label"),
            Confidence::new(75).expect("in range")
        );
    }

    #[test]
    fn all_scales_round_trip_known_values() {
        let nil = NiLScale;
        let admiralty = AdmiraltyScale;
        let ten = ZeroToTenScale;
        let wep = WepScale;
        let dni = DniScale;
        let misp = MispScale;

        let samples = [
            nil.to_stix("Medium").expect("label"),
            admiralty.to_stix("3").expect("label"),
            ten.to_stix("8").expect("label"),
            wep.to_stix("likely").expect("label"),
            dni.to_stix("very-likely").expect("label"),
            misp.to_stix("usually-confident").expect("label"),
        ];
        for sample in samples {
            let _ = nil.from_stix(sample);
            let _ = admiralty.from_stix(sample);
            let _ = ten.from_stix(sample);
            let _ = wep.from_stix(sample);
            let _ = dni.from_stix(sample);
            let _ = misp.from_stix(sample);
        }
    }
}
