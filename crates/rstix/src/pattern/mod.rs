//! STIX 2.1 patterning engine (STIX Specification §9).

mod ast;
mod error;
mod lexer;
mod parser;
mod typeck;

pub use ast::{PatternAst, PatternScoType, Span};
pub use error::{PatternError, PatternMatchError};
pub use lexer::MAX_PATTERN_BYTES;

use crate::core::ScoKind;

/// A parsed and type-checked STIX pattern syntax tree.
#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    ast: PatternAst,
    source: String,
}

impl Pattern {
    /// Parse and type-check a STIX pattern string (Levels 1–3 grammar).
    ///
    /// Returns an error with a byte offset on lex/parse failure, or a path string on
    /// type-check failure.
    pub fn parse(source: &str) -> Result<Self, PatternError> {
        let ast = parser::parse(source)?;
        typeck::type_check(&ast)?;
        Ok(Self {
            ast,
            source: source.to_owned(),
        })
    }

    /// Parse and type-check a Level-1 STIX pattern (single observation expression).
    pub fn parse_level1(source: &str) -> Result<Self, PatternError> {
        let ast = parser::parse_level1(source)?;
        typeck::type_check(&ast)?;
        Ok(Self {
            ast,
            source: source.to_owned(),
        })
    }

    /// Parsed syntax tree.
    pub fn ast(&self) -> &PatternAst {
        &self.ast
    }

    /// Original pattern source text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// SCO types referenced by this pattern (built-in types only).
    pub fn observed_types(&self) -> Vec<ScoKind> {
        self.ast.observed_types()
    }

    /// All SCO type names referenced by this pattern (built-in and custom).
    pub fn observed_type_names(&self) -> Vec<String> {
        self.ast.observed_type_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ScoKind;

    #[test]
    fn parse_spec_file_hash_example() {
        let pattern = Pattern::parse(
            "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
        )
        .expect("parse");
        assert_eq!(pattern.observed_types(), vec![ScoKind::File]);
    }

    #[test]
    fn parse_spec_ipv4_cidr_example() {
        let pattern = Pattern::parse("[ipv4-addr:value = '198.51.100.1/32']").expect("parse");
        assert_eq!(pattern.observed_types(), vec![ScoKind::Ipv4Addr]);
    }
}
