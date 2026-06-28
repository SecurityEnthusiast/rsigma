//! JSON depth and string-length guards for untrusted bundle input.

use crate::ParseError;
use crate::model::parse_options::ParseOptions;

/// Validate nesting depth and string lengths on a parsed JSON value.
pub fn validate_value_limits(
    value: &serde_json::Value,
    opts: &ParseOptions,
) -> Result<(), ParseError> {
    check_depth(value, 0, opts.max_nesting_depth)?;
    check_string_lengths(value, opts.max_string_length)?;
    Ok(())
}

fn check_depth(value: &serde_json::Value, depth: usize, max: usize) -> Result<(), ParseError> {
    if depth > max {
        return Err(ParseError::JsonNestingTooDeep { max });
    }
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                check_depth(item, depth + 1, max)?;
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                check_depth(item, depth + 1, max)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_string_lengths(value: &serde_json::Value, max: usize) -> Result<(), ParseError> {
    match value {
        serde_json::Value::String(text) if text.len() > max => Err(ParseError::JsonStringTooLong {
            len: text.len(),
            max,
        }),
        serde_json::Value::Array(items) => {
            for item in items {
                check_string_lengths(item, max)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                check_string_lengths(item, max)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Reader wrapper that enforces a maximum byte count.
pub struct LimitedReader<R> {
    inner: R,
    limit: usize,
    read: usize,
}

impl<R> LimitedReader<R> {
    /// Wrap `inner`, rejecting reads beyond `limit` bytes.
    pub fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            limit,
            read: 0,
        }
    }
}

impl<R: std::io::Read> std::io::Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read >= self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bundle byte limit exceeded",
            ));
        }
        let allowed = (self.limit - self.read).min(buf.len());
        let n = self.inner.read(&mut buf[..allowed])?;
        self.read += n;
        Ok(n)
    }
}
