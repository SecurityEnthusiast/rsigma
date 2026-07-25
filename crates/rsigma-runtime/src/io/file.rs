use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::io::{SinkFormat, serialize_result};

/// Appends ProcessResult to a file as one line per result, buffered.
pub struct FileSink {
    writer: BufWriter<File>,
    format: SinkFormat,
}

impl FileSink {
    /// Open (or create) the file at `path` for appending.
    pub fn open(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            writer: BufWriter::new(file),
            format: SinkFormat::default(),
        })
    }

    /// Select the wire format this sink serializes results into.
    #[must_use]
    pub fn with_format(mut self, format: SinkFormat) -> Self {
        self.format = format;
        self
    }

    /// The wire format this sink serializes results into.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    /// Serialize and append a ProcessResult to the file.
    pub fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }

        for m in result {
            let json = serialize_result(m, self.format, false)?;
            writeln!(self.writer, "{json}")?;
        }

        self.writer.flush()?;
        Ok(())
    }

    /// Write a pre-serialized JSON string directly to the file.
    pub fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        writeln!(self.writer, "{json}")?;
        self.writer.flush()?;
        Ok(())
    }
}
