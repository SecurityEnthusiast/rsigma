//! Line bookkeeping shared by the NDJSON sinks that write to a byte stream
//! (file and Unix socket): batches written in one go, and where a retried
//! delivery should resume.

use crate::io::DeliveryContext;

/// The NDJSON lines of one delivery, serialized into a single buffer so they
/// go out in one write, with the end offset of each line.
#[derive(Default)]
pub(crate) struct LineBatch {
    bytes: Vec<u8>,
    ends: Vec<usize>,
}

impl LineBatch {
    /// Append one line; the newline is added here.
    pub(crate) fn push(&mut self, json: &str) {
        self.bytes.extend_from_slice(json.as_bytes());
        self.bytes.push(b'\n');
        self.ends.push(self.bytes.len());
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many whole lines the first `written` bytes cover.
    pub(crate) fn complete_lines(&self, written: usize) -> usize {
        self.ends.partition_point(|&end| end <= written)
    }

    /// Byte offset where line `index` starts.
    pub(crate) fn line_start(&self, index: usize) -> usize {
        index.checked_sub(1).map_or(0, |i| self.ends[i])
    }

    /// Whether the first `written` bytes stop partway through a line.
    pub(crate) fn ends_mid_line(&self, written: usize) -> bool {
        written > self.line_start(self.complete_lines(written))
    }
}

/// How many lines of a delivery a sink has already written, kept across the
/// worker's retries of that delivery so a retry does not repeat them.
///
/// The delivery context is shared by every sink a result fans out to, so
/// each sink keeps its own resume point, keyed by the context's sequence
/// number.
#[derive(Default)]
pub(crate) struct ResumePoint {
    at: Option<(u64, usize)>,
}

impl ResumePoint {
    /// Lines to skip for this delivery. Always 0 without a context, and for a
    /// delivery other than the one last recorded.
    pub(crate) fn start(&self, ctx: Option<&DeliveryContext>) -> usize {
        match (ctx, self.at) {
            (Some(ctx), Some((seq, lines))) if ctx.seq() == seq => lines,
            _ => 0,
        }
    }

    /// Remember that the first `lines` lines of this delivery are written.
    pub(crate) fn record(&mut self, ctx: Option<&DeliveryContext>, lines: usize) {
        self.at = ctx.map(|ctx| (ctx.seq(), lines));
    }

    pub(crate) fn clear(&mut self) {
        self.at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_offsets() {
        let mut batch = LineBatch::default();
        batch.push("ab");
        batch.push("cde");
        assert_eq!(batch.bytes(), b"ab\ncde\n");
        assert_eq!(batch.complete_lines(0), 0);
        assert_eq!(batch.complete_lines(2), 0);
        assert_eq!(batch.complete_lines(3), 1);
        assert_eq!(batch.complete_lines(6), 1);
        assert_eq!(batch.complete_lines(7), 2);
        assert!(!batch.ends_mid_line(0));
        assert!(batch.ends_mid_line(1));
        assert!(!batch.ends_mid_line(3));
        assert!(batch.ends_mid_line(4));
        assert!(!batch.ends_mid_line(7));
        assert_eq!(batch.line_start(0), 0);
        assert_eq!(batch.line_start(1), 3);
        assert_eq!(batch.line_start(2), 7);
    }

    #[test]
    fn resume_point_is_per_delivery() {
        let first = DeliveryContext::new();
        let second = DeliveryContext::new();
        let mut resume = ResumePoint::default();
        resume.record(Some(&first), 2);
        assert_eq!(resume.start(Some(&first)), 2);
        assert_eq!(resume.start(Some(&second)), 0);
        assert_eq!(resume.start(None), 0);
        resume.clear();
        assert_eq!(resume.start(Some(&first)), 0);
    }
}
