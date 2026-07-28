//! Compile-time interop test inventory (`linkme` distributed slice).

/// Descriptor registered by each interop test for manifest drift detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestDescriptor {
    pub req_id: &'static str,
    pub test_id: &'static str,
}

/// One registered interop test (descriptor + runner).
#[derive(Clone, Copy)]
pub struct InteropTestEntry {
    pub descriptor: TestDescriptor,
    pub run: fn(),
}

#[linkme::distributed_slice]
pub static INTEROP_TESTS: [InteropTestEntry];
