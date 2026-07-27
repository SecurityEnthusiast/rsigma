//! Compile-time interop test inventory (`linkme` distributed slice).

/// Descriptor registered by each interop test for manifest drift detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestDescriptor {
    pub req_id: &'static str,
    pub test_id: &'static str,
}

#[linkme::distributed_slice]
pub static INTEROP_TEST_DESCRIPTORS: [TestDescriptor];
