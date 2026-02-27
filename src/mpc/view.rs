use crate::params::HASH_LEN;
use crate::hash::{Domain, DomainHasher};

/// Records gate outputs for one party during MPC circuit evaluation.
#[derive(Clone)]
pub struct View {
    /// Recorded gate outputs (u32 values from AND gates and Beaver triples).
    pub outputs: alloc::vec::Vec<u32>,
    /// Current read position (for verification replay).
    read_pos: usize,
}

impl View {
    /// Create a new empty view.
    pub fn new() -> Self {
        Self {
            outputs: alloc::vec::Vec::new(),
            read_pos: 0,
        }
    }

    /// Create a view with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            outputs: alloc::vec::Vec::with_capacity(cap),
            read_pos: 0,
        }
    }

    /// Record a gate output value.
    #[inline]
    pub fn record(&mut self, value: u32) {
        self.outputs.push(value);
    }

    /// Read the next recorded output (during verification replay).
    #[inline]
    pub fn next_output(&mut self) -> u32 {
        let val = self.outputs[self.read_pos];
        self.read_pos += 1;
        val
    }

    /// Reset the read position to the start.
    pub fn reset_read(&mut self) {
        self.read_pos = 0;
    }

    /// Number of recorded outputs.
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether the view is empty.
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Serialized size in bytes: each output is a u32 (4 bytes).
    pub fn serialized_size(&self) -> usize {
        self.outputs.len() * 4
    }

    /// Commit to this view: H(ViewCommit || output_0 || output_1 || ...).
    pub fn commit(&self) -> [u8; HASH_LEN] {
        let mut hasher = DomainHasher::new(Domain::ViewCommit);
        for &val in &self.outputs {
            hasher.update(&val.to_le_bytes());
        }
        hasher.finalize()
    }
}

impl core::fmt::Debug for View {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("View")
            .field("outputs_len", &self.outputs.len())
            .field("read_pos", &self.read_pos)
            .finish()
    }
}

impl Default for View {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_record_and_read() {
        let mut view = View::new();
        view.record(42);
        view.record(100);
        view.record(0xDEADBEEF);

        assert_eq!(view.len(), 3);
        assert_eq!(view.next_output(), 42);
        assert_eq!(view.next_output(), 100);
        assert_eq!(view.next_output(), 0xDEADBEEF);
    }

    #[test]
    fn test_view_reset_read() {
        let mut view = View::new();
        view.record(1);
        view.record(2);
        assert_eq!(view.next_output(), 1);
        view.reset_read();
        assert_eq!(view.next_output(), 1);
    }

    #[test]
    fn test_view_commit_deterministic() {
        let mut view1 = View::new();
        view1.record(42);
        view1.record(100);

        let mut view2 = View::new();
        view2.record(42);
        view2.record(100);

        assert_eq!(view1.commit(), view2.commit());
    }

    #[test]
    fn test_view_commit_differs_on_content() {
        let mut view1 = View::new();
        view1.record(42);

        let mut view2 = View::new();
        view2.record(43);

        assert_ne!(view1.commit(), view2.commit());
    }
}
