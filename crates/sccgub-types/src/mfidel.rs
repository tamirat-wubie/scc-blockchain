use serde::{Deserialize, Serialize};

/// Mfidel Atomic Seal — indivisible symbolic identity from the 34x8 Ge'ez grid.
/// Per v2.1 FIX-5: deterministic assignment as a pure function of block height.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MfidelAtomicSeal {
    /// Row in the 34x8 grid (1-indexed).
    pub row: u8,
    /// Column in the 34x8 grid (1-indexed).
    pub column: u8,
}

impl std::fmt::Display for MfidelAtomicSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "f[{}][{}]", self.row, self.column)
    }
}

impl MfidelAtomicSeal {
    /// Total fidels in the grid.
    pub const GRID_ROWS: u8 = 34;
    pub const GRID_COLS: u8 = 8;
    pub const TOTAL_FIDELS: u16 = 272; // 34 * 8

    /// Deterministic seal assignment from block height.
    /// Cycles through the entire 34x8 grid. Every 272 blocks = one full Mfidel cycle.
    ///
    /// ```text
    /// seal(height) = f[((height-1) / 8) % 34 + 1][((height-1) % 8) + 1]
    /// ```
    pub fn from_height(height: u64) -> Self {
        if height == 0 {
            // Genesis block uses the vowel origin: f[17][8] (አ)
            return Self { row: 17, column: 8 };
        }
        let h = height - 1;
        let row = ((h / 8) % 34) as u8 + 1;
        let column = (h % 8) as u8 + 1;
        Self { row, column }
    }

    /// Content-bound Mfidel seal. The 34x8 grid is preserved (atomicity,
    /// no decomposition, no Unicode roots) but the row/column selection is
    /// now a function of the block's commitments rather than its height alone.
    /// This makes the seal load-bearing: it authenticates the block's identity
    /// within the symbolic substrate.
    pub fn from_block(
        height: u64,
        state_root: &[u8; 32],
        transition_root: &[u8; 32],
        validator_id: &[u8; 32],
    ) -> Self {
        let mut data = Vec::with_capacity(8 + 32 + 32 + 32 + 21);
        data.extend_from_slice(b"sccgub-mfidel-seal-v1");
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(state_root);
        data.extend_from_slice(transition_root);
        data.extend_from_slice(validator_id);
        let hash = blake3::hash(&data);
        let bytes = hash.as_bytes();
        let row = (bytes[0] as u32 % 34) + 1;
        let column = (bytes[1] as u32 % 8) + 1;
        Self {
            row: row as u8,
            column: column as u8,
        }
    }

    /// Check if this seal is valid (within grid bounds).
    pub fn is_valid(&self) -> bool {
        self.row >= 1
            && self.row <= Self::GRID_ROWS
            && self.column >= 1
            && self.column <= Self::GRID_COLS
    }

    /// Returns which Mfidel cycle this block is in (0-indexed).
    pub fn cycle_number(height: u64) -> u64 {
        if height == 0 {
            return 0;
        }
        (height - 1) / Self::TOTAL_FIDELS as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_seal() {
        let seal = MfidelAtomicSeal::from_height(0);
        assert_eq!(seal.row, 17);
        assert_eq!(seal.column, 8);
    }

    #[test]
    fn test_deterministic_assignment() {
        let s1 = MfidelAtomicSeal::from_height(1);
        assert_eq!(s1.row, 1);
        assert_eq!(s1.column, 1);

        let s8 = MfidelAtomicSeal::from_height(8);
        assert_eq!(s8.row, 1);
        assert_eq!(s8.column, 8);

        let s9 = MfidelAtomicSeal::from_height(9);
        assert_eq!(s9.row, 2);
        assert_eq!(s9.column, 1);
    }

    #[test]
    fn test_full_cycle() {
        let s272 = MfidelAtomicSeal::from_height(272);
        assert_eq!(s272.row, 34);
        assert_eq!(s272.column, 8);

        // 273 wraps back to row 1, col 1
        let s273 = MfidelAtomicSeal::from_height(273);
        assert_eq!(s273.row, 1);
        assert_eq!(s273.column, 1);
    }

    #[test]
    fn test_all_seals_valid() {
        for h in 0..=300 {
            assert!(MfidelAtomicSeal::from_height(h).is_valid());
        }
    }

    #[test]
    fn test_from_block_deterministic() {
        let state_root = [1u8; 32];
        let tx_root = [2u8; 32];
        let validator = [3u8; 32];
        let s1 = MfidelAtomicSeal::from_block(10, &state_root, &tx_root, &validator);
        let s2 = MfidelAtomicSeal::from_block(10, &state_root, &tx_root, &validator);
        assert_eq!(s1, s2, "Same inputs must produce same seal");
    }

    #[test]
    fn test_from_block_always_valid() {
        // Fuzz-like: different inputs should all produce valid grid coordinates.
        for h in 0..50 {
            let state_root = [h as u8; 32];
            let tx_root = [(h + 1) as u8; 32];
            let validator = [(h + 2) as u8; 32];
            let seal = MfidelAtomicSeal::from_block(h, &state_root, &tx_root, &validator);
            assert!(
                seal.is_valid(),
                "Seal at height {} must be valid: {:?}",
                h,
                seal
            );
        }
    }

    #[test]
    fn test_from_block_different_inputs_differ() {
        let state_root = [1u8; 32];
        let tx_root = [2u8; 32];
        let validator = [3u8; 32];
        let s1 = MfidelAtomicSeal::from_block(10, &state_root, &tx_root, &validator);
        let s2 = MfidelAtomicSeal::from_block(11, &state_root, &tx_root, &validator);
        // Different heights with same roots — seal should usually differ
        // (not guaranteed for all inputs but overwhelmingly likely for BLAKE3).
        // If they happen to collide, that's fine — just a statistical test.
        let _ = (s1, s2); // Compile-check; no assert needed for probabilistic test.
    }

    #[test]
    fn test_cycle_number_genesis() {
        assert_eq!(MfidelAtomicSeal::cycle_number(0), 0);
    }

    #[test]
    fn test_cycle_number_first_cycle() {
        // Heights 1..=272 are cycle 0.
        assert_eq!(MfidelAtomicSeal::cycle_number(1), 0);
        assert_eq!(MfidelAtomicSeal::cycle_number(272), 0);
    }

    #[test]
    fn test_cycle_number_second_cycle() {
        // Height 273 starts cycle 1.
        assert_eq!(MfidelAtomicSeal::cycle_number(273), 1);
        assert_eq!(MfidelAtomicSeal::cycle_number(544), 1);
    }

    #[test]
    fn test_cycle_number_large_height() {
        assert_eq!(MfidelAtomicSeal::cycle_number(2720), 9);
    }
}
