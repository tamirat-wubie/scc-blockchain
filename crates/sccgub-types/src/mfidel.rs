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
}
