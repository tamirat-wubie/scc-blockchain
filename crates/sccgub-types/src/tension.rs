use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::{Add, Sub};

use crate::SymbolAddress;

/// Fixed-point tension value with 18 decimal places.
/// Stored as i128 where the value represents `raw / 10^18`.
/// This ensures deterministic arithmetic across all platforms (v2.1 fix C-9).
///
/// All arithmetic uses saturating operations to prevent panics from untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TensionValue(pub i128);

impl TensionValue {
    pub const ZERO: Self = Self(0);
    pub const SCALE: i128 = 1_000_000_000_000_000_000; // 10^18
    pub const MAX: Self = Self(i128::MAX);
    pub const MIN: Self = Self(i128::MIN);

    pub fn from_integer(n: i64) -> Self {
        Self((n as i128).saturating_mul(Self::SCALE))
    }

    pub fn raw(&self) -> i128 {
        self.0
    }

    /// Multiply two tension values (fixed-point multiplication).
    /// Uses unsigned absolute values to handle negative operands correctly,
    /// and split-multiply to avoid intermediate overflow.
    pub fn mul_fp(self, other: Self) -> Self {
        let a = self.0;
        let b = other.0;
        let sign: i128 = if (a < 0) ^ (b < 0) { -1 } else { 1 };
        let a_abs = a.unsigned_abs();
        let b_abs = b.unsigned_abs();
        let scale = Self::SCALE as u128;
        let whole = (a_abs / scale).saturating_mul(b_abs);
        let frac = (a_abs % scale).saturating_mul(b_abs) / scale;
        let result = whole.saturating_add(frac).min(i128::MAX as u128) as i128;
        Self(result.saturating_mul(sign))
    }

    /// Saturating addition.
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction.
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Clamp to non-negative.
    pub fn max(self, other: Self) -> Self {
        if self.0 >= other.0 {
            self
        } else {
            other
        }
    }
}

impl Add for TensionValue {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for TensionValue {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Default for TensionValue {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for TensionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / Self::SCALE;
        let frac = (self.0 % Self::SCALE).unsigned_abs();
        // Handle negative fractional values (e.g., -0.5)
        if self.0 < 0 && whole == 0 {
            write!(f, "-0.{:018}", frac)
        } else {
            write!(f, "{}.{:018}", whole, frac)
        }
    }
}

/// Tension field across the entire chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensionField {
    /// Total system tension: T = alpha*T_logic + beta*T_grounding + gamma*T_value + delta*T_resource
    pub total: TensionValue,
    /// Per-symbol tension map.
    pub map: HashMap<SymbolAddress, TensionValue>,
    /// Tension budget per block (max allowable increase).
    pub budget: TensionBudget,
}

impl Default for TensionField {
    fn default() -> Self {
        Self {
            total: TensionValue::ZERO,
            map: HashMap::new(),
            budget: TensionBudget::default(),
        }
    }
}

/// Tension budget policy per v2.1 FIX-3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensionBudget {
    pub current_budget: TensionValue,
    pub mode: TensionBudgetMode,
    pub min_budget: TensionValue,
    pub max_budget: TensionValue,
}

impl Default for TensionBudget {
    fn default() -> Self {
        Self {
            current_budget: TensionValue::from_integer(1000),
            mode: TensionBudgetMode::Fixed,
            min_budget: TensionValue::from_integer(100),
            max_budget: TensionValue::from_integer(10000),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TensionBudgetMode {
    Fixed,
    Governance,
    Adaptive {
        window: u32,
        target_utilization: TensionValue,
        adjustment_rate: TensionValue,
    },
}

/// Tension components broken down by source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TensionComponents {
    pub logic: TensionValue,
    pub grounding: TensionValue,
    pub value: TensionValue,
    pub resource: TensionValue,
}

impl TensionComponents {
    pub fn weighted_total(
        &self,
        alpha: TensionValue,
        beta: TensionValue,
        gamma: TensionValue,
        delta: TensionValue,
    ) -> TensionValue {
        alpha.mul_fp(self.logic)
            + beta.mul_fp(self.grounding)
            + gamma.mul_fp(self.value)
            + delta.mul_fp(self.resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saturating_arithmetic() {
        let a = TensionValue::from_integer(5);
        let b = TensionValue::from_integer(3);
        assert_eq!(a + b, TensionValue::from_integer(8));
        assert_eq!(a - b, TensionValue::from_integer(2));
        // Saturating: no panic on overflow
        let max = TensionValue::MAX;
        assert_eq!(max + TensionValue::from_integer(1), TensionValue::MAX);
    }

    #[test]
    fn test_mul_fp_no_overflow() {
        let a = TensionValue::from_integer(5);
        let b = TensionValue::from_integer(3);
        assert_eq!(a.mul_fp(b), TensionValue::from_integer(15));
        // Large values should not panic
        let big = TensionValue::from_integer(1_000_000_000);
        let result = big.mul_fp(big);
        assert!(result.raw() > 0);
    }

    #[test]
    fn test_display_negative_fractional() {
        let v = TensionValue(-(TensionValue::SCALE / 2)); // -0.5
        let s = format!("{}", v);
        assert!(s.starts_with('-'), "Negative fractional should show minus: {}", s);
    }

    #[test]
    fn test_display_positive() {
        let v = TensionValue::from_integer(42);
        assert_eq!(format!("{}", v), "42.000000000000000000");
    }
}
