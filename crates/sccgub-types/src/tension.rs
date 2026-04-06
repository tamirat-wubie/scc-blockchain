use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::{Add, Sub};

use crate::SymbolAddress;

/// Fixed-point tension value with 18 decimal places.
/// Stored as i128 where the value represents `raw / 10^18`.
/// This ensures deterministic arithmetic across all platforms (v2.1 fix C-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TensionValue(pub i128);

impl TensionValue {
    pub const ZERO: Self = Self(0);
    pub const SCALE: i128 = 1_000_000_000_000_000_000; // 10^18

    pub fn from_integer(n: i64) -> Self {
        Self(n as i128 * Self::SCALE)
    }

    pub fn raw(&self) -> i128 {
        self.0
    }

    /// Multiply two tension values (fixed-point multiplication).
    pub fn mul_fp(self, other: Self) -> Self {
        Self(self.0.checked_mul(other.0).expect("tension overflow") / Self::SCALE)
    }
}

impl Add for TensionValue {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.checked_add(rhs.0).expect("tension overflow"))
    }
}

impl Sub for TensionValue {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.checked_sub(rhs.0).expect("tension underflow"))
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
        write!(f, "{}.{:018}", whole, frac)
    }
}

/// Tension field across the entire chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensionField {
    /// Total system tension: T = α·T_logic + β·T_grounding + γ·T_value + δ·T_resource
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
    /// Budget never changes.
    Fixed,
    /// Requires SAFETY precedence governance proposal to change.
    Governance,
    /// Auto-adjusts based on moving average utilization.
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
    /// Compute weighted total using fixed-point weights.
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
    fn test_fixed_point_arithmetic() {
        let a = TensionValue::from_integer(5);
        let b = TensionValue::from_integer(3);
        assert_eq!(a + b, TensionValue::from_integer(8));
        assert_eq!(a - b, TensionValue::from_integer(2));
    }

    #[test]
    fn test_fixed_point_mul() {
        let a = TensionValue::from_integer(5);
        let b = TensionValue::from_integer(3);
        assert_eq!(a.mul_fp(b), TensionValue::from_integer(15));
    }

    #[test]
    fn test_display() {
        let v = TensionValue::from_integer(42);
        assert_eq!(format!("{}", v), "42.000000000000000000");
    }
}
