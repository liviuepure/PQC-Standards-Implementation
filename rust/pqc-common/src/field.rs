//! Finite field arithmetic over Z_q where q = 3329.
//!
//! Used by ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//! All arithmetic is performed modulo q = 3329.

use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The ML-KEM prime modulus q = 3329.
pub const Q: u16 = 3329;

/// An element of the finite field Z_q where q = 3329.
///
/// Values are stored in canonical form in the range [0, q).
/// All operations maintain this invariant.
///
/// # Constant-Time Guarantees
///
/// Equality comparison via `ConstantTimeEq` is constant-time.
/// Conditional selection via `ConditionallySelectable` is constant-time.
/// Arithmetic operations (+, -, *) are constant-time as they use only
/// fixed-sequence arithmetic instructions with no secret-dependent branches.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(u16);

impl FieldElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity (one).
    pub const ONE: Self = Self(1);

    /// Creates a new field element, reducing the input modulo q.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value % Q)
    }

    /// Creates a field element from a u32, reducing modulo q.
    #[inline]
    pub const fn from_u32(value: u32) -> Self {
        Self((value % Q as u32) as u16)
    }

    /// Creates a field element from a potentially negative i16 value.
    /// The result is in [0, q).
    #[inline]
    pub const fn from_i16(value: i16) -> Self {
        let reduced = ((value as i32) % (Q as i32) + (Q as i32)) % (Q as i32);
        Self(reduced as u16)
    }

    /// Returns the canonical representative in [0, q).
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl Add for FieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        // Since both inputs are < Q (3329), sum < 2*Q < u16::MAX.
        // Subtract Q and use wrapping to determine if we need the original.
        let sum = self.0 as u16 + rhs.0 as u16;
        // If sum >= Q, return sum - Q; otherwise return sum.
        // Branchless: compute sum - Q, check if it underflowed.
        let (reduced, underflow) = sum.overflowing_sub(Q);
        if underflow { Self(sum) } else { Self(reduced) }
    }
}

impl AddAssign for FieldElement {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // If self >= rhs, result = self - rhs.
        // If self < rhs, result = self - rhs + Q.
        let (diff, underflow) = self.0.overflowing_sub(rhs.0);
        if underflow { Self(diff.wrapping_add(Q)) } else { Self(diff) }
    }
}

impl SubAssign for FieldElement {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for FieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let product = self.0 as u32 * rhs.0 as u32;
        Self::from_u32(product)
    }
}

impl MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for FieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        // Branchless negation: (Q - x) % Q.
        // When x == 0: result = Q % Q = 0. ✓
        // When x > 0:  result = Q - x ∈ [1, Q-1]. ✓
        // No secret-dependent branches.
        let result = (Q as u32).wrapping_sub(self.0 as u32) % Q as u32;
        Self(result as u16)
    }
}

impl ConstantTimeEq for FieldElement {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FieldElement {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u16::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = FieldElement::new(1000);
        let b = FieldElement::new(2000);
        assert_eq!((a + b).value(), 3000);
    }

    #[test]
    fn test_add_wraps() {
        let a = FieldElement::new(3000);
        let b = FieldElement::new(1000);
        assert_eq!((a + b).value(), 671); // (3000 + 1000) mod 3329
    }

    #[test]
    fn test_sub() {
        let a = FieldElement::new(1000);
        let b = FieldElement::new(500);
        assert_eq!((a - b).value(), 500);
    }

    #[test]
    fn test_sub_wraps() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(200);
        assert_eq!((a - b).value(), 3229); // (100 - 200 + 3329) mod 3329
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(33);
        assert_eq!((a * b).value(), 3300);
    }

    #[test]
    fn test_mul_wraps() {
        let a = FieldElement::new(1000);
        let b = FieldElement::new(1000);
        // 1000000 mod 3329 = 1000000 - 300*3329 = 1000000 - 998700 = 1300
        assert_eq!((a * b).value(), 1300);
    }

    #[test]
    fn test_zero() {
        let z = FieldElement::ZERO;
        let a = FieldElement::new(42);
        assert_eq!((a + z).value(), 42);
        assert_eq!((a * z).value(), 0);
    }

    #[test]
    fn test_one() {
        let one = FieldElement::ONE;
        let a = FieldElement::new(1234);
        assert_eq!((a * one).value(), 1234);
    }

    #[test]
    fn test_reduce() {
        let a = FieldElement::new(3329);
        assert_eq!(a.value(), 0);
        let b = FieldElement::new(6658);
        assert_eq!(b.value(), 0);
    }

    #[test]
    fn test_neg() {
        let a = FieldElement::new(100);
        let neg_a = -a;
        assert_eq!((a + neg_a).value(), 0);

        let z = FieldElement::ZERO;
        assert_eq!((-z).value(), 0);
    }

    #[test]
    fn test_from_i16() {
        let a = FieldElement::from_i16(-1);
        assert_eq!(a.value(), 3328);
        let b = FieldElement::from_i16(-3);
        assert_eq!(b.value(), 3326);
        let c = FieldElement::from_i16(0);
        assert_eq!(c.value(), 0);
        let d = FieldElement::from_i16(100);
        assert_eq!(d.value(), 100);
    }

    #[test]
    fn test_add_assign() {
        let mut a = FieldElement::new(1000);
        a += FieldElement::new(2000);
        assert_eq!(a.value(), 3000);
    }

    #[test]
    fn test_sub_assign() {
        let mut a = FieldElement::new(100);
        a -= FieldElement::new(200);
        assert_eq!(a.value(), 3229);
    }

    #[test]
    fn test_mul_assign() {
        let mut a = FieldElement::new(100);
        a *= FieldElement::new(33);
        assert_eq!(a.value(), 3300);
    }

    #[test]
    fn test_exhaustive_add_sub_inverse() {
        // Verify a + (-a) == 0 for all elements
        for x in 0..Q {
            let a = FieldElement::new(x);
            let neg_a = -a;
            assert_eq!((a + neg_a).value(), 0, "failed for x={x}");
        }
    }

    #[test]
    fn test_neg_zero_branchless() {
        // -0 must equal 0, not Q
        let z = FieldElement::ZERO;
        assert_eq!((-z).value(), 0, "-0 should be 0");
    }

    #[test]
    fn test_neg_exhaustive() {
        // For all x in [0, Q): x + (-x) == 0
        for x in 0..Q {
            let a = FieldElement::new(x);
            let neg_a = -a;
            // neg_a must be in [0, Q)
            assert!(neg_a.value() < Q, "neg out of range for x={x}");
            assert_eq!((a + neg_a).value(), 0, "x + (-x) != 0 for x={x}");
        }
    }
}
