//! A simple implementation of raional numbers.

use std::fmt::{Debug, Display, Formatter, Result};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// An approximation of the integers
type Z = i128;

// stein's algorithm
fn gcd(x: Z, y: Z) -> Z {
    let mut x = x.wrapping_abs() as u128;
    let mut y = y.wrapping_abs() as u128;
    if y == 0 {
        return x as i128;
    }
    if x == 0 {
        return y as i128;
    }

    let shift = (x | y).trailing_zeros();

    x >>= x.trailing_zeros();
    y >>= y.trailing_zeros();

    while x != y {
        if x > y {
            x -= y;
            x >>= x.trailing_zeros();
        } else {
            y -= x;
            y >>= y.trailing_zeros();
        }
    }
    (x << shift) as i128
}

/// A rational number
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Q {
    /// an integer
    Z(Z),
    /// a ratio of integers in reduced form
    R(Z, Z),
}
use Q::*;

pub const MINUS: Q = Z(-1i128);
pub const ZERO: Q = Z(0i128);
pub const ONE: Q = Z(1i128);
pub const TWO: Q = Z(2i128);

impl Display for Q {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Z(x) => write!(f, "{x}"),
            R(x, y) => write!(f, "{x}/{y}"),
        }
    }
}

impl<T> From<T> for Q
where
    Z: From<T>,
{
    fn from(t: T) -> Self {
        Z(Z::from(t))
    }
}

impl Q {
    fn reduce(a: Z, b: Z) -> Self {
        let div = gcd(a, b);
        let mut num = a / div;
        let mut den = b / div;
        if den.is_negative() {
            num = num.neg();
            den = den.neg();
        }
        if den == 1 || num == 0 {
            Z(num)
        } else {
            R(num, den)
        }
    }
}

impl Add<&Q> for &Q {
    type Output = Q;
    fn add(self, rhs: &Q) -> Q {
        match (self, rhs) {
            (Z(x), Z(y)) => Z(x + y),
            (Z(x), R(a, b)) | (R(a, b), Z(x)) => Q::reduce(a + x * b, *b),
            (R(a, b), R(c, d)) => Q::reduce(a * d + c * b, b * d),
        }
    }
}

impl Add<Q> for Q {
    type Output = Q;
    #[inline]
    fn add(self, rhs: Q) -> Q {
        (&self).add(&rhs)
    }
}

impl Sub<&Q> for &Q {
    type Output = Q;
    fn sub(self, rhs: &Q) -> Q {
        match (self, rhs) {
            (Z(x), Z(y)) => Z(x - y),
            (Z(x), R(a, b)) | (R(a, b), Z(x)) => Q::reduce(a - x * b, *b),
            (R(a, b), R(c, d)) => Q::reduce(a * d - c * b, b * d),
        }
    }
}

impl Sub<Q> for Q {
    type Output = Q;
    #[inline]
    fn sub(self, rhs: Q) -> Q {
        (&self).sub(&rhs)
    }
}

impl Neg for &Q {
    type Output = Q;
    fn neg(self) -> Q {
        match self {
            Z(x) => Z(x.neg()),
            R(a, b) => R(a.neg(), *b),
        }
    }
}

impl Neg for Q {
    type Output = Q;
    #[inline]
    fn neg(self) -> Q {
        (&self).neg()
    }
}

impl Mul<&Q> for &Q {
    type Output = Q;
    fn mul(self, rhs: &Q) -> Q {
        match (self, rhs) {
            (Z(x), Z(y)) => Z(x * y),
            (Z(x), R(a, b)) | (R(a, b), Z(x)) => Q::reduce(a * x, *b),
            (R(a, b), R(c, d)) => Q::reduce(a * b, c * d),
        }
    }
}

impl Mul<Q> for Q {
    type Output = Q;
    #[inline]
    fn mul(self, rhs: Q) -> Q {
        (&self).mul(&rhs)
    }
}

impl Div<&Q> for &Q {
    type Output = Q;
    fn div(self, rhs: &Q) -> Q {
        match (self, rhs) {
            (Z(x), Z(y)) => Q::reduce(*x, *y),
            (Z(x), R(a, b)) => Q::reduce(x * b, *a),
            (R(a, b), Z(x)) => Q::reduce(*a, b * x),
            (R(a, b), R(c, d)) => Q::reduce(a * d, b * c),
        }
    }
}

impl Div<Q> for Q {
    type Output = Q;
    #[inline]
    fn div(self, rhs: Q) -> Q {
        (&self).div(&rhs)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(1, 0), 1);
        assert_eq!(gcd(0, 2), 2);
        assert_eq!(gcd(-1, 0), 1);
        assert_eq!(gcd(Z::MIN, Z::MAX), 1);
        assert_eq!(gcd(Z::MIN + 1, Z::MAX), Z::MAX);

        assert_eq!(gcd(6, 3), 3);
        assert_eq!(gcd(-6, 3), 3);
        assert_eq!(gcd(6, -3), 3);
        assert_eq!(gcd(-6, -3), 3);
    }

    #[test]
    fn test_q_reduce() {
        assert_eq!(R(-1, 2), Q::reduce(3, -6));
        assert_eq!(ONE, Q::reduce(-11, -11));
    }

    #[test]
    fn test_q() {
        let half = R(1, 2);
        let third = R(1, 3);
        let two_third = R(2, 3);
        let minus_third = -third;

        assert_eq!(ONE, third + two_third);
        assert_eq!(ZERO, half - half);
        assert_eq!(minus_third, two_third - ONE);
        assert_eq!(third, half * two_third);
        assert_eq!(ZERO, ZERO * two_third);
        assert_eq!(two_third, third / half);
    }
}
