//! What tests share.

use crate::field::F;

/// A small generator of test values (xorshift64*): the same on every
/// run, and random in no sense a proof needs.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    pub fn f(&mut self) -> F {
        F((self.next_u64() as u128) << 64 | self.next_u64() as u128)
    }

    pub fn fs(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.f()).collect()
    }
}
