//! Bytes: how proofs are written and read.
//!
//! Numbers are little-endian. A list is its length as four bytes and then
//! its items. A reader never panics on what it is given: every read says
//! whether the bytes were there.

use crate::field::F;
use crate::hash::Digest;

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u32(&mut self, x: u32) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }

    pub fn u64(&mut self, x: u64) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }

    pub fn f(&mut self, x: F) {
        self.0.extend_from_slice(&x.to_bytes());
    }

    pub fn digest(&mut self, d: &Digest) {
        self.0.extend_from_slice(d);
    }

    /// A list's length.
    pub fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).expect("a list of a proof is short"));
    }

    pub fn fs(&mut self, xs: &[F]) {
        self.len(xs.len());
        xs.iter().for_each(|x| self.f(*x));
    }

    pub fn digests(&mut self, ds: &[Digest]) {
        self.len(ds.len());
        ds.iter().for_each(|d| self.digest(d));
    }
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn f(&mut self) -> Option<F> {
        Some(F::from_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn digest(&mut self) -> Option<Digest> {
        Some(self.take(32)?.try_into().unwrap())
    }

    /// A list's length, for items of `item` bytes at least: none if the
    /// bytes left could not hold so many, so that a length is never
    /// taken on trust for an allocation.
    pub fn len(&mut self, item: usize) -> Option<usize> {
        let n = self.u32()? as usize;
        (n.checked_mul(item)? <= self.0.len()).then_some(n)
    }

    pub fn fs(&mut self) -> Option<Vec<F>> {
        let n = self.len(16)?;
        (0..n).map(|_| self.f()).collect()
    }

    pub fn digests(&mut self) -> Option<Vec<Digest>> {
        let n = self.len(32)?;
        (0..n).map(|_| self.digest()).collect()
    }

    /// Whether everything has been read.
    pub fn end(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_written_is_read() {
        let mut w = Writer::default();
        w.u32(7);
        w.u64(u64::MAX - 1);
        w.f(F(1 << 100));
        w.digest(&[9; 32]);
        w.fs(&[F(1), F(2)]);
        w.digests(&[[3; 32]]);
        let mut r = Reader(&w.0);
        assert_eq!(
            (r.u32(), r.u64(), r.f(), r.digest()),
            (Some(7), Some(u64::MAX - 1), Some(F(1 << 100)), Some([9; 32]))
        );
        assert_eq!((r.fs(), r.digests()), (Some(vec![F(1), F(2)]), Some(vec![[3; 32]])));
        assert!(r.end() && r.u32().is_none());
    }

    #[test]
    fn a_length_is_not_taken_on_trust() {
        // A list said to be longer than the bytes that follow.
        let mut w = Writer::default();
        w.u32(u32::MAX);
        w.f(F::ONE);
        assert!(Reader(&w.0).fs().is_none());
        assert!(Reader(&w.0).digests().is_none());
        assert!(Reader(&[1, 0, 0]).u32().is_none());
    }
}
