//! tabminer: a chain whose every block carries one proof of all of it.
//!
//! The proofs are over the field GF(2^128) ([`field`]) and hashed with
//! Blake3 ([`blake3`], [`hash`]), and nothing else: no other field and no
//! other hash is in this crate.

pub mod alg;
pub mod argument;
pub mod arith;
pub mod blake3;
pub mod block;
pub mod chain;
pub mod challenger;
pub mod circuit;
pub mod codec;
pub mod field;
pub mod grand;
pub mod hash;
pub mod header;
pub mod hidden;
pub mod ledger;
pub mod machine;
pub mod merkle;
pub mod name;
pub mod ntt;
pub mod parallel;
pub mod pcs;
pub mod policy;
pub mod pow;
pub mod proof;
pub mod reading;
pub mod recursion;
pub mod segment;
pub mod signature;
pub mod signed;
pub mod structure;
#[cfg(test)]
#[path = "tests/util.rs"]
pub(crate) mod test_util;
pub mod work;
pub mod wots;
pub mod xmss;
