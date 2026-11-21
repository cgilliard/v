//! tabminer: a chain whose every block carries one proof of all of it.
//!
//! The proofs are over the field GF(2^128) ([`field`]) and hashed with
//! Blake3 ([`blake3`], [`hash`]), and nothing else: no other field and no
//! other hash is in this crate.

pub mod address;
pub mod alg;
pub mod argument;
pub mod arith;
pub mod bip39;
pub mod blake3;
pub mod block;
pub mod block_proof;
pub mod chain;
pub mod chain_proof;
pub mod chacha20poly1305;
pub mod challenger;
pub mod circuit;
pub mod codec;
pub mod conditions;
pub mod consensus;
pub mod difficulty;
pub mod error;
pub mod field;
pub mod genesis;
pub mod grand;
pub mod hash;
pub mod header;
pub mod heap;
pub mod hidden;
pub mod keccak;
pub mod ledger;
pub mod logger;
pub mod machine;
pub mod mempool;
pub mod merkle;
pub mod mldsa;
pub mod mlkem;
pub mod name;
pub mod ntt;
pub mod output;
pub mod parallel;
pub mod pcs;
pub mod policy;
pub mod pow;
pub mod proof;
pub mod random;
pub mod reading;
pub mod recursion;
pub mod registry;
pub mod segment;
pub mod sha256;
pub mod signature;
pub mod signed;
pub mod store;
pub mod structure;
#[cfg(test)]
#[path = "tests/util.rs"]
pub(crate) mod test_util;
pub mod work;
pub mod transaction;
pub mod u256;
pub mod wots;
pub mod xmss;
