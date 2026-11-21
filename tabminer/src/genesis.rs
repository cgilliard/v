//! Mainnet's genesis: the time, the Bitcoin block and the target. They
//! are all there is to say of it: the header's work and the block's id
//! follow, and the program works them out
//! ([`crate::chain::params::ChainParams::genesis`]). A testing genesis:
//! a real one is these three changed, just before launch.
//!
//! The genesis block is empty, and its nonce is the hash of a Bitcoin
//! block, so the chain did not exist before that block. Its first
//! blocks need about `2^248 / (TARGET + 1)` hashes each: 65535 at the
//! testing target.

/// Genesis time, unix seconds; the ASERT anchor.
pub const TIMESTAMP: u64 = 1793322871;
/// The Bitcoin block hash, in the byte order block explorers show.
pub const BITCOIN_HASH_HEX: &str = "00000000000000000000c4750b0959be11adfd86268999ae3ca6b95f667e9737";
/// The same, as bytes: the genesis header's nonce.
pub const BITCOIN_HASH: [u8; 32] = unhex(BITCOIN_HASH_HEX);
/// Height and time of that Bitcoin block, for reference.
pub const BITCOIN_HEIGHT: u64 = 973758;
pub const BITCOIN_TIME: u64 = 1793322482;
/// Target of the first block after genesis (little-endian 64-bit limbs).
pub const TARGET: [u64; 4] = [0, 0, 0, 1099511627776];
/// The program of the chain's proof's step: that of the main network's
/// setup ([`crate::prover::Parts::mainnet`], which is checked against it).
pub const PROGRAM: [u8; 32] = [248, 159, 0, 253, 97, 53, 199, 184, 231, 194, 137, 186, 173, 112, 210, 110, 132, 239, 140, 186, 194, 82, 194, 151, 141, 6, 245, 10, 125, 222, 189, 237];

/// The 32 bytes `hex` writes, as 64 digits: the program is not built
/// of anything else.
const fn unhex(hex: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("a hash is written in the digits 0 to 9 and a to f"),
        }
    }
    let hex = hex.as_bytes();
    assert!(hex.len() == 64, "a hash is 64 digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(hex[2 * i]) << 4 | digit(hex[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_s_bytes_are_its_digits() {
        let hex: String = BITCOIN_HASH.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, BITCOIN_HASH_HEX);
        assert_eq!(unhex("00ff10abcdef0000000000000000000000000000000000000000000000000001")[..6], [0, 255, 16, 0xab, 0xcd, 0xef]);
    }
}
