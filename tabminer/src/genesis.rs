//! Mainnet's genesis: the time, the Bitcoin block and the target, and
//! the id they give (`chain::params` checks it). A testing genesis: a
//! real one is made just before launch.
//!
//! The genesis block is empty, timestamped 1793322871, and its nonce is
//! the hash of Bitcoin block 973758, so the chain did not exist before that block.
//! Its first blocks need about 65535 hashes each (the testing target).

/// Genesis time, unix seconds; the ASERT anchor.
pub const TIMESTAMP: u64 = 1793322871;
/// The Bitcoin block hash, in the byte order block explorers show.
pub const BITCOIN_HASH_HEX: &str = "00000000000000000000c4750b0959be11adfd86268999ae3ca6b95f667e9737";
pub const BITCOIN_HASH: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 117, 11, 9, 89, 190, 17, 173, 253, 134, 38, 137, 153, 174, 60, 166, 185, 95,
    102, 126, 151, 55,
];
/// Height and time of that Bitcoin block, for reference.
pub const BITCOIN_HEIGHT: u64 = 973758;
pub const BITCOIN_TIME: u64 = 1793322482;
/// Target of the first block after genesis (little-endian 64-bit limbs).
pub const TARGET: [u64; 4] = [0, 0, 0, 1099511627776];
/// Expected hashes per block at that target.
pub const HASHES_PER_BLOCK: u64 = 65535;
/// The genesis header's mix: its work's ([`crate::chain::params`] checks it).
pub const MIX: [u8; 32] = [121, 28, 226, 68, 226, 33, 253, 64, 172, 49, 11, 159, 154, 14, 34, 151, 195, 85, 212, 194, 125, 200, 238, 210, 212, 12, 125, 84, 210, 91, 111, 239];
/// The program of the chain's proof's step: that of the main network's
/// setup ([`crate::prover::Parts::mainnet`], which is checked against it).
pub const PROGRAM: [u8; 32] = [248, 159, 0, 253, 97, 53, 199, 184, 231, 194, 137, 186, 173, 112, 210, 110, 132, 239, 140, 186, 194, 82, 194, 151, 141, 6, 245, 10, 125, 222, 189, 237];
/// The genesis block id, as `tabminer show` prints it.
pub const ID: &str = "ed9fa1801a7928ff5f211491029912813d25df75ac2f9ef679cf13b37fd89bcb";
