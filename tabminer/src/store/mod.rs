//! The node's storage: its own files, read and written at offsets, with
//! no database beneath and no file mapped into memory.
//!
//! What a node keeps is of two kinds. The state (the unspent outputs and
//! the names, with the Merkle tree over them) changes in place a little
//! with every block and must never be seen half changed. The rest
//! (headers, bodies, the records that undo a block) is written once and
//! read back.
//!
//! # Copy on write
//!
//! The state lives in one file of pages ([`PageFile`]) and is never
//! overwritten. A block's changes are written as new pages into free
//! space; when they are safely on disk, one small root record is written
//! that points at them. Until that record is on disk the state is the
//! one before the block, whole; from then on it is the one after, whole.
//! A crash at any moment leaves one or the other, and there is nothing
//! to replay or repair on the way up: the last good root record is the
//! state.
//!
//! The same record carries whatever else must change with the state in
//! one step (the lengths of the files written once), so there is one
//! moment at which a block becomes applied, everywhere.
//!
//! A reader holds the root record it began with ([`PageFile::pin`]) and
//! goes on reading that state while blocks are applied: the pages it can
//! reach are not reused until it lets go.
//!
//! # Layers
//!
//! - [`backend`]: a file as the layers above see it: read here, write
//!   there, make it durable. The real one is a file; the tests' is memory
//!   that can lose power at any write.
//! - [`crc32c`]: the checksum every page and root record carries.
//! - [`freemap`]: which parts of the file are in use.
//! - [`pagefile`]: pages, root records and transactions, on the three
//!   above.
//! - [`sparse`]: the hashes of the state's Merkle tree, from the nodes
//!   that are not empty.
//! - [`trie`]: a trie over keys that is the Merkle tree of what it holds,
//!   whatever the tree's keys, records and hashes: on the pages.
//! - [`outputs`]: the unspent outputs, a trie over positions.
//! - [`names`]: the names, a trie over the keys of names, hashed by their
//!   own rule.
//! - [`window`]: what undoes each of the last blocks.
//! - [`blob`]: bytes too many for a page, as a chain of pages.
//! - [`blocks`]: the headers, the bodies kept and the chain by height,
//!   in tries of the same file.
//! - [`commits`]: which outputs are commits of names, and of what.
//! - [`partial`]: the paths of some leaves, changed in memory: what
//!   proving a block takes from the state.
//! - [`state`]: the two under one root record, with the block they are
//!   the state after: what a node applies blocks to.
//! - [`receive`]: a state taken from other nodes part by part, each
//!   part checked, until it is one to go on from.
//!
//! Memory is what these hold and no more: the map of free space (a bit
//! for every 512 bytes of the file), a transaction's write buffer, and
//! whatever buffers a caller reads into.

pub mod backend;
pub mod blob;
pub mod blocks;
pub mod commits;
pub mod crc32c;
pub mod freemap;
pub mod names;
pub mod outputs;
pub mod pagefile;
pub mod partial;
pub mod receive;
pub mod sparse;
pub mod state;
#[cfg(test)]
pub(crate) mod testing;
pub mod trie;
pub mod window;

pub use backend::{Backend, DirLock, FileBackend, ReadReq, WriteReq};
pub use pagefile::{Extent, PageFile, Pin, ROOT_MAX, ReadPages, Root, Txn, UNIT};
