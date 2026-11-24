//! A table that grows, kept so that a change costs what changed.
//!
//! The wallet's tables are each one run of bytes, written anew whole
//! when they change ([`super::records`]). For most that is nothing: a
//! handful of records. Two grow with every block a miner makes and are
//! never cut: its outputs, and the list of what it has done. Written
//! whole at every change, a year of blocks is tens of megabytes to
//! disk several times a block.
//!
//! So each of those two is kept as a table and a log beside it: the
//! table as it was when last written whole, and after it the entries
//! that have changed since, in the order they changed (an entry under
//! the same id again is the later one's; one marked removed is gone).
//! A change writes the log, which is short. When the log has grown
//! long (tens of kilobytes; more beside a table of many megabytes),
//! the table is written whole again and the log emptied: so what a
//! change costs to write stays small, however long the table.
//!
//! Both are written in the one step a change is written in: there is
//! no moment at which the log is of another table than the one beside
//! it.

use super::Id;
use crate::codec::{Reader, Writer};

/// The length that marks an entry of the log as a removal.
const REMOVED: u32 = u32::MAX;
/// A log shorter than this is never reason to write the table whole.
/// (A few entries, in the tests: so that every one of them that
/// changes a wallet more than a little goes through both.)
#[cfg(not(test))]
const LEAST: usize = 64 << 10;
#[cfg(test)]
const LEAST: usize = 600;

/// The log of one table, as it is on disk.
#[derive(Default)]
pub(super) struct Log {
    bytes: Vec<u8>,
    /// How long the table beside it is.
    base: usize,
}

/// What a change is written as.
pub(super) enum Step {
    /// The log, longer by the change.
    Log(Vec<u8>),
    /// The table whole (and the log, empty).
    Whole(Vec<u8>),
}

impl Log {
    pub(super) fn new(base: usize, bytes: Vec<u8>) -> Log {
        Log { bytes, base }
    }

    /// How `delta` (entries, as [`put`] writes them) is to be written:
    /// after the log, or, if that would be long beside the table, as
    /// the table whole, which `whole` gives.
    pub(super) fn step(&self, delta: &[u8], whole: impl FnOnce() -> Vec<u8>) -> Step {
        let long = self.bytes.len() + delta.len();
        // (A log as long as the root of the table's length, times what
        // an entry is: where writing the log at each change and the
        // table whole now and then cost the least together.)
        if long > LEAST.max((self.base * 400).isqrt()) {
            return Step::Whole(whole());
        }
        let mut log = Vec::with_capacity(long);
        log.extend_from_slice(&self.bytes);
        log.extend_from_slice(delta);
        Step::Log(log)
    }

    /// What was written, now that it is: the log and the table's
    /// length from here on.
    pub(super) fn written(&mut self, step: Step) {
        match step {
            Step::Log(bytes) => self.bytes = bytes,
            Step::Whole(table) => (self.bytes, self.base) = (Vec::new(), table.len()),
        }
    }
}

/// An entry of a log: `id` is `bytes` from here on, or is removed.
pub(super) fn put(out: &mut Vec<u8>, id: &Id, bytes: Option<&[u8]>) {
    let mut w = Writer::default();
    w.0.extend_from_slice(id);
    match bytes {
        Some(bytes) => {
            w.u32(bytes.len() as u32);
            w.0.extend_from_slice(bytes);
        }
        None => w.u32(REMOVED),
    }
    out.extend_from_slice(&w.finish());
}

/// The entries of a log, in the order they were written: `None` if
/// the bytes are no log.
pub(super) fn entries(bytes: &[u8]) -> Option<Vec<(Id, Option<&[u8]>)>> {
    let mut r = Reader(bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        let id: Id = r.take(32)?.try_into().ok()?;
        match r.u32()? {
            REMOVED => out.push((id, None)),
            n => out.push((id, Some(r.take(n as usize)?))),
        }
    }
    Some(out)
}
