//! The wallet's list of what it has done and been paid: one row each,
//! numbered as the wallet first saw it.
//!
//! The wallet keeps what it does by stage, a table a stage: payments
//! begun, payments signed, payments in a block with what proves them,
//! rewards, outputs added to others' payments, the steps of names. A
//! record moves from one table to the next and is dropped when the
//! chain has left it far enough behind, so none of them is a list of
//! everything, and none has a number that stays.
//!
//! This is the list. A row is of one record of those tables, found by
//! what names it there (a slate's id, a transaction's, an output's
//! commitment). Rows are added and their states brought up to date
//! whenever the wallet changes ([`relist`]), from the tables as they
//! then are: nothing else in the wallet writes a row, but for the two
//! things the tables do not say (which transaction a slate became, and
//! which one another takes the place of). A row is never removed, and
//! its number never changes; its state stays what it last was when the
//! record it is of has gone.
//!
//! A wallet made again from its words has no rows but of what it finds
//! on the chain, numbered afresh.

use super::{Id, State, Tables};
use crate::codec::{Reader, Writer};
use crate::hash::digest_to_bytes;
use crate::name::NameOp;

/// What a row is of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Sent,
    Received,
    Reward,
    Burn,
    NameCommit,
    NameReveal,
    NameUpdate,
    NameTransfer,
    /// Another payment taken back, or sped up: `of` says which.
    Cancel,
    Bump,
}

/// How a row stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// Begun and not yet signed; or, of what is to come to this wallet,
    /// not yet in a block.
    Begun,
    /// Signed, and in no block yet.
    Pooled,
    /// In a block.
    Confirmed,
    /// Given up before it was signed, or never made.
    Cancelled,
    /// Another transaction was signed in its place: `by` says which.
    Replaced,
    /// In a block that was undone.
    Orphaned,
    /// Signed for outputs that lie elsewhere now, or are in no block
    /// any more: to be made again.
    Remake,
    /// Given up by the wallet itself: no block could have had it (a
    /// reveal whose commit is no longer in the chain).
    Failed,
}

const KINDS: [Kind; 10] = [
    Kind::Sent,
    Kind::Received,
    Kind::Reward,
    Kind::Burn,
    Kind::NameCommit,
    Kind::NameReveal,
    Kind::NameUpdate,
    Kind::NameTransfer,
    Kind::Cancel,
    Kind::Bump,
];
const STAGES: [Stage; 8] = [
    Stage::Begun,
    Stage::Pooled,
    Stage::Confirmed,
    Stage::Cancelled,
    Stage::Replaced,
    Stage::Orphaned,
    Stage::Remake,
    Stage::Failed,
];

/// A row of the list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Row {
    /// From one: the row's number, for good.
    pub number: u32,
    pub kind: Kind,
    pub stage: Stage,
    /// What names the record the row is of where it began: a slate's
    /// id, a transaction's, or the commitment of an output that came to
    /// this wallet.
    pub id: Id,
    /// The transaction, once there is one; zeros until then, and for a
    /// row of an output.
    pub txid: Id,
    /// The row this one takes back or speeds up; and the row that took
    /// this one's place. Zero for none.
    pub of: u32,
    pub by: u32,
    pub amount: u64,
    pub fee: u64,
    /// Unix time the wallet first saw it.
    pub created: u64,
    /// The chain's height when a transaction was first seen to have
    /// gone into it; zero if not known (of an output, the chain says).
    pub height: u32,
    /// The name, of a step of a name, if the wallet knows it.
    pub name: Vec<u8>,
}

impl Row {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96 + self.name.len());
        w.0.push(KINDS.iter().position(|k| *k == self.kind).unwrap_or(0) as u8);
        w.0.push(STAGES.iter().position(|s| *s == self.stage).unwrap_or(0) as u8);
        w.0.extend_from_slice(&self.id);
        w.0.extend_from_slice(&self.txid);
        w.u32(self.of);
        w.u32(self.by);
        w.u64(self.amount);
        w.u64(self.fee);
        w.u64(self.created);
        w.u32(self.height);
        w.0.extend_from_slice(&self.name);
        w.finish()
    }

    fn from_bytes(number: u32, bytes: &[u8]) -> Option<Row> {
        let mut r = Reader(bytes);
        let head = r.take(2)?;
        let (kind, stage) = (*KINDS.get(head[0] as usize)?, *STAGES.get(head[1] as usize)?);
        let id: Id = r.take(32)?.try_into().ok()?;
        let txid: Id = r.take(32)?.try_into().ok()?;
        let (of, by, amount, fee, created, height) = (r.u32()?, r.u32()?, r.u64()?, r.u64()?, r.u64()?, r.u32()?);
        let name = r.0.to_vec();
        Some(Row { number, kind, stage, id, txid, of, by, amount, fee, created, height, name })
    }

    /// The transaction's id, if the row has one.
    pub fn transaction(&self) -> Option<Id> {
        (self.txid != [0; 32]).then_some(self.txid)
    }

    /// Whether the row is of something that came to this wallet: its
    /// `id` is then an output's commitment.
    pub fn is_output(&self) -> bool {
        matches!(self.kind, Kind::Received | Kind::Reward)
    }
}

/// The rows of `now` that are other than those of `was`, which is the
/// list as it was from its row at `from` on (the first not at rest:
/// the rows before never change): as entries of the list's log
/// ([`super::journal`]).
pub(super) fn changed(was: &[Row], from: usize, now: &[Row]) -> Vec<u8> {
    let mut delta = Vec::new();
    for (i, row) in now.iter().enumerate().skip(from) {
        if was.get(i - from) != Some(row) {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&row.number.to_be_bytes());
            super::journal::put(&mut delta, &id, Some(&row.to_bytes()));
        }
    }
    delta
}

/// The rows as the wallet's file keeps them: by number.
pub(super) fn encode(rows: &[Row]) -> Vec<u8> {
    let keyed: Vec<(Id, Vec<u8>)> = rows
        .iter()
        .map(|row| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&row.number.to_be_bytes());
            (id, row.to_bytes())
        })
        .collect();
    super::put_entries(keyed.iter().map(|(id, bytes)| (id, bytes.clone())))
}

/// The rows a file keeps, in their order: `None` if they are not rows,
/// or not numbered from one without a gap.
pub(super) fn decode(bytes: &[u8], log: &[u8]) -> Option<Vec<Row>> {
    let mut rows = Vec::new();
    for (i, (id, bytes)) in super::get_entries(bytes)?.into_iter().enumerate() {
        let number = u32::from_be_bytes(id[..4].try_into().ok()?);
        if number as usize != i + 1 {
            return None;
        }
        rows.push(Row::from_bytes(number, bytes)?);
    }
    // And the rows that have changed, or been added, since: each in
    // the place of the one of its number, or after the last.
    for (id, bytes) in super::journal::entries(log)? {
        let number = u32::from_be_bytes(id[..4].try_into().ok()?);
        let row = Row::from_bytes(number, bytes?)?;
        match (number as usize).checked_sub(1)? {
            at if at < rows.len() => rows[at] = row,
            at if at == rows.len() => rows.push(row),
            _ => return None,
        }
    }
    Some(rows)
}

/// How deep a block is that no branch a node goes over to undoes:
/// twice what a node keeps to undo, by default.
const DEEP: u32 = 2016;

/// What a transaction is, by what it carries: a step of a name, if it
/// carries an operation on one; else a payment.
fn kind_of(ops: &[NameOp]) -> (Kind, Vec<u8>) {
    match ops.first() {
        Some(NameOp::Commit { .. }) => (Kind::NameCommit, Vec::new()),
        Some(NameOp::Reveal { record, .. }) => (Kind::NameReveal, record.name.as_bytes().to_vec()),
        Some(NameOp::Update { record, .. }) => (Kind::NameUpdate, record.name.as_bytes().to_vec()),
        None => (Kind::Sent, Vec::new()),
    }
}

impl Tables {
    /// (From the last: what is looked for is nearly always new.)
    fn row_of(&self, id: &Id) -> Option<usize> {
        self.list.iter().rposition(|row| row.id == *id || row.txid == *id)
    }

    fn add(&mut self, kind: Kind, stage: Stage, id: Id, amount: u64, fee: u64, created: u64) -> usize {
        let number = self.list.len() as u32 + 1;
        let (txid, name) = ([0; 32], Vec::new());
        self.list.push(Row { number, kind, stage, id, txid, of: 0, by: 0, amount, fee, created, height: 0, name });
        self.list.len() - 1
    }

    /// A slate has become a transaction: its row is that transaction's
    /// from here on. (`burn`: of coins burned, not paid.)
    pub(super) fn signed(&mut self, slate: &Id, txid: &Id, burn: bool) {
        if let Some(at) = self.row_of(slate) {
            let row = &mut self.list[at];
            row.txid = *txid;
            row.stage = Stage::Pooled;
            if burn {
                row.kind = Kind::Burn;
            }
        }
    }

    /// The transaction `txid` is given up by the wallet itself, since
    /// no block could have it: its row says so from here on.
    pub(super) fn failed(&mut self, txid: &Id) {
        if let Some(at) = self.row_of(txid) {
            self.list[at].stage = Stage::Failed;
        }
    }

    /// The transaction `new` was signed in the place of `old`, to take
    /// it back or to speed it up: a row of its own, and the old one's
    /// says which took its place.
    pub(super) fn replaced(&mut self, old: &Id, new: &Id, kind: Kind, fee: u64, created: u64) {
        let of = self.row_of(old);
        let at = self.add(kind, Stage::Pooled, *new, 0, fee, created);
        self.list[at].txid = *new;
        if let Some(of) = of {
            (self.list[at].of, self.list[at].name) = (self.list[of].number, self.list[of].name.clone());
            // (Sped up, it is the same payment still.)
            if kind == Kind::Bump {
                self.list[at].amount = self.list[of].amount;
            }
            (self.list[of].stage, self.list[of].by) = (Stage::Replaced, self.list[at].number);
        }
    }
}

/// Brings the list up to the tables as they are: a row for each record
/// that has none, and each row's state. Whether anything changed.
pub(super) fn relist(t: &mut Tables) -> bool {
    // (The rows at rest are not looked at: a miner's list is of every
    // block it has made, and this is done at every change.)
    t.rest = t.rest.min(t.list.len());
    let (from, before) = (t.rest, t.list[t.rest..].to_vec());
    // Payments begun.
    let begun: Vec<(Id, u64, u64)> = t.slates.iter().map(|(id, p)| (*id, p.amount, p.fee)).collect();
    for (id, amount, fee) in begun {
        if t.row_of(&id).is_none() {
            t.add(Kind::Sent, Stage::Begun, id, amount, fee, 0);
        }
    }
    // Transactions signed that no slate was the beginning of: steps of
    // names, coins burned, and what a wallet has from before it kept
    // this list.
    let signed: Vec<Id> = t.sent.keys().copied().collect();
    for txid in signed {
        if t.row_of(&txid).is_some() {
            continue;
        }
        let sent = &t.sent[&txid];
        let (kind, name) = kind_of(&sent.tx.ops);
        let amount = t.payments.get(&txid).map_or(0, |p| p.proof.amount);
        let (fee, created) = (sent.fee, sent.created);
        let at = t.add(kind, Stage::Pooled, txid, amount, fee, created);
        (t.list[at].txid, t.list[at].name) = (txid, name);
    }
    // What is coming to this wallet by others' payments; the rewards of
    // blocks it has won; and what a look through the chain found.
    let coming: Vec<Id> = t.answered.iter().copied().collect();
    let won: Vec<Id> = t.rewards.iter().filter(|(_, (_, block))| *block != [0; 32]).map(|(c, _)| *c).collect();
    // (Those in the order they lie in the chain: the list of a wallet
    // made again reads oldest first, as one that grew does.)
    // (Only after such a look: there may be very many of them.)
    let looked = std::mem::take(&mut t.scanned);
    let mut found: Vec<(Option<u64>, Id)> =
        t.outputs.iter().filter(|(_, o)| looked && o.recovered).map(|(c, o)| (o.position, *c)).collect();
    found.sort();
    let found: Vec<Id> = found.into_iter().map(|(_, c)| c).collect();
    for (kind, ids) in [(Kind::Received, coming), (Kind::Reward, won), (Kind::Received, found)] {
        for id in ids {
            if t.row_of(&id).is_none()
                && let Some(o) = t.outputs.get(&id).copied()
            {
                t.add(kind, Stage::Begun, id, o.amount, 0, o.created);
            }
        }
    }
    // Where each row stands.
    for at in t.rest..t.list.len() {
        let row = t.list[at].clone();
        let (stage, height) = match row.is_output() {
            true => match t.outputs.get(&row.id) {
                Some(_) if t.lost.contains_key(&row.id) => (Stage::Orphaned, 0),
                Some(o) if o.position.is_some() => (Stage::Confirmed, row.height),
                Some(_) => (Stage::Begun, 0),
                // (Gone: spent and settled, if it was ever in a block;
                // never made, if not.)
                None if row.stage == Stage::Begun => (Stage::Cancelled, 0),
                None => (row.stage, row.height),
            },
            false if t.slates.contains_key(&row.id) => (Stage::Begun, 0),
            false => match t.sent.get(&row.txid) {
                Some(sent) => match t.landed.get(&row.txid) {
                    // (The block's own height where a block was seen
                    // to make what it makes; else that of the chain
                    // when it was first seen to be in.)
                    Some(at) => (Stage::Confirmed, if row.height > 0 { row.height } else { *at }),
                    None => {
                        // Signed for where its outputs lay: if one lies
                        // elsewhere now, it spends nothing; nor if what
                        // it was to spend is in no block any more.
                        let at = sent.tx.spent_positions();
                        let moved = sent.inputs.iter().zip(&at).any(|(c, signed)| {
                            let now = t.outputs.get(&digest_to_bytes(c)).and_then(|o| o.position);
                            now.is_some_and(|now| now != *signed)
                        });
                        let stranded = t.lost.contains_key(&row.txid);
                        (if moved || stranded { Stage::Remake } else { Stage::Pooled }, 0)
                    }
                },
                // (No record of it any more: given up before it was
                // signed; or settled, or replaced, and as it was.)
                None if row.stage == Stage::Begun => (Stage::Cancelled, 0),
                None if matches!(row.stage, Stage::Pooled | Stage::Remake) && row.by == 0 => {
                    // Signed, and forgotten without having been seen in
                    // a block: taken back because nobody would have it.
                    (Stage::Cancelled, 0)
                }
                None => (row.stage, row.height),
            },
        };
        (t.list[at].stage, t.list[at].height) = (stage, height);
        // (A commit's name, once the wallet has it.)
        if row.kind == Kind::NameCommit && row.name.is_empty() {
            let named = t.sent.get(&row.txid).and_then(|sent| match sent.tx.ops.first() {
                Some(NameOp::Commit { commit, .. }) => t.commits.get(&digest_to_bytes(commit))?.name.clone(),
                _ => None,
            });
            t.list[at].name = named.unwrap_or_default();
        }
    }
    // The blocks just seen to make outputs: the height of each one's
    // row, and of the row of the transaction that made it.
    // (One whose row is not there yet is kept for when it is: the
    // reward of a block is a row only once the block is known to be
    // this wallet's, which may be said after the block is seen.)
    let mut waiting = Vec::new();
    for (id, height) in std::mem::take(&mut t.located) {
        let mut placed = false;
        for at in t.rest..t.list.len() {
            let row = &t.list[at];
            let makes = |sent: &super::Sent| sent.tx.outputs.iter().any(|o| digest_to_bytes(&o.commitment) == id);
            if (row.is_output() && row.id == id) || (row.by == 0 && t.sent.get(&row.txid).is_some_and(makes)) {
                t.list[at].height = height;
                placed = true;
            }
        }
        if !placed && t.outputs.contains_key(&id) {
            waiting.push((id, height));
        }
    }
    // (No more of them than a node's branches are long.)
    let over = waiting.len().saturating_sub(4096);
    t.located = waiting.split_off(over);
    // The first rows that are at rest now: done with, as they stand.
    // Of a transaction, when the wallet has let go of its record; of
    // an output, when it is gone, or so deep in the chain that no
    // branch undoes it.
    let tip = t.synced.map_or(0, |(height, _)| height);
    while let Some(row) = t.list.get(t.rest) {
        let resting = match (row.is_output(), t.outputs.get(&row.id)) {
            (true, None) => true,
            (true, Some(_)) => {
                let deep = row.height > 0 && tip >= row.height.saturating_add(DEEP);
                row.stage == Stage::Confirmed && deep && !t.lost.contains_key(&row.id)
            }
            (false, _) => !t.slates.contains_key(&row.id) && !t.sent.contains_key(&row.txid),
        };
        if !resting {
            break;
        }
        t.rest += 1;
    }
    let _ = State::Unspent;
    // (What was at rest before is as it was: only the others are held
    // against what they were.)
    t.list[from..] != before[..]
}
