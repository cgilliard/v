//! The node's wallet: a 12-word BIP39 phrase, one-time keys derived per
//! output, and the outputs paid to them, in a file of its own
//! ([`records`]).
//!
//! # Keys and memos
//!
//! The phrase's BIP39 seed hashes to a master secret `m`. Every output the
//! wallet creates gets a fresh random 124-bit nonce `r` (four field
//! elements) and its own key, generated from `H(m, r)`. Its memo, which
//! goes on chain with the commitment, is the nonce and a tag `H(m, r)'`
//! of one element: so only the wallet can tell its outputs from others'
//! (a stranger's memo matches once in 2^31; the commitment confirms a
//! match). Recovery from the phrase alone ([`Wallet::scan`]) reads every
//! unspent output's memo, keeps those whose tag matches, and confirms
//! each by making its commitment again.
//!
//! # Leaves
//!
//! A key's tree has 16 leaves. An output this wallet created signs from
//! leaves 0 to 7: its spend, then up to seven replacements. An output
//! found by [`Wallet::scan`] signs from leaves 8 to 15, starting at a
//! random one and wrapping, so a restored copy never signs from a leaf
//! the original used, and two restored copies rarely collide. A leaf is
//! on disk as used before the signature made from it leaves the wallet,
//! so a crash can waste a leaf but never use one twice.
//!
//! # Outputs and slates
//!
//! An output's record holds its nonce, amount, commitment and a state:
//! unspent, reserved by a pending slate, or spent by a signed
//! transaction. Whether an unspent output is confirmed is whether the
//! chain's state holds it where it was last seen.
//!
//! A payment is agreed in a [`Slate`] passed between the two wallets:
//! [`Wallet::send`] picks and reserves inputs, adds change and says the
//! amount and fee; [`Wallet::receive_slate`] adds the recipient's
//! output; [`Wallet::finalize`] checks that nothing else changed, signs,
//! and marks the inputs spent.
//!
//! # What is not here yet
//!
//! The reference's wallet also has an address others pay by name, a
//! receipt in every answered slate, names, policies, proofs of payment
//! and the replacing of a payment sent. A slate here carries no receipt
//! and names no sender, and says so by a magic of its own: it is not the
//! reference's slate.
//!
//! Nothing here reads a clock or the chain: the time is given, and what
//! the chain's state holds is asked through [`Unspent`].

pub mod follow;
pub mod list;
pub mod names;
pub mod records;

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::bip39;
use crate::chacha20poly1305;
use crate::codec::{Reader, Writer};
use crate::hash::hash_domain;
use crate::hash::{digest_from_bytes, digest_to_bytes};
use crate::mempool::{MAX_TX_SIZE, MIN_FEE_PER_UNIT, Policy, REPLACEMENT_FEE_PER_UNIT, Weights};
use crate::output::{Commitment, EMPTY_MEMO, INPUT_SIZE, Key, Memo, OUTPUT_SIZE, Output, key_commitment, pubkey_hash};
use crate::store::Backend;
use crate::store::state::Snapshot;
use crate::transaction::{Transaction, UnsignedTransaction};
use crate::xmss::{PublicKey, SEED_SIZE};
use records::Records;

/// How the tables are laid out.
const FORMAT: u8 = 1;
/// The tables of the wallet's file.
const T_META: usize = 0;
const T_OUTPUTS: usize = 1;
const T_SLATES: usize = 2;
const T_SENT: usize = 3;
const T_REWARDS: usize = 4;
const T_ANSWERED: usize = 5;
const T_LANDED: usize = 6;
const T_LOST: usize = 7;
const T_RECENT: usize = 8;
const T_COMMITS: usize = 9;
const T_NAMES: usize = 10;
/// The address counter ([`Wallet::identity_key`]): eight bytes, or
/// nothing for the first address.
const T_ADDRESS: usize = 11;
/// Whom each pending slate was sent to, of those sent over the message
/// layer: by the slate's id, the id of the wallet.
const T_SENT_TO: usize = 12;
/// The names this wallet has given out under names it holds
/// ([`crate::subnames`]): by the id each full name is reached by, the
/// label, the name, the wallet it is, and the number and time of the
/// certificate last signed for it.
const T_NAMES_GIVEN: usize = 13;
/// The full names this wallet is: by the id each is reached by, the
/// number of its certificate and until when it holds (eight bytes
/// each), and the certificate with what goes with it.
const T_NAMES_HELD: usize = 14;
/// The names this wallet's key signs for by the word of whoever holds
/// them ([`crate::subnames::delegate`]): by an id made of the name,
/// that word.
const T_NAMES_SIGNED: usize = 15;
/// The payments made and the coins burned, each with what proves it
/// ([`crate::proofs`]): by the id of its transaction.
const T_PAYMENTS: usize = 16;
/// What the slates that paid this wallet said (their notes): by the
/// commitment of the output each made.
const T_NOTES: usize = 17;
/// The list of what the wallet has done and been paid ([`list`]).
const T_LIST: usize = 18;

/// A name this wallet has given out under a name it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Given {
    pub label: Vec<u8>,
    pub name: Vec<u8>,
    /// The wallet the full name is.
    pub holder: crate::hash::Digest,
    /// The number of the certificate last signed for it, and until
    /// when that one holds (Unix seconds).
    pub seq: u64,
    pub expires: u64,
}

impl Given {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.label.len() as u8];
        out.extend_from_slice(&self.label);
        out.push(self.name.len() as u8);
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&digest_to_bytes(&self.holder));
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.expires.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Given> {
        let (n, rest) = bytes.split_first()?;
        let (label, rest) = rest.split_at_checked(*n as usize)?;
        let (n, rest) = rest.split_first()?;
        let (name, rest) = rest.split_at_checked(*n as usize)?;
        let (holder, rest) = rest.split_at_checked(32)?;
        let (seq, expires) = rest.split_at_checked(8).filter(|(_, expires)| expires.len() == 8)?;
        Some(Given {
            label: label.to_vec(),
            name: name.to_vec(),
            holder: digest_from_bytes(holder)?,
            seq: u64::from_le_bytes(seq.try_into().ok()?),
            expires: u64::from_le_bytes(expires.try_into().ok()?),
        })
    }

    /// The full name, as it is written.
    pub fn full(&self) -> String {
        format!("{}@{}", String::from_utf8_lossy(&self.label), String::from_utf8_lossy(&self.name))
    }
}

/// Blocks looked at that the wallet remembers, at the most: as far back
/// as it can find where the chain parted from what it knew.
const RECENT: usize = 2048;

/// A slate of this wallet's making: the reference's, less its sender and
/// its receipt.
const SLATE_MAGIC: &[u8; 8] = b"tabslt0q";
/// What a slate as text is marked with.
pub const SLATE_MARKER: &str = "TAB SLATE";

const DOM_MASTER: u32 = 65;
const DOM_TAG: u32 = 66;
const DOM_KEY: u32 = 67;
/// The seed of the wallet's Dilithium key, its identity on the message
/// layer: of the master key and the address counter.
const DOM_IDENTITY: u32 = 70;

/// Bytes of the nonce in a memo; the rest of a memo is the tag a scan
/// knows this wallet's outputs by.
pub const NONCE: usize = 16;
/// What an output of the wallet's is made from.
pub type Nonce = [u8; NONCE];
/// Leaves a key may sign from, in each half of its tree.
pub const LEAVES_PER_HALF: u32 = 8;

/// What a record of the wallet is named by: a commitment's bytes, a
/// slate's id.
type Id = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unspent,
    /// Picked as an input of a pending slate.
    Reserved,
    /// Signed away by a finalized transaction.
    Spent,
}

impl State {
    fn to_u8(self) -> u8 {
        match self {
            State::Unspent => 0,
            State::Reserved => 1,
            State::Spent => 2,
        }
    }

    fn from_u8(b: u8) -> Option<State> {
        match b {
            0 => Some(State::Unspent),
            1 => Some(State::Reserved),
            2 => Some(State::Spent),
            _ => None,
        }
    }
}

/// An output paid to one of the wallet's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub commitment: Commitment,
    pub nonce: Nonce,
    pub amount: u64,
    pub state: State,
    /// Unix time the record was made.
    pub created: u64,
    /// Found by [`Wallet::scan`] rather than created by this wallet: signs
    /// from leaves 8 to 15.
    pub recovered: bool,
    /// Offset of the first leaf within the key's half (random when
    /// recovered, zero otherwise).
    pub start: u8,
    /// Signatures made so far, at most [`LEAVES_PER_HALF`].
    pub used: u8,
    /// Where the output is in the chain's state, once a block made it
    /// (see [`Wallet::locate`]).
    pub position: Option<u64>,
}

impl Owned {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.bytes(&self.nonce);
        w.u64(self.amount);
        w.0.push(self.state.to_u8());
        w.u64(self.created);
        w.0.push(self.recovered as u8);
        w.0.push(self.start);
        w.0.push(self.used);
        if let Some(p) = self.position {
            w.u64(p);
        }
        w.finish()
    }

    fn from_bytes(commitment: Commitment, bytes: &[u8]) -> Option<Owned> {
        let mut r = Reader(bytes);
        let nonce = r.take(NONCE)?.try_into().ok()?;
        let amount = r.u64()?;
        let state = State::from_u8(r.take(1)?[0])?;
        let created = r.u64()?;
        let flags = r.take(3)?;
        let (recovered, start, used) = (flags[0] == 1, flags[1], flags[2]);
        if flags[0] > 1 || u32::from(start) >= LEAVES_PER_HALF || u32::from(used) > LEAVES_PER_HALF {
            return None;
        }
        let position = if r.is_empty() { None } else { Some(r.u64()?) };
        r.is_empty().then_some(Owned { commitment, nonce, amount, state, created, recovered, start, used, position })
    }

    /// Signatures this output can still make.
    pub fn signatures_left(&self) -> u32 {
        LEAVES_PER_HALF - u32::from(self.used)
    }
}

/// A payment being agreed, as the two wallets pass it between them.
/// Stage 1: the sender's inputs, change and terms. Stage 2: the
/// recipient's output added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slate {
    pub id: [u8; 32],
    pub stage: u8,
    pub amount: u64,
    pub fee: u64,
    /// Whoever pays, as the receipt names it: the hash of a secret the
    /// paying wallet keeps ([`crate::proofs::sender_tag`]). Not its
    /// address, nor anything that is had from it.
    pub sender: crate::hash::Digest,
    /// What the payment is for, in the words of whoever pays: a number
    /// the wallet that is paid gave out, say. Up to
    /// [`crate::proofs::MAX_NOTE`] bytes; nothing, if nothing is said.
    pub note: Vec<u8>,
    /// The receipt of the wallet that is paid: there once the slate is
    /// answered, and not before.
    pub receipt: Option<crate::proofs::Receipt>,
    pub inputs: Vec<(PublicKey, u64)>,
    /// The sender's change (if any) first, then the recipient's output.
    pub outputs: Vec<Output>,
    /// How many of `outputs` are the sender's change.
    pub change: u32,
}

impl Slate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.0.extend_from_slice(SLATE_MAGIC);
        w.0.extend_from_slice(&self.id);
        w.0.push(self.stage);
        w.u64(self.amount);
        w.u64(self.fee);
        w.u32(self.change);
        w.digest(&self.sender);
        w.0.push(self.note.len() as u8);
        w.0.extend_from_slice(&self.note);
        w.u32(self.inputs.len() as u32);
        for (pk, amount) in &self.inputs {
            w.0.extend_from_slice(&pk.to_bytes());
            w.u64(*amount);
        }
        w.u32(self.outputs.len() as u32);
        for o in &self.outputs {
            w.0.extend_from_slice(&o.to_bytes());
        }
        if let Some(receipt) = &self.receipt {
            w.0.extend_from_slice(&receipt.to_bytes());
        }
        w.finish()
    }

    /// A slate from its bytes; `None` if they are not one.
    pub fn from_bytes(bytes: &[u8]) -> Option<Slate> {
        let mut r = Reader(bytes);
        if r.take(8)? != SLATE_MAGIC {
            return None;
        }
        let id: [u8; 32] = r.take(32)?.try_into().ok()?;
        let stage = r.take(1)?[0];
        let amount = r.u64()?;
        let fee = r.u64()?;
        let change = r.u32()?;
        let sender = r.digest()?;
        let noted = r.take(1)?[0] as usize;
        let note = r.take(noted)?.to_vec();
        let n = r.len(PublicKey::SIZE + 8)?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let pk = PublicKey::from_bytes(r.take(PublicKey::SIZE)?).ok()?;
            inputs.push((pk, r.u64()?));
        }
        let n = r.len(OUTPUT_SIZE)?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            outputs.push(Output::from_bytes(r.take(OUTPUT_SIZE)?).ok()?);
        }
        if (change as usize) > outputs.len() || !(1..=2).contains(&stage) {
            return None;
        }
        // (Answered, it carries a receipt; not yet answered, none.)
        let receipt = match stage {
            2 => Some(crate::proofs::Receipt::from_bytes(r.take(crate::proofs::Receipt::SIZE)?)?),
            _ => None,
        };
        r.is_empty().then_some(Slate { id, stage, amount, fee, sender, note, receipt, inputs, outputs, change })
    }

    /// The slate as text to paste or keep in a file: base64 between
    /// markers, 64 characters a line.
    pub fn to_text(&self) -> String {
        let b64 = base64_encode(&self.to_bytes());
        let mut out = format!("-----BEGIN {SLATE_MARKER}-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str(&format!("-----END {SLATE_MARKER}-----\n"));
        out
    }

    /// A slate from text holding one between its markers, whatever
    /// surrounds it.
    pub fn from_text(text: &str) -> Option<Slate> {
        let begin = format!("-----BEGIN {SLATE_MARKER}-----");
        let end = format!("-----END {SLATE_MARKER}-----");
        let body = &text[text.find(&begin)? + begin.len()..];
        let b64: String = body[..body.find(&end)?].chars().filter(|c| !c.is_whitespace()).collect();
        Slate::from_bytes(&base64_decode(&b64)?)
    }

    /// Whether `text` holds a slate's end marker: a paste is complete.
    pub fn text_ends(text: &str) -> bool {
        text.contains(&format!("-----END {SLATE_MARKER}-----"))
    }

    /// The unsigned transaction a stage-2 slate describes.
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction::new(self.inputs.clone(), self.outputs.clone())
    }

    pub fn id_hex(&self) -> String {
        hex(&self.id)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64, with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let v = chunk.iter().enumerate().fold(0u32, |v, (i, b)| v | (*b as u32) << (16 - 8 * i));
        for k in 0..4 {
            match k <= chunk.len() {
                true => out.push(B64[(v >> (18 - 6 * k)) as usize & 63] as char),
                false => out.push('='),
            }
        }
    }
    out
}

/// What [`base64_encode`] encoded; `None` for anything else.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (at, chunk) in bytes.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && at + 1 != bytes.len() / 4) {
            return None;
        }
        let mut v = 0u32;
        for (k, c) in chunk.iter().enumerate() {
            let six = match k < 4 - pad {
                true => B64.iter().position(|b| b == c)? as u32,
                false => 0,
            };
            v |= six << (18 - 6 * k);
        }
        // (What padding stands for is nothing: bits there are no encoding.)
        if pad > 0 && v & ((1 << (8 * pad)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&v.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

/// What the sender keeps about a pending slate: its inputs and change, by
/// commitment, and the amount and fee it offered, which the answered
/// slate must still show.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    inputs: Vec<Commitment>,
    change: Option<Commitment>,
    amount: u64,
    fee: u64,
    /// The secret this payment is this wallet's by: its hash is what
    /// the slate, and the receipt, name whoever pays by.
    secret: [u8; 32],
    /// What the slate said the payment is for.
    note: Vec<u8>,
}

/// A payment made, or coins burned: the transaction, and what proves
/// it to whoever has the chain's headers ([`crate::proofs::Proof`]),
/// once the block that made its output is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub txid: Commitment,
    pub fee: u64,
    pub created: u64,
    /// Whether the proof's path is of the block the output is in: the
    /// proof holds. Until then its height, position and path are
    /// nothing.
    pub proven: bool,
    /// Where a block made the output, once one has: its height, and
    /// the output's position.
    pub landed: Option<(u32, u64)>,
    pub proof: crate::proofs::Proof,
}

impl Payment {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.digest(&self.txid);
        w.u64(self.fee);
        w.u64(self.created);
        w.0.push(self.proven as u8);
        w.0.push(self.landed.is_some() as u8);
        let (height, position) = self.landed.unwrap_or_default();
        w.u32(height);
        w.u64(position);
        w.0.extend_from_slice(&self.proof.to_bytes());
        w.finish()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Payment> {
        let mut r = Reader(bytes);
        let (txid, fee, created) = (r.digest()?, r.u64()?, r.u64()?);
        let (proven, landed) = (r.take(1)?[0] == 1, r.take(1)?[0] == 1);
        let at = (r.u32()?, r.u64()?);
        let proof = crate::proofs::Proof::from_bytes(r.0)?;
        Some(Payment { txid, fee, created, proven, landed: landed.then_some(at), proof })
    }
}

/// What the sender keeps about a finalized payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub txid: Commitment,
    pub inputs: Vec<Commitment>,
    pub fee: u64,
    pub size: usize,
    pub created: u64,
    /// The signed transaction, to send again.
    pub tx: Transaction,
}

fn write_commitments(w: &mut Writer, cs: &[Commitment]) {
    w.u32(cs.len() as u32);
    for c in cs {
        w.digest(c);
    }
}

fn read_commitments(r: &mut Reader) -> Option<Vec<Commitment>> {
    let n = r.len(32)?;
    (0..n).map(|_| r.digest()).collect()
}

impl Pending {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_commitments(&mut w, &self.inputs);
        w.0.push(self.change.is_some() as u8);
        if let Some(c) = &self.change {
            w.digest(c);
        }
        w.u64(self.amount);
        w.u64(self.fee);
        w.0.extend_from_slice(&self.secret);
        w.0.push(self.note.len() as u8);
        w.0.extend_from_slice(&self.note);
        w.finish()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Pending> {
        let mut r = Reader(bytes);
        let inputs = read_commitments(&mut r)?;
        let change = match r.take(1)?[0] {
            0 => None,
            1 => Some(r.digest()?),
            _ => return None,
        };
        let amount = r.u64()?;
        let fee = r.u64()?;
        // (One begun before slates said who pays: with no secret, and
        // not to be finalized as it is. Given up with `cancel`.)
        if r.is_empty() {
            return Some(Pending { inputs, change, amount, fee, secret: [0; 32], note: Vec::new() });
        }
        let secret = r.take(32)?.try_into().ok()?;
        let noted = r.take(1)?[0] as usize;
        let note = r.take(noted)?.to_vec();
        r.is_empty().then_some(Pending { inputs, change, amount, fee, secret, note })
    }
}

impl Sent {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_commitments(&mut w, &self.inputs);
        w.u64(self.fee);
        w.u64(self.size as u64);
        w.u64(self.created);
        w.0.extend_from_slice(&self.tx.to_bytes());
        w.finish()
    }

    fn from_bytes(txid: Commitment, bytes: &[u8]) -> Option<Sent> {
        let mut r = Reader(bytes);
        let inputs = read_commitments(&mut r)?;
        let fee = r.u64()?;
        let size = r.u64()? as usize;
        let created = r.u64()?;
        let tx = Transaction::from_bytes(r.0).ok()?;
        Some(Sent { txid, inputs, fee, size, created, tx })
    }
}

/// The fee a transaction of this wallet's pays: a total, or a rate the
/// total follows from once its inputs are chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fee {
    /// Base units in all.
    Total(u64),
    /// Base units a unit of the transaction's weight
    /// ([`crate::mempool::Weights`]), at least the floor.
    PerUnit(u64),
}

impl Fee {
    /// The fee of a transaction of `weight`.
    pub fn for_weight(self, weight: u64) -> u64 {
        match self {
            Fee::Total(f) => f,
            Fee::PerUnit(r) => r.saturating_mul(weight),
        }
    }

    /// A rate below the floor is refused before anything is chosen.
    fn check(self, size: u64) -> Result<()> {
        match self {
            Fee::PerUnit(r) if r < MIN_FEE_PER_UNIT => {
                Err(WalletError::FeeTooLow { min: Policy::MAINNET.min_fee_for(size) })
            }
            _ => Ok(()),
        }
    }

    fn is_total(self) -> bool {
        matches!(self, Fee::Total(_))
    }
}

/// `None`: the floor rate; `Some`: a total.
impl From<Option<u64>> for Fee {
    fn from(fee: Option<u64>) -> Fee {
        fee.map_or(Fee::PerUnit(MIN_FEE_PER_UNIT), Fee::Total)
    }
}

#[derive(Debug)]
pub enum WalletError {
    Io(io::Error),
    Phrase(bip39::PhraseError),
    Corrupt(&'static str),
    /// Not enough confirmed, unreserved funds.
    Insufficient {
        have: u128,
        need: u128,
    },
    /// The slate is malformed or not at the expected stage.
    BadSlate(&'static str),
    /// No pending slate or sent payment with that id.
    Unknown,
    /// An output has made all the signatures its leaves allow.
    Exhausted,
    /// The fee is below what the pool takes.
    FeeTooLow {
        min: u64,
    },
    /// The wallet's file is of a format not known here.
    OldFormat,
    /// The wallet's password is wrong (or none was given for a locked
    /// wallet).
    WrongPassword,
    /// Restoring over an existing wallet.
    Exists,
    /// A name operation the wallet cannot make.
    Name(String),
    /// An input has not been seen in a block yet.
    Unconfirmed,
    /// The transaction's inputs are no longer unspent on chain: it (or
    /// another spend of them) has landed.
    Landed,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::Io(e) => write!(f, "the wallet's file: {e}"),
            WalletError::Phrase(e) => write!(f, "{e}"),
            WalletError::Corrupt(w) => write!(f, "corrupt wallet record: {w}"),
            WalletError::Insufficient { have, need } => write!(f, "insufficient funds: have {have}, need {need}"),
            WalletError::BadSlate(w) => write!(f, "bad slate: {w}"),
            WalletError::Unknown => f.write_str("no pending slate or sent payment with that id"),
            WalletError::Exhausted => f.write_str("an input has no signatures left"),
            WalletError::FeeTooLow { min } => write!(f, "the fee must be at least {min} base units"),
            WalletError::OldFormat => f.write_str("the wallet's file is of a format not known here"),
            WalletError::WrongPassword => f.write_str("wrong wallet password"),
            WalletError::Exists => f.write_str("a wallet already exists there"),
            WalletError::Name(m) => f.write_str(m),
            WalletError::Unconfirmed => f.write_str("an input is not confirmed yet"),
            WalletError::Landed => f.write_str("the inputs are already spent on chain"),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<io::Error> for WalletError {
    fn from(e: io::Error) -> Self {
        WalletError::Io(e)
    }
}

impl From<bip39::PhraseError> for WalletError {
    fn from(e: bip39::PhraseError) -> Self {
        WalletError::Phrase(e)
    }
}

pub type Result<T> = core::result::Result<T, WalletError>;

/// Totals of a wallet's outputs by status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// Unspent and on chain: spendable.
    pub confirmed: u128,
    /// Unspent and not yet on chain: incoming (change, rewards).
    pub pending: u128,
    /// Outputs this wallet added to others' slates, not yet on chain: a
    /// slate can claim anything until its transaction lands, so these are
    /// not counted as pending.
    pub unverified: u128,
    /// Picked as inputs of a pending slate, not yet signed.
    pub reserved: u128,
    /// As much of what is confirmed as has been in the chain for as
    /// many blocks as this wallet waits before it spends
    /// ([`Wallet::set_min_confirmations`]).
    pub spendable: u128,
    /// Signed away by a payment that has not confirmed: about to leave.
    pub locked: u128,
    /// Unspent, once in the chain and no longer: the block that made
    /// them was undone. They are not counted as coming; they are found
    /// again if a block makes them again.
    pub lost: u128,
}

/// What looking at the chain again changed in what the wallet keeps
/// ([`Wallet::reconcile`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Payments sent that were in a block and are not any more: what
    /// they spend is unspent again.
    pub undone: usize,
    /// Payments sent whose block is deep enough to rely on: done with.
    pub settled: usize,
    /// Outputs that were in the chain and are not any more.
    pub lost: usize,
    /// Outputs lost that are in the chain again.
    pub returned: usize,
    /// Outputs lost for so long that they are forgotten.
    pub forgotten: usize,
}

/// A signed transaction and, for every input whose last signature it was,
/// that input's commitment.
#[derive(Clone, Debug)]
pub struct Signed {
    pub tx: Transaction,
    pub last_signatures: Vec<Commitment>,
}

/// What the wallet asks of the chain's state: the unspent outputs.
pub trait Unspent {
    /// Whether the output at `position` is unspent, and of `commitment`.
    fn holds(&self, position: u64, commitment: &Commitment) -> io::Result<bool>;
    /// How many blocks the output at `position` has been in, the one
    /// that made it counted: none, unless it is unspent and of
    /// `commitment`.
    fn confirmations(&self, position: u64, commitment: &Commitment) -> io::Result<Option<u32>>;
    /// Calls `f` with every unspent output: its position, commitment,
    /// memo and amount.
    fn each(&self, f: &mut dyn FnMut(u64, &Commitment, &Memo, u64)) -> io::Result<()>;
}

/// Blocks an output is to have been in before this wallet spends it,
/// unless told otherwise: an output of a block that is undone is no
/// output, and what spent it no payment, so what is spent is what the
/// chain is unlikely to go back on. A rule of the wallet's, not of the
/// chain's, which lets an output be spent in the block after its own.
pub const MIN_CONFIRMATIONS: u32 = 6;

impl<B: Backend + 'static> Unspent for Snapshot<'_, B> {
    fn holds(&self, position: u64, commitment: &Commitment) -> io::Result<bool> {
        Ok(self.output(position)?.is_some_and(|(r, live)| live && r.commitment == *commitment))
    }

    fn confirmations(&self, position: u64, commitment: &Commitment) -> io::Result<Option<u32>> {
        let found = self.output(position)?.filter(|(r, live)| *live && r.commitment == *commitment);
        Ok(found.map(|(r, _)| (self.tip().0 + 1).saturating_sub(r.height)))
    }

    fn each(&self, f: &mut dyn FnMut(u64, &Commitment, &Memo, u64)) -> io::Result<()> {
        self.outputs().for_each(self.pages(), &mut |position, r, live| {
            if live {
                f(position, &r.commitment, &r.memo, r.amount)
            }
        })
    }
}

/// `N` bytes from the system's random source.
pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    crate::random::fill(&mut out)?;
    Ok(out)
}

/// The master secret of a BIP39 seed.
fn master_of(seed: &[u8; 64]) -> crate::hash::Digest {
    hash_domain(DOM_MASTER, seed)
}

/// PBKDF2 rounds for a wallet password's key: about a quarter of a second on
/// a desktop core. The count is stored with the record, so it can change.
const PASSWORD_ROUNDS: u32 = 200_000;

/// What [`Wallet::open_with`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// A password for a new wallet; empty for none.
    New,
    /// The password of an existing, locked wallet.
    Unlock,
}

/// The wallet's secret: the phrase's entropy and its BIP39 seed (which
/// also depends on the BIP39 passphrase), stored as one record:
///
/// ```text
/// 0 | entropy (16) | seed (64)                                 no password
/// 1 | rounds (4) | salt (16) | nonce (12) | sealed entropy|seed (80 + 16)
/// ```
///
/// Locked under ChaCha20-Poly1305 with a key PBKDF2-HMAC-SHA512 makes from
/// the password; the header is the associated data.
struct Secret {
    entropy: [u8; bip39::ENTROPY_BYTES],
    seed: [u8; 64],
}

impl Secret {
    fn plain(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(bip39::ENTROPY_BYTES + 64);
        out.extend_from_slice(&self.entropy);
        out.extend_from_slice(&self.seed);
        out
    }

    fn from_plain(b: &[u8]) -> Option<Secret> {
        if b.len() != bip39::ENTROPY_BYTES + 64 {
            return None;
        }
        Some(Secret {
            entropy: b[..bip39::ENTROPY_BYTES].try_into().ok()?,
            seed: b[bip39::ENTROPY_BYTES..].try_into().ok()?,
        })
    }

    fn key(password: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
        let mut s = b"tabminer wallet".to_vec();
        s.extend_from_slice(salt);
        bip39::pbkdf2_hmac_sha512(password.as_bytes(), &s, rounds)[..32].try_into().unwrap()
    }

    /// The record, locked under `password` unless it is empty.
    fn seal(&self, password: &str) -> io::Result<Vec<u8>> {
        if password.is_empty() {
            let mut out = vec![0];
            out.extend_from_slice(&self.plain());
            return Ok(out);
        }
        let salt = random_bytes::<16>()?;
        let nonce = random_bytes::<{ chacha20poly1305::NONCE_LEN }>()?;
        let mut out = vec![1];
        out.extend_from_slice(&PASSWORD_ROUNDS.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        let key = Self::key(password, &salt, PASSWORD_ROUNDS);
        let sealed = chacha20poly1305::seal(&key, &nonce, &out, &self.plain());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Whether a record is locked.
    fn locked(b: &[u8]) -> bool {
        b.first() == Some(&1)
    }

    /// Opens a record; a plain one ignores the password.
    fn open(b: &[u8], password: &str) -> Result<Secret> {
        const HEADER: usize = 1 + 4 + 16 + chacha20poly1305::NONCE_LEN;
        match b.first() {
            Some(0) => Secret::from_plain(&b[1..]).ok_or(WalletError::Corrupt("secret")),
            Some(1) if b.len() > HEADER => {
                let rounds = u32::from_le_bytes(b[1..5].try_into().unwrap());
                let salt = &b[5..21];
                let nonce: [u8; chacha20poly1305::NONCE_LEN] = b[21..HEADER].try_into().unwrap();
                let key = Self::key(password, salt, rounds);
                let plain = chacha20poly1305::open(&key, &nonce, &b[..HEADER], &b[HEADER..])
                    .ok_or(WalletError::WrongPassword)?;
                Secret::from_plain(&plain).ok_or(WalletError::Corrupt("secret"))
            }
            _ => Err(WalletError::Corrupt("secret")),
        }
    }
}

/// Everything the wallet keeps, as it is in memory: read whole when the
/// wallet is opened, and written, the tables a change touches, when it
/// changes.
#[derive(Clone, Default)]
struct Tables {
    /// The secret's record ([`Secret`]).
    secret: Vec<u8>,
    /// Whether a restore waits for its first scan.
    scan_pending: bool,
    /// Whom each pending slate was sent to ([`Wallet::sent_to`]).
    sent_to: BTreeMap<Id, Id>,
    /// The names given out under names this wallet holds, and the full
    /// names it is ([`Wallet::give_name`], [`Wallet::hold_name`]).
    names_given: BTreeMap<Id, Given>,
    names_held: BTreeMap<Id, Vec<u8>>,
    /// The names this wallet signs for by their holders' word.
    names_signed: BTreeMap<Id, Vec<u8>>,
    /// The payments made and coins burned, and what each slate that
    /// paid this wallet said.
    payments: BTreeMap<Id, Payment>,
    notes: BTreeMap<Id, Vec<u8>>,
    /// Which of the wallet's addresses it is at: the first, for a new
    /// wallet; one drawn at random, for a wallet made again from its
    /// words, so that it is at an address never used before.
    address: u64,
    /// Height and id of the block up to which [`Wallet::locate`] has
    /// been given the outputs.
    synced: Option<(u32, [u8; 32])>,
    outputs: BTreeMap<Id, Owned>,
    /// Pending slates, by id.
    slates: BTreeMap<Id, Pending>,
    /// Payments finalized, by transaction id.
    sent: BTreeMap<Id, Sent>,
    /// Rewards of blocks this wallet made, until settled: by commitment,
    /// the block's height and its id (zero until it is found).
    rewards: BTreeMap<Id, (u32, [u8; 32])>,
    /// Outputs this wallet added to others' slates, until they land.
    answered: BTreeSet<Id>,
    /// Payments sent whose inputs the chain no longer holds: by
    /// transaction id, the chain's height when that was first seen.
    landed: BTreeMap<Id, u32>,
    /// Outputs that were in the chain and are not: by commitment, the
    /// chain's height when that was first seen.
    lost: BTreeMap<Id, u32>,
    /// The blocks last looked at, the newest last: each one's height,
    /// its id, and the position the next output after it takes. Where
    /// the chain has gone over to another branch, the newest of these
    /// that is still of the chain is where the branches part.
    recent: std::collections::VecDeque<(u32, [u8; 32], u64)>,
    /// Commits of names awaiting their reveal, by commit.
    commits: BTreeMap<Id, names::PendingCommit>,
    /// The names the wallet holds or awaits, by name.
    names: BTreeMap<Vec<u8>, names::OwnedName>,
    /// What the wallet has done and been paid, a row each, numbered
    /// from one ([`list`]).
    list: Vec<list::Row>,
    /// Outputs a block was just seen to make, and its height: for the
    /// list's rows, and not kept (taken up when the list is next
    /// brought up to date, which is at once).
    located: Vec<(Id, u32)>,
}

/// A table of records each named by 32 bytes.
fn put_entries<'a>(entries: impl Iterator<Item = (&'a Id, Vec<u8>)>) -> Vec<u8> {
    let mut w = Writer::default();
    for (id, bytes) in entries {
        w.0.extend_from_slice(id);
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.finish()
}

fn get_entries(bytes: &[u8]) -> Option<Vec<(Id, &[u8])>> {
    let mut r = Reader(bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        let id: Id = r.take(32)?.try_into().ok()?;
        let n = r.u32()? as usize;
        out.push((id, r.take(n)?));
    }
    Some(out)
}

impl Tables {
    fn encode(&self, table: usize) -> Vec<u8> {
        match table {
            T_META => {
                let mut w = Writer::default();
                w.0.extend_from_slice(&[FORMAT, self.scan_pending as u8, self.synced.is_some() as u8]);
                let (height, id) = self.synced.unwrap_or((0, [0; 32]));
                w.u32(height);
                w.0.extend_from_slice(&id);
                w.0.extend_from_slice(&self.secret);
                w.finish()
            }
            T_OUTPUTS => put_entries(self.outputs.iter().map(|(id, o)| (id, o.to_bytes()))),
            T_SLATES => put_entries(self.slates.iter().map(|(id, p)| (id, p.to_bytes()))),
            T_SENT => put_entries(self.sent.iter().map(|(id, s)| (id, s.to_bytes()))),
            T_REWARDS => put_entries(self.rewards.iter().map(|(id, (height, block))| {
                let mut b = height.to_le_bytes().to_vec();
                b.extend_from_slice(block);
                (id, b)
            })),
            T_ANSWERED => put_entries(self.answered.iter().map(|id| (id, Vec::new()))),
            T_LANDED => put_entries(self.landed.iter().map(|(id, height)| (id, height.to_le_bytes().to_vec()))),
            T_LOST => put_entries(self.lost.iter().map(|(id, height)| (id, height.to_le_bytes().to_vec()))),
            T_COMMITS => put_entries(self.commits.iter().map(|(id, c)| (id, c.to_bytes()))),
            T_NAMES => names::put_names(self.names.values()),
            T_SENT_TO => put_entries(self.sent_to.iter().map(|(slate, whom)| (slate, whom.to_vec()))),
            T_NAMES_GIVEN => put_entries(self.names_given.iter().map(|(at, given)| (at, given.to_bytes()))),
            T_NAMES_HELD => put_entries(self.names_held.iter().map(|(at, bundle)| (at, bundle.clone()))),
            T_NAMES_SIGNED => put_entries(self.names_signed.iter().map(|(at, word)| (at, word.clone()))),
            T_PAYMENTS => put_entries(self.payments.iter().map(|(id, payment)| (id, payment.to_bytes()))),
            T_NOTES => put_entries(self.notes.iter().map(|(id, note)| (id, note.clone()))),
            T_LIST => list::encode(&self.list),
            T_ADDRESS => match self.address {
                0 => Vec::new(),
                at => at.to_le_bytes().to_vec(),
            },
            T_RECENT => put_entries(self.recent.iter().map(|(height, id, next)| {
                let mut b = height.to_le_bytes().to_vec();
                b.extend_from_slice(&next.to_le_bytes());
                (id, b)
            })),
            _ => unreachable!("no such table"),
        }
    }

    fn read<B: Backend>(records: &Records<B>) -> Result<Tables> {
        let mut t = Tables::default();
        let meta = records.read(T_META)?;
        if !meta.is_empty() {
            if meta.len() < 39 || meta[0] != FORMAT || meta[1] > 1 || meta[2] > 1 {
                return Err(WalletError::OldFormat);
            }
            t.scan_pending = meta[1] == 1;
            let height = u32::from_le_bytes(meta[3..7].try_into().unwrap());
            t.synced = (meta[2] == 1).then_some((height, meta[7..39].try_into().unwrap()));
            t.secret = meta[39..].to_vec();
        }
        let table = |at: usize| records.read(at);
        t.address = match &table(T_ADDRESS)?[..] {
            [] => 0,
            at => u64::from_le_bytes(at.try_into().map_err(|_| WalletError::Corrupt("address counter"))?),
        };
        for (slate, whom) in get_entries(&table(T_SENT_TO)?).ok_or(WalletError::Corrupt("recipients"))? {
            t.sent_to.insert(slate, whom.try_into().map_err(|_| WalletError::Corrupt("recipient"))?);
        }
        for (at, given) in get_entries(&table(T_NAMES_GIVEN)?).ok_or(WalletError::Corrupt("names given"))? {
            t.names_given.insert(at, Given::from_bytes(given).ok_or(WalletError::Corrupt("name given"))?);
        }
        for (id, payment) in get_entries(&table(T_PAYMENTS)?).ok_or(WalletError::Corrupt("payments"))? {
            t.payments.insert(id, Payment::from_bytes(payment).ok_or(WalletError::Corrupt("payment"))?);
        }
        for (id, note) in get_entries(&table(T_NOTES)?).ok_or(WalletError::Corrupt("notes"))? {
            t.notes.insert(id, note.to_vec());
        }
        t.list = list::decode(&table(T_LIST)?).ok_or(WalletError::Corrupt("list"))?;
        for (at, word) in get_entries(&table(T_NAMES_SIGNED)?).ok_or(WalletError::Corrupt("names signed for"))? {
            t.names_signed.insert(at, word.to_vec());
        }
        for (at, held) in get_entries(&table(T_NAMES_HELD)?).ok_or(WalletError::Corrupt("names held"))? {
            if held.len() < 16 {
                return Err(WalletError::Corrupt("name held"));
            }
            t.names_held.insert(at, held.to_vec());
        }
        let commitment = |id: &Id| digest_from_bytes(id);
        for (id, b) in get_entries(&table(T_OUTPUTS)?).ok_or(WalletError::Corrupt("outputs"))? {
            let o = commitment(&id).and_then(|c| Owned::from_bytes(c, b)).ok_or(WalletError::Corrupt("output"))?;
            t.outputs.insert(id, o);
        }
        for (id, b) in get_entries(&table(T_SLATES)?).ok_or(WalletError::Corrupt("slates"))? {
            t.slates.insert(id, Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?);
        }
        for (id, b) in get_entries(&table(T_SENT)?).ok_or(WalletError::Corrupt("sent"))? {
            let s = commitment(&id).and_then(|c| Sent::from_bytes(c, b)).ok_or(WalletError::Corrupt("sent payment"))?;
            t.sent.insert(id, s);
        }
        for (id, b) in get_entries(&table(T_REWARDS)?).ok_or(WalletError::Corrupt("rewards"))? {
            if b.len() != 36 {
                return Err(WalletError::Corrupt("reward"));
            }
            t.rewards.insert(id, (u32::from_le_bytes(b[..4].try_into().unwrap()), b[4..].try_into().unwrap()));
        }
        for (id, _) in get_entries(&table(T_ANSWERED)?).ok_or(WalletError::Corrupt("answered"))? {
            t.answered.insert(id);
        }
        let height = |b: &[u8]| Some(u32::from_le_bytes(b.try_into().ok()?));
        for (id, b) in get_entries(&table(T_LANDED)?).ok_or(WalletError::Corrupt("landed"))? {
            t.landed.insert(id, height(b).ok_or(WalletError::Corrupt("landed payment"))?);
        }
        for (id, b) in get_entries(&table(T_LOST)?).ok_or(WalletError::Corrupt("lost"))? {
            t.lost.insert(id, height(b).ok_or(WalletError::Corrupt("lost output"))?);
        }
        for (id, b) in get_entries(&table(T_COMMITS)?).ok_or(WalletError::Corrupt("commits"))? {
            let c = commitment(&id).and_then(|c| names::PendingCommit::from_bytes(c, b));
            t.commits.insert(id, c.ok_or(WalletError::Corrupt("commit"))?);
        }
        for name in names::get_names(&table(T_NAMES)?).ok_or(WalletError::Corrupt("names"))? {
            t.names.insert(name.name.clone(), name);
        }
        for (id, b) in get_entries(&table(T_RECENT)?).ok_or(WalletError::Corrupt("recent"))? {
            if b.len() != 12 {
                return Err(WalletError::Corrupt("recent block"));
            }
            let next = u64::from_le_bytes(b[4..].try_into().unwrap());
            t.recent.push_back((u32::from_le_bytes(b[..4].try_into().unwrap()), id, next));
        }
        Ok(t)
    }
}

pub struct Wallet<B: Backend> {
    records: Records<B>,
    master: crate::hash::Digest,
    t: Tables,
    /// Blocks an output is to have been in before it is spent.
    min_confirmations: u32,
}

impl<B: Backend> Wallet<B> {
    /// Opens the wallet kept in `backend`, asking `ask` for its password
    /// if it is locked, or for a new one if there is no wallet yet and
    /// one is made, of a fresh phrase. Returns the wallet and, if it was
    /// just made, its phrase.
    pub fn open_with(backend: B, ask: &mut dyn FnMut(Ask) -> Result<String>) -> Result<(Wallet<B>, Option<String>)> {
        let mut records = Records::open(backend)?;
        let mut t = Tables::read(&records)?;
        let (secret, created) = match t.secret.is_empty() {
            false => {
                let password = if Secret::locked(&t.secret) { ask(Ask::Unlock)? } else { String::new() };
                (Secret::open(&t.secret, &password)?, None)
            }
            true => {
                let entropy = random_bytes::<{ bip39::ENTROPY_BYTES }>()?;
                let phrase = bip39::phrase(&entropy);
                let secret = Secret { entropy, seed: bip39::seed(&phrase, "")? };
                t.secret = secret.seal(&ask(Ask::New)?)?;
                records.write(&[(T_META, &t.encode(T_META))])?;
                (secret, Some(phrase))
            }
        };
        Ok((Wallet { records, master: master_of(&secret.seed), t, min_confirmations: MIN_CONFIRMATIONS }, created))
    }

    /// [`Wallet::open_with`], with no password asked for or given.
    pub fn open(backend: B) -> Result<(Wallet<B>, Option<String>)> {
        Self::open_with(backend, &mut |_| Ok(String::new()))
    }

    /// Makes a wallet in `backend`, which holds none, from a phrase and
    /// BIP39 passphrase, locked under `password` unless it is empty; the
    /// outputs come back with [`Wallet::scan`] once the chain is here.
    pub fn restore(backend: B, phrase: &str, passphrase: &str, password: &str) -> Result<Wallet<B>> {
        let secret = Secret { entropy: bip39::entropy(phrase)?, seed: bip39::seed(phrase, passphrase)? };
        let mut records = Records::open(backend)?;
        let mut t = Tables::read(&records)?;
        if !t.secret.is_empty() || !t.outputs.is_empty() {
            return Err(WalletError::Exists);
        }
        t.secret = secret.seal(password)?;
        t.scan_pending = true;
        // An address of its own: what the wallet that was lost was
        // reached at is not taken up again by this one, which cannot
        // know what was sent there meanwhile or who else holds its
        // words.
        let mut drawn = [0u8; 8];
        crate::random::fill(&mut drawn)?;
        t.address = (u64::from_le_bytes(drawn) >> 4).max(1);
        records.write(&[(T_META, &t.encode(T_META)), (T_ADDRESS, &t.encode(T_ADDRESS))])?;
        Ok(Wallet { records, master: master_of(&secret.seed), t, min_confirmations: MIN_CONFIRMATIONS })
    }

    /// Puts `t` in place of what the wallet keeps: the tables `dirty` on
    /// disk first, all at once, and only then in memory.
    fn commit(&mut self, mut t: Tables, dirty: &[usize]) -> Result<()> {
        // (The list of what the wallet has done follows from the rest:
        // brought up to it with every change, and kept with it.)
        let listed = list::relist(&mut t);
        let dirty: Vec<usize> = dirty.iter().copied().chain(listed.then_some(T_LIST)).collect();
        let encoded: Vec<(usize, Vec<u8>)> = dirty.iter().map(|table| (*table, t.encode(*table))).collect();
        let changes: Vec<(usize, &[u8])> = encoded.iter().map(|(table, bytes)| (*table, &bytes[..])).collect();
        self.records.write(&changes)?;
        self.t = t;
        Ok(())
    }

    /// Has the wallet spend only outputs that have been in the chain for
    /// `blocks` blocks, the one that made each counted: one at the
    /// least ([`MIN_CONFIRMATIONS`] unless this is said).
    pub fn set_min_confirmations(&mut self, blocks: u32) {
        self.min_confirmations = blocks.max(1);
    }

    /// Blocks an output is to have been in before the wallet spends it.
    pub fn min_confirmations(&self) -> u32 {
        self.min_confirmations
    }

    /// Whether the chain holds `o` where the wallet last saw it, and
    /// has for as many blocks as the wallet waits before it spends.
    fn ripe(&self, o: &Owned, chain: &impl Unspent) -> Result<bool> {
        match o.position {
            Some(p) => Ok(chain.confirmations(p, &o.commitment)?.is_some_and(|n| n >= self.min_confirmations)),
            None => Ok(false),
        }
    }

    /// Whether a restore is waiting for its first scan.
    pub fn scan_pending(&self) -> bool {
        self.t.scan_pending
    }

    /// Marks the restore's first scan done.
    pub fn clear_scan_pending(&mut self) -> Result<()> {
        let mut t = self.t.clone();
        t.scan_pending = false;
        self.commit(t, &[T_META])
    }

    /// Whether the wallet's secret is locked under a password.
    pub fn locked(&self) -> bool {
        Secret::locked(&self.t.secret)
    }

    /// The wallet's 12-word phrase; `password` is checked if the wallet is
    /// locked.
    pub fn phrase(&self, password: &str) -> Result<String> {
        Ok(bip39::phrase(&Secret::open(&self.t.secret, password)?.entropy))
    }

    /// Locks the wallet's secret under `new` instead of `old` (either may
    /// be empty, for none).
    pub fn set_password(&mut self, old: &str, new: &str) -> Result<()> {
        let mut t = self.t.clone();
        t.secret = Secret::open(&self.t.secret, old)?.seal(new)?;
        self.commit(t, &[T_META])
    }

    /// The wallet's Dilithium (ML-DSA-65) key: what it is known by on
    /// the message layer, and signs what it says there with. Of the
    /// master key and the address counter, so the same words at the
    /// same counter are the same key.
    pub fn identity_key(&self) -> crate::mldsa::SecretKey {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.master);
        input[32..].copy_from_slice(&self.t.address.to_le_bytes());
        crate::mldsa::keygen(&hash_domain(DOM_IDENTITY, &input))
    }

    /// The wallet's id: the hash of its Dilithium key
    /// ([`crate::address::id_of`]).
    pub fn id(&self) -> crate::hash::Digest {
        crate::address::id_of(self.identity_key().public_key())
    }

    /// The wallet's address: its id as `tab1…`.
    pub fn address(&self) -> String {
        crate::address::encode(&self.id())
    }

    /// Which of its addresses the wallet is at.
    pub fn address_index(&self) -> u64 {
        self.t.address
    }

    fn with_master(&self, domain: u32, nonce: &Nonce) -> crate::hash::Digest {
        let mut input = [0u8; 32 + NONCE];
        input[..32].copy_from_slice(&self.master);
        input[32..].copy_from_slice(nonce);
        hash_domain(domain, &input)
    }

    /// The key of the output with nonce `nonce`, at its first leaf.
    pub fn key(&self, nonce: &Nonce) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_KEY, nonce));
        Key::generate(&seed)
    }

    /// The memo of the output with nonce `nonce`: the nonce, then a tag
    /// from the master key by which a scan tells this wallet's outputs
    /// from others'.
    fn memo(&self, nonce: &Nonce) -> Memo {
        let mut memo = EMPTY_MEMO;
        memo[..NONCE].copy_from_slice(nonce);
        let tag = self.with_master(DOM_TAG, nonce);
        memo[NONCE..].copy_from_slice(&tag[..crate::output::MEMO_LEN - NONCE]);
        memo
    }

    /// The nonce a memo holds, if its tag is this wallet's.
    fn open_memo(&self, memo: &Memo) -> Option<Nonce> {
        let nonce: Nonce = memo[..NONCE].try_into().unwrap();
        (memo[NONCE..] == self.with_master(DOM_TAG, &nonce)[..crate::output::MEMO_LEN - NONCE]).then_some(nonce)
    }

    /// The output of nonce `nonce` paying `amount` to this wallet.
    fn output_of(&self, nonce: &Nonce, amount: u64) -> Output {
        let pk = self.key(nonce).public_key();
        Output::with_memo(&pubkey_hash(&pk), amount, self.memo(nonce))
    }

    /// A fresh output paying `amount` to this wallet, with its memo,
    /// recorded in `t` as unspent, made at `now`.
    fn receive_in(&self, t: &mut Tables, amount: u64, now: u64) -> Result<Output> {
        let nonce = random_bytes::<NONCE>()?;
        let out = self.output_of(&nonce, amount);
        let o = Owned {
            commitment: out.commitment,
            nonce,
            amount,
            state: State::Unspent,
            created: now,
            recovered: false,
            start: 0,
            used: 0,
            position: None,
        };
        t.outputs.insert(digest_to_bytes(&out.commitment), o);
        Ok(out)
    }

    /// A fresh output paying `amount` to this wallet, with its memo,
    /// recorded as unspent (and unconfirmed until the chain holds it).
    pub fn receive(&mut self, amount: u64, now: u64) -> Result<Output> {
        let mut t = self.t.clone();
        let out = self.receive_in(&mut t, amount, now)?;
        self.commit(t, &[T_OUTPUTS])?;
        Ok(out)
    }

    /// The record of an output, by commitment.
    pub fn owned(&self, c: &Commitment) -> Option<Owned> {
        self.t.outputs.get(&digest_to_bytes(c)).copied()
    }

    /// Every recorded output, oldest first.
    pub fn outputs(&self) -> Vec<Owned> {
        let mut out: Vec<Owned> = self.t.outputs.values().copied().collect();
        out.sort_by_key(|o| (o.created, digest_to_bytes(&o.commitment)));
        out
    }

    /// Whether the chain's state holds `o` where the wallet last saw it.
    pub fn held(&self, o: &Owned, chain: &impl Unspent) -> Result<bool> {
        match o.position {
            Some(p) => Ok(chain.holds(p, &o.commitment)?),
            None => Ok(false),
        }
    }

    /// Height and id of the block up to which [`Wallet::locate`] has been
    /// given the outputs, if any.
    pub fn synced(&self) -> Option<(u32, [u8; 32])> {
        self.t.synced
    }

    /// Records the positions of this wallet's outputs among `outputs`,
    /// the commitments of the outputs a block made from position `first`
    /// on, and that every block up to that one (of this height and id,
    /// the next output after it taking the position `end`) has been
    /// looked at. Returns how many were this wallet's.
    pub fn locate(
        &mut self,
        first: u64,
        outputs: &[Commitment],
        height: u32,
        block: &[u8; 32],
        end: u64,
    ) -> Result<usize> {
        let mut t = self.t.clone();
        let (mut found, mut paid) = (0, 0);
        for (i, c) in outputs.iter().enumerate() {
            let id = digest_to_bytes(c);
            if let Some(o) = t.outputs.get_mut(&id) {
                o.position = Some(first + i as u64);
                t.answered.remove(&id);
                t.located.push((id, height));
                found += 1;
            }
            // An output this wallet paid for, or burned: where it is,
            // for its proof. (Of a block other than it was in before,
            // if the chain went another way: proven again.)
            for payment in t.payments.values_mut().filter(|p| p.proof.output().commitment == *c) {
                let here = Some((height, first + i as u64));
                if payment.landed != here {
                    (payment.landed, payment.proven) = (here, false);
                    paid += 1;
                }
            }
        }
        t.synced = Some((height, *block));
        // (Blocks are looked at in order: what is remembered of this
        // height or above is of a branch gone from.)
        while t.recent.back().is_some_and(|(h, _, _)| *h >= height) {
            t.recent.pop_back();
        }
        t.recent.push_back((height, *block, end));
        while t.recent.len() > RECENT {
            t.recent.pop_front();
        }
        let mut dirty = vec![T_META, T_RECENT];
        if found > 0 {
            dirty.extend([T_OUTPUTS, T_ANSWERED]);
        }
        if paid > 0 {
            dirty.push(T_PAYMENTS);
        }
        self.commit(t, &dirty)?;
        Ok(found)
    }

    /// The blocks last looked at, the newest first: each one's height,
    /// its id, and the position the next output after it takes.
    pub fn recent(&self) -> impl Iterator<Item = &(u32, [u8; 32], u64)> {
        self.t.recent.iter().rev()
    }

    /// Forgets how far the outputs have been looked at: so that they
    /// are looked for again from `to`, or from nothing known.
    pub fn set_synced(&mut self, to: Option<(u32, [u8; 32])>) -> Result<()> {
        let mut t = self.t.clone();
        t.synced = to;
        t.recent.clear();
        self.commit(t, &[T_META, T_RECENT])
    }

    /// Unspent, unreserved outputs that can still sign and that the
    /// chain has held for as many blocks as the wallet waits, largest
    /// first.
    pub fn spendable(&self, chain: &impl Unspent) -> Result<Vec<Owned>> {
        let mut keep: Vec<Owned> = Vec::new();
        for o in self.outputs() {
            if o.state == State::Unspent && o.signatures_left() > 0 && self.ripe(&o, chain)? {
                keep.push(o);
            }
        }
        keep.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.created.cmp(&b.created)));
        Ok(keep)
    }

    /// Confirmed (unspent and held by the chain), pending (unspent, not
    /// yet there), unverified (added to another's slate, not yet there),
    /// reserved (in a pending slate) and locked (signed, still held)
    /// totals.
    pub fn balance(&self, chain: &impl Unspent) -> Result<Balance> {
        let mut b = Balance::default();
        for o in self.outputs() {
            let held = self.held(&o, chain)?;
            match (o.state, held) {
                (State::Unspent, true) => {
                    b.confirmed += o.amount as u128;
                    if self.ripe(&o, chain)? {
                        b.spendable += o.amount as u128;
                    }
                }
                (State::Unspent, false) if self.t.lost.contains_key(&digest_to_bytes(&o.commitment)) => {
                    b.lost += o.amount as u128
                }
                (State::Unspent, false) if self.t.answered.contains(&digest_to_bytes(&o.commitment)) => {
                    b.unverified += o.amount as u128
                }
                (State::Unspent, false) => b.pending += o.amount as u128,
                (State::Reserved, _) => b.reserved += o.amount as u128,
                (State::Spent, true) => b.locked += o.amount as u128,
                (State::Spent, false) => {}
            }
        }
        Ok(b)
    }

    /// Forgets an unspent output that will never land, by commitment: the
    /// reward of a block the miner gave up. Returns whether a record went.
    pub fn forget(&mut self, c: &Commitment) -> Result<bool> {
        let id = digest_to_bytes(c);
        let mut t = self.t.clone();
        let gone = t.outputs.get(&id).is_some_and(|o| o.state == State::Unspent) && t.outputs.remove(&id).is_some();
        t.rewards.remove(&id);
        self.commit(t, &[T_OUTPUTS, T_REWARDS])?;
        Ok(gone)
    }

    /// A fresh output for the reward of a block being made at `height`,
    /// paying `amount`: recorded as unspent and as a reward, to be
    /// forgotten if the block never joins the chain ([`Wallet::forget`]).
    pub fn reward(&mut self, amount: u64, height: u32, now: u64) -> Result<Output> {
        let mut t = self.t.clone();
        let out = self.receive_in(&mut t, amount, now)?;
        t.rewards.insert(digest_to_bytes(&out.commitment), (height, [0; 32]));
        self.commit(t, &[T_OUTPUTS, T_REWARDS])?;
        Ok(out)
    }

    /// Notes the id of the block whose reward is `c`, once it is found
    /// and before it is handed over.
    pub fn reward_found(&mut self, c: &Commitment, block: &[u8; 32]) -> Result<()> {
        let mut t = self.t.clone();
        if let Some(reward) = t.rewards.get_mut(&digest_to_bytes(c)) {
            reward.1 = *block;
            self.commit(t, &[T_REWARDS])?;
        }
        Ok(())
    }

    /// The rewards not yet settled: each one's commitment, its block's
    /// height, and its block's id (zero if it was never found).
    pub fn rewards(&self) -> Vec<(Commitment, u32, [u8; 32])> {
        let known = |id: &Id| digest_from_bytes(id);
        self.t.rewards.iter().filter_map(|(id, (height, block))| Some((known(id)?, *height, *block))).collect()
    }

    /// Stops tracking the reward `c`: its block is deep in the chain.
    pub fn reward_settled(&mut self, c: &Commitment) -> Result<()> {
        let mut t = self.t.clone();
        if t.rewards.remove(&digest_to_bytes(c)).is_some() {
            self.commit(t, &[T_REWARDS])?;
        }
        Ok(())
    }

    /// Finds this wallet's unspent outputs in the chain's state by their
    /// memos and records the ones it does not know, as recovered, and
    /// where the known ones are. Returns how many were added and their
    /// total.
    pub fn scan(&mut self, chain: &impl Unspent, now: u64) -> Result<(usize, u128)> {
        self.memo_scan(chain, true, now)
    }

    /// Finds where this wallet's known outputs are in the chain's state
    /// by their memos: after a gap in [`Wallet::locate`] too long to fill
    /// from the blocks kept.
    pub fn relocate(&mut self, chain: &impl Unspent, now: u64) -> Result<()> {
        self.memo_scan(chain, false, now).map(|_| ())
    }

    fn memo_scan(&mut self, chain: &impl Unspent, add: bool, now: u64) -> Result<(usize, u128)> {
        let mut t = self.t.clone();
        let (mut found, mut total) = (0usize, 0u128);
        let mut failed: Option<io::Error> = None;
        // A record at a time: the set may be far larger than memory.
        chain.each(&mut |position, commitment, memo, amount| {
            let Some(nonce) = self.open_memo(memo) else { return };
            let pk = self.key(&nonce).public_key();
            if key_commitment(&pubkey_hash(&pk), amount) != *commitment {
                return;
            }
            let id = digest_to_bytes(commitment);
            match t.outputs.get_mut(&id) {
                Some(o) => o.position = Some(position),
                None if add => {
                    let start = match random_bytes::<1>() {
                        Ok(b) => b[0] % LEAVES_PER_HALF as u8,
                        Err(e) => {
                            failed.get_or_insert(e);
                            return;
                        }
                    };
                    let o = Owned {
                        commitment: *commitment,
                        nonce,
                        amount,
                        state: State::Unspent,
                        created: now,
                        recovered: true,
                        start,
                        used: 0,
                        position: Some(position),
                    };
                    t.outputs.insert(id, o);
                    found += 1;
                    total += amount as u128;
                }
                None => {}
            }
        })?;
        if let Some(e) = failed {
            return Err(e.into());
        }
        self.commit(t, &[T_OUTPUTS])?;
        Ok((found, total))
    }

    /// The key of `c` at its next leaf, that leaf marked used in `t`.
    /// Also whether this is the output's last signature.
    fn signing_key(&self, t: &mut Tables, c: &Commitment) -> Result<(Key, bool)> {
        let o = t.outputs.get_mut(&digest_to_bytes(c)).ok_or(WalletError::Corrupt("missing output"))?;
        if u32::from(o.used) >= LEAVES_PER_HALF {
            return Err(WalletError::Exhausted);
        }
        let base = if o.recovered { LEAVES_PER_HALF } else { 0 };
        let leaf = base + (u32::from(o.start) + u32::from(o.used)) % LEAVES_PER_HALF;
        o.used += 1;
        let last = u32::from(o.used) == LEAVES_PER_HALF;
        let mut key = self.key(&o.nonce);
        key.set_next_index(u64::from(leaf));
        Ok((key, last))
    }

    /// Signs `unsigned`, whose inputs must be the wallet's outputs
    /// `inputs` in order, gives each input its output's position, and
    /// marks them spent, all in `t`: the leaves used, the spent marks
    /// and whatever the caller records about the payment are written
    /// together, before the transaction leaves the wallet.
    fn sign(&self, t: &mut Tables, unsigned: UnsignedTransaction, inputs: &[Commitment]) -> Result<Signed> {
        let record = |t: &Tables, c: &Commitment| t.outputs.get(&digest_to_bytes(c)).copied();
        for c in inputs {
            if record(t, c).is_none_or(|o| o.signatures_left() == 0) {
                return Err(WalletError::Exhausted);
            }
        }
        let mut positions = Vec::with_capacity(inputs.len());
        for c in inputs {
            positions.push(record(t, c).and_then(|o| o.position).ok_or(WalletError::Unconfirmed)?);
        }
        let mut keys = Vec::with_capacity(inputs.len());
        let mut last_signatures = Vec::new();
        for c in inputs {
            let (key, last) = self.signing_key(t, c)?;
            if last {
                last_signatures.push(*c);
            }
            keys.push(key);
        }
        // (Where each output lies is signed: what is signed spends that
        // output, and no other of the same key and amount.)
        let mut unsigned = unsigned;
        if unsigned.positions.len() != positions.len() {
            return Err(WalletError::BadSlate("an input for each output spent"));
        }
        unsigned.positions = positions;
        let tx = unsigned.sign(|i, pk, msg| {
            let key = &mut keys[i];
            if key.public_key() != *pk {
                return Err(WalletError::BadSlate("input key is not the wallet's"));
            }
            key.sign(msg).map_err(|_| WalletError::Exhausted)
        })?;
        for c in inputs {
            if let Some(o) = t.outputs.get_mut(&digest_to_bytes(c)) {
                o.state = State::Spent;
            }
        }
        Ok(Signed { tx, last_signatures })
    }

    /// The smallest fee a payment from `inputs` inputs may carry, with a
    /// recipient output and change: what the pool asks.
    pub fn min_fee(inputs: usize) -> u64 {
        Policy::MAINNET.min_fee_for(Self::payment_weight(inputs))
    }

    /// The weight of a payment from `inputs` inputs, with a recipient
    /// output and change.
    pub fn payment_weight(inputs: usize) -> u64 {
        Weights::DEFAULT.of(inputs, 2)
    }

    /// Starts a payment of `amount` with `fee` (or the smallest the pool
    /// takes, if `None`): picks confirmed inputs largest first, reserves
    /// them, adds change to a fresh output, and returns the stage-1 slate
    /// for the recipient. Change below the dust limit goes to the fee.
    pub fn send(&mut self, amount: u64, fee: impl Into<Fee>, chain: &impl Unspent, now: u64) -> Result<Slate> {
        self.send_noted(amount, fee, &[], chain, now)
    }

    /// [`Wallet::send`], with what the payment is for: `note`, which
    /// the slate carries to the wallet that is paid, and its receipt
    /// is over.
    pub fn send_noted(
        &mut self,
        amount: u64,
        fee: impl Into<Fee>,
        note: &[u8],
        chain: &impl Unspent,
        now: u64,
    ) -> Result<Slate> {
        if note.len() > crate::proofs::MAX_NOTE {
            return Err(WalletError::BadSlate("the note is too long"));
        }
        if amount == 0 {
            return Err(WalletError::BadSlate("amount is zero"));
        }
        let dust = Policy::MAINNET.dust;
        if amount < dust {
            return Err(WalletError::BadSlate("amount is below the dust limit"));
        }
        let coins = self.spendable(chain)?;
        // The fee depends on the inputs, which depend on the fee: with a
        // fee for the inputs chosen so far, choose again until it holds.
        let mut inputs = 1;
        let given: Fee = fee.into();
        given.check(Self::payment_weight(1))?;
        let fee = loop {
            let fee = given.for_weight(Self::payment_weight(inputs));
            let need = amount as u128 + fee as u128;
            let mut picked = 0usize;
            let mut total = 0u128;
            for c in &coins {
                if total >= need {
                    break;
                }
                total += c.amount as u128;
                picked += 1;
            }
            if total < need {
                return Err(WalletError::Insufficient { have: total, need });
            }
            let min = Self::min_fee(picked.max(1));
            if given.is_total() && fee < min {
                return Err(WalletError::FeeTooLow { min });
            }
            if picked <= inputs {
                break fee;
            }
            inputs = picked;
        };
        let need = amount as u128 + fee as u128;
        let mut picked = Vec::new();
        let mut total = 0u128;
        for c in coins {
            if total >= need {
                break;
            }
            total += c.amount as u128;
            picked.push(c);
        }
        let change_amount = (total - need) as u64;
        let fee = if change_amount < dust { fee + change_amount } else { fee };
        // The change record, the reservation and the slate in one
        // change: a crash leaves all or none of them.
        let mut t = self.t.clone();
        let mut outputs = Vec::new();
        let mut change = None;
        if change_amount >= dust {
            let out = self.receive_in(&mut t, change_amount, now)?;
            change = Some(out.commitment);
            outputs.push(out);
        }
        for c in &picked {
            if let Some(o) = t.outputs.get_mut(&digest_to_bytes(&c.commitment)) {
                o.state = State::Reserved;
            }
        }
        let (id, secret) = (random_bytes::<32>()?, random_bytes::<32>()?);
        let (commitments, note) = (picked.iter().map(|c| c.commitment).collect(), note.to_vec());
        let pending = Pending { inputs: commitments, change, amount, fee, secret, note: note.clone() };
        t.slates.insert(id, pending);
        self.commit(t, &[T_OUTPUTS, T_SLATES])?;
        let inputs = picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        // (Whoever pays, in the slate: this wallet's address, hashed
        // with the secret. The wallet that is paid has neither of it.)
        let (sender, change) = (crate::proofs::sender_tag(&self.id(), &secret), u32::from(change.is_some()));
        Ok(Slate { id, stage: 1, amount, fee, sender, note, receipt: None, inputs, outputs, change })
    }

    /// The recipient's step: adds an output for the slate's amount,
    /// recorded as unspent, and advances the slate to stage 2.
    pub fn receive_slate(&mut self, slate: &mut Slate, now: u64) -> Result<()> {
        if slate.stage != 1 {
            return Err(WalletError::BadSlate("not a stage-1 slate"));
        }
        if slate.outputs.len() != slate.change as usize {
            return Err(WalletError::BadSlate("already has a recipient output"));
        }
        if slate.amount < Policy::MAINNET.dust {
            return Err(WalletError::BadSlate("amount is below the dust limit"));
        }
        let mut t = self.t.clone();
        let out = self.receive_in(&mut t, slate.amount, now)?;
        t.answered.insert(digest_to_bytes(&out.commitment));
        // (What it is for, as whoever pays said: kept with the output.)
        if !slate.note.is_empty() {
            t.notes.insert(digest_to_bytes(&out.commitment), slate.note.clone());
        }
        self.commit(t, &[T_OUTPUTS, T_ANSWERED, T_NOTES])?;
        // The receipt: this wallet's word, by the key its address is
        // the hash of, that the output is its own, for this slate.
        let key = self.identity_key();
        slate.receipt = Some(crate::proofs::Receipt::sign(&key, &out, &slate.id, &slate.sender, &slate.note));
        slate.outputs.push(out);
        slate.stage = 2;
        Ok(())
    }

    /// The sender's last step: checks the stage-2 slate against the
    /// pending record and the balance, signs the inputs (marking them
    /// spent), records the payment, and returns the transaction to pool.
    pub fn finalize(&mut self, slate: &Slate, now: u64) -> Result<Signed> {
        self.finalize_as(slate, now, None)
    }

    /// [`Wallet::finalize`]; or, with `burn`, the signing of a slate
    /// whose one output this wallet made itself, for nobody: there is
    /// no receipt, and what proves it is what the output's memo is the
    /// hash of.
    fn finalize_as(&mut self, slate: &Slate, now: u64, burn: Option<crate::proofs::Burn>) -> Result<Signed> {
        let is_burn = burn.is_some();
        if slate.stage != 2 {
            return Err(WalletError::BadSlate("not a stage-2 slate"));
        }
        let pending = self.t.slates.get(&slate.id).cloned().ok_or(WalletError::Unknown)?;
        // Answered by a receipt for this payment: the output the slate
        // now has, its id and note, to whoever holds this wallet's
        // secret for it. (Whose the receipt is, is for whoever sent
        // the slate to hold against whom it sent it to.)
        let made = slate.outputs.last().ok_or(WalletError::BadSlate("no recipient output"))?.clone();
        let tag = crate::proofs::sender_tag(&self.id(), &pending.secret);
        let claim = match (burn, &slate.receipt) {
            (Some(burn), _) => crate::proofs::Claim::Burn(burn),
            (None, Some(receipt)) if receipt.verify(&made, &slate.id, &tag, &pending.note) => {
                let (secret, note, receipt) = (pending.secret, pending.note.clone(), receipt.clone());
                // This wallet's own word that the payment is its own:
                // kept with the receipt, for the proof.
                let key = self.identity_key();
                let payer = crate::proofs::Receipt::sign_as_payer(&key, &made, &slate.id, &tag, &note);
                crate::proofs::Claim::Payment { secret, slate: slate.id, note, receipt, payer }
            }
            (None, _) => return Err(WalletError::BadSlate("no receipt for this payment")),
        };
        if pending.inputs.len() != slate.inputs.len() {
            return Err(WalletError::BadSlate("inputs changed"));
        }
        for (c, (pk, amount)) in pending.inputs.iter().zip(&slate.inputs) {
            let o = self.owned(c).ok_or(WalletError::Corrupt("reserved input"))?;
            if self.key(&o.nonce).public_key() != *pk || o.amount != *amount {
                return Err(WalletError::BadSlate("inputs changed"));
            }
        }
        if slate.outputs.len() <= slate.change as usize {
            return Err(WalletError::BadSlate("no recipient output"));
        }
        // The recipient may only have added its output: the amount and
        // fee offered must stand, or it could pocket the fee.
        if slate.amount != pending.amount || slate.fee != pending.fee {
            return Err(WalletError::BadSlate("amount or fee changed"));
        }
        let ins: u128 = slate.inputs.iter().map(|(_, a)| *a as u128).sum();
        let outs: u128 = slate.outputs.iter().map(|o| o.amount as u128).sum();
        let paid: u128 = slate.outputs[slate.change as usize..].iter().map(|o| o.amount as u128).sum();
        if paid != slate.amount as u128 || ins != outs + slate.fee as u128 {
            return Err(WalletError::BadSlate("amounts do not balance"));
        }
        // The change output, memo included: a changed memo would still
        // spend, but a wallet restored from the phrase could never find it.
        let change_ok = match pending.change {
            Some(c) => {
                let o = self.owned(&c).ok_or(WalletError::Corrupt("change output"))?;
                slate.change == 1 && slate.outputs[0].to_bytes() == self.output_of(&o.nonce, o.amount).to_bytes()
            }
            None => slate.change == 0,
        };
        if !change_ok {
            return Err(WalletError::BadSlate("change output changed"));
        }
        // What the pool will refuse is not worth a signature.
        if slate.outputs.iter().any(|o| o.amount == 0) {
            return Err(WalletError::BadSlate("an output is for zero"));
        }
        if slate.outputs.iter().any(|o| o.amount < Policy::MAINNET.dust) {
            return Err(WalletError::BadSlate("an output is below the dust limit"));
        }
        if 12 + slate.inputs.len() * INPUT_SIZE + slate.outputs.len() * OUTPUT_SIZE > MAX_TX_SIZE {
            return Err(WalletError::BadSlate("too many outputs for one transaction"));
        }
        if slate.outputs.len() != slate.change as usize + 1 {
            return Err(WalletError::BadSlate("not one recipient output"));
        }
        let mut t = self.t.clone();
        let signed = self.sign(&mut t, slate.unsigned(), &pending.inputs)?;
        t.slates.remove(&slate.id);
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: pending.inputs,
            fee: slate.fee,
            size: signed.tx.size(),
            created: now,
            tx: signed.tx.clone(),
        };
        // What will prove it, once a block has made its output.
        let (key_hash, amount, memo) = (made.key_hash, made.amount, made.memo);
        let path = [[0; 32]; crate::store::state::STATE_HEIGHT];
        let proof = crate::proofs::Proof { height: 0, position: 0, key_hash, amount, memo, path, claim };
        let payment = Payment { txid: sent.txid, fee: slate.fee, created: now, proven: false, landed: None, proof };
        t.payments.insert(digest_to_bytes(&sent.txid), payment);
        t.signed(&slate.id, &digest_to_bytes(&sent.txid), is_burn);
        t.sent.insert(digest_to_bytes(&sent.txid), sent);
        self.commit(t, &[T_OUTPUTS, T_SLATES, T_SENT, T_PAYMENTS])?;
        Ok(signed)
    }

    /// Burns `amount`, for `burn`: a transaction of this wallet's with
    /// an output nobody can spend, whose memo is the hash of whom the
    /// burn is to the credit of and what for. Signed at once: nobody
    /// answers it. Kept, with what will prove it
    /// ([`Wallet::payments`]).
    pub fn burn(
        &mut self,
        amount: u64,
        fee: impl Into<Fee>,
        burn: crate::proofs::Burn,
        chain: &impl Unspent,
        now: u64,
    ) -> Result<Signed> {
        if burn.purpose.len() > crate::proofs::MAX_NOTE {
            return Err(WalletError::BadSlate("what the burn is for is too long"));
        }
        let mut slate = self.send(amount, fee, chain, now)?;
        slate.outputs.push(burn.output(amount));
        slate.stage = 2;
        match self.finalize_as(&slate, now, Some(burn)) {
            Ok(signed) => Ok(signed),
            Err(e) => {
                let _ = self.cancel_slate(&slate.id);
                Err(e)
            }
        }
    }

    /// The payments made and the coins burned, the newest first.
    pub fn payments(&self) -> Vec<Payment> {
        let mut all: Vec<Payment> = self.t.payments.values().cloned().collect();
        all.sort_by_key(|p| std::cmp::Reverse(p.created));
        all
    }

    /// Those of them a block has made the output of, and whose proof
    /// is not yet of that block: each one's transaction, the height of
    /// the block, and the output's position.
    pub fn payments_to_prove(&self) -> Vec<(Commitment, u32, u64)> {
        let due = self.t.payments.values().filter(|p| !p.proven);
        due.filter_map(|p| p.landed.map(|(height, position)| (p.txid, height, position))).collect()
    }

    /// The output of the payment of this transaction was made by the
    /// block at `height`, at `position`, and `path` is its path to
    /// that block's state root: its proof holds from now on. `memo` is
    /// the memo of the output the chain has there: another's, if it is
    /// not this payment's (two burns of one amount look alike until
    /// their memos are seen), and then nothing is kept.
    pub fn prove_payment(
        &mut self,
        txid: &Commitment,
        height: u32,
        position: u64,
        memo: &Memo,
        path: [crate::hash::Digest; crate::store::state::STATE_HEIGHT],
    ) -> Result<bool> {
        let mut t = self.t.clone();
        let Some(payment) = t.payments.get_mut(&digest_to_bytes(txid)) else { return Ok(false) };
        if payment.proof.memo != *memo {
            (payment.landed, payment.proven) = (None, false);
            self.commit(t, &[T_PAYMENTS])?;
            return Ok(false);
        }
        (payment.proof.height, payment.proof.position, payment.proof.path) = (height, position, path);
        (payment.landed, payment.proven) = (Some((height, position)), true);
        self.commit(t, &[T_PAYMENTS])?;
        Ok(true)
    }

    /// What the slate that made the output of commitment `c` said it
    /// was for, if it said anything.
    pub fn note_of(&self, c: &Commitment) -> Option<&[u8]> {
        self.t.notes.get(&digest_to_bytes(c)).map(|note| &note[..])
    }

    /// Gives up a transaction this wallet signed and nobody took: one
    /// the pool refused, so that no block can ever hold it. What it
    /// would have spent is the wallet's to spend again, and what it
    /// would have made is forgotten. (Never of one that was sent on:
    /// that one may yet be mined, and is taken back with a replacement,
    /// [`Wallet::cancel_sent`].) Whether there was such a transaction.
    pub fn unsend(&mut self, txid: &Commitment) -> Result<bool> {
        let mut t = self.t.clone();
        let was = Self::unsend_in(&mut t, txid);
        self.commit(t, &[T_OUTPUTS, T_SENT, T_PAYMENTS])?;
        Ok(was)
    }

    /// [`Wallet::unsend`], in tables not yet written.
    fn unsend_in(t: &mut Tables, txid: &Commitment) -> bool {
        let Some(sent) = t.sent.remove(&digest_to_bytes(txid)) else { return false };
        for c in &sent.inputs {
            if let Some(o) = t.outputs.get_mut(&digest_to_bytes(c)) {
                o.state = State::Unspent;
            }
        }
        for made in &sent.tx.outputs {
            t.outputs.remove(&digest_to_bytes(&made.commitment));
        }
        t.payments.remove(&digest_to_bytes(txid));
        true
    }

    /// Abandons a pending slate: its inputs become spendable again and its
    /// change record is dropped.
    pub fn cancel_slate(&mut self, id: &[u8; 32]) -> Result<()> {
        let mut t = self.t.clone();
        let pending = t.slates.remove(id).ok_or(WalletError::Unknown)?;
        for c in &pending.inputs {
            if let Some(o) = t.outputs.get_mut(&digest_to_bytes(c)) {
                o.state = State::Unspent;
            }
        }
        if let Some(c) = pending.change {
            t.outputs.remove(&digest_to_bytes(&c));
        }
        self.commit(t, &[T_OUTPUTS, T_SLATES])
    }

    /// The smallest fee a cancellation of `sent` may pay: its fee plus
    /// [`REPLACEMENT_FEE_PER_UNIT`] per byte of the replacement, its
    /// inputs paid back to one output (see [`crate::mempool`]).
    pub fn min_replacement_fee(sent: &Sent) -> u64 {
        sent.fee + REPLACEMENT_FEE_PER_UNIT * Self::cancel_weight(sent)
    }

    fn cancel_weight(sent: &Sent) -> u64 {
        Weights::DEFAULT.of(sent.inputs.len(), 1)
    }

    /// The smallest fee a bump of `sent` may pay: its fee plus the
    /// increment per byte of the bump, which is its size.
    pub fn min_bump_fee(sent: &Sent) -> u64 {
        sent.fee + REPLACEMENT_FEE_PER_UNIT * Weights::DEFAULT.of_tx(&sent.tx)
    }

    /// The record of a payment sent, and its inputs as a transaction
    /// spends them: an error if the chain no longer holds them.
    fn sent_inputs(&self, txid: &Commitment, chain: &impl Unspent) -> Result<(Sent, Vec<(PublicKey, u64)>)> {
        let sent = self.t.sent.get(&digest_to_bytes(txid)).cloned().ok_or(WalletError::Unknown)?;
        let mut inputs = Vec::with_capacity(sent.inputs.len());
        for c in &sent.inputs {
            let o = self.owned(c).ok_or(WalletError::Corrupt("sent input"))?;
            if !self.held(&o, chain)? {
                return Err(WalletError::Landed);
            }
            inputs.push((self.key(&o.nonce).public_key(), o.amount));
        }
        Ok((sent, inputs))
    }

    /// Signs what is to take the place of the payment `sent`, spending
    /// the same inputs, each from its next leaf, and puts its record in
    /// place of the payment's: all of it, with whatever `t` already
    /// holds of the change, written at once.
    fn replace(
        &mut self,
        mut t: Tables,
        sent: Sent,
        unsigned: UnsignedTransaction,
        fee: u64,
        now: u64,
        kind: list::Kind,
    ) -> Result<Signed> {
        let signed = self.sign(&mut t, unsigned, &sent.inputs)?;
        list::relist(&mut t);
        t.replaced(&digest_to_bytes(&sent.txid), &digest_to_bytes(&signed.tx.txid()), kind, fee, now);
        t.sent.remove(&digest_to_bytes(&sent.txid));
        let next = Sent {
            txid: signed.tx.txid(),
            inputs: sent.inputs,
            fee,
            size: signed.tx.size(),
            created: now,
            tx: signed.tx.clone(),
        };
        t.sent.insert(digest_to_bytes(&next.txid), next);
        self.commit(t, &[T_OUTPUTS, T_SENT, T_COMMITS, T_NAMES])?;
        Ok(signed)
    }

    /// Cancels a finalized payment that is not yet confirmed: signs a
    /// replacement spending the same inputs back to a fresh output of this
    /// wallet with `fee` (at least [`Wallet::min_replacement_fee`]), using
    /// each input's next leaf. The payment's record now points at the
    /// replacement, which can itself be cancelled while leaves remain.
    pub fn cancel_sent(
        &mut self,
        txid: &Commitment,
        fee: impl Into<Fee>,
        chain: &impl Unspent,
        now: u64,
    ) -> Result<Signed> {
        let (sent, inputs) = self.sent_inputs(txid, chain)?;
        let min = Self::min_replacement_fee(&sent);
        let fee = match fee.into() {
            Fee::Total(f) => f,
            Fee::PerUnit(r) => min.max(r.saturating_mul(Self::cancel_weight(&sent))),
        };
        if fee < min {
            return Err(WalletError::FeeTooLow { min });
        }
        let total: u128 = inputs.iter().map(|(_, amount)| *amount as u128).sum();
        if total <= fee as u128 {
            return Err(WalletError::Insufficient { have: total, need: fee as u128 + 1 });
        }
        let mut t = self.t.clone();
        let back = self.receive_in(&mut t, (total - fee as u128) as u64, now)?;
        // The replacement carries none of the payment's name operations:
        // their entries go back to where they were before it was signed.
        // Should the payment land after all, the names are taken up from
        // what it wrote ([`Wallet::sync_names`]).
        for op in &sent.tx.ops {
            self.undo_name_op_in(&mut t, op);
        }
        self.replace(t, sent, UnsignedTransaction::new(inputs, vec![back]), fee, now, list::Kind::Cancel)
    }

    /// Speeds up a finalized payment that is not yet confirmed: signs a
    /// replacement with the same outputs but the change, which pays the
    /// higher `fee` (at least [`Wallet::min_bump_fee`]; at a rate, that
    /// rate on its size), using each input's next leaf. Change that would
    /// fall below the dust limit goes to the fee whole. The recipient's
    /// output stands: the payment's record moves to the replacement.
    pub fn bump_sent(
        &mut self,
        txid: &Commitment,
        fee: impl Into<Fee>,
        chain: &impl Unspent,
        now: u64,
    ) -> Result<Signed> {
        let (sent, inputs) = self.sent_inputs(txid, chain)?;
        let min = Self::min_bump_fee(&sent);
        let fee = match fee.into() {
            Fee::Total(f) => f,
            Fee::PerUnit(r) => min.max(r.saturating_mul(Weights::DEFAULT.of_tx(&sent.tx))),
        };
        if fee < min {
            return Err(WalletError::FeeTooLow { min });
        }
        // The change: the one output of the transaction this wallet holds.
        let change = sent.tx.outputs.iter().rposition(|o| self.owned(&o.commitment).is_some());
        let i = change.ok_or(WalletError::BadSlate("no change to pay a higher fee from; cancel it instead"))?;
        let more = fee - sent.fee;
        let old = sent.tx.outputs[i];
        let have = old.amount;
        let mut outputs = sent.tx.outputs.clone();
        let mut t = self.t.clone();
        let fee = if have >= more && have - more >= Policy::MAINNET.dust {
            outputs[i] = self.receive_in(&mut t, have - more, now)?;
            fee
        } else if have >= more {
            outputs.remove(i);
            sent.fee + have
        } else {
            return Err(WalletError::Insufficient { have: have as u128 + sent.fee as u128, need: fee as u128 });
        };
        let unsigned = UnsignedTransaction::with_ops(inputs, outputs, sent.tx.ops.clone());
        self.replace(t, sent, unsigned, fee, now, list::Kind::Bump)
    }

    /// A sent transaction as it was signed, to send again. Where its
    /// inputs' outputs lie is signed: if the chain has gone over to a
    /// branch on which one of them lies elsewhere, what was signed
    /// spends nothing there, and the payment is to be made again.
    pub fn resend(&self, txid: &Commitment) -> Result<Transaction> {
        let sent = self.t.sent.get(&digest_to_bytes(txid)).cloned().ok_or(WalletError::Unknown)?;
        let tx = sent.tx;
        let positions = tx.spent_positions();
        if sent.inputs.len() == positions.len() {
            for (p, c) in positions.iter().zip(&sent.inputs) {
                if self.owned(c).and_then(|o| o.position).is_some_and(|q| q != *p) {
                    return Err(WalletError::BadSlate("an output it spends has moved: it is to be made again"));
                }
            }
        }
        Ok(tx)
    }

    /// Forgets unspent outputs the chain does not hold: outputs of
    /// blocks or payments that never landed (the change of a payment
    /// replaced, say). The change of a pending slate stays, as do the
    /// rewards not yet settled and anything in `keep`: the outputs of
    /// pooled transactions, which may yet land. Returns how many went.
    pub fn prune_pending(&mut self, chain: &impl Unspent, keep: &[Commitment]) -> Result<usize> {
        self.prune_pending_of(chain, keep, true)
    }

    /// Forgets an output this wallet added to another's payment, while
    /// no block has made it: the wallet no longer expects it. (Whoever
    /// pays can sign all the same, having the answer; the output is
    /// then found only by a look through the chain, `scan`.)
    pub fn cancel_received(&mut self, commitment: &Commitment, chain: &impl Unspent) -> Result<()> {
        let id = digest_to_bytes(commitment);
        let o = self.t.outputs.get(&id).copied().ok_or(WalletError::Unknown)?;
        if !self.t.answered.contains(&id) || o.state != State::Unspent {
            return Err(WalletError::Unknown);
        }
        if self.held(&o, chain)? {
            return Err(WalletError::Landed);
        }
        let mut t = self.t.clone();
        t.outputs.remove(&id);
        t.answered.remove(&id);
        t.notes.remove(&id);
        self.commit(t, &[T_OUTPUTS, T_ANSWERED, T_NOTES])
    }

    /// [`Wallet::prune_pending`]; with `answered` false, what this
    /// wallet added to others' payments is kept whether a pool has it
    /// or not: whoever pays may sign days later, and nobody asked for
    /// the output to be forgotten. That is what the wallet does of
    /// itself at every block.
    pub fn prune_pending_of(&mut self, chain: &impl Unspent, keep: &[Commitment], answered: bool) -> Result<usize> {
        let mut t = self.t.clone();
        let mut in_flight: BTreeSet<Id> = keep.iter().map(digest_to_bytes).collect();
        // (What a transaction this wallet signed makes may yet be made,
        // whether the pool here has it or has lost it: it is sent
        // again from its record.)
        in_flight.extend(t.sent.values().flat_map(|s| s.tx.outputs.iter().map(|o| digest_to_bytes(&o.commitment))));
        if !answered {
            in_flight.extend(t.answered.iter().copied());
        }
        in_flight.extend(t.slates.values().filter_map(|p| p.change.as_ref().map(digest_to_bytes)));
        in_flight.extend(t.rewards.keys().copied());
        let mut gone = 0;
        // (What a reorganization undid goes when it has been gone long
        // enough: the chain may yet go back, [`Wallet::reconcile`].)
        in_flight.extend(t.lost.keys().copied());
        for o in self.outputs() {
            let id = digest_to_bytes(&o.commitment);
            let held = self.held(&o, chain)?;
            let waiting = in_flight.contains(&id);
            if o.state == State::Unspent && !waiting && !held {
                t.outputs.remove(&id);
                gone += 1;
            }
            if held || (o.state == State::Unspent && !waiting) {
                t.answered.remove(&id);
            }
        }
        self.commit(t, &[T_OUTPUTS, T_ANSWERED])?;
        Ok(gone)
    }

    /// Notes signatures seen on the network (pooled spends) from the
    /// wallet's outputs, `(commitment, leaf)`: a leaf the wallet took for
    /// unused (its file gone back to a copy kept, a machine's snapshot)
    /// is skipped, with every leaf before it, so it never signs twice.
    /// Returns how many outputs were behind.
    pub fn observe_signatures(&mut self, seen: &[(Commitment, u64)]) -> Result<usize> {
        let mut t = self.t.clone();
        let mut behind = 0;
        for (c, leaf) in seen {
            let Some(o) = t.outputs.get_mut(&digest_to_bytes(c)) else { continue };
            let base = if o.recovered { LEAVES_PER_HALF } else { 0 };
            let Some(offset) = (*leaf as u32).checked_sub(base).filter(|&x| x < LEAVES_PER_HALF) else { continue };
            // Its place in this copy's order, from the start leaf.
            let k = (offset + LEAVES_PER_HALF - u32::from(o.start)) % LEAVES_PER_HALF;
            if u32::from(o.used) <= k {
                o.used = (k + 1) as u8;
                behind += 1;
            }
        }
        if behind > 0 {
            self.commit(t, &[T_OUTPUTS])?;
        }
        Ok(behind)
    }

    /// Records that the pending slate of id `slate` was sent to the
    /// wallet of id `whom`: so that its answer is taken from that
    /// wallet and from no other ([`Wallet::sent_to`]). (Those of slates
    /// no longer pending are let go.)
    pub fn send_to(&mut self, slate: &[u8; 32], whom: &crate::hash::Digest) -> Result<()> {
        let mut t = self.t.clone();
        t.sent_to.retain(|id, _| t.slates.contains_key(id));
        t.sent_to.insert(*slate, digest_to_bytes(whom));
        self.commit(t, &[T_SENT_TO])
    }

    /// Gives `label@name` to the wallet of id `holder`, at `unix`: a
    /// certificate of this wallet's key, with a number higher than any
    /// it signed for that full name, holding for a week. (It is the
    /// name's certificate if this wallet's address is what the name
    /// says on the chain: whoever calls sees to that.) Kept, to be
    /// signed again as its time runs out ([`Wallet::names_to_renew`]).
    /// The certificate as it travels: with `word`, the word of the
    /// name's holder that this wallet's key signs for the name, where
    /// it is by that word and not as the holder that this wallet
    /// signs.
    pub fn give_name(
        &mut self,
        label: &[u8],
        name: &[u8],
        holder: &crate::hash::Digest,
        unix: u64,
        word: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use crate::subnames::{HOLDS, bundle, certify, point};
        let at = digest_to_bytes(&point(label, name));
        let seq = self.t.names_given.get(&at).map_or(0, |given| given.seq + 1).max(unix);
        let expires = unix + HOLDS;
        let certificate = certify(&self.identity_key(), label, name, holder, seq, expires);
        let mut t = self.t.clone();
        t.names_given.insert(at, Given { label: label.to_vec(), name: name.to_vec(), holder: *holder, seq, expires });
        self.commit(t, &[T_NAMES_GIVEN])?;
        Ok(bundle(&certificate, word))
    }

    /// Keeps the word of a name's holder that this wallet's key signs
    /// for the name: in place of an earlier one for that name.
    pub fn sign_for(&mut self, name: &[u8], word: &[u8]) -> Result<()> {
        let mut t = self.t.clone();
        t.names_signed.insert(digest_to_bytes(&crate::subnames::point(b"", name)), word.to_vec());
        self.commit(t, &[T_NAMES_SIGNED])
    }

    /// The word by which this wallet's key signs for `name`, if it was
    /// given one.
    pub fn signs_for(&self, name: &[u8]) -> Option<&[u8]> {
        self.t.names_signed.get(&digest_to_bytes(&crate::subnames::point(b"", name))).map(|word| &word[..])
    }

    /// Every such word.
    pub fn signs_for_all(&self) -> Vec<Vec<u8>> {
        self.t.names_signed.values().cloned().collect()
    }

    /// The names this wallet has given out, in the order of their ids.
    pub fn names_given(&self) -> Vec<Given> {
        self.t.names_given.values().cloned().collect()
    }

    /// Those of them whose certificate was signed long enough ago, at
    /// `unix`, for another to be due.
    pub fn names_to_renew(&self, unix: u64) -> Vec<Given> {
        use crate::subnames::{HOLDS, RENEWED};
        let due = |given: &&Given| given.expires < unix + HOLDS - RENEWED;
        self.t.names_given.values().filter(due).cloned().collect()
    }

    /// Gives `label@name` out no longer: no certificate is signed for
    /// it again, and the last one holds until its time is past. Whether
    /// it was given.
    pub fn take_name_back(&mut self, label: &[u8], name: &[u8]) -> Result<bool> {
        let mut t = self.t.clone();
        let was = t.names_given.remove(&digest_to_bytes(&crate::subnames::point(label, name))).is_some();
        self.commit(t, &[T_NAMES_GIVEN])?;
        Ok(was)
    }

    /// Keeps a certificate by which this wallet is a full name: one
    /// that was read, and names this wallet. In place of an older one
    /// for that name; or, of a name it was not yet, if it is fewer
    /// than `most` names. Whether it was kept.
    pub fn hold_name(&mut self, checked: &crate::subnames::Checked, bundle: &[u8], most: usize) -> Result<bool> {
        let at = digest_to_bytes(&checked.point());
        let number = |held: &Vec<u8>| u64::from_le_bytes(held[..8].try_into().expect("eight bytes"));
        let takes = match self.t.names_held.get(&at) {
            Some(held) => number(held) < checked.seq,
            None => self.t.names_held.len() < most,
        };
        if !takes || checked.holder != self.id() {
            return Ok(false);
        }
        let mut t = self.t.clone();
        let kept = [&checked.seq.to_le_bytes()[..], &checked.expires.to_le_bytes(), bundle].concat();
        t.names_held.insert(at, kept);
        self.commit(t, &[T_NAMES_HELD])?;
        Ok(true)
    }

    /// The certificates by which this wallet is a full name: the id
    /// each name is reached by, the certificate's number, and the
    /// certificate as it was given, with what goes with it.
    pub fn names_held(&self) -> Vec<(crate::hash::Digest, u64, Vec<u8>)> {
        let number = |held: &Vec<u8>| u64::from_le_bytes(held[..8].try_into().expect("eight bytes"));
        let each = self.t.names_held.iter();
        each.filter_map(|(at, held)| Some((digest_from_bytes(at)?, number(held), held[16..].to_vec()))).collect()
    }

    /// Is `label@name` no longer. Whether it was.
    pub fn drop_name(&mut self, label: &[u8], name: &[u8]) -> Result<bool> {
        let mut t = self.t.clone();
        let was = t.names_held.remove(&digest_to_bytes(&crate::subnames::point(label, name))).is_some();
        self.commit(t, &[T_NAMES_HELD])?;
        Ok(was)
    }

    /// Whom the pending slate of id `slate` was sent to, if it was sent
    /// to a wallet (and not written to a file, for anyone to answer).
    pub fn sent_to(&self, slate: &[u8; 32]) -> Option<crate::hash::Digest> {
        self.t
            .slates
            .contains_key(slate)
            .then(|| self.t.sent_to.get(slate))
            .flatten()
            .and_then(|w| digest_from_bytes(w))
    }

    /// The pending slates: each one's id, and what it is to pay.
    pub fn pending_slates(&self) -> Vec<([u8; 32], u64)> {
        self.t.slates.iter().map(|(id, p)| (*id, p.amount)).collect()
    }

    /// The payments finalized, oldest first.
    pub fn sent(&self) -> Vec<Sent> {
        let mut out: Vec<Sent> = self.t.sent.values().cloned().collect();
        out.sort_by_key(|s| s.created);
        out
    }

    /// Whether the output of this commitment was in the chain and is not
    /// any more ([`Wallet::reconcile`]).
    pub fn is_lost(&self, c: &Commitment) -> bool {
        self.t.lost.contains_key(&digest_to_bytes(c))
    }

    /// The list of what the wallet has done and been paid, in the
    /// order it first saw each ([`list`]).
    pub fn list(&self) -> &[list::Row] {
        &self.t.list
    }

    /// The row of number `number`.
    pub fn listed(&self, number: u32) -> Option<&list::Row> {
        self.t.list.get((number as usize).checked_sub(1)?)
    }

    /// The outputs that have a row in the list, lie in the chain, and
    /// whose row does not say which block made them, with where each
    /// lies: those found by looking through the unspent outputs, not
    /// in a block as it went by. For whoever can ask the chain
    /// ([`Wallet::placed`]).
    pub fn unplaced(&self) -> Vec<(Commitment, u64)> {
        let rows = self.t.list.iter().filter(|row| row.is_output() && row.height == 0);
        rows.filter_map(|row| {
            let o = self.t.outputs.get(&row.id)?;
            Some((o.commitment, o.position?))
        })
        .collect()
    }

    /// The heights of the blocks that made these outputs, for their
    /// rows.
    pub fn placed(&mut self, heights: &[(Commitment, u32)]) -> Result<()> {
        if heights.is_empty() {
            return Ok(());
        }
        let mut t = self.t.clone();
        t.located.extend(heights.iter().map(|(c, height)| (digest_to_bytes(c), *height)));
        self.commit(t, &[])
    }

    /// The row meant by `what`: its number; or the first digits, in
    /// hex, of an id it has (the slate's it began as, its
    /// transaction's, or its output's). A number that is a row's is
    /// that row, whatever ids begin with those digits. Else the numbers
    /// of the rows that fit: none, or more than one.
    pub fn row(&self, what: &str) -> std::result::Result<&list::Row, Vec<u32>> {
        if let Some(row) = what.parse::<u32>().ok().and_then(|n| self.listed(n)) {
            return Ok(row);
        }
        let what = what.to_ascii_lowercase();
        let hex = |id: &Id| id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let fits = |row: &&list::Row| {
            !what.is_empty()
                && (hex(&row.id).starts_with(&what) || row.transaction().is_some_and(|t| hex(&t).starts_with(&what)))
        };
        let found: Vec<&list::Row> = self.t.list.iter().filter(fits).collect();
        match found[..] {
            [one] => Ok(one),
            _ => Err(found.iter().map(|row| row.number).collect()),
        }
    }

    /// The numbers of the rows that made the output of `commitment` and
    /// that spend it, where the wallet knows: a transaction it signed
    /// that has the output among those it makes, or the row of the
    /// output itself as it came; and a transaction it signed that has
    /// it among its inputs.
    pub fn rows_of_output(&self, commitment: &Commitment) -> (Option<u32>, Option<u32>) {
        let id = digest_to_bytes(commitment);
        let signed = |row: &&list::Row| self.t.sent.get(&row.txid);
        let made = self.t.list.iter().find(|row| {
            (row.is_output() && row.id == id)
                || signed(row).is_some_and(|s| s.tx.outputs.iter().any(|o| o.commitment == *commitment))
        });
        // (The last of them: a payment taken back or sped up spends
        // what the one before it did.)
        let spent = self.t.list.iter().rev().find(|row| {
            row.by == 0 && signed(row).is_some_and(|s| s.inputs.contains(commitment))
                || self.t.slates.get(&row.id).is_some_and(|p| p.inputs.contains(commitment))
        });
        (made.map(|row| row.number), spent.map(|row| row.number))
    }

    /// The payments sent that no block has: those of which the chain
    /// still holds something they spend. Oldest first.
    pub fn unconfirmed(&self, chain: &impl Unspent) -> Result<Vec<Sent>> {
        let mut out = Vec::new();
        for sent in self.sent() {
            let mut held = false;
            for c in &sent.inputs {
                if let Some(o) = self.owned(c) {
                    held |= self.held(&o, chain)?;
                }
            }
            if held {
                out.push(sent);
            }
        }
        Ok(out)
    }

    /// Holds what the wallet keeps against the chain as it is, of
    /// `height` blocks: after every change of its last block, and above
    /// all after it has gone over to another branch.
    ///
    /// A payment sent is kept until the block that has it is `depth`
    /// blocks deep, deep enough that the chain will not go back on it:
    /// until then, if what it spends is unspent again, it is a payment
    /// to be mined again, and its record is what it is sent again from.
    ///
    /// An output that was in the chain and is not any more is lost:
    /// kept apart from what is coming, found again if a block makes it
    /// again, and forgotten once it has been gone for `depth` blocks.
    ///
    /// Outputs can only be lost where blocks were undone: `undone_from`
    /// is the position from which the outputs made were of blocks that
    /// are undone (none, where none was), and only those are looked up.
    /// Those lost already are looked up each time, for their return.
    pub fn reconcile(
        &mut self,
        chain: &impl Unspent,
        height: u32,
        depth: u32,
        undone_from: Option<u64>,
    ) -> Result<Reconciled> {
        let mut t = self.t.clone();
        let mut did = Reconciled::default();
        let mut changed = false;
        for (id, sent) in &self.t.sent {
            let mut held = false;
            for c in &sent.inputs {
                if let Some(o) = self.owned(c) {
                    held |= self.held(&o, chain)?;
                }
            }
            match (held, t.landed.get(id).copied()) {
                (false, None) => drop(t.landed.insert(*id, height)),
                (false, Some(at)) if height >= at.saturating_add(depth) => {
                    t.sent.remove(id);
                    t.landed.remove(id);
                    did.settled += 1;
                }
                (true, Some(_)) => {
                    t.landed.remove(id);
                    did.undone += 1;
                }
                _ => continue,
            }
            changed = true;
        }
        // What may be newly lost, and what is lost already.
        let made_above = |o: &Owned| undone_from.is_some_and(|from| o.position.is_some_and(|p| p >= from));
        let candidates: Vec<Owned> = self
            .t
            .outputs
            .iter()
            .filter(|(id, o)| o.state == State::Unspent && (self.t.lost.contains_key(*id) || made_above(o)))
            .map(|(_, o)| *o)
            .collect();
        for o in candidates {
            let id = digest_to_bytes(&o.commitment);
            match (self.held(&o, chain)?, t.lost.get(&id).copied()) {
                (false, None) => {
                    t.lost.insert(id, height);
                    did.lost += 1;
                }
                (false, Some(at)) if height >= at.saturating_add(depth) => {
                    t.outputs.remove(&id);
                    t.lost.remove(&id);
                    t.answered.remove(&id);
                    did.forgotten += 1;
                }
                (true, Some(_)) => {
                    t.lost.remove(&id);
                    did.returned += 1;
                }
                _ => continue,
            }
            changed = true;
        }
        if changed {
            self.commit(t, &[T_OUTPUTS, T_SENT, T_ANSWERED, T_LANDED, T_LOST])?;
        }
        Ok(did)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
