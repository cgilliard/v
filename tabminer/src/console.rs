//! The node's commands: what is typed at its prompt, and what it says.
//!
//! A command is a line of words. [`Console::run`] takes one and gives
//! back what is to be said of it: it prints nothing, so that whoever
//! asks (the prompt on a terminal, or a program the node is part of)
//! does with the answer what it will.
//!
//! The commands of the node itself need no wallet. Those of the wallet
//! say that there is none where the node was started without one.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::chain::params::{COIN, DECIMALS};
use crate::hash::digest_to_bytes;
use crate::logger::fmt::commas;
use crate::name::NameOp;
use crate::net::node::Handle;
use crate::prover::ChainVerifier;
use crate::store::Backend;
use crate::wallet::names::{NameStage, Registry};
use crate::wallet::{Fee, Slate, State, Wallet, follow};

/// What an offer of a name as text is marked with.
pub const OFFER_MARKER: &str = "TAB NAME OFFER";

/// What the prompt says its commands are.
pub const HELP: &str = "commands:
  status                    the chain's last block, peers, the pool, the wallet's total
  supply                    what the blocks so far have paid, by the schedule, and what
                            the unspent outputs come to: the two are the same, or it
                            says by how much they are not (it reads every output:
                            slow on a long chain)
  peers                     how many peers are known, and how many are live
  fees                      what a payment is to pay for its weight, to be in a block soon, by
                            the hour, or within the day
  leaves                    the sixteen leaves the blocks made here commit to
  set-leaf INDEX FILE       set leaf INDEX (0 to 15) to the SHA-256 of FILE; leaf 0 is
                            the vote for a consensus file, which FILE must be
  set-leaf-value INDEX HEX  set leaf INDEX to 32 bytes given in hex (all zero: none)
  consensus                 the consensus file in force, and how it is voted on
  relays                    the relays of the file in force, with a mark beside those
                            this wallet is reached at
  mempool                   the transactions waiting to be mined
  address                   this wallet's address: what it is known by, as tab1…
  balance                   what there is to spend; what is confirmed but too new to
                            spend; and pending, unverified, reserved and locked funds
                            (and orphaned: paid to this wallet by a block that was
                            undone. Rewards of such blocks are under `mining`)
  mining                    the blocks this node won of late, and those of them that
                            were orphaned: undone, for a longer chain without them
  txs [ROW | pending | mined] [--all]
                            everything the wallet has done and been paid, a row each
                            with a number that stays: payments sent and received,
                            rewards, coins burned, the steps of names, and what was
                            taken back or sped up. `txs ROW` says all of one; `txs
                            pending` those in no block yet; `txs mined` the rewards.
                            The last thirty are listed, or with --all every one
  outputs [--all]           the wallet's outputs that are unspent (with --all, those
                            it has spent too): each one's block, where it lies
                            among the chain's outputs, how many of its eight
                            signatures are used (*last* beside it when one is
                            left), and the rows of `txs` that made it and spend it
                            (a dash where the wallet does not know)
  send AMOUNT [FEE] TO      pay AMOUNT (or `all`: everything that can be spent, less
                            the fee, in one output) to the wallet at TO: its address (tab1…), its
                            name (@name), or a name under a name (label@name). Its
                            wallet answers and this one signs, with nothing more
                            asked: both must be reached
  subname set LABEL@NAME ADDRESS
                            give a name under NAME, which this wallet holds, to the
                            wallet at ADDRESS: it is sent a certificate, signed again
                            daily while this node runs
  subname delegate NAME ADDRESS [DAYS] FILE
                            say that the key of the wallet at ADDRESS signs for NAME,
                            which this wallet holds, for DAYS days (30): so that the
                            wallet that holds a name need not be the one that runs
                            all day. Written to FILE, for that wallet to take
  subname signer FILE       take such a word: this wallet then gives names under
                            that name
  subname del LABEL@NAME    sign for it no longer: its last certificate holds until
                            its time is past (there is no ending it sooner, but by
                            giving the name to another wallet)
  subname drop LABEL@NAME   be a name this wallet was given no longer
  subnames                  the names given out, and the names this wallet is
  send … \"NOTE\"             a note for the wallet that is paid, last and between
                            quotes (send 5 tab1… \"deposit 4821\"): what the payment is
                            for. It goes in the slate, to that wallet alone, which
                            keeps it; its receipt is over it
  payments                  the payments made and the coins burned, the block that
                            has each, and whether its proof is ready
  payment-proof ROW [FILE]  the proof of a payment: that the block made the output,
                            and the paid wallet's word that it is its own. Text, said
                            or written to FILE; for whoever has the chain's headers
  burn AMOUNT \"PURPOSE\" [FOR [FEE]]
                            burn AMOUNT, which nobody can spend from then on, to the
                            credit of FOR: an address, @name or label@name as it is
                            written (this wallet's address, if not said)
  burn-proof TXID [FILE]    the proof of a burn
  verify-proof FILE         check a proof against this node's chain, and say what it
                            shows
  send-file AMOUNT [FEE] FILE
                            start a payment by file: write the slate to FILE for the
                            recipient to `receive`, then `finalize` its answer
                            (FEE: coins in all, or N/unit; the least the pool takes
                            if not given)
  receive FILE [OUT]        answer a slate: add your output (writes OUT, FILE.received
                            if not given)
  finalize FILE             sign an answered slate and pool the transaction
                            (a slate is text, `-----BEGIN TAB SLATE-----` and base64,
                            to keep in a file or copy; FILE `-` is the terminal, for
                            what a command writes)
  ROW, wherever a command takes one, is a row of `txs`: its number, or the
                            first digits of its id (enough of them to be no other's)
  cancel ROW [FEE]          undo a row of `txs`, if it can still be undone. Of a payment
                            begun: gives it up, freeing what it was to spend. Of
                            one sent and in no block yet: another is signed that
                            pays what it spent back to this wallet (FEE as for
                            send-file, at least the smallest that replaces it). Of
                            one in a block: nothing, and it says so
  bump ROW [FEE]            pay a payment sent the same with a higher fee, from its
                            change
  resend ROW                pool a payment sent again, as it was signed (after a
                            restart dropped it: `txs` then says `not in the pool`)
  seed                      this wallet's recovery phrase: its twelve words (its
                            password is asked for, if it has one)
  password                  give the wallet a password, another, or none: asked for
  names                     this wallet's names, and its commits not yet revealed
  name NAME                 look a name up on the chain
  name-commit NAME [VALUE [FEE]]
                            start registering NAME: pool a transaction committing to
                            it, which says nothing of the name (VALUE: what the name
                            is to say, an address or 64 hex digits; this wallet's
                            address if not said, so that the name is paid by; `-`
                            for nothing)
  name-reveal NAME [WAIT [FEE]]
                            reveal a committed name once its commit is WAIT blocks
                            old: at least 1; as many as the wallet waits before it
                            spends an output (--min-confirmations) if not given
  name-update NAME VALUE [FEE]
                            change what a name says, putting it under a fresh key
  name-offer NAME FILE [VALUE]
                            write a record for NAME under a key of yours, for its
                            owner to sign over with name-transfer: an offer, as text
                            (`-----BEGIN TAB NAME OFFER-----`); FILE `-` says it here
  name-transfer FILE [FEE]  sign a name over to the offer in FILE
  scan                      find this wallet's outputs and names on the chain (after a
                            restore)
  help                      this
  quit                      stop the node";

/// What is said after a payment sent has been taken back, and after one
/// has been sped up.
/// The commands there are, by name: for what is said of one given
/// what it does not take, and for finishing one begun
/// ([`complete`]).
pub const COMMANDS: &[&str] = &[
    "address",
    "balance",
    "bump",
    "burn",
    "burn-proof",
    "cancel",
    "consensus",
    "exit",
    "fees",
    "finalize",
    "help",
    "leaves",
    "mempool",
    "mining",
    "name",
    "name-commit",
    "name-offer",
    "name-reveal",
    "name-transfer",
    "name-update",
    "names",
    "outputs",
    "password",
    "payment-proof",
    "payments",
    "peers",
    "prune",
    "quit",
    "receive",
    "relays",
    "resend",
    "scan",
    "seed",
    "send",
    "send-file",
    "set-leaf",
    "set-leaf-value",
    "status",
    "subname",
    "subnames",
    "supply",
    "txs",
    "verify-proof",
];

/// The commands whose words may be a file's name.
const OF_FILES: &[&str] = &[
    "burn-proof",
    "finalize",
    "name-offer",
    "name-transfer",
    "payment-proof",
    "receive",
    "send-file",
    "set-leaf",
    "subname",
    "verify-proof",
];

/// What the word being typed could be, for whoever finishes it at a
/// tab ([`crate::terminal`]): given the line up to the cursor, where
/// its last word begins (in characters) and what that word could be.
/// The first word is a command; a later one is a word the command
/// knows (`txs pending`), or, of a command that takes a file or where
/// the word is written as a path, a file there is.
pub fn complete(before: &str) -> (usize, Vec<String>) {
    let begins = before.rfind(' ').map_or(0, |at| at + 1);
    let (from, word) = (before[..begins].chars().count(), &before[begins..]);
    let mut words = before[..begins].split_whitespace();
    let Some(command) = words.next() else {
        let fit = COMMANDS.iter().filter(|c| c.starts_with(word)).map(|c| c.to_string()).collect();
        return (from, fit);
    };
    let known: &[&str] = match (command, words.count()) {
        ("txs", 0) => &["pending", "mined", "--all"],
        ("txs", 1) | ("outputs", 0) => &["--all"],
        ("send" | "send-file", 0) => &["all"],
        ("subname", 0) => &["set", "delegate", "signer", "del", "drop"],
        _ => &[],
    };
    let mut fit: Vec<String> = known.iter().filter(|k| k.starts_with(word)).map(|k| k.to_string()).collect();
    let path = word.contains('/') || word.starts_with('.') || word.starts_with('~');
    if path || (OF_FILES.contains(&command) && fit.is_empty()) {
        // The files of the directory the word is in, that begin as it
        // does: each as the word would be written, a directory with
        // its stroke. (Those whose names begin with a dot only if the
        // word does.)
        let (dir, begun) = word.rfind('/').map_or(("", word), |at| word.split_at(at + 1));
        let home = std::env::var("HOME").unwrap_or_default();
        let read = match dir {
            "" => ".".to_string(),
            dir if dir.starts_with("~/") && !home.is_empty() => format!("{home}/{}", &dir[2..]),
            dir => dir.to_string(),
        };
        for entry in std::fs::read_dir(read).into_iter().flatten().flatten() {
            let Ok(name) = entry.file_name().into_string() else { continue };
            // (A name with a space in it cannot be said at the prompt.)
            if name.starts_with(begun) && (begun.starts_with('.') || !name.starts_with('.')) && !name.contains(' ') {
                let stroke = if entry.file_type().is_ok_and(|t| t.is_dir()) { "/" } else { "" };
                fit.push(format!("{dir}{name}{stroke}"));
            }
        }
    }
    (from, fit)
}

/// Rows `txs` lists, the last of them, unless all are asked for.
const TXS_SHOWN: usize = 30;

const CANCELLED: &str = "The transaction has been cancelled, but it could still end up in a block: \
`txs` says which of the two did.";
const BUMPED: &str = "The transaction has been replaced, but the one before it could still end up in a block: \
`txs` says which of the two did.";

/// What came of a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// To be said.
    Said(String),
    /// Something was wrong: to be said as an error.
    Wrong(String),
    /// The node is to stop.
    Quit,
    /// An empty line: nothing.
    Nothing,
    /// The wallet's password is to be asked for, and given to
    /// [`Console::seed`]: of a wallet that has one, asked for its words.
    Password,
    /// The wallet's password is to be changed: the one it has is to be
    /// asked for, if it has one ([`Console::locked`]), and the new one
    /// twice, and both given to [`Console::set_password`].
    NewPassword,
}

/// What is said of a wallet's twelve words when they are shown: when
/// the wallet is made, and when they are asked for. One line.
pub fn made(phrase: &str) -> String {
    format!("Recovery phrase: {phrase}")
}

/// What is said of a wallet made again from its words: its address,
/// which is another than the wallet had.
pub fn restored(address: &str) -> String {
    format!("Wallet's restored address: {address} (Note: this is different than the previous address)")
}

/// What the commands are run on.
pub struct Console<B: Backend + 'static, W: Backend, V = ChainVerifier> {
    pub hold: Handle<B, V>,
    /// None for a node started without a wallet.
    pub wallet: Option<Arc<Mutex<Wallet<W>>>>,
    /// The time by the calendar, in seconds.
    pub unix: fn() -> u64,
    /// Told of what this node's own wallet does with a payment (begun,
    /// answered, signed, given up): a line for the main log. Nothing of
    /// anybody else's transactions is said there.
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
    /// Whether what is only for trying things may be done here: on a
    /// network for that, in a build for that.
    pub debug: bool,
    /// Full names this wallet may be at the most ([`crate::subnames`]).
    pub max_names: usize,
    /// What is remembered between the prompt and what takes the
    /// wallet's messages.
    pub names: Arc<Mutex<Named>>,
}

/// What is remembered of full names while the node runs.
#[derive(Default)]
pub struct Named {
    /// The full name each payment begun was sent to, by its slate's
    /// id: to say it by, whatever becomes of it.
    sent: std::collections::BTreeMap<[u8; 32], String>,
    /// The names given out whose certificate did not reach the wallet
    /// it is for: given again when names are next looked to.
    again: std::collections::BTreeSet<[u8; 32]>,
}

/// An amount of coins as it is written: its whole part with commas, and
/// as many decimals as it has.
pub fn coins(units: u128) -> String {
    let (whole, part) = (units / COIN as u128, (units % COIN as u128) as u64);
    let whole = commas(whole.min(u64::MAX as u128) as u64);
    match part {
        0 => whole,
        part => format!("{whole}.{}", format!("{part:0width$}", width = DECIMALS).trim_end_matches('0')),
    }
}

/// The base units of an amount of coins as written: digits, with a
/// point and up to ten decimals if there are any. None for anything
/// else, or for more than there can be.
pub fn parse_coins(text: &str) -> Option<u64> {
    let (whole, part) = match text.split_once('.') {
        Some((_, "")) => return None,
        Some(parts) => parts,
        None => (text, ""),
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(part) || part.len() > DECIMALS {
        return None;
    }
    let part = format!("{part:0<width$}", width = DECIMALS).parse::<u64>().ok()?;
    whole.parse::<u64>().ok()?.checked_mul(COIN)?.checked_add(part)
}

/// What a line says, in its words: what is between double quotes is
/// one word, spaces and all, and is said to have been quoted.
fn split(line: &str) -> (Vec<String>, Vec<bool>) {
    let (mut words, mut quoted) = (Vec::new(), Vec::new());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.peek().copied() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' {
            chars.next();
            words.push(chars.by_ref().take_while(|c| *c != '"').collect());
            quoted.push(true);
        } else {
            let mut word = String::new();
            while let Some(c) = chars.peek().copied().filter(|c| !c.is_whitespace()) {
                word.push(c);
                chars.next();
            }
            words.push(word);
            quoted.push(false);
        }
    }
    (words, quoted)
}

/// What a slate's note says, for a line of the log or the terminal:
/// with nothing in it that would break the line.
fn shown(note: &[u8]) -> String {
    String::from_utf8_lossy(note).chars().map(|c| if c.is_control() || c == '"' { '?' } else { c }).collect()
}

fn short(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

type Said = Result<String, String>;

/// Has `wallet` note which of its outputs' leaves the pool's
/// transactions were signed from: so that a wallet whose file has gone
/// back to an earlier state never signs from one of them again. How
/// many outputs it was behind on.
/// Lets go of what the wallet expected and will not have: outputs that
/// the chain does not hold and nothing will make (of payments taken
/// back, say). How many outputs, and which names' commits. Done by the
/// wallet itself at every block (`asked` false): nobody has to ask.
pub fn tidy<B: Backend + 'static, W: Backend, V: crate::chain::verify::ProofVerifier + Sync>(
    hold: &Handle<B, V>,
    wallet: &Mutex<Wallet<W>>,
    asked: bool,
) -> Result<(usize, Vec<String>), String> {
    // (What the pool's transactions make may yet be made.)
    let (mut keep, mut commits) = (Vec::new(), Vec::new());
    hold.pool(&mut |pool| {
        for e in pool.entries() {
            keep.extend(e.tx().outputs().iter().map(|o| o.commitment));
            commits.extend(e.tx().ops().filter_map(|op| match op {
                NameOp::Commit { commit, .. } => Some(commit),
                _ => None,
            }));
        }
    });
    let mut wallet = wallet.lock().unwrap_or_else(|e| e.into_inner());
    let state = hold.chain().whole().map_err(|e| e.to_string())?;
    let snap = state.snapshot().map_err(|e| e.to_string())?;
    // (Asked for: what was added to others' payments goes too, and
    // commits to names no pool has. Of itself: neither, since whoever
    // pays may yet sign, and a commit the pool has lost is sent again.)
    let gone = wallet.prune_pending_of(&snap, &keep, asked).map_err(|e| e.to_string())?;
    let names = match asked {
        true => wallet.prune_commits(&snap, &commits).map_err(|e| e.to_string())?,
        false => Vec::new(),
    };
    Ok((gone, names))
}

pub fn observe<B: Backend + 'static, W: Backend, V: crate::chain::verify::ProofVerifier + Sync>(
    hold: &Handle<B, V>,
    wallet: &Mutex<Wallet<W>>,
) -> Result<usize, String> {
    let mut seen = Vec::new();
    hold.pool(&mut |pool| {
        for e in pool.entries() {
            seen.extend(e.tx().inputs().map(|i| (i.commitment(), i.signature.index)));
        }
    });
    wallet.lock().unwrap_or_else(|e| e.into_inner()).observe_signatures(&seen).map_err(|e| e.to_string())
}

impl<B: Backend + 'static, W: Backend, V: crate::chain::verify::ProofVerifier + Sync> Console<B, W, V> {
    /// Does what `line` asks, and gives what is to be said of it.
    pub fn run(&self, line: &str) -> Reply {
        // (Words; and what is between quotes is one, spaces and all:
        // the note of a payment, or what a burn is for.)
        let (owned, quoted) = split(line);
        let words: Vec<&str> = owned.iter().map(String::as_str).collect();
        let q = |at: usize| quoted.get(at).copied().unwrap_or(false);
        let noted = quoted.last().copied().unwrap_or(false);
        let Some((command, args)) = words.split_first() else { return Reply::Nothing };
        let said = match (*command, args) {
            ("quit" | "exit", []) => return Reply::Quit,
            ("help", []) => Ok(HELP.to_string()),
            ("status", []) => self.status(),
            ("supply", []) => self.supply(),
            ("peers", []) => self.peers(),
            ("mempool", []) => self.mempool(),
            ("fees", []) => self.fees(),
            ("leaves", []) => self.leaves(),
            ("set-leaf", [index, file]) => self.set_leaf(index, Some(file), None),
            ("set-leaf-value", [index, value]) => self.set_leaf(index, None, Some(value)),
            ("consensus", []) => self.consensus(),
            ("relays", []) => self.relays(),
            ("debug-consensus", [file]) if self.debug => self.debug_consensus(file),
            ("subname", ["set", full, to]) => self.subname_set(full, to),
            ("subname", ["delegate", name, signer, file]) => self.subname_delegate(name, signer, "30", file),
            ("subname", ["delegate", name, signer, days, file]) => self.subname_delegate(name, signer, days, file),
            ("subname", ["signer", file]) => self.subname_signer(file),
            ("subname", ["del", full]) => self.subname_del(full),
            ("subname", ["drop", full]) => self.subname_drop(full),
            ("subnames", []) => self.subnames(),
            ("balance", []) => self.balance(),
            ("address", []) => self.wallet().map(|wallet| wallet.address()),
            ("outputs", []) => self.outputs(false),
            ("outputs", ["--all"]) => self.outputs(true),
            ("txs", []) => self.txs(None, false),
            ("txs", ["--all"]) => self.txs(None, true),
            ("txs", [which @ ("pending" | "mined"), "--all"]) => self.txs(Some(which), true),
            ("txs", [which]) => self.txs(Some(which), false),
            ("mining", []) => self.mining(),
            ("send", [amount, to]) if !noted => self.send(amount, None, to, ""),
            ("send", [amount, to, note]) if noted => self.send(amount, None, to, note),
            ("send", [amount, fee, to]) if !noted => self.send(amount, Some(fee), to, ""),
            ("send", [amount, fee, to, note]) if noted => self.send(amount, Some(fee), to, note),
            ("send-file", [amount, file]) if !noted => self.send_file(amount, None, file, ""),
            ("send-file", [amount, file, note]) if noted => self.send_file(amount, None, file, note),
            ("send-file", [amount, fee, file]) if !noted => self.send_file(amount, Some(fee), file, ""),
            ("send-file", [amount, fee, file, note]) if noted => self.send_file(amount, Some(fee), file, note),
            ("payments", []) => self.payments(),
            ("payment-proof" | "burn-proof", [txid]) => self.proof(txid, "-"),
            ("payment-proof" | "burn-proof", [txid, file]) => self.proof(txid, file),
            ("verify-proof", [file]) => self.verify_proof(file),
            ("burn", [amount, purpose]) if q(2) => self.burn(amount, purpose, None, None),
            ("burn", [amount, purpose, to]) if q(2) => self.burn(amount, purpose, Some(to), None),
            ("burn", [amount, purpose, to, fee]) if q(2) => self.burn(amount, purpose, Some(to), Some(fee)),
            ("receive", [file]) => self.receive(file, &format!("{file}.received")),
            ("receive", [file, out]) => self.receive(file, out),
            ("finalize", [file]) => self.finalize(file),
            ("cancel", [id]) => self.cancel(id, None, false),
            ("cancel", [id, "yes"]) => self.cancel(id, None, true),
            ("cancel", [id, fee]) => self.cancel(id, Some(fee), false),
            ("cancel", [id, fee, "yes"]) => self.cancel(id, Some(fee), true),
            ("bump", [id]) => self.bump(id, None),
            ("bump", [id, fee]) => self.bump(id, Some(fee)),
            ("resend", [id]) => self.resend(id),
            ("prune", []) => self.prune(),
            ("password", []) => match self.wallet() {
                Ok(_) => return Reply::NewPassword,
                Err(e) => Err(e),
            },
            // (Its password asked for first, of a wallet that has one.)
            ("seed", []) => match self.wallet().map(|w| w.locked()) {
                Ok(true) => return Reply::Password,
                Ok(false) => self.seed(""),
                Err(e) => Err(e),
            },
            ("names", []) => self.names(),
            ("name", [name]) => self.name(name),
            ("name-commit", [name]) => self.name_commit(name, "", None),
            ("name-commit", [name, value]) => self.name_commit(name, value, None),
            ("name-commit", [name, value, fee]) => self.name_commit(name, value, Some(fee)),
            ("name-reveal", [name]) => self.name_reveal(name, "", None),
            ("name-reveal", [name, wait]) => self.name_reveal(name, wait, None),
            ("name-reveal", [name, wait, fee]) => self.name_reveal(name, wait, Some(fee)),
            ("name-update", [name, value]) => self.name_update(name, value, None),
            ("name-update", [name, value, fee]) => self.name_update(name, value, Some(fee)),
            ("name-offer", [name, file]) => self.name_offer(name, file, ""),
            ("name-offer", [name, file, value]) => self.name_offer(name, file, value),
            ("name-transfer", [file]) => self.name_transfer(file, None),
            ("name-transfer", [file, fee]) => self.name_transfer(file, Some(fee)),
            ("scan", []) => self.scan(),
            (known, _) if COMMANDS.contains(&known) => Err(format!("{command}: not what it takes (see help)")),
            _ => Err(format!("{command}: no such command (see help)")),
        };
        match said {
            Ok(text) => Reply::Said(text),
            Err(text) => Reply::Wrong(text),
        }
    }

    /// Whether the wallet has a password.
    pub fn locked(&self) -> bool {
        self.wallet().is_ok_and(|w| w.locked())
    }

    /// Gives the wallet the password `new` in place of `old`: either
    /// may be none.
    pub fn set_password(&self, old: &str, new: &str) -> Result<String, String> {
        self.wallet()?.set_password(old, new).map_err(|e| e.to_string())?;
        (self.log)(if new.is_empty() {
            "The wallet's password was taken off"
        } else {
            "The wallet's password was set"
        });
        Ok(match new.is_empty() {
            true => "The wallet has no password now: its file is all it takes to spend from it.".to_string(),
            false => "The wallet's password is set: it is asked for when the node starts.".to_string(),
        })
    }

    /// The wallet's twelve words, if `password` is its password (any,
    /// of a wallet that has none).
    pub fn seed(&self, password: &str) -> Result<String, String> {
        let phrase = self.wallet()?.phrase(password).map_err(|e| e.to_string())?;
        Ok(made(&phrase))
    }

    fn wallet(&self) -> Result<MutexGuard<'_, Wallet<W>>, String> {
        let wallet = self.wallet.as_ref().ok_or("this node has no wallet (it was started with --no-wallet)")?;
        Ok(wallet.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// What the chain's blocks have paid by the schedule, against what
    /// the unspent outputs come to, added up one by one: the same, or
    /// something is wrong, and it says so. (Coins burned are in outputs
    /// nobody can spend, which are among the unspent: said apart.)
    fn supply(&self) -> Said {
        let chain = self.hold.chain();
        let state = chain.whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let height = snap.tip().0;
        let expected = chain.params().issued(height);
        let (mut unspent, mut burned, mut outputs) = (0u128, 0u128, 0u64);
        let walked = snap.outputs().for_each(snap.pages(), &mut |_, record, live| {
            if live {
                outputs += 1;
                unspent += record.amount as u128;
                let nobodys = crate::output::key_commitment(&crate::proofs::BURN_KEY_HASH, record.amount);
                if record.commitment == nobodys {
                    burned += record.amount as u128;
                }
            }
        });
        walked.map_err(|e| e.to_string())?;
        let said = format!(
            "block {}\nexpected: {}\nunspent:  {} in {} outputs\nburned:   {} of them\ncirculating: {}",
            commas(height as u64),
            coins(expected),
            coins(unspent),
            commas(outputs),
            coins(burned),
            coins(unspent - burned),
        );
        match unspent == expected {
            true => Ok(format!("{said}\nthe supply is as expected")),
            false => {
                let (more, by) = (unspent > expected, coins(unspent.abs_diff(expected)));
                let which = if more { "more" } else { "less" };
                Err(format!("{said}\nTHE SUPPLY IS WRONG: the unspent outputs come to {by} {which} than was paid"))
            }
        }
    }

    fn status(&self) -> Said {
        let standing = self.hold.read();
        let tip = self.hold.chain().tip().map_err(|e| e.to_string())?;
        let (pooled, bytes) = self.hold.pool_size();
        let mut out = format!(
            "block {} ({})\npeers: {} live of {} known\npool: {} transactions, {} bytes",
            commas(tip.height as u64),
            short(&digest_to_bytes(&tip.hash())),
            commas(standing.live as u64),
            commas(standing.peers as u64),
            commas(pooled as u64),
            commas(bytes as u64)
        );
        // The message layer: where this node's wallet is reached, and
        // the wallets this node is where others are reached.
        let (sessions, reached, said) = self.hold.sessions();
        if said > 0 {
            out.push_str(&format!("\nreached at: {reached} of {said} nodes"));
        }
        if sessions > 0 {
            out.push_str(&format!("\nsessions: {} wallets are reached here", commas(sessions as u64)));
        }
        out.push_str(&format!("\nmemory: {} MB", commas(crate::heap::now() as u64 / 1_000_000)));
        // (Of the store's file, what is in use and how long it is: the
        // rest is space inside it, taken again before the file grows.)
        if let Ok(state) = self.hold.chain().whole() {
            let (used, end) = state.file().space();
            let mb = |units: u64| commas(units * crate::store::pagefile::UNIT as u64 / 1_000_000);
            // (The file's length is said only where it is another.)
            match mb(used) == mb(end) {
                true => out.push_str(&format!("\nstore: {} MB", mb(used))),
                false => out.push_str(&format!("\nstore: {} MB, in a file of {} MB", mb(used), mb(end))),
            }
        }
        if let Ok(wallet) = self.wallet() {
            let balance = follow::balance(self.hold.chain(), &wallet).map_err(|e| e.to_string())?;
            out.push_str(&format!("\nwallet: {} confirmed", coins(balance.confirmed)));
        }
        Ok(out)
    }

    fn peers(&self) -> Said {
        let standing = self.hold.read();
        let mut lines = vec![format!(
            "{} peers known, {} of them live",
            commas(standing.peers as u64),
            commas(standing.live as u64)
        )];
        // Each of them: where it is, how it stands, how high it says
        // its chain is, and how long since anything came from it.
        for peer in self.hold.peer_list() {
            let stands = match (peer.live, peer.answered) {
                (true, _) => "live",
                (false, true) => "silent",
                (false, false) => "never answered",
            };
            let height = peer.height.map_or("-".to_string(), |h| format!("block {}", commas(h as u64)));
            let heard = match peer.silent {
                Some(micros) => format!("heard {} s ago", commas(micros / 1_000_000)),
                None => "never heard".to_string(),
            };
            let seed = if peer.seed { "  (seed or given)" } else { "" };
            lines.push(format!("  {:<21}  {stands:<14}  {height:<14}  {heard}{seed}", peer.addr.to_string()));
        }
        Ok(lines.join("\n"))
    }

    /// The sixteen leaves the blocks made here commit to, and their
    /// root: what a header's auxiliary bytes are.
    fn leaves(&self) -> Said {
        let chain = self.hold.chain();
        let leaves = chain.aux_leaves().map_err(|e| e.to_string())?;
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut lines: Vec<String> = Vec::new();
        for (i, leaf) in leaves.iter().enumerate().filter(|(_, leaf)| **leaf != [0u8; 32]) {
            let what = if i == 0 { "  (the vote for a consensus file)" } else { "" };
            lines.push(format!("  {i:>2}  {}{what}", hex(leaf)));
        }
        if lines.is_empty() {
            return Ok("no leaf is set: the blocks made here commit to nothing".to_string());
        }
        lines.push(format!("root  {}", hex(&chain.aux_root().map_err(|e| e.to_string())?)));
        Ok(lines.join("\n"))
    }

    /// Sets one of the leaves: to the SHA-256 of a file, or to 32 bytes
    /// given in hex. Leaf 0 is the vote for a consensus file: the file
    /// must be one, and is kept, to be served to whoever asks for what
    /// was voted for.
    fn set_leaf(&self, index: &str, file: Option<&str>, value: Option<&str>) -> Said {
        use crate::chain::leaves::AUX_LEAVES;
        let chain = self.hold.chain();
        let index: usize = index.parse().ok().filter(|i| *i < AUX_LEAVES).ok_or("the leaves are 0 to 15")?;
        let (leaf, said) = match (file, value) {
            (Some(file), _) => {
                let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
                match index {
                    0 => {
                        let parsed = crate::consensus::File::parse(&bytes).map_err(|e| format!("{file}: {e}"))?;
                        let hash = chain.put_consensus_file(&bytes).map_err(|e| e.to_string())?;
                        (hash, format!("the blocks made here vote for {file}: mode {}", parsed.mode))
                    }
                    _ => (crate::sha256::sha256(&bytes), format!("leaf {index} is the SHA-256 of {file}")),
                }
            }
            (None, Some(value)) => {
                let digits = value.as_bytes();
                if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
                    return Err("the value is 64 hex digits".to_string());
                }
                let leaf: [u8; 32] =
                    core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap());
                // (A vote is for a file this node can hand over: not
                // for whatever a number happens to name. But none at
                // all is a vote withdrawn.)
                if index == 0 && leaf != [0u8; 32] && chain.consensus_file(&leaf).map_err(|e| e.to_string())?.is_none()
                {
                    return Err("leaf 0 is a vote for a consensus file: set it with set-leaf 0 FILE".to_string());
                }
                (leaf, format!("leaf {index} is set"))
            }
            (None, None) => return Err("nothing to set it to".to_string()),
        };
        let root = chain.set_aux_leaf(index, leaf).map_err(|e| e.to_string())?;
        (self.log)(&format!("Leaf {index} of the blocks made here was set"));
        let hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!("{said}\nroot  {hex}"))
    }

    /// The consensus file in force, how it was voted for, and what it
    /// says.
    /// Puts a consensus file in force at this node alone, whatever the
    /// chain has decided: to try what relays do without a day of
    /// blocks voting for them.
    fn debug_consensus(&self, path: &str) -> Said {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let file = crate::consensus::File::parse(&bytes).map_err(|e| format!("{path}: {e}"))?;
        self.hold.force_consensus(&file);
        Ok(format!(
            "here the message layer is in {} mode, of {} relays, whatever the chain decides",
            file.mode,
            file.relays.len()
        ))
    }

    fn consensus(&self) -> Said {
        use crate::consensus::{Current, Skip, WINDOW, boundary};
        let chain = self.hold.chain();
        let (current, votes) = chain.consensus().map_err(|e| e.to_string())?;
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        // (Why a file voted for does not count, beside its votes: but
        // for too few votes in all, which the line above them says.)
        let why = |skip: &Skip| match skip {
            Skip::TooFew(_) => String::new(),
            skip => format!(" ({skip})"),
        };
        let height = self.hold.read().height;
        let mut lines = vec![format!("Mode: {}", current.mode)];
        if let Some((hash, _)) = &current.winner {
            lines.push(format!("File: {}", hex(hash)));
        }
        // What decided it: nothing, before the first boundary.
        if boundary(height) > 0 {
            lines.push(format!(
                "Decided at block: {} ({} of {} votes)",
                commas(boundary(height) as u64),
                commas(votes.cast() as u64),
                commas(votes.blocks as u64)
            ));
            for (hash, n, skip) in current.skipped.iter().filter(|s| !matches!(s.2, Skip::TooFew(_))) {
                lines.push(format!("    not counted: {}: {}{}", hex(hash), commas(*n as u64), why(skip)));
            }
        }
        if let Some(file) = &current.file {
            lines.push(format!("Relays: {} (see: relays)", commas(file.relays.len() as u64)));
        }
        let next = boundary(height) + WINDOW;
        lines.push(format!("Next decision block: {}", commas(next as u64)));
        // What is being voted for now, towards the next boundary; and
        // of each file, whether it would count were it decided as it
        // stands: so that a file that is not held, or is no file, is
        // found out now and not at the boundary.
        let running = chain.consensus_votes(height + 1 - boundary(height)).map_err(|e| e.to_string())?;
        match running.counts.is_empty() {
            true => lines.push("Votes: none".to_string()),
            false => {
                let would = Current::decide(&running, WINDOW, |hash| chain.consensus_file(hash).ok().flatten());
                lines.push(format!("Votes ({} needed):", Current::needed(WINDOW)));
                for (hash, n, _) in &running.counts {
                    let skipped = would.skipped.iter().find(|s| s.0 == *hash).map_or(String::new(), |s| why(&s.2));
                    lines.push(format!("    {}: {}{skipped}", hex(hash), commas(*n as u64)));
                }
            }
        }
        // What the blocks made here vote for: of those begun since it
        // was set (one being made when it was set does not carry it).
        lines.push(match chain.aux_leaves().map_err(|e| e.to_string())?[0] {
            vote if vote == [0u8; 32] => "Our vote: none".to_string(),
            vote => format!("Our vote: {}", hex(&vote)),
        });
        Ok(lines.join("\n"))
    }

    /// The relays of the consensus file in force, one a line: there may
    /// be thousands, so they are not part of what `consensus` says.
    /// With a mark beside those this node's wallet is to be reached at,
    /// and whether it is; while no file names relays, the seeds that
    /// stand in for them.
    fn relays(&self) -> Said {
        let (current, _) = self.hold.chain().consensus().map_err(|e| e.to_string())?;
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        // Where this node's wallet is reached, by what is in force.
        let points = self.hold.rendezvous().map(|(_, nodes)| nodes).unwrap_or_default();
        let mark = |addr: &str| match points.iter().find(|(node, _)| node.to_string() == addr) {
            Some((_, true)) => "  *",
            Some((_, false)) => "  * (not reached)",
            None => "",
        };
        let reached = points.iter().filter(|node| node.1).count();
        let own = match (self.wallet.is_some(), points.len()) {
            (false, _) => None,
            (true, 0) => Some("This wallet is reached nowhere yet".to_string()),
            (true, n) => Some(format!("This wallet is reached at {reached} of its {n} (marked *)")),
        };
        let mut lines = Vec::new();
        match (&current.winner, &current.file) {
            (Some((hash, _)), Some(file)) => {
                lines.push(format!("Relays of {}: {}", hex(hash), commas(file.relays.len() as u64)));
                lines.extend(own);
                for relay in &file.relays {
                    let id = crate::address::encode(&relay.id);
                    lines.push(format!("    {id} {}{}", relay.addr, mark(&relay.addr)));
                }
            }
            _ => {
                lines.push("No file is in force: the seeds stand in for relays".to_string());
                lines.extend(own);
                for (node, _) in &points {
                    lines.push(format!("    {node}{}", mark(&node.to_string())));
                }
            }
        }
        Ok(lines.join("\n"))
    }

    /// What a payment is to pay to be in a block soon, by the hour, or
    /// within the day: as the pool reckons it from what it holds and
    /// what it has seen blocks take.
    fn fees(&self) -> Said {
        use crate::mempool::{TARGET_BLOCK, TARGET_DAY, TARGET_HOUR};
        let unix = (self.unix)();
        // A simple payment: an input, and an output and change.
        let weight = Wallet::<W>::payment_weight(1);
        let size = 16 + crate::output::INPUT_SIZE + 2 * crate::output::OUTPUT_SIZE;
        let mut lines = Vec::new();
        self.hold.pool(&mut |pool| {
            lines.push(format!(
                "the least a unit of weight is {}; the pool takes from {}",
                commas(pool.policy().min_fee_per_unit),
                commas(pool.admission_fee(unix))
            ));
            for (what, target) in [("next block", TARGET_BLOCK), ("an hour", TARGET_HOUR), ("a day", TARGET_DAY)] {
                let seen = if pool.estimate(target, unix).is_some() { "" } else { " (too little seen yet: the least)" };
                lines.push(format!("  within {what:<11} {} a unit{seen}", commas(pool.suggest(target, size, unix))));
            }
            lines.push(match pool.reserve_wait(size) {
                Some(blocks) => format!(
                    "  the least         {} a unit: about {} blocks at the most, by its age",
                    commas(pool.admission_fee(unix)),
                    commas(blocks)
                ),
                None => format!(
                    "  the least         {} a unit: when blocks have room for it (nothing is kept here for what waits)",
                    commas(pool.admission_fee(unix))
                ),
            });
        });
        lines.push(format!(
            "a simple payment weighs {} (an input 1, an output 3 by default); fees are in base units",
            commas(weight)
        ));
        Ok(lines.join("\n"))
    }

    fn mempool(&self) -> Said {
        let mut lines = Vec::new();
        let unix = (self.unix)();
        self.hold.pool(&mut |pool| {
            lines.push(format!(
                "{} transactions, {} bytes; the pool asks {} a unit of weight",
                commas(pool.len() as u64),
                commas(pool.bytes() as u64),
                commas(pool.admission_fee(unix))
            ));
            let mut entries: Vec<_> = pool.entries().collect();
            entries.sort_by_key(|e| (e.arrived, e.order));
            for e in entries.iter().take(50) {
                lines.push(format!(
                    "  {}  {} bytes  weight {}  fee {}  ({} a unit)",
                    short(&digest_to_bytes(&e.txid)),
                    commas(e.size() as u64),
                    commas(e.weight),
                    coins(e.fee as u128),
                    commas(e.fee / e.weight.max(1))
                ));
            }
            if entries.len() > 50 {
                lines.push(format!("  and {} more", commas(entries.len() as u64 - 50)));
            }
        });
        Ok(lines.join("\n"))
    }

    fn balance(&self) -> Said {
        let wallet = self.wallet()?;
        let b = follow::balance(self.hold.chain(), &wallet).map_err(|e| e.to_string())?;
        // What is there to spend, first; then what is confirmed and
        // has not been in the chain long enough to be.
        let mut out = format!("spendable   {}", coins(b.spendable));
        if b.confirmed > b.spendable {
            out.push_str(&format!(
                "\nconfirmed   {}  (in the chain for fewer than {} blocks: not spent yet)",
                coins(b.confirmed - b.spendable),
                wallet.min_confirmations()
            ));
        }
        // (Of what was in the chain and is no longer, the rewards of
        // blocks this node made are not here: they are nothing the
        // wallet was paid, and `mining` says them.)
        let rewards: std::collections::BTreeSet<_> =
            wallet.rewards().into_iter().map(|(c, ..)| digest_to_bytes(&c)).collect();
        let all = wallet.outputs();
        let orphaned =
            all.iter().filter(|o| rewards.contains(&digest_to_bytes(&o.commitment)) && wallet.is_lost(&o.commitment));
        let orphaned: u128 = orphaned.map(|o| o.amount as u128).sum();
        let rest = [
            ("pending", b.pending),
            ("unverified", b.unverified),
            ("reserved", b.reserved),
            ("locked", b.locked),
            ("orphaned", b.lost.saturating_sub(orphaned)),
        ];
        for (what, amount) in rest {
            if amount > 0 {
                out.push_str(&format!("\n{what:<11} {}", coins(amount)));
            }
        }
        Ok(out)
    }

    /// The blocks this node won, of those not yet so deep in the chain
    /// that nothing undoes them: how many, what they paid, and each
    /// that was orphaned (undone, for a longer chain that has not it).
    fn mining(&self) -> Said {
        let wallet = self.wallet()?;
        let chain = self.hold.chain();
        let amounts: std::collections::BTreeMap<_, _> =
            wallet.outputs().iter().map(|o| (digest_to_bytes(&o.commitment), o.amount)).collect();
        let mut won = Vec::new();
        for (c, height, block) in wallet.rewards() {
            // (One of no block yet is of the block being made now.)
            if block == [0; 32] {
                continue;
            }
            let header = chain.header_at(height).map_err(|e| e.to_string())?;
            let kept = header.is_some_and(|h| digest_to_bytes(&h.hash()) == block);
            won.push((height, block, amounts.get(&digest_to_bytes(&c)).copied().unwrap_or(0), kept));
        }
        won.sort_by_key(|(height, ..)| std::cmp::Reverse(*height));
        let within = commas(chain.keep() as u64);
        if won.is_empty() {
            return Ok(format!("no blocks won in the last {within} (those before are settled, and not kept count of)"));
        }
        let total = |kept: bool| -> (usize, u128) {
            let of = won.iter().filter(|w| w.3 == kept);
            (of.clone().count(), of.map(|w| w.2 as u128).sum())
        };
        let ((kept, paid), (orphans, gone)) = (total(true), total(false));
        let mut said = format!(
            "blocks won in the last {within}: {} in the chain, which paid {}",
            commas(kept as u64),
            coins(paid)
        );
        if orphans > 0 {
            said.push_str(&format!("; {} orphaned, which would have paid {}", commas(orphans as u64), coins(gone)));
        }
        let mut lines = vec![said];
        let line = |(height, block, amount, kept): &(u32, [u8; 32], u64, bool)| {
            let what = if *kept { "in the chain" } else { "orphaned" };
            format!("  block {:>9} ({})  {:>20}  {what}", commas(*height as u64), short(block), coins(*amount as u128))
        };
        // The newest of those kept, and every one that was not.
        const SHOWN: usize = 10;
        lines.extend(won.iter().filter(|w| w.3).take(SHOWN).map(line));
        if kept > SHOWN {
            lines.push(format!("  … and {} before", commas((kept - SHOWN) as u64)));
        }
        if orphans > 0 {
            lines.push("orphaned (another chain went further without them; what they paid is not there):".to_string());
            lines.extend(won.iter().filter(|w| !w.3).map(line));
        }
        Ok(lines.join("\n"))
    }

    fn outputs(&self, all: bool) -> Said {
        use crate::wallet::Unspent;
        let wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let tip = snap.tip().0;
        let dash = |n: Option<u64>| n.map_or("-".to_string(), commas);
        // In the order they lie in the chain; those in no block last,
        // as they were made.
        let mut outputs = wallet.outputs();
        outputs.sort_by_key(|o| (o.position.is_none(), o.position, o.created));
        let (mut rows, mut spent_ones) = (Vec::new(), 0u64);
        // (Which rows made and spend each: found for all at once.)
        let of_rows = wallet.rows_of_outputs();
        for o in outputs {
            let held = wallet.held(&o, &snap).map_err(|e| e.to_string())?;
            // The block that made it: the chain says, while it is
            // unspent there; of one spent, the row that made it does.
            let deep = o.position.and_then(|p| snap.confirmations(p, &o.commitment).ok().flatten());
            let (made, spent) = of_rows.get(&digest_to_bytes(&o.commitment)).copied().unwrap_or_default();
            let block = deep.map(|deep| u64::from(tip + 1 - deep.min(tip + 1))).or_else(|| {
                let height = made.and_then(|n| wallet.listed(n)).map_or(0, |row| row.height);
                (height > 0 && o.position.is_some()).then_some(u64::from(height))
            });
            let wait = wallet.min_confirmations().saturating_sub(deep.unwrap_or(0));
            let what = match (o.state, held) {
                (State::Unspent, true) if wait > 0 => {
                    format!("spendable in {wait} block{}", if wait == 1 { "" } else { "s" })
                }
                (State::Unspent, true) => "confirmed".to_string(),
                (State::Unspent, false) if wallet.is_lost(&o.commitment) => "orphaned".to_string(),
                (State::Unspent, false) => "pending".to_string(),
                (State::Reserved, _) => "reserved".to_string(),
                (State::Spent, true) => "locked".to_string(),
                (State::Spent, false) => "spent".to_string(),
            };
            if what == "spent" {
                spent_ones += 1;
                if !all {
                    continue;
                }
            }
            // (How many of its eight signatures are used; the last one
            // left is marked.)
            let last = if o.signatures_left() == 1 { " *last*" } else { "" };
            let sigs = format!("{}{last}", o.used);
            // (What the slate that paid it said it was for.)
            let note = wallet.note_of(&o.commitment).map_or(String::new(), |note| format!("  \"{}\"", shown(note)));
            rows.push((
                what,
                [
                    short(&digest_to_bytes(&o.commitment)),
                    coins(o.amount as u128),
                    dash(block),
                    dash(o.position),
                    sigs,
                    dash(made.map(u64::from)),
                    dash(spent.map(u64::from)),
                ],
                note,
            ));
        }
        let wide = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(9);
        let mut lines = vec![format!(
            "  {:<8}  {:>24}  {:<wide$}  {:>9}  {:>12}  {:<8}  {:>7}  {:>8}",
            "id", "amount", "state", "block", "position", "sigs", "made by", "spent by"
        )];
        for (what, [id, amount, block, position, sigs, made, spent], note) in &rows {
            lines.push(format!(
                "  {id}  {amount:>24}  {what:<wide$}  {block:>9}  {position:>12}  {sigs:<8}  {made:>7}  {spent:>8}{note}"
            ));
        }
        let mut out = match rows.len() {
            0 if all || spent_ones == 0 => "no outputs".to_string(),
            0 => "no unspent outputs".to_string(),
            _ => lines.join("\n"),
        };
        if !all && spent_ones > 0 {
            out.push_str(&format!(
                "\nSpent outputs are not listed ({}): outputs --all lists every output.",
                commas(spent_ones)
            ));
        }
        Ok(out)
    }

    /// The wallet's list of what it has done and been paid
    /// ([`crate::wallet::list`]): all of it, a part of it (`pending`,
    /// `mined`), or everything of one row.
    fn txs(&self, which: Option<&&str>, all: bool) -> Said {
        use crate::wallet::Unspent;
        use crate::wallet::list::{Kind, Row, Stage};
        let wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let tip = snap.tip().0;
        let kind = |row: &Row| match row.kind {
            Kind::Sent => "sent".to_string(),
            Kind::Received => "received".to_string(),
            Kind::Reward => "reward".to_string(),
            Kind::Burn => "burn".to_string(),
            Kind::NameCommit => "name commit".to_string(),
            Kind::NameReveal => "name reveal".to_string(),
            Kind::NameUpdate => "name update".to_string(),
            Kind::NameTransfer => "name transfer".to_string(),
            Kind::Cancel => format!("cancel of {}", row.of),
            Kind::Bump => format!("bump of {}", row.of),
        };
        let stage = |row: &Row| match row.stage {
            Stage::Begun if row.is_output() => "pending".to_string(),
            Stage::Begun => "begun".to_string(),
            Stage::Pooled => match crate::hash::digest_from_bytes(&row.txid) {
                Some(txid) if !self.hold.pooled(&txid) => format!("not in the pool (resend {})", row.number),
                _ => "pooled".to_string(),
            },
            Stage::Confirmed => "confirmed".to_string(),
            Stage::Cancelled => "cancelled".to_string(),
            Stage::Replaced => format!("replaced by {}", row.by),
            Stage::Orphaned => "orphaned".to_string(),
            Stage::Remake => "to be made again".to_string(),
            Stage::Failed => "failed".to_string(),
        };
        // The block: of an output, the one the chain says made it; of a
        // transaction, the height at which it was seen to be in.
        let block = |row: &Row| -> Option<u64> {
            if row.stage != Stage::Confirmed {
                return None;
            }
            // (As the row has it; of an output from before rows kept
            // it, as the chain says while it is unspent.)
            match row.is_output() {
                _ if row.height > 0 => Some(u64::from(row.height)),
                true => {
                    let o = wallet.owned(&crate::hash::digest_from_bytes(&row.id)?)?;
                    let deep = snap.confirmations(o.position?, &o.commitment).ok().flatten()?;
                    Some(u64::from(tip + 1 - deep.min(tip + 1)))
                }
                false => None,
            }
        };
        let dash = |n: Option<u64>| n.map_or("-".to_string(), commas);
        let amount = |n: u64| if n == 0 { "-".to_string() } else { coins(n as u128) };
        // Whom a row is of, after it: the name of a step of a name; of
        // a payment made, the address it paid (cut short in the list)
        // and before it the name it was made to, where the wallet that
        // was paid signed for one; of a payment received, the name it
        // was paid as. The address is what a payment is to: the name
        // is how it was found, and is there or not.
        let whom = |row: &Row, short_address: bool| -> String {
            let name = String::from_utf8_lossy(&row.name);
            match row.kind {
                Kind::Sent => {
                    let address = wallet.paid_to(&row.txid).map(|to| crate::address::encode(&to));
                    let address = address.map(|a| match short_address {
                        true => format!("{}…{}", &a[..8], &a[a.len() - 6..]),
                        false => a,
                    });
                    match (row.name.is_empty(), address) {
                        (true, None) => String::new(),
                        (true, Some(address)) => format!("  to {address}"),
                        (false, None) => format!("  to {name}"),
                        (false, Some(address)) => format!("  to {name} ({address})"),
                    }
                }
                Kind::Received if !row.name.is_empty() => format!("  as {name}"),
                _ if row.name.is_empty() => String::new(),
                _ => format!("  @{name}"),
            }
        };
        let rows: Vec<&Row> = match which.copied() {
            None => wallet.list().iter().collect(),
            Some("pending") => wallet
                .list()
                .iter()
                .filter(|r| matches!(r.stage, Stage::Begun | Stage::Pooled | Stage::Remake))
                .collect(),
            Some("mined") => wallet.list().iter().filter(|r| r.kind == Kind::Reward).collect(),
            Some(n) => {
                let row = &Self::row(&wallet, n)?;
                // Everything of one row.
                let id = row.transaction().unwrap_or(row.id);
                let mut out = format!("{}  {}  {}", row.number, kind(row), stage(row));
                out.push_str(&whom(row, false));
                out.push_str(&format!("\namount: {}\nfee: {}", amount(row.amount), amount(row.fee)));
                out.push_str(&format!("\nblock: {}", dash(block(row))));
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                out.push_str(&format!("\nid: {hex}"));
                if let Some(sent) = wallet.sent().into_iter().find(|s| digest_to_bytes(&s.txid) == row.txid) {
                    let positions = sent.tx.spent_positions();
                    for (c, at) in sent.inputs.iter().zip(positions) {
                        let used = wallet.owned(c).map_or("-".to_string(), |o| o.used.to_string());
                        out.push_str(&format!(
                            "\nspends: {} at {} (signatures used of its key: {used})",
                            short(&digest_to_bytes(c)),
                            commas(at)
                        ));
                    }
                    for o in &sent.tx.outputs {
                        let whose = if wallet.owned(&o.commitment).is_some() { " (this wallet's)" } else { "" };
                        out.push_str(&format!(
                            "\nmakes: {}  {}{whose}",
                            short(&digest_to_bytes(&o.commitment)),
                            coins(o.amount as u128)
                        ));
                    }
                }
                if let Some(payment) = wallet.payments().into_iter().find(|p| digest_to_bytes(&p.txid) == row.txid) {
                    out.push_str(if payment.proven { "\nproof: ready" } else { "\nproof: not yet" });
                }
                if row.is_output()
                    && let Some(c) = crate::hash::digest_from_bytes(&row.id)
                    && let Some(note) = wallet.note_of(&c)
                {
                    out.push_str(&format!("\nnote: \"{}\"", shown(note)));
                }
                return Ok(out);
            }
        };
        // The last of them, unless all are asked for: a miner's list
        // is of every block it has made.
        let earlier = if all { 0 } else { rows.len().saturating_sub(TXS_SHOWN) };
        let rows = &rows[earlier..];
        let stages: Vec<String> = rows.iter().map(|row| stage(row)).collect();
        let wide = stages.iter().map(|s| s.len()).max().unwrap_or(0).max(16);
        let mut lines = vec![format!(
            "  {:>4}  {:<14}  {:<wide$}  {:>24}  {:>14}  {:>9}  {}",
            "#", "kind", "state", "amount", "fee", "block", "id"
        )];
        for (row, stage) in rows.iter().zip(&stages) {
            let name = whom(row, true);
            lines.push(format!(
                "  {:>4}  {:<14}  {stage:<wide$}  {:>24}  {:>14}  {:>9}  {}{name}",
                row.number,
                kind(row),
                amount(row.amount),
                amount(row.fee),
                dash(block(row)),
                short(&row.transaction().unwrap_or(row.id)),
            ));
        }
        match (lines.len(), which.copied()) {
            (1, Some("pending")) => Ok("nothing pending".to_string()),
            (1, Some("mined")) => Ok("no rewards yet".to_string()),
            (1, _) => Ok("nothing yet".to_string()),
            _ if earlier > 0 => {
                let of = which.map_or(String::new(), |which| format!(" {which}"));
                Ok(format!(
                    "{}\nThe last {TXS_SHOWN} are listed, of {}: txs{of} --all lists every one.",
                    lines.join("\n"),
                    commas((earlier + rows.len()) as u64)
                ))
            }
            _ => Ok(lines.join("\n")),
        }
    }

    /// The row of `txs` a command is told of: by its number, or by the
    /// first digits of an id it has ([`Wallet::row`]).
    fn row(wallet: &Wallet<W>, what: &str) -> Result<crate::wallet::list::Row, String> {
        wallet.row(what).cloned().map_err(|fit| match fit[..] {
            [] => format!("no row with that number, or an id that starts {what}: see txs"),
            _ => {
                let rows: Vec<String> = fit.iter().map(|n| n.to_string()).collect();
                format!("rows {} have ids that start {what}: say more of it, or the row's number", rows.join(", "))
            }
        })
    }

    /// The transaction of `row`, if it is one this wallet signed that
    /// no block has: what can be taken back, sped up or sent again
    /// (`doing`). Else why not.
    fn in_flight(row: &crate::wallet::list::Row, doing: &str) -> Result<crate::hash::Digest, String> {
        use crate::wallet::list::Stage;
        let n = row.number;
        match row.stage {
            _ if row.is_output() => Err(format!("row {n} came to this wallet: there is nothing to {doing}")),
            Stage::Pooled | Stage::Remake => {
                crate::hash::digest_from_bytes(&row.txid).ok_or_else(|| format!("row {n} has no transaction"))
            }
            Stage::Begun => Err(format!("row {n} is not signed yet: there is nothing to {doing}")),
            Stage::Confirmed => Err(format!("a block has it already: there is nothing to {doing}")),
            _ => Err(format!("row {n} is done with already")),
        }
    }

    /// Writes `text` to the file `file`, or gives it to be said if the
    /// file is `-`; else says `done`.
    fn write(file: &str, text: String, done: String) -> Said {
        if file == "-" {
            return Ok(format!("{text}{done}"));
        }
        std::fs::write(Path::new(file), text).map_err(|e| format!("cannot write {file}: {e}"))?;
        Ok(done)
    }

    fn read_slate(file: &str) -> Result<Slate, String> {
        let text = std::fs::read_to_string(Path::new(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        Slate::from_text(&text).ok_or_else(|| format!("{file} holds no slate"))
    }

    /// What is said of a payment the wallet could not make: where it
    /// has the funds and they have not been in the chain long enough to
    /// spend, that, and not that it has none.
    fn short_of(wallet: &Wallet<W>, chain: &impl crate::wallet::Unspent, e: crate::wallet::WalletError) -> String {
        let crate::wallet::WalletError::Insufficient { have, need } = e else { return e.to_string() };
        let waiting = wallet.balance(chain).map_or(0, |b| b.confirmed.saturating_sub(b.spendable));
        let blocks = wallet.min_confirmations();
        match waiting {
            0 => format!("insufficient funds: {} to spend, {} needed", coins(have), coins(need)),
            waiting => format!(
                "nothing to spend it from yet: {} to spend, {} needed. {} more is confirmed, but the wallet spends \
                 only what has been in the chain for {blocks} blocks (--min-confirmations)",
                coins(have),
                coins(need),
                coins(waiting)
            ),
        }
    }

    /// A fee as it is written: coins in all, or `N/unit`; the least
    /// that will do if none is.
    /// The fee as it was said; or, said nothing of, the least: which is
    /// this node's own least, where that is more than the network's
    /// (else its own pool would not take what its wallet makes).
    fn fee(&self, text: Option<&&str>) -> Result<Fee, String> {
        let mut floor = 0;
        self.hold.pool(&mut |pool| floor = pool.policy().min_fee_per_unit);
        let floor = floor.max(crate::mempool::MIN_FEE_PER_UNIT);
        match text {
            None => Ok(Fee::PerUnit(floor)),
            Some(text) => match text.strip_suffix("/unit") {
                Some(rate) => match rate.parse().map_err(|_| format!("'{text}' is not a fee"))? {
                    rate if rate < floor => {
                        Err(format!("this node takes nothing that pays less than {floor} a unit of weight"))
                    }
                    rate => Ok(Fee::PerUnit(rate)),
                },
                None => Ok(Fee::Total(parse_coins(text).ok_or_else(|| format!("'{text}' is not a fee"))?)),
            },
        }
    }

    fn observe(&self) -> Result<usize, String> {
        match &self.wallet {
            Some(wallet) => observe(&self.hold, wallet),
            None => Ok(0),
        }
    }

    /// The amount a payment is of, as it was said: so many coins; or
    /// `all`, which is everything the wallet can spend, less the fee
    /// of spending it into one output. As many outputs as a block
    /// takes signatures at the most, the largest: with it, how many
    /// are left for another payment.
    fn amount_of(
        wallet: &Wallet<W>,
        chain: &impl crate::wallet::Unspent,
        said: &str,
        fee: Fee,
    ) -> Result<(u64, usize), String> {
        if said != "all" {
            let amount = parse_coins(said).ok_or_else(|| format!("'{said}' is not an amount of coins, nor `all`"))?;
            return Ok((amount, 0));
        }
        // (Largest first, as the wallet takes them.)
        let spendable = wallet.spendable(chain).map_err(|e| e.to_string())?;
        let taken = spendable.len().min(crate::miner::MAX_SIGNATURES);
        let total: u128 = spendable[..taken].iter().map(|o| o.amount as u128).sum();
        let fee = fee.for_weight(Wallet::<W>::payment_weight(taken)) as u128;
        match total.checked_sub(fee).filter(|left| *left >= crate::mempool::Policy::MAINNET.dust as u128 && taken > 0) {
            Some(amount) => Ok((amount as u64, spendable.len() - taken)),
            None => {
                Err(format!("there is nothing to send: {} can be spent, and the fee is {}", coins(total), coins(fee)))
            }
        }
    }

    /// What is said after a payment of `all` that did not take all.
    fn left_over(left: usize) -> String {
        match left {
            0 => String::new(),
            n => format!(
                " ({} outputs are left: no more than {} fit one transaction; send all again for those)",
                commas(n as u64),
                crate::miner::MAX_SIGNATURES
            ),
        }
    }

    fn send_file(&self, amount: &str, fee: Option<&&str>, file: &str, note: &str) -> Said {
        let fee = self.fee(fee)?;
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let (amount, left) = Self::amount_of(&wallet, &snap, amount, fee)?;
        let slate = wallet
            .send_noted(amount, fee, note.as_bytes(), &snap, (self.unix)())
            .map_err(|e| Self::short_of(&wallet, &snap, e))?;
        let done = format!(
            "Payment {} begun: {} and a fee of {}, from {} outputs{}",
            &slate.id_hex()[..8],
            coins(slate.amount as u128),
            coins(slate.fee as u128),
            slate.inputs.len(),
            Self::left_over(left)
        );
        (self.log)(&done);
        Self::write(file, slate.to_text(), format!("{done}; to be answered and then finalized"))
    }

    /// The payments made and the coins burned: each one's
    /// transaction, how much, to whom or for what, the block that has
    /// it, and whether its proof is ready.
    fn payments(&self) -> Said {
        use crate::proofs::Claim;
        let wallet = self.wallet()?;
        let mut lines = Vec::new();
        for p in wallet.payments() {
            let what = match &p.proof.claim {
                Claim::Payment { receipt, note, .. } => {
                    let note = if note.is_empty() { String::new() } else { format!(" \"{}\"", shown(note)) };
                    format!("paid to {}{note}", crate::address::encode(&receipt.recipient()))
                }
                Claim::Burn(burn) => format!("burned for {}, for \"{}\"", burn.beneficiary.said(), burn.purpose),
            };
            let at = match (p.landed, p.proven) {
                (Some((height, _)), true) => format!("in block {}, proof ready", commas(height as u64)),
                (Some((height, _)), false) => format!("in block {}, no proof yet", commas(height as u64)),
                (None, _) => "in no block yet".to_string(),
            };
            lines.push(format!(
                "  {}  {:>20}  {what}: {at}",
                short(&digest_to_bytes(&p.txid)),
                coins(p.proof.amount as u128)
            ));
        }
        match lines.is_empty() {
            true => Ok("no payments made, and nothing burned".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    /// The proof of the payment (or the burn) of the transaction whose
    /// id begins `txid`: text, written to `file` or said. Made now, if
    /// a block has the payment and its path has not been taken yet.
    fn proof(&self, txid: &str, file: &str) -> Said {
        let mut wallet = self.wallet()?;
        let hex = |p: &crate::wallet::Payment| Self::hex(&p.txid);
        // (A row of `txs`, by its number or an id of its; or, of a
        // wallet from before there were rows, the transaction's.)
        let of_row = wallet.row(txid).ok().and_then(|row| row.transaction());
        let mut found: Vec<crate::wallet::Payment> = wallet
            .payments()
            .into_iter()
            .filter(|p| match of_row {
                Some(of_row) => digest_to_bytes(&p.txid) == of_row,
                None => !txid.is_empty() && hex(p).starts_with(txid),
            })
            .collect();
        let payment = match found.len() {
            0 => {
                return Err(format!(
                    "no payment or burn is row {txid}, or of a transaction that begins {txid} (see txs)"
                ));
            }
            1 => found.remove(0),
            n => return Err(format!("{n} payments are of transactions that begin {txid}: say more of it")),
        };
        let Some((height, position)) = payment.landed else {
            return Err("that payment is in no block yet: there is nothing to prove".to_string());
        };
        if !payment.proven {
            let path = self.hold.chain().output_proof_at(position, height).map_err(|e| {
                format!("the block that has it is further back than this node can go to make its proof: {e}")
            })?;
            let Some((record, path)) = path else { return Err("the chain has no such output there".to_string()) };
            wallet.prove_payment(&payment.txid, height, position, &record.memo, path).map_err(|e| e.to_string())?;
        }
        let payment = wallet.payments().into_iter().find(|p| p.txid == payment.txid).filter(|p| p.proven);
        let payment = payment.ok_or("the output the chain has there is another's: no proof")?;
        let done =
            format!("the proof of {}, in block {}", short(&digest_to_bytes(&payment.txid)), commas(height as u64));
        Self::write(file, payment.proof.to_text(), done)
    }

    /// Checks the proof in `file` against this node's chain, and says
    /// what it shows.
    fn verify_proof(&self, file: &str) -> Said {
        use crate::proofs::Claim;
        let text = std::fs::read_to_string(Path::new(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        let proof = crate::proofs::Proof::from_text(&text).ok_or_else(|| format!("{file} holds no proof"))?;
        let chain = self.hold.chain();
        let header = chain.header_at(proof.height).map_err(|e| e.to_string())?;
        let header = header.ok_or_else(|| {
            format!("the chain here has no block {}: the proof cannot be checked", commas(proof.height as u64))
        })?;
        proof.check(&header.state_root).map_err(|e| format!("the proof does not hold: {e}"))?;
        let confirmations = self.hold.read().height.saturating_sub(proof.height) + 1;
        let block = format!(
            "Block: {} ({}) ({} confirmation{})",
            commas(proof.height as u64),
            short(&digest_to_bytes(&header.hash())),
            commas(confirmations as u64),
            if confirmations == 1 { "" } else { "s" }
        );
        // (Of a payment, both wallets say so, each by its own key; of
        // a burn, nobody can spend it: that is what holding means.)
        Ok(match &proof.claim {
            Claim::Payment { note, name, bundle, receipt, payer, .. } => {
                let note = if note.is_empty() { String::new() } else { format!("Note: \"{}\"\n", shown(note)) };
                // The name it was made to, where the paid wallet signed
                // for one and it is that wallet's still, by the chain
                // as it is here now (and, of a name under a name, by
                // its certificate, if that has not run out). A name
                // that does not hold is not shown: the address is what
                // was paid, and is shown always.
                let to = receipt.recipient();
                let address = crate::address::encode(&to);
                let to = match self.holds(name, bundle, &to) {
                    true => format!("{} ({address})", String::from_utf8_lossy(name)),
                    false => address,
                };
                format!(
                    "the proof holds:\nFrom: {}\nTo: {to}\nAmount: {}\n{note}{block}",
                    crate::address::encode(&payer.recipient()),
                    coins(proof.amount as u128),
                )
            }
            Claim::Burn(burn) => format!(
                "the proof holds:\nBurned: {}\nFor: {}\nPurpose: \"{}\"\n{block}",
                coins(proof.amount as u128),
                burn.beneficiary.said(),
                burn.purpose
            ),
        })
    }

    /// Whether `name`, as a payment was made to it (`@name`, or
    /// `label@name` with its certificate `bundle`), is the wallet of
    /// address `whose` by the chain as it is here now: the name's
    /// record says that address; or the certificate, signed by the
    /// key the name's record says and not run out, says the name
    /// under it is that wallet.
    fn holds(&self, name: &[u8], bundle: &[u8], whose: &crate::hash::Digest) -> bool {
        let says = |name: &[u8]| -> Option<crate::hash::Digest> {
            let state = self.hold.chain().whole().ok()?;
            let snap = state.snapshot().ok()?;
            Some(Registry::record(&snap, name).ok()??.value)
        };
        match name.strip_prefix(b"@") {
            Some(name) => says(name) == Some(*whose),
            None => crate::subnames::read(bundle, (self.unix)()).is_some_and(|checked| {
                checked.full().as_bytes() == name && checked.holder == *whose && says(&checked.name) == Some(checked.by)
            }),
        }
    }

    /// Burns `amount` for `purpose`, to the credit of `to` (an
    /// address, or a name as it is written; this wallet's address if
    /// nobody is said): a transaction with an output nobody can spend.
    fn burn(&self, amount: &str, purpose: &str, to: Option<&&str>, fee: Option<&&str>) -> Said {
        use crate::proofs::{Beneficiary, Burn, MAX_NOTE};
        let amount = parse_coins(amount).ok_or_else(|| format!("'{amount}' is not an amount of coins"))?;
        let fee = self.fee(fee)?;
        if purpose.is_empty() || purpose.len() > MAX_NOTE {
            return Err(format!("what a burn is for is 1 to {MAX_NOTE} bytes, between quotes"));
        }
        self.observe()?;
        let mut wallet = self.wallet()?;
        let beneficiary = match to {
            None => Beneficiary::Address(wallet.id()),
            Some(to) => Beneficiary::read(to)
                .ok_or_else(|| format!("'{to}' is no address (tab1…), no @name and no label@name"))?,
        };
        let mut nonce = [0u8; 32];
        crate::random::fill(&mut nonce).map_err(|e| e.to_string())?;
        let burn = Burn { beneficiary, nonce, purpose: purpose.to_string() };
        let unix = (self.unix)();
        let signed = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            wallet.burn(amount, fee, burn.clone(), &snap, unix).map_err(|e| Self::short_of(&wallet, &snap, e))?
        };
        let id = short(&digest_to_bytes(&signed.tx.txid()));
        match self.hold.submit(&signed.tx.to_bytes(), unix) {
            Ok(_) => {
                let done = format!(
                    "Burned: {} for {}, for \"{purpose}\": transaction {id}, with a fee of {}. Nobody can spend it; \
                     its proof is had with burn-proof {id} once a block has it",
                    coins(amount as u128),
                    burn.beneficiary.said(),
                    coins(signed.tx.balance().max(0) as u128)
                );
                (self.log)(&done);
                Ok(done)
            }
            Err(why) => {
                wallet.unsend(&signed.tx.txid()).map_err(|e| e.to_string())?;
                let failed = format!("the pool does not take the burn: {why}. Nothing was burned");
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    /// Whom a payment is to: a wallet's address, or the name of one
    /// (`@name`), which says its address.
    fn whom(&self, to: &str) -> Result<crate::hash::Digest, String> {
        let Some(name) = to.strip_prefix('@') else {
            return crate::address::decode(to).ok_or_else(|| format!("'{to}' is no address (tab1…) and no @name"));
        };
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let record = Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())?;
        let record = record.ok_or_else(|| format!("{name} is not registered"))?;
        // (What a name says is a digest: an address, where it is one.)
        match record.value == [0u8; 32] {
            false => Ok(record.value),
            true => Err(format!("{name} says no address")),
        }
    }

    /// Begins a payment to a wallet, by its address or its name: the
    /// slate is sent to it, sealed, through a node it is reached at;
    /// its wallet answers, and this one signs the answer and pools the
    /// transaction, with nothing more asked of either.
    fn send(&self, amount: &str, fee: Option<&&str>, to: &str, note: &str) -> Said {
        // A name under a name: whose it is, is asked of the nodes the
        // full name is reached at when the payment is sent. Until one
        // of them shows it, the payment is to the name.
        let under = match to.split_once('@') {
            Some((label, _)) if !label.is_empty() => {
                let (label, name) = crate::subnames::split(to).ok_or_else(|| format!("'{to}' is no label@name"))?;
                self.value_of(name)?;
                Some(crate::subnames::point(label.as_bytes(), name.as_bytes()))
            }
            _ => None,
        };
        let whom = match under {
            Some(n) => n,
            None => self.whom(to)?,
        };
        let fee = self.fee(fee)?;
        // (To this wallet itself, if that is what is asked: a payment
        // that shows the wallet is reached, or makes its outputs one.)
        let mut wallet = self.wallet()?;
        // (The chain's state is let go of before anything else is
        // asked for: whoever holds it and waits for another lock holds
        // up everyone, once someone comes to write to the chain.)
        let (slate, left) = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            let (amount, left) = Self::amount_of(&wallet, &snap, amount, fee)?;
            let mut slate = wallet
                .send_noted(amount, fee, note.as_bytes(), &snap, (self.unix)())
                .map_err(|e| Self::short_of(&wallet, &snap, e))?;
            // (Made to a name: said in the slate, for the wallet that
            // is paid to sign for if the name is its own, and kept
            // with the payment, which is known by it afterwards.)
            if to.contains('@') {
                wallet.name_payment(&mut slate, to.as_bytes()).map_err(|e| e.to_string())?;
            }
            (slate, left)
        };
        let done = format!(
            "Payment {} begun: {} and a fee of {}, to {}{}",
            &slate.id_hex()[..8],
            coins(slate.amount as u128),
            coins(slate.fee as u128),
            if under.is_some() { to.to_string() } else { crate::address::encode(&whom) },
            Self::left_over(left)
        );
        (self.log)(&done);
        // Whom it is sent to is kept with it: its answer is taken from
        // that wallet, and from no other. (Of a name under a name,
        // from nobody until it is known whose the name is.)
        let done = if note.is_empty() { done } else { format!("{done}, note: \"{}\"", shown(note.as_bytes())) };
        wallet.send_to(&slate.id, &whom).map_err(|e| e.to_string())?;
        // (And the wallet, before the names are taken and the node is
        // given what to send: nothing is held while those are waited
        // for.)
        drop(wallet);
        let body = slate.to_text().into_bytes();
        match under {
            Some(n) => {
                self.names.lock().unwrap_or_else(|e| e.into_inner()).sent.insert(slate.id, to.to_string());
                self.hold.post_to_name(n, crate::msg::KIND_SLATE, slate.id, body);
            }
            None => self.hold.post(whom, crate::msg::KIND_SLATE, slate.id, body),
        }
        Ok(format!("{done}; sent to its wallet, to be answered"))
    }

    /// Takes a message that has come for this wallet, and does what it
    /// asks: a slate of a payment to this wallet is answered, and the
    /// answer sent back; the answer to a slate this wallet began is
    /// signed, and the transaction pooled. What was done, to be said.
    pub fn take(&self, message: &crate::msg::Opened) -> Said {
        if message.kind == crate::msg::KIND_NAME {
            return self.given(&message.body);
        }
        if message.kind != crate::msg::KIND_SLATE {
            return Err(format!("a message of a kind not known ({})", message.kind));
        }
        // (Who sent a message is not said, and is nobody's to know: of
        // an answer, who answers is, by a key that was checked.)
        let from = message.from.map_or("its sender".to_string(), |from| crate::address::encode(&from));
        let text = std::str::from_utf8(&message.body).map_err(|_| format!("what {from} sent is no slate"))?;
        let mut slate = Slate::from_text(text).ok_or_else(|| format!("what {from} sent is no slate"))?;
        let unix = (self.unix)();
        // An answer, to a slate this wallet began. (Signed only if it
        // is the slate that was begun, answered: the wallet sees to
        // that.) A slate that comes as no answer is a payment to this
        // wallet, whoever began it: this wallet itself, if it likes.
        let ours = message.answers.is_some();
        if ours {
            if !self.wallet()?.pending_slates().iter().any(|(id, _)| *id == slate.id) {
                return Err(format!("an answer to payment {}, which this wallet has not begun", &slate.id_hex()[..8]));
            }
            // From the wallet it was sent to, or it is nobody's answer:
            // whoever answers says where the payment goes. (One begun
            // in a file was sent to nobody, and is finalized by hand.)
            match self.wallet()?.sent_to(&slate.id) {
                // (And its receipt is that wallet's, as the answer is.)
                Some(whom)
                    if Some(whom) == message.from && slate.receipt.as_ref().map(|r| r.recipient()) == Some(whom) => {}
                Some(whom) => {
                    let whom = crate::address::encode(&whom);
                    return Err(format!(
                        "Payment {} was sent to {whom}, and {from} answers it: not signed",
                        &slate.id_hex()[..8]
                    ));
                }
                None => {
                    return Err(format!(
                        "Payment {} was begun in a file, and {from} answers it over the network: not signed (finalize \
                         its answer from a file)",
                        &slate.id_hex()[..8]
                    ));
                }
            }
            self.observe()?;
            let signed = self.wallet()?.finalize(&slate, unix).map_err(|e| e.to_string())?;
            let id = short(&digest_to_bytes(&signed.tx.txid()));
            return match self.hold.submit(&signed.tx.to_bytes(), unix) {
                Ok(_) => {
                    let done = format!(
                        "Payment {} answered by {from}, signed and pooled: transaction {id}, {} with a fee of {}",
                        &slate.id_hex()[..8],
                        coins(slate.amount as u128),
                        coins(slate.fee as u128)
                    );
                    (self.log)(&done);
                    Ok(done)
                }
                Err(why) => {
                    let failed =
                        format!("Payment {} is signed, but the pool does not take it: {why}", &slate.id_hex()[..8]);
                    (self.log)(&format!("Error: {failed}"));
                    Err(failed)
                }
            };
        }
        // One somebody else began, to pay this wallet: answered.
        self.wallet()?.receive_slate(&mut slate, unix).map_err(|e| e.to_string())?;
        // (Who pays is not known here, and need not be: the answer
        // goes back the way the slate came.)
        let said = if slate.note.is_empty() { String::new() } else { format!(", note: \"{}\"", shown(&slate.note)) };
        // (Paid as a name of this wallet's, if it was made to one.)
        let paid_as = match slate.name.is_empty() {
            true => String::new(),
            false => format!(" as {}", String::from_utf8_lossy(&slate.name)),
        };
        let done = format!(
            "Payment {} answered: {} to this wallet{paid_as}{said}",
            &slate.id_hex()[..8],
            coins(slate.amount as u128)
        );
        (self.log)(&done);
        if !self.hold.answer(message, crate::msg::KIND_SLATE, slate.id, slate.to_text().into_bytes()) {
            return Err(format!("Payment {} cannot be answered: it came by no node", &slate.id_hex()[..8]));
        }
        Ok(done)
    }

    /// A message this wallet sent was not passed on: `why`. If it was a
    /// payment this wallet began, the payment is given up, and what it
    /// would have spent is the wallet's to spend again. What is to be
    /// said of it.
    pub fn undelivered(&self, to: &crate::hash::Digest, slate: &[u8; 32], why: &str) -> String {
        // (A certificate that did not reach the wallet it is for: its
        // tag is the id of the name. Given again later. Asked of the
        // wallet before the names are taken, never while they are held:
        // the wallet and the names are never both waited for.)
        let given = self.wallet().ok().and_then(|wallet| {
            wallet
                .names_given()
                .into_iter()
                .find(|g| digest_to_bytes(&crate::subnames::point(&g.label, &g.name)) == *slate)
        });
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(given) = given {
            names.again.insert(*slate);
            let holder = crate::address::encode(&given.holder);
            return format!(
                "Error: the certificate of {} was not given to {holder} ({why}): it is tried again while this node runs",
                given.full()
            );
        }
        let to = names.sent.remove(slate).unwrap_or_else(|| crate::address::encode(to));
        drop(names);
        let given_up =
            self.wallet().is_ok_and(|mut wallet| wallet.sent_to(slate).is_some() && wallet.cancel_slate(slate).is_ok());
        match given_up {
            true => format!(
                "Error: payment {} to {to} was not delivered ({why}): given up, nothing was spent",
                short(slate)
            ),
            false => format!("Error: a message to {to} was not delivered ({why})"),
        }
    }

    /// What `name` says on the chain: the id of whoever holds it.
    fn value_of(&self, name: &str) -> Result<crate::hash::Digest, String> {
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let record = Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())?;
        Ok(record.ok_or_else(|| format!("{name} is not registered"))?.value)
    }

    /// Whether the payment of this slate is one this wallet began, sent
    /// to a wallet, and still waits for its answer.
    pub fn awaits_answer(&self, slate: &[u8; 32]) -> bool {
        self.wallet().is_ok_and(|wallet| wallet.sent_to(slate).is_some())
    }

    /// Whose the full name a payment was sent to turned out to be: its
    /// answer is taken from that wallet, and from no other.
    pub fn resolved(&self, slate: &[u8; 32], whom: &crate::hash::Digest) -> Said {
        let mut wallet = self.wallet()?;
        if wallet.sent_to(slate).is_none() {
            return Ok(String::new());
        }
        let names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        let name = names.sent.get(slate).cloned().unwrap_or_default();
        wallet.send_to(slate, whom).map_err(|e| e.to_string())?;
        Ok(format!("Payment {}: {name} is {}", short(slate), crate::address::encode(whom)))
    }

    /// Gives `label@name`, a name under a name this wallet holds, to
    /// the wallet at `to`: a certificate, sent to that wallet.
    fn subname_set(&self, full: &str, to: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        let holder = crate::address::decode(to).ok_or_else(|| format!("'{to}' is no address (tab1…)"))?;
        let mut wallet = self.wallet()?;
        let word = self.signs(&wallet, name)?;
        let unix = (self.unix)();
        let bundle = wallet
            .give_name(label.as_bytes(), name.as_bytes(), &holder, unix, word.as_deref())
            .map_err(|e| e.to_string())?;
        let own = holder == wallet.id();
        drop(wallet);
        let days = crate::subnames::HOLDS / 86_400;
        let done = format!("{full} is {to}, by a certificate that holds {days} days and is signed again daily");
        (self.log)(&format!("Name given: {done}"));
        match own {
            true => drop(self.given(&bundle)?),
            false => self.send_certificate(label.as_bytes(), name.as_bytes(), holder, bundle),
        }
        Ok(format!("{done}; sent to that wallet, which is the name once it has it"))
    }

    /// Whether this wallet signs for `name`: as the wallet the name
    /// says, with nothing more; or by the word of the wallet it says,
    /// which then goes with what is signed. An error if neither.
    fn signs(&self, wallet: &Wallet<W>, name: &str) -> Result<Option<Vec<u8>>, String> {
        let says = self.value_of(name)?;
        if says == wallet.id() {
            return Ok(None);
        }
        let unix = (self.unix)();
        let word = wallet.signs_for(name.as_bytes()).and_then(|word| {
            let read = crate::subnames::delegated(word, unix)?;
            (read.by == says && read.signer == wallet.id()).then(|| word.to_vec())
        });
        word.map(Some).ok_or_else(|| {
            format!(
                "{name} is not this wallet's to give names under: it says {}, this wallet is {}, and has no word of that wallet's that holds (subname signer FILE)",
                crate::address::encode(&says),
                wallet.address()
            )
        })
    }

    /// Says that the key of the wallet at `signer` signs for `name`,
    /// for `days` days: the word of this wallet, which holds the name,
    /// written to `file` for that wallet to take (`subname signer`).
    /// (Nothing is asked of the chain: a wallet kept where nothing can
    /// get at it has none. The word is the name's holder's if this
    /// wallet's address is what the name says.)
    fn subname_delegate(&self, name: &str, signer: &str, days: &str, file: &str) -> Said {
        if !crate::name::valid_name(name.as_bytes()) {
            return Err(format!("{name} is not a valid name"));
        }
        let to = crate::address::decode(signer).ok_or_else(|| format!("'{signer}' is no address (tab1…)"))?;
        let most = crate::subnames::MOST_HOLDS / 86_400;
        let days: u64 = days
            .parse()
            .ok()
            .filter(|d| (1..=most).contains(d))
            .ok_or_else(|| format!("'{days}' is not a number of days from 1 to {most}"))?;
        let wallet = self.wallet()?;
        let until = (self.unix)() + days * 86_400 - 1;
        let word = crate::subnames::delegate(&wallet.identity_key(), name.as_bytes(), &to, until);
        let done = format!(
            "for {days} days the key of {signer} signs for {name}, by the word of this wallet ({}): there is no taking it back sooner, but by having the name say another address",
            wallet.address()
        );
        (self.log)(&format!("Name {name}: {done}"));
        std::fs::write(file, word).map_err(|e| format!("{file}: {e}"))?;
        Ok(format!("{done}. Written to {file}, for that wallet to take with: subname signer {file}"))
    }

    /// Takes the word of a name's holder that this wallet's key signs
    /// for the name.
    fn subname_signer(&self, file: &str) -> Said {
        let word = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        let unix = (self.unix)();
        let read = crate::subnames::delegated(&word, unix)
            .ok_or_else(|| format!("{file} is not the word of a name's holder, or is past its time"))?;
        let name = String::from_utf8_lossy(&read.name).to_string();
        let mut wallet = self.wallet()?;
        if read.signer != wallet.id() {
            return Err(format!(
                "{file} says the key of {} signs for {name}: this wallet is {}",
                crate::address::encode(&read.signer),
                wallet.address()
            ));
        }
        let says = self.value_of(&name)?;
        if says != read.by {
            return Err(format!(
                "{file} is the word of {}, and {name} says {}: not taken",
                crate::address::encode(&read.by),
                crate::address::encode(&says)
            ));
        }
        wallet.sign_for(read.name.as_slice(), &word).map_err(|e| e.to_string())?;
        let days = read.expires.saturating_sub(unix) as f64 / 86_400.0;
        let done = format!(
            "this wallet signs for {name} for {days:.1} days more, by the word of {}",
            crate::address::encode(&read.by)
        );
        (self.log)(&format!("Name {name}: {done}"));
        Ok(done)
    }

    fn send_certificate(&self, label: &[u8], name: &[u8], holder: crate::hash::Digest, bundle: Vec<u8>) {
        let tag = digest_to_bytes(&crate::subnames::point(label, name));
        self.hold.post(holder, crate::msg::KIND_NAME, tag, bundle);
    }

    /// Gives a name out no longer.
    fn subname_del(&self, full: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        match self.wallet()?.take_name_back(label.as_bytes(), name.as_bytes()).map_err(|e| e.to_string())? {
            true => Ok(format!(
                "{full} is given out no longer: its certificate is not signed again, and the last holds until its time is past (give the name to another wallet to end it at once)"
            )),
            false => Err(format!("{full} is not a name this wallet gave out")),
        }
    }

    /// Is a full name no longer.
    fn subname_drop(&self, full: &str) -> Said {
        let (label, name) = crate::subnames::split(full).ok_or_else(|| format!("'{full}' is no label@name"))?;
        let was = self.wallet()?.drop_name(label.as_bytes(), name.as_bytes()).map_err(|e| e.to_string())?;
        self.reached_by_names()?;
        match was {
            true => Ok(format!("this wallet is {full} no longer")),
            false => Err(format!("this wallet is not {full}")),
        }
    }

    /// The names given out, and the full names this wallet is.
    fn subnames(&self) -> Said {
        let wallet = self.wallet()?;
        let unix = (self.unix)();
        let days = |until: u64| format!("{:.1} days", until.saturating_sub(unix) as f64 / 86_400.0);
        let mut lines = Vec::new();
        for (n, _, bundle) in wallet.names_held() {
            match crate::subnames::read(&bundle, unix) {
                Some(c) => lines.push(format!(
                    "this wallet is {}, for {} more: reached by it at {} nodes",
                    c.full(),
                    days(c.expires),
                    self.hold.name_reached(&n)
                )),
                None => lines.push("a certificate past its time (it is this wallet's name no longer)".to_string()),
            }
        }
        for word in wallet.signs_for_all() {
            if let Some(read) = crate::subnames::delegated(&word, unix) {
                lines.push(format!(
                    "signs for {}, by the word of {}, for {} more",
                    String::from_utf8_lossy(&read.name),
                    crate::address::encode(&read.by),
                    days(read.expires)
                ));
            }
        }
        for given in wallet.names_given() {
            let to = crate::address::encode(&given.holder);
            lines.push(format!("given: {} is {to}, for {} more", given.full(), days(given.expires)));
        }
        match lines.is_empty() {
            true => Ok("no names under names: none given, and this wallet is none".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    /// A certificate has come that this wallet is a name under a name:
    /// kept, if it is the name's by the chain and names this wallet,
    /// and the wallet is not too many names already.
    fn given(&self, bundle: &[u8]) -> Said {
        let unix = (self.unix)();
        let checked = crate::subnames::read(bundle, unix).ok_or("what came is no certificate of a name")?;
        let full = checked.full();
        let says = self.value_of(&String::from_utf8_lossy(&checked.name))?;
        if says != checked.by {
            return Err(format!("a certificate of {full} that is not signed for whoever holds its name: not kept"));
        }
        let mut wallet = self.wallet()?;
        if checked.holder != wallet.id() {
            return Err(format!("a certificate of {full} that names another wallet: not kept"));
        }
        if !wallet.hold_name(&checked, bundle, self.max_names).map_err(|e| e.to_string())? {
            let held = wallet.names_held();
            let known = held.iter().any(|(n, seq, _)| *n == checked.point() && *seq >= checked.seq);
            return match known {
                true => Ok(String::new()),
                false => Err(format!(
                    "a certificate of {full} is not kept: this wallet is {} names already (subname drop one, or                      --max-names)",
                    held.len()
                )),
            };
        }
        drop(wallet);
        self.reached_by_names()?;
        let days = (checked.expires.saturating_sub(unix)) as f64 / 86_400.0;
        let done = format!("This wallet is {full}, by a certificate that holds {days:.1} days more");
        (self.log)(&done);
        Ok(done)
    }

    /// Tells the node which full names its wallet is to be reached by:
    /// those whose certificates hold now.
    pub fn reached_by_names(&self) -> Result<(), String> {
        let unix = (self.unix)();
        let held = self.wallet()?.names_held();
        let hold = held.into_iter().filter(|(_, _, bundle)| crate::subnames::read(bundle, unix).is_some());
        self.hold.set_names(hold.collect());
        Ok(())
    }

    /// Looks to the names given out: signs another certificate for
    /// each whose last was signed a day ago, and for each whose last
    /// did not reach its wallet, and sends it.
    pub fn renew_names(&self) -> Result<(), String> {
        let unix = (self.unix)();
        let again = std::mem::take(&mut self.names.lock().unwrap_or_else(|e| e.into_inner()).again);
        let mut wallet = self.wallet()?;
        let at = |g: &crate::wallet::Given| digest_to_bytes(&crate::subnames::point(&g.label, &g.name));
        let mut due = wallet.names_to_renew(unix);
        due.extend(wallet.names_given().into_iter().filter(|g| again.contains(&at(g))));
        for given in due {
            // (Only of a name this wallet still signs for.)
            let name = String::from_utf8_lossy(&given.name).to_string();
            let Ok(word) = self.signs(&wallet, &name) else { continue };
            let bundle = wallet
                .give_name(&given.label, &given.name, &given.holder, unix, word.as_deref())
                .map_err(|e| e.to_string())?;
            match given.holder == wallet.id() {
                true => drop(wallet.hold_name(
                    &crate::subnames::read(&bundle, unix).ok_or("no certificate")?,
                    &bundle,
                    usize::MAX,
                )),
                false => self.send_certificate(&given.label, &given.name, given.holder, bundle),
            }
        }
        drop(wallet);
        self.reached_by_names()
    }

    fn receive(&self, file: &str, out: &str) -> Said {
        let mut slate = Self::read_slate(file)?;
        let mut wallet = self.wallet()?;
        wallet.receive_slate(&mut slate, (self.unix)()).map_err(|e| e.to_string())?;
        let done = format!("Payment {} answered: {} to this wallet", &slate.id_hex()[..8], coins(slate.amount as u128));
        (self.log)(&done);
        Self::write(out, slate.to_text(), format!("{done}, once its sender finalizes it"))
    }

    fn finalize(&self, file: &str) -> Said {
        let slate = Self::read_slate(file)?;
        let unix = (self.unix)();
        self.observe()?;
        // (The wallet is let go of before the pool is asked for.)
        let signed = self.wallet()?.finalize(&slate, unix).map_err(|e| e.to_string())?;
        let id = short(&digest_to_bytes(&signed.tx.txid()));
        match self.hold.submit(&signed.tx.to_bytes(), unix) {
            Ok(_) => {
                let done = format!(
                    "Payment {} signed and pooled: transaction {id}, {} with a fee of {}",
                    &slate.id_hex()[..8],
                    coins(slate.amount as u128),
                    coins(slate.fee as u128)
                );
                (self.log)(&done);
                Ok(done)
            }
            Err(why) => {
                let failed =
                    format!("Payment {} is signed, but the pool does not take it: {why}", &slate.id_hex()[..8]);
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    /// Pools what the wallet signed in place of a payment sent, and says
    /// what was done: `done`, with the transaction and its fee.
    fn replaced(&self, done: &str, after: &str, was: &crate::hash::Digest, signed: &crate::wallet::Signed) -> Said {
        let (was, id) = (short(&digest_to_bytes(was)), short(&digest_to_bytes(&signed.tx.txid())));
        let fee = coins(signed.tx.balance().max(0) as u128);
        match self.hold.submit(&signed.tx.to_bytes(), (self.unix)()) {
            Ok(_) => {
                let said = format!("Payment sent {was} {done}: transaction {id}, with a fee of {fee}");
                (self.log)(&said);
                Ok(format!("{said}\n{after}"))
            }
            Err(why) => {
                let failed = format!("Payment sent {was} {done}, but the pool does not take transaction {id}: {why}");
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    fn cancel(&self, what: &str, fee: Option<&&str>, sure: bool) -> Said {
        use crate::wallet::list::{Kind, Stage};
        let fee = self.fee(fee)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let row = Self::row(&wallet, what)?;
        let n = row.number;
        let landed = "a block has it already: it cannot be taken back (what it spent is spent on chain)";
        match (row.kind, row.stage) {
            // What is to come by another's payment, and is in no
            // block: no longer expected.
            (Kind::Received, Stage::Begun) => {
                let c = crate::hash::digest_from_bytes(&row.id).ok_or("not an output")?;
                let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
                let snap = state.snapshot().map_err(|e| e.to_string())?;
                wallet.cancel_received(&c, &snap).map_err(|e| match e {
                    crate::wallet::WalletError::Landed => {
                        "a block has made it already: it is this wallet's".to_string()
                    }
                    e => e.to_string(),
                })?;
                Ok(format!(
                    "row {n}: the payment is no longer expected. Whoever pays can still sign it: \
                     if they do, `scan` finds it"
                ))
            }
            (Kind::Received | Kind::Reward, _) => Err("it is not this wallet's to cancel: it came to it".into()),
            (Kind::NameCommit, Stage::Confirmed) => {
                Err("a block has it: a commit cannot be cancelled. Left unrevealed, it is swept later".into())
            }
            (_, Stage::Confirmed) => Err(landed.into()),
            (_, Stage::Cancelled | Stage::Replaced | Stage::Orphaned | Stage::Failed) => {
                Err(format!("row {n} is done with already"))
            }
            // A reveal that has been sent has said its name.
            (Kind::NameReveal, _) if !sure => Err(format!(
                "the reveal has been sent, and has said the name: taking it back does not unsay it, \
                 and another may register the name. To take it back all the same: cancel {n} yes"
            )),
            // A payment begun: given up.
            (_, Stage::Begun) => {
                wallet.cancel_slate(&row.id).map_err(|e| e.to_string())?;
                let done = format!("Payment {} given up", short(&row.id));
                (self.log)(&done);
                Ok(done)
            }
            // One signed that no block has: taken back.
            (_, Stage::Pooled | Stage::Remake) => {
                let was = Self::in_flight(&row, "take back")?;
                let signed = {
                    let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
                    let snap = state.snapshot().map_err(|e| e.to_string())?;
                    wallet.cancel_sent(&was, fee, &snap, (self.unix)()).map_err(|e| match e {
                        crate::wallet::WalletError::Landed => landed.to_string(),
                        e => e.to_string(),
                    })?
                };
                drop(wallet);
                self.replaced("taken back", CANCELLED, &was, &signed)
            }
        }
    }

    fn bump(&self, what: &str, fee: Option<&&str>) -> Said {
        let fee = self.fee(fee)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let was = Self::in_flight(&Self::row(&wallet, what)?, "speed up")?;
        let signed = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            wallet.bump_sent(&was, fee, &snap, (self.unix)()).map_err(|e| match e {
                crate::wallet::WalletError::Landed => {
                    "a block has it already: there is nothing to speed up".to_string()
                }
                e => e.to_string(),
            })?
        };
        drop(wallet);
        self.replaced("sped up", BUMPED, &was, &signed)
    }

    fn resend(&self, what: &str) -> Said {
        let wallet = self.wallet()?;
        let was = Self::in_flight(&Self::row(&wallet, what)?, "send again")?;
        let tx = wallet.resend(&was).map_err(|e| e.to_string())?;
        drop(wallet);
        match self.hold.submit(&tx.to_bytes(), (self.unix)()) {
            Ok(_) => Ok(format!("Payment sent {} pooled again", short(&digest_to_bytes(&was)))),
            Err(why) => Err(format!("the pool does not take it: {why}")),
        }
    }

    /// What `prune` did by hand is done by the wallet itself at every
    /// block ([`tidy`]); asked for, it is done now.
    fn prune(&self) -> Said {
        let wallet = self.wallet.as_ref().ok_or("this node has no wallet (it was started with --no-wallet)")?;
        let (gone, commits) = tidy(&self.hold, wallet, true)?;
        let mut out = format!("{} outputs expected that will not be made were forgotten", commas(gone as u64));
        for name in commits {
            out.push_str(&format!("\nthe commit to {name} forgotten: it never reached the chain"));
        }
        Ok(out)
    }

    fn scan(&self) -> Said {
        let mut wallet = self.wallet()?;
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        let (found, total) = wallet.scan(&snap, (self.unix)()).map_err(|e| e.to_string())?;
        let (names, commits) = wallet.scan_names(&snap, (self.unix)()).map_err(|e| e.to_string())?;
        Ok(format!(
            "{} outputs found that were not known, {} in all; {} names; {} commits not yet revealed",
            commas(found as u64),
            coins(total),
            commas(names as u64),
            commas(commits as u64)
        ))
    }

    /// What a name says, as it is written: an address (`tab1…`), or
    /// 64 hex digits; nothing, for `-`.
    fn value(text: &str) -> Result<crate::hash::Digest, String> {
        if text == "-" {
            return Ok([0u8; 32]);
        }
        if let Some(id) = crate::address::decode(text) {
            return Ok(id);
        }
        let bytes: Vec<u8> = match text.len() == 64 && text.is_ascii() {
            true => (0..32).filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()).collect(),
            false => Vec::new(),
        };
        crate::hash::digest_from_bytes(&bytes).filter(|_| bytes.len() == 32).ok_or_else(|| {
            format!("'{text}' is not what a name says: an address (tab1…), 64 hex digits, or - for nothing")
        })
    }

    fn hex(d: &crate::hash::Digest) -> String {
        digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect()
    }

    fn names(&self) -> Said {
        let wallet = self.wallet()?;
        let mut lines = Vec::new();
        for n in wallet.owned_names() {
            let stage = match (n.stage, n.transferring, n.pending.is_some()) {
                (_, true, _) => "being given away",
                (NameStage::Owned, _, true) => "owned, a change signed",
                (NameStage::Owned, _, _) => "owned",
                (NameStage::Revealed, _, _) => "revealed, not yet in the chain",
                (NameStage::Offered, _, _) => "offered to this wallet",
            };
            lines.push(format!("  {:<32}  {stage}  says {}", String::from_utf8_lossy(&n.name), Self::hex(&n.value)));
        }
        let commits = wallet.pending_commits();
        if !commits.is_empty() {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            // (The block a reveal would be in, and how deep the wallet
            // waits for a commit to be: as `name-reveal` has them.)
            let next = snap.tip().0 + 1;
            let wait = wallet.min_confirmations().max(self.hold.chain().params().min_reveal);
            for c in commits {
                let name =
                    c.name.as_deref().map_or("(a name not known: reveal it by name)".into(), String::from_utf8_lossy);
                let made = Registry::commit(&snap, &c.commit).map_err(|e| e.to_string())?.map(|(_, made)| made);
                let stands = match made {
                    None => "committed, not yet in a block".to_string(),
                    Some(made) if next < made.saturating_add(wait) => {
                        let blocks = made + wait - next;
                        format!("committed, can be revealed in {blocks} block{}", if blocks == 1 { "" } else { "s" })
                    }
                    Some(made) => format!(
                        "committed, ready to reveal (until block {})",
                        commas(u64::from(made.saturating_add(crate::name::MAX_REVEAL)))
                    ),
                };
                lines.push(format!("  {name:<32}  {stands}"));
            }
        }

        match lines.is_empty() {
            true => Ok("no names".to_string()),
            false => Ok(lines.join("\n")),
        }
    }

    fn name(&self, name: &str) -> Said {
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        match Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())? {
            Some(record) => {
                // (As an address too, which is what it mostly is.)
                let zero = record.value == [0u8; 32];
                let address = if zero {
                    String::new()
                } else {
                    format!("\n  as an address: {}", crate::address::encode(&record.value))
                };
                Ok(format!(
                    "{name} says {}{address}\n  its owner's key: {}",
                    Self::hex(&record.value),
                    Self::hex(&record.owner)
                ))
            }
            None => Ok(format!("{name} is not registered")),
        }
    }

    /// Has a transaction of the wallet's carry `op`, and pools it:
    /// `done` is what is then said, with the transaction. If none can
    /// carry it, it is as if the operation had not been made.
    fn carry(&self, wallet: &mut Wallet<W>, op: NameOp, fee: Fee, done: &str) -> Said {
        let unix = (self.unix)();
        let signed = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            wallet.carry(vec![op.clone()], fee, &snap, unix).map_err(|e| Self::short_of(wallet, &snap, e))
        };
        let signed = match signed {
            Ok(signed) => signed,
            Err(e) => {
                wallet.undo_name_op(&op).map_err(|e| e.to_string())?;
                return Err(e);
            }
        };
        let id = short(&digest_to_bytes(&signed.tx.txid()));
        match self.hold.submit(&signed.tx.to_bytes(), unix) {
            Ok(_) => {
                let said =
                    format!("{done}: transaction {id}, with a fee of {}", coins(signed.tx.balance().max(0) as u128));
                (self.log)(&said);
                Ok(said)
            }
            // (Refused: no block can hold it. The wallet is as it was
            // before: what the transaction would have spent is its to
            // spend, and the name is where it stood.)
            Err(why) => {
                wallet.unsend(&signed.tx.txid()).map_err(|e| e.to_string())?;
                wallet.undo_name_op(&op).map_err(|e| e.to_string())?;
                let what = done.split(':').next().unwrap_or(done);
                let failed = format!("{what}: the pool does not take the transaction: {why}. Nothing was done");
                (self.log)(&format!("Error: {failed}"));
                Err(failed)
            }
        }
    }

    /// An error if `name` is registered already, to another wallet's
    /// key: there is no use committing to it, or revealing it.
    fn free_to_take(&self, name: &str) -> Result<(), String> {
        let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
        let snap = state.snapshot().map_err(|e| e.to_string())?;
        match Registry::record(&snap, name.as_bytes()).map_err(|e| e.to_string())? {
            Some(_) => Err(format!("{name} is registered already, to another wallet: see `name {name}`")),
            None => Ok(()),
        }
    }

    fn name_commit(&self, name: &str, value: &str, fee: Option<&&str>) -> Said {
        let fee = self.fee(fee)?;
        self.free_to_take(name)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        // (What it is to say, if that is not said: this wallet's
        // address, so that the name is one to be paid by.)
        let value = match value {
            "" => wallet.id(),
            value => Self::value(value)?,
        };
        let op = wallet.name_commit(name.as_bytes(), value, (self.unix)()).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: committed to"))
    }

    fn name_reveal(&self, name: &str, wait: &str, fee: Option<&&str>) -> Said {
        let fee = self.fee(fee)?;
        // (Registered by another since it was committed to: the commit
        // is kept as it is, and nothing is signed.)
        self.free_to_take(name)?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        // Not said: as long as the wallet waits before it spends an
        // output, for the same reason.
        let wait: u32 = match wait {
            "" => wallet.min_confirmations(),
            wait => wait.parse().map_err(|_| format!("'{wait}' is not a number of blocks"))?,
        };
        let op = {
            let state = self.hold.chain().whole().map_err(|e| e.to_string())?;
            let snap = state.snapshot().map_err(|e| e.to_string())?;
            let (height, least) = (snap.tip().0 + 1, self.hold.chain().params().min_reveal);
            wallet.name_reveal(name.as_bytes(), wait, least, &snap, height, (self.unix)()).map_err(|e| e.to_string())?
        };
        self.carry(&mut wallet, op, fee, &format!("Name {name}: revealed"))
    }

    fn name_update(&self, name: &str, value: &str, fee: Option<&&str>) -> Said {
        let (value, fee) = (Self::value(value)?, self.fee(fee)?);
        self.observe()?;
        let mut wallet = self.wallet()?;
        let (op, _) = wallet.name_update(name.as_bytes(), value).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: changed"))
    }

    fn name_offer(&self, name: &str, file: &str, value: &str) -> Said {
        let mut wallet = self.wallet()?;
        let value = match value {
            "" => wallet.id(),
            value => Self::value(value)?,
        };
        let record = wallet.name_offer(name.as_bytes(), value, (self.unix)()).map_err(|e| e.to_string())?;
        drop(wallet);
        let b64 = crate::wallet::base64_encode(&record.to_bytes());
        let mut text = format!("-----BEGIN {OFFER_MARKER}-----\n");
        for line in b64.as_bytes().chunks(64) {
            text.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
            text.push('\n');
        }
        text.push_str(&format!("-----END {OFFER_MARKER}-----\n"));
        let done = format!("Name {name}: an offer written, for its owner to sign over with name-transfer");
        (self.log)(&done);
        Self::write(file, text, done)
    }

    fn name_transfer(&self, file: &str, fee: Option<&&str>) -> Said {
        let fee = self.fee(fee)?;
        let text = std::fs::read_to_string(Path::new(file)).map_err(|e| format!("cannot read {file}: {e}"))?;
        let (begin, end) = (format!("-----BEGIN {OFFER_MARKER}-----"), format!("-----END {OFFER_MARKER}-----"));
        let record = text
            .find(&begin)
            .and_then(|at| {
                let body = &text[at + begin.len()..];
                let b64: String = body[..body.find(&end)?].chars().filter(|c| !c.is_whitespace()).collect();
                crate::name::Record::from_bytes(&crate::wallet::base64_decode(&b64)?).ok()
            })
            .ok_or_else(|| format!("{file} holds no offer of a name"))?;
        self.observe()?;
        let mut wallet = self.wallet()?;
        let name = record.name.as_str().to_string();
        let (op, _) = wallet.name_transfer(record).map_err(|e| e.to_string())?;
        self.carry(&mut wallet, op, fee, &format!("Name {name}: signed over"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use crate::chain::apply::tests::{extend, grow};
    use crate::chain::headers::tests::{NOW, easy, seed, table};
    use crate::chain::verify::AcceptAllProofs;
    use crate::net::node::Node;
    use crate::store::testing::MemBackend;
    use crate::wallet::follow::follow;

    type TestChain = Chain<MemBackend, AcceptAllProofs>;
    type TestConsole = Console<MemBackend, MemBackend, AcceptAllProofs>;

    /// A node's chain, with the prompts of wallets on it: what each was
    /// told is kept, and the files they pass each other are in a
    /// directory of the test's own.
    struct Desk {
        chain: Arc<TestChain>,
        node: Node<MemBackend, AcceptAllProofs>,
        hold: Handle<MemBackend, AcceptAllProofs>,
        logged: Arc<Mutex<Vec<String>>>,
        dir: std::path::PathBuf,
    }

    impl Drop for Desk {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Desk {
        fn new(name: &str) -> Desk {
            let chain = Chain::open(MemBackend::new(), 64, easy(), seed(), AcceptAllProofs).unwrap();
            chain.set_dataset(table());
            let chain = Arc::new(chain);
            let node = Node::new(crate::net::config::Config::default(), *b"TEST", Arc::clone(&chain), [9; 32], 0);
            let dir = std::env::temp_dir().join(format!("tabminer-console-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let hold = node.hold();
            Desk { chain, node, hold, logged: Arc::default(), dir }
        }

        /// A prompt with a new wallet, or with none.
        fn prompt(&self, with_wallet: bool) -> TestConsole {
            let wallet = with_wallet.then(|| {
                let mut wallet = Wallet::open(MemBackend::new()).unwrap().0;
                wallet.set_min_confirmations(1);
                Arc::new(Mutex::new(wallet))
            });
            let logged = Arc::clone(&self.logged);
            Console {
                hold: self.hold.clone(),
                wallet,
                unix: || NOW,
                log: Arc::new(move |line: &str| logged.lock().unwrap().push(line.to_string())),
                debug: true,
                max_names: 5,
                names: Arc::default(),
            }
        }

        fn file(&self, name: &str) -> String {
            self.dir.join(name).display().to_string()
        }

        /// A block of everything the pool holds, its reward and its fees
        /// paid to `to`; and the wallets of `all` brought up to it.
        fn mine(&self, to: &TestConsole, all: &[&TestConsole]) {
            let (mut pooled, mut fees) = (Vec::new(), 0u64);
            self.hold.pool(&mut |pool| {
                for entry in pool.entries() {
                    pooled.push(entry.tx().to_transaction());
                    fees += entry.fee;
                }
            });
            let height = self.chain.tip().unwrap().height + 1;
            let due = self.chain.params().subsidy(height) + fees;
            let reward = to.wallet.as_ref().unwrap().lock().unwrap().reward(due, height, NOW).unwrap();
            let outputs = [&reward].into_iter().chain(pooled.iter().flat_map(|tx| &tx.outputs));
            let body = crate::block::Body {
                inputs: pooled.iter().flat_map(|tx| tx.spent_positions()).collect(),
                outputs: outputs.map(|output| output.block_output()).collect(),
                ops: pooled.iter().flat_map(|tx| &tx.ops).map(|op| op.block_op()).collect(),
                ..Default::default()
            };
            extend(&self.chain, &body);
            // (Its maker's wallet is told which block its reward is of,
            // as the node tells it.)
            let won = digest_to_bytes(&self.chain.tip().unwrap().hash());
            to.wallet.as_ref().unwrap().lock().unwrap().reward_found(&reward.commitment, &won).unwrap();
            self.node.pool_follows(1);
            for console in all {
                follow(&self.chain, &mut console.wallet.as_ref().unwrap().lock().unwrap(), NOW).unwrap();
            }
        }
    }

    /// What a command says, which is no error; and the error one says.
    fn said(console: &TestConsole, line: &str) -> String {
        match console.run(line) {
            Reply::Said(text) => text,
            other => panic!("{line}: {other:?}"),
        }
    }

    fn wrong(console: &TestConsole, line: &str) -> String {
        match console.run(line) {
            Reply::Wrong(text) => text,
            other => panic!("{line}: {other:?}"),
        }
    }

    /// What is asked of a node at its prompt, of one with no wallet and
    /// of one whose wallet holds nothing: each command says what there
    /// is, or what it lacks.
    #[test]
    fn a_prompt_says_how_the_node_stands() {
        let desk = Desk::new("stands");
        grow(&desk.chain, 2, 1);
        let (bare, held) = (desk.prompt(false), desk.prompt(true));
        assert_eq!(bare.run(""), Reply::Nothing);
        assert_eq!(bare.run("quit"), Reply::Quit);
        assert_eq!(bare.run("exit"), Reply::Quit);
        assert!(said(&bare, "help").starts_with("commands:"));
        assert_eq!(wrong(&bare, "nonsense"), "nonsense: no such command (see help)");
        assert_eq!(wrong(&bare, "send"), "send: not what it takes (see help)");
        for line in ["status", "peers", "mempool", "fees", "leaves", "consensus"] {
            assert!(!said(&bare, line).is_empty(), "{line}");
        }
        assert!(said(&bare, "status").starts_with("block 2 ("), "{}", said(&bare, "status"));
        assert_eq!(said(&bare, "consensus"), "Mode: init\nNext decision block: 144\nVotes: none\nOur vote: none");
        assert_eq!(said(&bare, "relays"), "No file is in force: the seeds stand in for relays");
        assert!(said(&bare, "leaves").starts_with("no leaf is set"));
        assert!(said(&bare, "mempool").starts_with("0 transactions, 0 bytes; the pool asks 25,000 a unit of weight"));
        assert!(said(&bare, "fees").contains("a simple payment weighs 7 (an input 1, an output 3 by default)"));
        assert_eq!(said(&bare, "peers"), "0 peers known, 0 of them live");
        // What is the wallet's is asked of a wallet.
        let none = "this node has no wallet (it was started with --no-wallet)";
        for line in ["balance", "address", "outputs", "txs", "names", "payments", "subnames", "prune", "mining"] {
            assert_eq!(wrong(&bare, line), none, "{line}");
            assert!(!said(&held, line).is_empty(), "{line}");
        }
        assert_eq!(bare.run("seed"), Reply::Wrong(none.to_string()));
        assert_eq!(bare.run("password"), Reply::Wrong(none.to_string()));
        assert_eq!(held.run("password"), Reply::NewPassword);
        assert_eq!(said(&held, "seed").split_whitespace().count(), 14);
        assert!(said(&held, "seed").starts_with("Recovery phrase: ") && !said(&held, "seed").contains('\n'));
        assert!(said(&held, "address").starts_with("tab1"));
        assert_eq!(said(&held, "balance"), "spendable   0");
        assert_eq!(said(&held, "outputs"), "no outputs");
        assert_eq!(said(&held, "txs"), "nothing yet");
        assert_eq!(said(&held, "txs pending"), "nothing pending");
        assert_eq!(said(&held, "txs mined"), "no rewards yet");
        // (What `txs` took the place of is gone.)
        assert_eq!(wrong(&held, "sent"), "sent: no such command (see help)");
        assert_eq!(wrong(&held, "slates"), "slates: no such command (see help)");
        assert_eq!(said(&held, "names"), "no names");
        assert_eq!(said(&held, "payments"), "no payments made, and nothing burned");
        assert!(said(&held, "mining").starts_with("no blocks won in the last 64"));
        assert!(wrong(&held, "send-file lots x").contains("is not an amount of coins"));
        // A wallet that holds nothing pays nothing.
        assert!(!wrong(&held, &format!("send-file 1 {}", desk.file("none.slate"))).is_empty());
        assert!(wrong(&held, &format!("receive {}", desk.file("none.slate"))).contains("none"));
    }

    /// A payment between two wallets at their prompts, by a slate in a
    /// file: begun, answered, signed and pooled, and in a block.
    #[test]
    fn a_payment_is_made_at_the_prompt() {
        let (desk, payer, paid) = funded("pays");
        assert_eq!(said(&payer, "balance"), "spendable   3,000");
        assert_eq!(said(&payer, "outputs").matches("1,500  confirmed").count(), 2);
        // The blocks its wallet was paid by: both in the chain. And one
        // that another chain went further without.
        let won = said(&payer, "mining");
        assert!(won.starts_with("blocks won in the last 64: 2 in the chain, which paid 3,000\n  block"), "{won}");
        assert_eq!(won.matches("in the chain").count(), 3);
        {
            let mut wallet = payer.wallet.as_ref().unwrap().lock().unwrap();
            let lost = wallet.reward(1_500 * COIN, 2, NOW).unwrap();
            wallet.reward_found(&lost.commitment, &[7; 32]).unwrap();
        }
        let won = said(&payer, "mining");
        assert!(
            won.contains("; 1 orphaned, which would have paid ") && won.contains("\norphaned (another chain"),
            "{won}"
        );
        assert!(won.ends_with("  orphaned"), "{won}");
        let slate = desk.file("payment.slate");
        let begun = said(&payer, &format!("send-file 12.5 {slate}"));
        assert!(begun.contains("begun: 12.5 and a fee of"), "{begun}");
        assert!(begun_ones(&payer).contains("12.5"));
        let answered = said(&paid, &format!("receive {slate}"));
        assert!(answered.contains("answered: 12.5 to this wallet"), "{answered}");
        assert_eq!(said(&paid, "balance"), "spendable   0\nunverified  12.5");
        let signed = said(&payer, &format!("finalize {slate}.received"));
        assert!(signed.contains("signed and pooled"), "{signed}");
        assert_eq!(begun_ones(&payer), "");
        assert!(said(&payer, "mempool").starts_with("1 transactions, "));
        assert!(said(&payer, "mempool").contains("weight 7  fee 0.0000175  (25,000 a unit)"));
        assert!(pooled_ones(&payer).contains("0.0000175"), "{}", said(&payer, "txs"));
        desk.mine(&payer, &[&payer, &paid]);
        assert_eq!(said(&paid, "balance"), "spendable   12.5");
        assert!(said(&payer, "payments").contains("12.5  paid to tab1"));
        assert!(said(&payer, "payments").ends_with(": in block 3, proof ready"));
        assert!(said(&paid, "status").contains("wallet: 12.5 confirmed"));
        assert_eq!(pooled_ones(&payer), "");
        let logged = desk.logged.lock().unwrap().join("\n");
        assert!(
            logged.contains("begun: 12.5") && logged.contains("answered: 12.5") && logged.contains("signed and pooled")
        );
        // A payment with a note and a fee said; and more than there is.
        let noted = said(&payer, &format!("send-file 1 0.001 {slate} \"for the tea\""));
        assert!(noted.contains("begun: 1 and a fee of 0.001"), "{noted}");
        assert!(!wrong(&payer, &format!("send-file 1000000 {slate}")).is_empty());
        assert!(wrong(&payer, &format!("send-file 1 nothing {slate}")).contains("is not a fee"));
    }

    #[test]
    fn coins_are_written_and_read() {
        for (units, text) in [
            (0u64, "0"),
            (1, "0.0000000001"),
            (COIN, "1"),
            (15 * COIN / 10, "1.5"),
            (1_234_567 * COIN + 890, "1,234,567.000000089"),
        ] {
            assert_eq!(coins(units as u128), text);
            assert_eq!(parse_coins(&text.replace(',', "")), Some(units), "{text}");
        }
        assert_eq!(parse_coins("1.50"), Some(15 * COIN / 10));
        for bad in ["", ".5", "1.", "1.00000000001", "-1", "1e3", "1,000", "99999999999999999999", "1844674408"] {
            assert_eq!(parse_coins(bad), None, "{bad}");
        }
    }

    /// A desk with a payer whose wallet has two blocks' rewards, and
    /// another wallet.
    /// The rows of `txs pending` that are of payments begun, and those
    /// of what is signed and in the pool: the lines, or nothing.
    fn begun_ones(prompt: &TestConsole) -> String {
        let pending = said(prompt, "txs pending");
        pending.lines().filter(|l| l.contains(" begun ")).collect::<Vec<_>>().join("\n")
    }

    fn pooled_ones(prompt: &TestConsole) -> String {
        let pending = said(prompt, "txs pending");
        pending.lines().filter(|l| l.contains(" pooled ")).collect::<Vec<_>>().join("\n")
    }

    fn funded(name: &str) -> (Desk, TestConsole, TestConsole) {
        let desk = Desk::new(name);
        let (payer, paid) = (desk.prompt(true), desk.prompt(true));
        desk.mine(&payer, &[&payer, &paid]);
        desk.mine(&payer, &[&payer, &paid]);
        (desk, payer, paid)
    }

    /// A payment of `amount` from `payer` to `paid`, pooled: the id of
    /// its transaction, as it is said.
    fn pay(desk: &Desk, payer: &TestConsole, paid: &TestConsole, amount: &str) -> String {
        let slate = desk.file("payment.slate");
        assert!(said(payer, &format!("send-file {amount} {slate}")).contains("begun"));
        assert!(said(paid, &format!("receive {slate}")).contains("answered"));
        let signed = said(payer, &format!("finalize {slate}.received"));
        signed.split("transaction ").nth(1).unwrap()[..8].to_string()
    }

    /// A word begun at the prompt is finished: a command; a word a
    /// command knows; a file, for a command that takes one or a word
    /// written as a path. And every command there is, is one that
    /// could be meant.
    #[test]
    fn what_is_begun_at_the_prompt_could_be() {
        let could = |before: &str| {
            let (from, mut fit) = complete(before);
            fit.sort();
            (from, fit.join(" "))
        };
        assert_eq!(could("sta"), (0, "status".to_string()));
        assert_eq!(could("send"), (0, "send send-file".to_string()));
        assert_eq!(could("zz"), (0, String::new()));
        assert_eq!(complete("").1.len(), COMMANDS.len());
        assert_eq!(could("txs "), (4, "--all mined pending".to_string()));
        assert_eq!(could("txs p"), (4, "pending".to_string()));
        assert_eq!(could("txs mined -"), (10, "--all".to_string()));
        assert_eq!(could("outputs "), (8, "--all".to_string()));
        assert_eq!(could("send a"), (5, "all".to_string()));
        assert_eq!(could("status x"), (7, String::new()));
        // Files: of the directory the word is in.
        let dir = std::env::temp_dir().join(format!("tabminer-complete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for name in ["pay.slate", "pay.slate.received", ".hidden", "a b"] {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        let at = dir.display().to_string();
        assert_eq!(could(&format!("receive {at}/p")), (8, format!("{at}/pay.slate {at}/pay.slate.received")));
        assert_eq!(could(&format!("receive {at}/")), (8, format!("{at}/pay.slate {at}/pay.slate.received {at}/sub/")));
        assert_eq!(could(&format!("status {at}/s")), (7, format!("{at}/sub/")));
        assert_eq!(could(&format!("receive {at}/.")), (8, format!("{at}/.hidden")));
        let _ = std::fs::remove_dir_all(&dir);
        // Every command is known to the prompt as one: given what it
        // does not take, it says so, and not that there is none.
        let (_desk, payer, _) = funded("commands");
        for command in COMMANDS {
            let said = payer.run(&format!("{command} a b c d e f g h"));
            assert!(!matches!(&said, Reply::Wrong(text) if text.ends_with("no such command (see help)")), "{command}");
        }
    }

    /// A payment sent is sped up and taken back while no block has it;
    /// and what will not be made is forgotten.
    #[test]
    fn a_payment_sent_is_sped_up_and_taken_back() {
        let (desk, payer, paid) = funded("back");
        let id = pay(&desk, &payer, &paid, "3");
        assert!(pooled_ones(&payer).contains(&id));
        assert_eq!(wrong(&payer, &format!("resend {id}")), "the pool does not take it: already in the pool");
        // Sped up: another transaction in its place, paying twice the
        // rate.
        let bumped = said(&payer, &format!("bump {id}"));
        assert!(bumped.starts_with(&format!("Payment sent {id} sped up: transaction ")), "{bumped}");
        assert!(bumped.contains("with a fee of 0.000035\n") && bumped.ends_with(BUMPED), "{bumped}");
        assert!(said(&payer, "mempool").contains("fee 0.000035  (50,000 a unit)"));
        // (An id no payment has: not how this one's begins, whatever
        // that is.)
        let no = if id.starts_with("00") { "ffffffffffffffff" } else { "0000000000000000" };
        let none = |what: &str| format!("no row with that number, or an id that starts {what}: see txs");
        assert_eq!(wrong(&payer, &format!("bump {no}")), none(no));
        assert_eq!(wrong(&payer, "cancel zz"), none("zz"));
        assert_eq!(wrong(&payer, &format!("resend {no}")), none(no));
        assert_eq!(wrong(&payer, &format!("txs {no}")), none(no));
        // A row is named by its number or by the digits of its id,
        // whatever is asked of it; and what cannot be done to it is
        // said of the row, not that there is none.
        assert!(said(&payer, &format!("txs {id}")).contains("replaced by 4"));
        assert_eq!(said(&payer, &format!("txs {id}")), said(&payer, "txs 3"));
        assert_eq!(wrong(&payer, "bump 1"), "row 1 came to this wallet: there is nothing to speed up");
        assert_eq!(wrong(&payer, "resend 3"), "row 3 is done with already");
        assert_eq!(wrong(&payer, &format!("bump {id}")), "row 3 is done with already");
        assert_eq!(wrong(&payer, "bump"), "bump: not what it takes (see help)");
        // Taken back: the same outputs spent to the wallet itself.
        let now = pooled_ones(&payer).split_whitespace().last().unwrap().to_string();
        let back = said(&payer, &format!("cancel {now}"));
        assert!(back.starts_with(&format!("Payment sent {now} taken back: transaction ")), "{back}");
        assert!(back.ends_with(CANCELLED), "{back}");
        assert_eq!(said(&paid, "balance"), "spendable   0\nunverified  3");
        desk.mine(&payer, &[&payer, &paid]);
        assert_eq!(pooled_ones(&payer), "");
        // What the other was to have is never made: forgotten when
        // asked.
        assert_eq!(said(&paid, "prune"), "1 outputs expected that will not be made were forgotten");
        assert_eq!(said(&paid, "balance"), "spendable   0");
        let logged = desk.logged.lock().unwrap().join("\n");
        assert!(logged.contains(" sped up: transaction ") && logged.contains(" taken back: transaction "), "{logged}");
        // A payment begun and not yet answered is given up.
        let slate = desk.file("given-up.slate");
        let begun = said(&payer, &format!("send-file 2 {slate}"));
        let id = begun.split_whitespace().nth(1).unwrap().to_string();
        let given = payer.run(&format!("cancel {id}"));
        assert!(matches!(&given, Reply::Said(_)), "{given:?}");
        assert_eq!(begun_ones(&payer), "");
    }

    /// Everything a wallet can spend is sent at once, into one output;
    /// what it spent is then listed only when all is asked for, each
    /// with the block that made it still.
    #[test]
    fn everything_is_sent_at_once() {
        let (desk, payer, paid) = funded("all");
        let slate = desk.file("all.slate");
        let begun = said(&payer, &format!("send-file all {slate}"));
        assert!(begun.contains("begun: 2,999.99998 and a fee of 0.00002, from 2 outputs;"), "{begun}");
        assert!(said(&paid, &format!("receive {slate}")).contains("answered: 2,999.99998 to this wallet"));
        assert!(said(&payer, &format!("finalize {slate}.received")).contains("signed and pooled"));
        // (Nothing is left to send; nor is nothing an amount.)
        assert!(
            wrong(&payer, &format!("send-file all {slate}")).starts_with("there is nothing to send: 0 can be spent")
        );
        assert!(wrong(&payer, &format!("send-file some {slate}")).ends_with("is not an amount of coins, nor `all`"));
        desk.mine(&paid, &[&payer, &paid]);
        // (With the reward of the block, and the fee that came with it.)
        assert_eq!(said(&paid, "balance"), "spendable   4,500");
        // No change was made: the wallet has nothing unspent.
        let unspent = said(&payer, "outputs");
        let note = "Spent outputs are not listed (2): outputs --all lists every output.";
        assert_eq!(unspent, format!("no unspent outputs\n{note}"));
        let all = said(&payer, "outputs --all");
        let spent: Vec<Vec<&str>> =
            all.lines().filter(|l| l.contains("  spent  ")).map(|l| l.split_whitespace().collect()).collect();
        // (In the order they lie in the chain; each with its block,
        // the row that made it and the row that spent it.)
        assert_eq!(spent.len(), 2, "{all}");
        assert_eq!((spent[0][3], spent[0][6], spent[0][7]), ("1", "1", "3"), "{all}");
        assert_eq!((spent[1][3], spent[1][6], spent[1][7]), ("2", "2", "3"), "{all}");
        assert!(!all.contains("not listed"), "{all}");
        // And the wallet that was paid lists what it has: that, and
        // the block's reward.
        let held = said(&paid, "outputs");
        assert!(held.lines().count() == 3 && !held.contains("not listed"), "{held}");
        // The row of what it was paid has its block, and keeps it when
        // the output is spent.
        let row = |text: &str| text.lines().nth(1).unwrap().split_whitespace().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(row(&said(&paid, "txs"))[..5], ["1", "received", "confirmed", "2,999.99998", "-"]);
        assert_eq!(row(&said(&paid, "txs"))[5], "3");
        let back = desk.file("back.slate");
        said(&paid, &format!("send-file all {back}"));
        said(&payer, &format!("receive {back}"));
        said(&paid, &format!("finalize {back}.received"));
        desk.mine(&paid, &[&payer, &paid]);
        assert_eq!(row(&said(&paid, "txs"))[5], "3");
    }

    /// What was paid is listed, proven in a file and verified from it;
    /// and coins are burned.
    #[test]
    fn payments_are_proven_and_coins_burned() {
        let (desk, payer, paid) = funded("proofs");
        let id = pay(&desk, &payer, &paid, "7");
        desk.mine(&payer, &[&payer, &paid]);
        desk.mine(&payer, &[&payer, &paid]);
        let file = desk.file("payment.proof");
        let listed = said(&payer, "payments");
        assert!(listed.contains(&format!("  {id}")) && listed.ends_with(": in block 3, proof ready"), "{listed}");
        assert!(said(&payer, &format!("payment-proof {id}")).starts_with("-----BEGIN TAB PAYMENT PROOF-----\n"));
        assert_eq!(said(&payer, &format!("payment-proof {id} {file}")), format!("the proof of {id}, in block 3"));
        // Whoever has the file and the chain can say what it proves.
        for anyone in [&payer, &paid] {
            let holds = said(anyone, &format!("verify-proof {file}"));
            let lines: Vec<&str> = holds.lines().collect();
            assert_eq!((lines.len(), lines[0], lines[3]), (5, "the proof holds:", "Amount: 7"), "{holds}");
            assert!(lines[1].starts_with("From: tab1") && lines[2].starts_with("To: tab1"), "{holds}");
            assert!(lines[4].starts_with("Block: 3 (") && lines[4].ends_with(") (2 confirmations)"), "{holds}");
        }
        assert_eq!(
            wrong(&payer, "payment-proof 0000000000"),
            "no payment or burn is row 0000000000, or of a transaction that begins 0000000000 (see txs)"
        );
        assert!(wrong(&payer, &format!("verify-proof {}", desk.file("none"))).starts_with("cannot read "));
        std::fs::write(desk.file("nonsense"), "nonsense").unwrap();
        assert!(!wrong(&payer, &format!("verify-proof {}", desk.file("nonsense"))).is_empty());
        // Coins burned, for a purpose that is said: what it is for is
        // between quotes.
        assert_eq!(wrong(&payer, "burn 2 for"), "burn: not what it takes (see help)");
        assert_eq!(wrong(&payer, "burn lots \"for the test\""), "'lots' is not an amount of coins");
        let burned = said(&payer, "burn 2 \"for the test\"");
        assert!(burned.starts_with("Burned: 2 for tab1"), "{burned}");
        assert!(burned.contains(", for \"for the test\": transaction "), "{burned}");
        assert!(pooled_ones(&payer) != "");
        desk.mine(&payer, &[&payer, &paid]);
        desk.mine(&payer, &[&payer, &paid]);
        let listed = said(&payer, "payments");
        assert!(listed.contains("2  burned for tab1"), "{listed}");
        assert!(listed.contains("for \"for the test\": in block 5, proof ready"), "{listed}");
        let burn =
            listed.lines().find(|l| l.contains("burned")).unwrap().split_whitespace().next().unwrap().to_string();
        assert_eq!(said(&payer, &format!("burn-proof {burn} {file}")), format!("the proof of {burn}, in block 5"));
        assert!(said(&paid, &format!("verify-proof {file}")).starts_with("the proof holds:\nBurned: "));
        assert_eq!(said(&payer, "balance"), "spendable   8,991");
        let outputs = said(&payer, "outputs");
        assert!(outputs.contains("  spent ") && outputs.contains("  confirmed "), "{outputs}");
        let status = said(&payer, "status");
        assert!(status.starts_with("block 6 (") && status.ends_with("wallet: 8,991 confirmed"), "{status}");
    }

    /// A name is committed to, revealed, changed, offered and signed
    /// over, at the prompts of two wallets.
    #[test]
    fn a_name_is_registered_changed_and_given() {
        let (desk, maker, other) = funded("names");
        let all = [&maker, &other];
        assert_eq!(said(&maker, "names"), "no names");
        assert_eq!(said(&maker, "name alice"), "alice is not registered");
        assert_eq!(wrong(&maker, "name-commit Alice"), "Alice is not a valid name");
        // Committed to: which says nothing of the name. Revealed once
        // the commit has been in the chain for as long as is asked.
        assert!(said(&maker, "name-commit alice -").starts_with("Name alice: committed to: transaction "));
        assert!(said(&maker, "names").ends_with("committed, not yet in a block"));
        assert_eq!(wrong(&maker, "name-commit alice"), "the wallet has already committed to that name");
        assert_eq!(wrong(&maker, "name-reveal alice"), "the commit is not on chain yet");
        let mut stood = Vec::new();
        let revealed = (0..40).any(|_| {
            desk.mine(&maker, &all);
            // (What `names` says of the commit is what `name-reveal`
            // then does: not before it says ready.)
            let names = said(&maker, "names");
            let ready = names.contains("committed, ready to reveal (until block ");
            assert!(ready || names.contains("committed, can be revealed in "), "{names}");
            stood.push(ready);
            let done = matches!(maker.run("name-reveal alice"), Reply::Said(text) if text.starts_with("Name alice: revealed: "));
            assert_eq!(done, ready, "{names}");
            done
        });
        assert!(revealed && stood.last() == Some(&true), "{stood:?}");
        assert!(revealed);
        assert_eq!(wrong(&maker, "name-reveal alice"), "no commit for alice");
        desk.mine(&maker, &all);
        let nothing = "0".repeat(64);
        assert!(said(&maker, "names").contains(&format!("  owned  says {nothing}")));
        assert!(said(&maker, "name alice").starts_with(&format!("alice says {nothing}\n  its owner's key: ")));
        assert_eq!(said(&other, "name alice"), said(&maker, "name alice"));
        // Changed: what it says.
        let says = "01000000".repeat(8);
        assert!(wrong(&maker, "name-update alice nonsense").starts_with("'nonsense' is not what a name says"));
        assert!(said(&maker, &format!("name-update alice {says}")).starts_with("Name alice: changed: transaction "));
        assert!(said(&maker, "names").contains("owned, a change signed"));
        desk.mine(&maker, &all);
        assert!(said(&other, "name alice").starts_with(&format!("alice says {says}\n  as an address: tab1")));
        assert!(said(&maker, "names").contains(&format!("  owned  says {says}")));
        // Given to the other wallet: which writes the record, for the
        // owner to sign over.
        let offer = desk.file("alice.offer");
        assert!(said(&other, &format!("name-offer alice {offer} -")).starts_with("Name alice: an offer written"));
        assert!(said(&other, "names").contains("offered to this wallet"));
        assert!(said(&maker, &format!("name-transfer {offer}")).starts_with("Name alice: signed over: transaction "));
        assert!(said(&maker, "names").contains("being given away"));
        desk.mine(&maker, &all);
        assert_eq!(said(&maker, "names"), "no names");
        assert!(said(&other, "names").contains(&format!("  owned  says {nothing}")));
        let logged = desk.logged.lock().unwrap().join("\n");
        for step in ["committed to", "revealed", "changed", "signed over"] {
            assert!(logged.contains(&format!("Name alice: {step}: transaction ")), "{step}: {logged}");
        }
        // A wallet looks for what is its own on the chain, and finds
        // nothing it did not know.
        assert!(said(&other, "scan").starts_with("0 outputs found that were not known"));
        for line in ["subname set bob.alice x", "subname del bob.alice", "subname drop bob.alice"] {
            assert_eq!(wrong(&other, line), "'bob.alice' is no label@name");
        }
    }

    /// The wallet's password is set and asked for; leaves are set, and
    /// a consensus file voted for.
    #[test]
    fn a_wallet_is_locked_and_leaves_are_set() {
        let (desk, payer, _) = funded("locked");
        assert!(!payer.locked());
        assert!(payer.set_password("", "a password").unwrap().starts_with("The wallet's password is set"));
        assert!(payer.locked());
        assert_eq!(payer.run("seed"), Reply::Password);
        assert_eq!(payer.run("password"), Reply::NewPassword);
        assert_eq!(payer.seed("wrong"), Err("wrong wallet password".to_string()));
        assert_eq!(payer.seed("a password").unwrap().split_whitespace().count(), 14);
        assert_eq!(payer.set_password("wrong", "x"), Err("wrong wallet password".to_string()));
        assert!(payer.set_password("a password", "").unwrap().starts_with("The wallet has no password now"));
        assert!(!payer.locked());
        // Leaves: what the blocks made here commit to, a value each.
        let value = "ab".repeat(32);
        let set = said(&payer, &format!("set-leaf-value 1 {value}"));
        assert!(set.starts_with("leaf 1 is set\nroot  "), "{set}");
        assert!(said(&payer, "leaves").starts_with(&format!("   1  {value}\nroot  ")));
        assert_eq!(wrong(&payer, "set-leaf-value 1 nonsense"), "the value is 64 hex digits");
        assert_eq!(wrong(&payer, "set-leaf-value 99 00"), "the leaves are 0 to 15");
        // The first is the vote for a consensus file: one that is none
        // is not voted for; one that is, is.
        let file = desk.file("consensus.txt");
        std::fs::write(&file, "nonsense\n").unwrap();
        let no_mode = "the first directive must be `mode init` or `mode onion`";
        assert!(wrong(&payer, &format!("set-leaf 0 {file}")).ends_with(no_mode));
        assert!(wrong(&payer, &format!("debug-consensus {file}")).ends_with(no_mode));
        assert!(wrong(&payer, &format!("set-leaf 0 {}", desk.file("none"))).contains("none"));
        std::fs::write(&file, "mode onion\n").unwrap();
        assert!(wrong(&payer, &format!("set-leaf 0 {file}")).contains("fewer than the 3 needed"));
        let relays: Vec<String> = (1..=3u32).map(|i| crate::address::encode(&[i as u8; 32])).collect();
        let text: String = relays.iter().enumerate().map(|(i, id)| format!("relay {id} 10.0.0.{i}:3737\n")).collect();
        std::fs::write(&file, format!("# three relays\nmode onion\n{text}")).unwrap();
        let voted = said(&payer, &format!("set-leaf 0 {file}"));
        assert!(voted.contains("vote for") && voted.contains("mode onion"), "{voted}");
        assert!(said(&payer, "leaves").contains("(the vote for a consensus file)"));
        assert!(said(&payer, "consensus").starts_with("Mode: init\n"));
        // (Debugging: the file in force at once, with no vote.)
        let forced = payer.run(&format!("debug-consensus {file}"));
        assert!(matches!(&forced, Reply::Said(_)), "{forced:?}");
        let forced = said(&payer, "consensus");
        assert!(forced.contains("\nOur vote: ") && !forced.ends_with("Our vote: none"), "{forced}");
        // A payment to an address goes to its wallet by the message
        // layer; to what is no address, nowhere.
        assert_eq!(wrong(&payer, "send 1 nobody"), "'nobody' is no address (tab1…) and no @name");
        let begun = said(&payer, &format!("send 1 {}", crate::address::encode(&[7; 32])));
        assert!(begun.contains("begun: 1 and a fee of"), "{begun}");
        assert!(begun.ends_with("sent to its wallet, to be answered"), "{begun}");
        assert!(begun_ones(&payer).contains(" 1 "));
    }

    /// A message as it comes for a wallet: one sent to it, to be
    /// answered by the node it came by; or the answer to one, from
    /// whoever answers.
    fn message(kind: u8, body: Vec<u8>, from: Option<crate::hash::Digest>) -> crate::msg::Opened {
        crate::msg::Opened {
            id: [1; 32],
            from,
            answers: from.map(|_| [1; 32]),
            reply: if from.is_some() { Vec::new() } else { vec![1] },
            by: from.is_none().then(|| "10.0.0.1:3737".parse().unwrap()),
            kind,
            body,
        }
    }

    /// The id of a prompt's wallet, and the last message of a kind
    /// that the node was given to send: whom it is for and what it says.
    fn id_of(console: &TestConsole) -> crate::hash::Digest {
        console.wallet.as_ref().unwrap().lock().unwrap().id()
    }

    fn last_post(desk: &Desk, kind: u8) -> (crate::hash::Digest, Vec<u8>) {
        let (to, _, body) = desk.node.posts().into_iter().rev().find(|p| p.1 == kind).expect("a message");
        (to, body)
    }

    /// A payment made to a name is known by the name afterwards: in
    /// both wallets' lists, with the address beside it in the one that
    /// paid; and in its proof, for as long as the name is that
    /// wallet's by the chain. The address is shown always, the name
    /// only while it holds.
    #[test]
    fn a_payment_to_a_name_says_the_name() {
        use crate::msg::KIND_SLATE;
        let (desk, payer, paid) = funded("named");
        let all = [&payer, &paid];
        // The wallet to be paid registers a name that says its address.
        assert!(said(&payer, "name-commit shop").starts_with("Name shop: committed to"));
        let revealed = (0..40).any(|_| {
            desk.mine(&payer, &all);
            matches!(payer.run("name-reveal shop"), Reply::Said(_))
        });
        assert!(revealed);
        desk.mine(&payer, &all);
        // (Here the one that pays is `paid`, and `payer` holds the name.)
        let (shop, buyer) = (&payer, &paid);
        desk.mine(buyer, &all);
        desk.mine(buyer, &all);
        let address = said(shop, "address");
        let begun = said(buyer, "send 5 @shop");
        assert!(begun.contains(&format!("begun: 5 and a fee of 0.0000175, to {address}")), "{begun}");
        let (_, slate) = last_post(&desk, KIND_SLATE);
        let answered = shop.take(&message(KIND_SLATE, slate, None)).unwrap();
        assert!(answered.ends_with("answered: 5 to this wallet as @shop"), "{answered}");
        let (_, answer) = last_post(&desk, KIND_SLATE);
        let signed = buyer.take(&message(KIND_SLATE, answer, Some(id_of(shop)))).unwrap();
        assert!(signed.contains("signed and pooled"), "{signed}");
        // Each list says it: to the name, with the address it paid;
        // and as the name.
        let last = |prompt: &TestConsole| said(prompt, "txs").lines().last().unwrap().to_string();
        let cut = format!("{}…{}", &address[..8], &address[address.len() - 6..]);
        assert!(last(buyer).ends_with(&format!("  to @shop ({cut})")), "{}", last(buyer));
        assert!(last(shop).ends_with("  as @shop"), "{}", last(shop));
        let n = last(buyer).split_whitespace().next().unwrap().to_string();
        assert!(said(buyer, &format!("txs {n}")).lines().next().unwrap().ends_with(&format!("  to @shop ({address})")));
        // Proven: to the name, and the address with it.
        desk.mine(shop, &all);
        let file = desk.file("named.proof");
        assert!(said(buyer, &format!("payment-proof {n} {file}")).starts_with("the proof of "));
        let holds = said(shop, &format!("verify-proof {file}"));
        assert!(holds.contains(&format!("\nTo: @shop ({address})\nAmount: 5\n")), "{holds}");
        // The name says another address from here on: the proof holds
        // as it did, and shows the address alone.
        let elsewhere = crate::address::encode(&[7; 32]);
        assert!(said(shop, &format!("name-update shop {elsewhere}")).starts_with("Name shop: "));
        desk.mine(shop, &all);
        let holds = said(buyer, &format!("verify-proof {file}"));
        assert!(holds.contains(&format!("\nTo: {address}\nAmount: 5\n")), "{holds}");
        // And a payment to an address is known by its address.
        let begun = said(buyer, &format!("send 1 {address}"));
        assert!(begun.contains("begun: 1 and a fee of"), "{begun}");
        let (_, slate) = last_post(&desk, KIND_SLATE);
        let answered = shop.take(&message(KIND_SLATE, slate, None)).unwrap();
        assert!(answered.ends_with("answered: 1 to this wallet"), "{answered}");
        let (_, answer) = last_post(&desk, KIND_SLATE);
        buyer.take(&message(KIND_SLATE, answer, Some(id_of(shop)))).unwrap();
        assert!(last(buyer).ends_with(&format!("  to {cut}")), "{}", last(buyer));
    }

    /// A payment sent to an address goes to its wallet as a message,
    /// is answered by a message, and is signed when the answer comes
    /// from the wallet it was sent to: and from no other, nor of what
    /// was not begun, or was begun in a file. One that is not delivered
    /// is given up.
    #[test]
    fn a_payment_is_made_by_messages() {
        use crate::msg::KIND_SLATE;
        let (desk, payer, paid) = funded("messages");
        let to = said(&paid, "address");
        let begun = said(&payer, &format!("send 5 {to}"));
        assert!(begun.contains(&format!("begun: 5 and a fee of 0.0000175, to {to}")), "{begun}");
        let (whom, slate) = last_post(&desk, KIND_SLATE);
        assert_eq!(whom, id_of(&paid));
        let id = Slate::from_text(std::str::from_utf8(&slate).unwrap()).unwrap().id;
        assert!(payer.awaits_answer(&id) && !paid.awaits_answer(&id));
        // The wallet's list has it, numbered: begun, and what it is to
        // spend says which row spends it.
        let row = |text: &str, n: u32| -> Vec<String> {
            let line = text.lines().find(|l| l.split_whitespace().next() == Some(&n.to_string()));
            line.unwrap_or_else(|| panic!("no row {n}: {text}")).split_whitespace().map(str::to_string).collect()
        };
        // (What the two blocks paid is what the outputs come to.)
        let supply = said(&payer, "supply");
        let as_paid = "block 2\nexpected: 3,000\nunspent:  3,000 in 2 outputs\nburned:   0 of them";
        assert!(supply.starts_with(as_paid) && supply.ends_with("the supply is as expected"), "{supply}");
        let listed = said(&payer, "txs");
        assert_eq!(row(&listed, 1)[..4], ["1", "reward", "confirmed", "1,500"], "{listed}");
        assert_eq!(row(&listed, 3)[..4], ["3", "sent", "begun", "5"], "{listed}");
        let pending = said(&payer, "txs pending");
        assert_eq!((pending.lines().count(), row(&pending, 3)[2].as_str()), (2, "begun"), "{pending}");
        assert_eq!(said(&payer, "txs mined").lines().count(), 3);
        let outputs = said(&payer, "outputs");
        assert!(outputs.lines().any(|l| l.contains("reserved") && l.trim_end().ends_with(" 3")), "{outputs}");
        assert_eq!(said(&paid, "txs"), "nothing yet");
        // What comes that is no slate, or of no kind there is.
        assert_eq!(paid.take(&message(99, vec![], None)), Err("a message of a kind not known (99)".to_string()));
        let nonsense = paid.take(&message(KIND_SLATE, b"nonsense".to_vec(), None));
        assert_eq!(nonsense, Err("what its sender sent is no slate".to_string()));
        // Answered by the wallet it is for, back by the node it came by.
        let answered = paid.take(&message(KIND_SLATE, slate.clone(), None)).unwrap();
        assert!(answered.ends_with("answered: 5 to this wallet"), "{answered}");
        // (What is coming to the wallet that is paid is a row of its
        // list too, and its output says that row made it.)
        let coming = said(&paid, "txs");
        assert_eq!(row(&coming, 1)[..4], ["1", "received", "pending", "5"], "{coming}");
        let outputs = said(&paid, "outputs");
        assert!(
            outputs.lines().any(|l| l.contains("pending") && l.split_whitespace().rev().nth(1) == Some("1")),
            "{outputs}"
        );
        // (A second payment begun to it, answered, and then no longer
        // wanted: its row says so, and its output is gone.)
        let file = desk.file("unwanted.slate");
        said(&payer, &format!("send-file 1 {file}"));
        said(&paid, &format!("receive {file}"));
        assert!(said(&paid, "cancel 2").starts_with("row 2: the payment is no longer expected"));
        assert_eq!(row(&said(&paid, "txs"), 2)[..4], ["2", "received", "cancelled", "1"]);
        assert_eq!(said(&paid, "outputs").lines().count(), 2);
        let slate_id = said(&payer, "txs").lines().last().unwrap().split_whitespace().last().unwrap().to_string();
        assert!(said(&payer, &format!("cancel {slate_id}")).ends_with("given up"));
        let (_, answer) = last_post(&desk, KIND_SLATE);
        assert_ne!(answer, slate);
        // One that came by no node cannot be answered.
        let mut lost = message(KIND_SLATE, slate, None);
        lost.by = None;
        assert!(desk.prompt(true).take(&lost).unwrap_err().ends_with("cannot be answered: it came by no node"));
        // The answer from another wallet is nobody's.
        let other = payer.take(&message(KIND_SLATE, answer.clone(), Some([9; 32]))).unwrap_err();
        assert!(
            other.contains(&format!("was sent to {to}, and ")) && other.ends_with("answers it: not signed"),
            "{other}"
        );
        assert!(payer.awaits_answer(&id));
        let signed = payer.take(&message(KIND_SLATE, answer.clone(), Some(id_of(&paid)))).unwrap();
        assert!(signed.contains(&format!("answered by {to}, signed and pooled: transaction ")), "{signed}");
        assert!(pooled_ones(&payer) != "" && !payer.awaits_answer(&id));
        // The same row, of the transaction now: pooled, and all of it
        // said when it is asked for by its number.
        let listed = said(&payer, "txs");
        assert_eq!(row(&listed, 3)[..4], ["3", "sent", "pooled", "5"], "{listed}");
        let one = said(&payer, "txs 3");
        assert!(
            one.starts_with(&format!("3  sent  pooled  to {to}\namount: 5\n"))
                && one.contains("\nspends: ")
                && one.contains("\nmakes: ")
        );
        assert!(one.contains("(this wallet's)") && one.contains("\nproof: not yet"), "{one}");
        assert!(matches!(payer.run("txs zz"), Reply::Wrong(_)));
        let again = payer.take(&message(KIND_SLATE, answer, Some(id_of(&paid)))).unwrap_err();
        assert!(again.ends_with("which this wallet has not begun"), "{again}");
        assert_eq!(payer.resolved(&id, &id_of(&paid)), Ok(String::new()));
        // Of a message that was no payment of this wallet's still to be
        // answered, that it was not delivered is all there is to say.
        let said_of = payer.undelivered(&id_of(&paid), &id, "nobody there");
        assert_eq!(said_of, format!("Error: a message to {to} was not delivered (nobody there)"));
        // A payment begun and not delivered is given up.
        let begun = said(&payer, &format!("send 2 {to} \"a note\""));
        assert!(begun.contains("note: \"a note\""), "{begun}");
        let (_, slate) = last_post(&desk, KIND_SLATE);
        let id = Slate::from_text(std::str::from_utf8(&slate).unwrap()).unwrap().id;
        let given_up = payer.undelivered(&id_of(&paid), &id, "nobody there");
        assert!(given_up.ends_with("was not delivered (nobody there): given up, nothing was spent"), "{given_up}");
        assert_eq!(begun_ones(&payer), "");
        // It keeps its row, which says what became of it; and a row
        // that is done with is not cancelled again.
        let listed = said(&payer, "txs");
        assert_eq!(row(&listed, 5)[..4], ["5", "sent", "cancelled", "2"], "{listed}");
        assert_eq!(payer.run("cancel 5"), Reply::Wrong("row 5 is done with already".to_string()));
        // Nor is what came to the wallet.
        assert_eq!(payer.run("cancel 1"), Reply::Wrong("it is not this wallet's to cancel: it came to it".to_string()));
        // One begun in a file is finalized from a file.
        let file = desk.file("by-file.slate");
        said(&payer, &format!("send-file 1 {file}"));
        said(&paid, &format!("receive {file}"));
        let answer = std::fs::read(format!("{file}.received")).unwrap();
        let by_file = payer.take(&message(KIND_SLATE, answer, Some(id_of(&paid)))).unwrap_err();
        assert!(by_file.contains("was begun in a file") && by_file.ends_with("(finalize its answer from a file)"));
        // The pool does not take a payment of what is spent already.
        let logged = desk.logged.lock().unwrap().join("\n");
        assert!(logged.contains("answered by ") && logged.contains("answered: 5 to this wallet"), "{logged}");
    }

    /// Names under a name: asked of a wallet that holds no name, each
    /// command says what it lacks; a key is let sign for a name, by a
    /// file that only the wallet it names takes.
    #[test]
    fn names_under_a_name_are_asked_for_at_the_prompt() {
        let (desk, holder, other) = funded("under");
        let (mine, theirs) = (said(&holder, "address"), said(&other, "address"));
        assert_eq!((holder.reached_by_names(), holder.renew_names()), (Ok(()), Ok(())));
        assert_eq!(wrong(&holder, "subname set bob@alice x"), "'x' is no address (tab1…)");
        assert_eq!(wrong(&holder, &format!("subname set bob@alice {theirs}")), "alice is not registered");
        assert_eq!(wrong(&holder, "subname del bob@alice"), "bob@alice is not a name this wallet gave out");
        assert_eq!(wrong(&holder, "subname drop bob@alice"), "this wallet is not bob@alice");
        assert_eq!(wrong(&holder, "send 1 bob@alice"), "alice is not registered");
        assert!(said(&holder, "subnames").starts_with("no names under names"));
        // A key that signs for a name, for so many days: written for the
        // wallet whose key it is, and taken by no other.
        let file = desk.file("alice.signer");
        let let_sign = said(&holder, &format!("subname delegate alice {theirs} {file}"));
        assert!(let_sign.starts_with(&format!("for 30 days the key of {theirs} signs for alice")), "{let_sign}");
        assert!(said(&holder, &format!("subname delegate alice {theirs} 7 {file}")).starts_with("for 7 days "));
        assert!(!wrong(&holder, &format!("subname delegate alice {theirs} many {file}")).is_empty());
        let not_mine = wrong(&holder, &format!("subname signer {file}"));
        assert!(not_mine.ends_with(&format!("this wallet is {mine}")), "{not_mine}");
        assert_eq!(wrong(&other, &format!("subname signer {file}")), "alice is not registered");
        assert!(wrong(&other, &format!("subname signer {}", desk.file("none"))).contains("none"));
        // What comes as a name given, and is none.
        assert!(other.take(&message(crate::msg::KIND_NAME, b"nonsense".to_vec(), None)).is_err());
    }

    /// A name under a name is given by the wallet that holds the name,
    /// by a certificate sent to the wallet it is given to, which is the
    /// name once it has it; a payment is sent to it; a key is let sign
    /// for the name; and a name given is taken back, and let go of.
    #[test]
    fn a_name_under_a_name_is_given_paid_and_taken_back() {
        let (desk, holder, other) = funded("given");
        let all = [&holder, &other];
        let (mine, theirs) = (said(&holder, "address"), said(&other, "address"));
        // The name says its holder's address.
        assert!(said(&holder, &format!("name-commit alice {mine}")).starts_with("Name alice: committed to"));
        let revealed = (0..40).any(|_| {
            desk.mine(&holder, &all);
            matches!(holder.run("name-reveal alice"), Reply::Said(_))
        });
        assert!(revealed);
        desk.mine(&holder, &all);
        assert!(said(&holder, "name alice").contains(&format!("\n  as an address: {mine}\n")));
        // Given: a certificate, sent to the wallet it names.
        let given = said(&holder, &format!("subname set bob@alice {theirs}"));
        assert!(given.starts_with(&format!("bob@alice is {theirs}, by a certificate that holds 7 days")), "{given}");
        assert_eq!(said(&holder, "subnames"), format!("given: bob@alice is {theirs}, for 7.0 days more"));
        let (whom, bundle) = last_post(&desk, crate::msg::KIND_NAME);
        assert_eq!(whom, id_of(&other));
        let taken = other.take(&message(crate::msg::KIND_NAME, bundle.clone(), None)).unwrap();
        assert_eq!(taken, "This wallet is bob@alice, by a certificate that holds 7.0 days more");
        assert!(
            said(&other, "subnames").starts_with("this wallet is bob@alice, for 7.0 days more: reached by it at 0")
        );
        // (A certificate for another wallet is not this one's.)
        assert!(holder.take(&message(crate::msg::KIND_NAME, bundle, None)).is_err());
        // A key let sign for the name, taken by the wallet it names.
        let file = desk.file("alice.signer");
        let let_sign = said(&holder, &format!("subname delegate alice {theirs} {file}"));
        assert!(let_sign.contains("there is no taking it back sooner, but by having the name say"), "{let_sign}");
        let signs = said(&other, &format!("subname signer {file}"));
        assert_eq!(signs, format!("this wallet signs for alice for 30.0 days more, by the word of {mine}"));
        assert!(said(&other, "subnames").contains(&format!("signs for alice, by the word of {mine}, for 30.0 days")));
        // Paid by its name: the payment waits to know whose it is.
        let begun = said(&holder, "send 1 bob@alice");
        assert!(begun.contains("begun: 1 and a fee of 0.0000175, to bob@alice; sent to its wallet"), "{begun}");
        let (asked, slate) = last_post(&desk, crate::msg::KIND_SLATE);
        let id = Slate::from_text(std::str::from_utf8(&slate).unwrap()).unwrap().id;
        assert_ne!(asked, id_of(&other));
        let whose = holder.resolved(&id, &id_of(&other)).unwrap();
        assert!(whose.ends_with(&format!(": bob@alice is {theirs}")), "{whose}");
        let lost = holder.undelivered(&id_of(&other), &id, "nobody there");
        assert!(lost.contains(" to bob@alice was not delivered (nobody there): given up"), "{lost}");
        // Let go of by the wallet that is it, and given out no longer.
        assert_eq!(said(&other, "subname drop bob@alice"), "this wallet is bob@alice no longer");
        let taken_back = said(&holder, "subname del bob@alice");
        assert!(taken_back.starts_with("bob@alice is given out no longer"), "{taken_back}");
        assert!(taken_back.contains("the last holds until its time is past"), "{taken_back}");
        assert!(said(&holder, "subnames").starts_with("no names under names"));
        assert_eq!((holder.reached_by_names(), other.renew_names(), holder.renew_names()), (Ok(()), Ok(()), Ok(())));
    }
}
