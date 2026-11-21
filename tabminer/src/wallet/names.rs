//! The wallet's names: registering one, changing what it says, and
//! giving it to another wallet.
//!
//! A name registration draws one nonce `r`, like an output: the owner
//! key is generated from `H(m, r)` under its own domain, the commit's
//! salt is `H(m, r)` under another, and the memo of both the commit's
//! output and the name's record is the output memo with a zero amount.
//! So a wallet made again from its phrase finds its names among the
//! records every node keeps (the memo opens, and the owner key's hash
//! is the record's owner), and its commits among the commits' outputs
//! (the memo opens; the name itself is learned when it is revealed, by
//! making the commit again).
//!
//! A name is registered in two steps, each an operation a transaction
//! of the wallet's carries ([`Wallet::carry`]): a commit, which says
//! nothing of the name, and once that has been in the chain a while, a
//! reveal. Every operation the owner signs afterwards puts the name
//! under a fresh key; the key before signs from its leaves as an
//! output's does, for replacements. A name is given to another wallet
//! by an update to a record that wallet wrote ([`Wallet::name_offer`]),
//! signed by the owner ([`Wallet::name_transfer`]).

use std::io;

use super::{
    Commitment, Fee, LEAVES_PER_HALF, NONCE, Nonce, Result, Sent, Signed, T_COMMITS, T_NAMES, T_OUTPUTS, T_SENT,
    Tables, Unspent, Wallet, WalletError, random_bytes,
};
use crate::codec::{Reader, Writer};
use crate::hash::Digest;
use crate::mempool::Policy;
use crate::name::{self, NameOp, Record, commit_hash, name_hash};
use crate::output::{Key, memo_slot, pubkey_hash, slot_parts};
use crate::hash::digest_to_bytes;
use crate::store::Backend;
use crate::store::state::Snapshot;
use crate::transaction::UnsignedTransaction;
use crate::xmss::{PublicKey, SEED_SIZE};

const DOM_OWNER: u32 = 68;
const DOM_SALT: u32 = 69;

/// What the wallet asks of the chain's registry of names.
pub trait Registry {
    /// The record registered for `name`.
    fn record(&self, name: &[u8]) -> io::Result<Option<Record>>;
    /// Where the commit of hash `commit` is, and the height of the
    /// block that made it.
    fn commit(&self, commit: &Digest) -> io::Result<Option<(u64, u32)>>;
    /// Calls `f` with every record.
    fn each_record(&self, f: &mut dyn FnMut(&Record)) -> io::Result<()>;
    /// Calls `f` with every commit not yet revealed or swept: its hash,
    /// and the memo of its output.
    fn each_commit(&self, f: &mut dyn FnMut(&Digest, &crate::output::Memo)) -> io::Result<()>;
}

impl<B: Backend + 'static> Registry for Snapshot<'_, B> {
    fn record(&self, name: &[u8]) -> io::Result<Option<Record>> {
        match name::name_key(name) {
            Ok(key) => Ok(self.name(key)?.filter(|r| r.name.as_bytes() == name)),
            Err(_) => Ok(None),
        }
    }

    fn commit(&self, commit: &Digest) -> io::Result<Option<(u64, u32)>> {
        let Some(position) = self.commits().position_of(self.pages(), commit)? else { return Ok(None) };
        Ok(self.commits().at(self.pages(), position)?.map(|c| (position, c.height)))
    }

    fn each_record(&self, f: &mut dyn FnMut(&Record)) -> io::Result<()> {
        self.names().for_each(self.pages(), &mut |_, record| f(record))
    }

    fn each_commit(&self, f: &mut dyn FnMut(&Digest, &crate::output::Memo)) -> io::Result<()> {
        for (position, commit) in self.commits().between(self.pages(), 0, u64::MAX)? {
            if let Some((record, _)) = self.output(position)? {
                f(&commit.hash, &record.memo);
            }
        }
        Ok(())
    }
}

/// A commit this wallet made, or found by a scan, awaiting its reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommit {
    pub commit: Commitment,
    pub nonce: Nonce,
    /// Unknown for a commit found by a scan, until the user reveals it.
    pub name: Option<Vec<u8>>,
    pub value: Commitment,
    pub created: u64,
    pub recovered: bool,
}

impl PendingCommit {
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(&self.nonce);
        let name = self.name.as_deref().unwrap_or(&[]);
        w.0.push(name.len() as u8);
        w.0.extend_from_slice(name);
        w.digest(&self.value);
        w.u64(self.created);
        w.0.push(self.recovered as u8);
        w.finish()
    }

    pub(super) fn from_bytes(commit: Commitment, bytes: &[u8]) -> Option<PendingCommit> {
        let mut r = Reader(bytes);
        let nonce = r.take(NONCE)?.try_into().ok()?;
        let n = r.take(1)?[0] as usize;
        let name = r.take(n)?.to_vec();
        let value = r.digest()?;
        let created = r.u64()?;
        let recovered = r.take(1)?[0] == 1;
        r.is_empty().then_some(PendingCommit {
            commit,
            nonce,
            name: (n > 0).then_some(name),
            value,
            created,
            recovered,
        })
    }
}

/// Where a name of the wallet's stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameStage {
    /// Its reveal is signed; the record is not on chain yet.
    Revealed,
    /// The chain's record names this wallet's key.
    Owned,
    /// The wallet wrote a record for it, to receive it from its owner.
    Offered,
}

/// A name this wallet owns, or is about to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedName {
    pub name: Vec<u8>,
    /// The current owner key's nonce.
    pub nonce: Nonce,
    pub value: Commitment,
    pub created: u64,
    pub stage: NameStage,
    /// Found by a scan: the key signs from leaves 8 to 15.
    pub recovered: bool,
    pub start: u8,
    pub used: u8,
    /// A rotation signed but not yet on chain: the new key's nonce and the
    /// value written.
    pub pending: Option<(Nonce, Commitment)>,
    /// Signed over to another wallet; the record goes once the chain shows it.
    pub transferring: bool,
}

impl OwnedName {
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(&self.nonce);
        w.digest(&self.value);
        w.u64(self.created);
        w.0.push(match self.stage {
            NameStage::Revealed => 0,
            NameStage::Owned => 1,
            NameStage::Offered => 2,
        });
        w.0.extend_from_slice(&[self.recovered as u8, self.start, self.used, self.transferring as u8]);
        match &self.pending {
            Some((nonce, value)) => {
                w.0.push(1);
                w.bytes(nonce);
                w.digest(value);
            }
            None => w.0.push(0),
        }
        w.finish()
    }

    pub(super) fn from_bytes(name: Vec<u8>, bytes: &[u8]) -> Option<OwnedName> {
        let mut r = Reader(bytes);
        let nonce = r.take(NONCE)?.try_into().ok()?;
        let value = r.digest()?;
        let created = r.u64()?;
        let stage = match r.take(1)?[0] {
            0 => NameStage::Revealed,
            1 => NameStage::Owned,
            2 => NameStage::Offered,
            _ => return None,
        };
        let flags = r.take(4)?;
        let (recovered, start, used, transferring) = (flags[0] == 1, flags[1], flags[2], flags[3] == 1);
        if u32::from(start) >= LEAVES_PER_HALF || u32::from(used) > LEAVES_PER_HALF {
            return None;
        }
        let pending = match r.take(1)?[0] {
            0 => None,
            1 => Some((r.take(NONCE)?.try_into().ok()?, r.digest()?)),
            _ => return None,
        };
        r.is_empty().then_some(OwnedName {
            name,
            nonce,
            value,
            created,
            stage,
            recovered,
            start,
            used,
            pending,
            transferring,
        })
    }

    /// Signatures the current owner key can still make.
    pub fn signatures_left(&self) -> u32 {
        LEAVES_PER_HALF - u32::from(self.used)
    }
}

fn said(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn fresh_nonce() -> io::Result<Nonce> {
    random_bytes::<NONCE>()
}

impl<B: Backend> Wallet<B> {
    /// The owner key of the name registration with nonce `nonce`.
    pub fn owner_key(&self, nonce: &Nonce) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_OWNER, nonce));
        Key::generate(&seed)
    }

    fn owner_hash(&self, nonce: &Nonce) -> Commitment {
        pubkey_hash(&self.owner_key(nonce).public_key())
    }

    /// The commit salt of the registration with nonce `nonce`.
    fn salt(&self, nonce: &Nonce) -> Commitment {
        self.with_master(DOM_SALT, nonce)
    }

    /// The 32-byte memo of a name record: the memo padded with zeros, as a
    /// memo slot of amount zero.
    fn name_memo(&self, nonce: &Nonce) -> Digest {
        memo_slot(&self.memo(nonce), 0)
    }

    /// The nonce a name memo ([`Wallet::name_memo`]) holds, if it is one of
    /// this wallet's.
    fn open_name_memo(&self, memo: &Digest) -> Option<Nonce> {
        match slot_parts(memo)? {
            (m, 0) => self.open_memo(&m),
            _ => None,
        }
    }

    /// The record this wallet writes for `name` under the key of `nonce`.
    fn name_record(&self, name: &[u8], nonce: &Nonce, value: &Commitment) -> Result<Record> {
        Record::new(name, self.owner_hash(nonce), *value, self.name_memo(nonce))
            .map_err(|_| WalletError::Name(format!("{} is not a valid name", said(name))))
    }

    fn commit_of(&self, name: &[u8], nonce: &Nonce) -> Option<Commitment> {
        let nh = name_hash(name).ok()?;
        Some(commit_hash(&nh, &self.salt(nonce), &self.owner_hash(nonce)))
    }

    /// The wallet's record of `name`, if any.
    pub fn owned_name(&self, name: &[u8]) -> Option<OwnedName> {
        self.t.names.get(name).cloned()
    }

    /// Every name the wallet holds or awaits, by name.
    pub fn owned_names(&self) -> Vec<OwnedName> {
        self.t.names.values().cloned().collect()
    }

    /// Every commit awaiting its reveal, oldest first.
    pub fn pending_commits(&self) -> Vec<PendingCommit> {
        let mut out: Vec<PendingCommit> = self.t.commits.values().cloned().collect();
        out.sort_by_key(|c| c.created);
        out
    }

    /// Starts registering `name` with `value`: a commit operation to carry
    /// in a transaction, remembered for the reveal.
    pub fn name_commit(&mut self, name: &[u8], value: Commitment, now: u64) -> Result<NameOp> {
        if !name::valid_name(name) {
            return Err(WalletError::Name(format!("{} is not a valid name", said(name))));
        }
        if self.t.names.contains_key(name) {
            return Err(WalletError::Name("the wallet already holds that name".into()));
        }
        if self.t.commits.values().any(|c| c.name.as_deref() == Some(name)) {
            return Err(WalletError::Name("the wallet has already committed to that name".into()));
        }
        let nonce = fresh_nonce()?;
        let commit = self.commit_of(name, &nonce).expect("validated name");
        let entry = PendingCommit { commit, nonce, name: Some(name.to_vec()), value, created: now, recovered: false };
        let mut t = self.t.clone();
        t.commits.insert(digest_to_bytes(&commit), entry);
        self.commit(t, &[T_COMMITS])?;
        Ok(NameOp::Commit { commit, memo: self.memo(&nonce) })
    }

    /// Reveals `name` from its commit, for a block at `height`, once the
    /// commit is at least `wait` blocks old (at least `min_reveal`, the
    /// network's). A commit found by a scan is matched to the name here.
    /// The name's record is then awaited on chain.
    pub fn name_reveal(
        &mut self,
        name: &[u8],
        wait: u32,
        min_reveal: u32,
        registry: &impl Registry,
        height: u32,
        now: u64,
    ) -> Result<NameOp> {
        let pending = self.pending_commits();
        let entry = pending
            .iter()
            .find(|c| c.name.as_deref() == Some(name))
            .or_else(|| pending.iter().find(|c| c.name.is_none() && self.commit_of(name, &c.nonce) == Some(c.commit)))
            .cloned()
            .ok_or_else(|| WalletError::Name(format!("no commit for {}", said(name))))?;
        let (position, made) = registry
            .commit(&entry.commit)?
            .ok_or_else(|| WalletError::Name("the commit is not on chain yet".into()))?;
        let wait = wait.max(min_reveal);
        if height < made.saturating_add(wait) {
            return Err(WalletError::Name(format!(
                "the commit is {} blocks old; wait {} more",
                height.saturating_sub(made),
                made + wait - height
            )));
        }
        let record = self.name_record(name, &entry.nonce, &entry.value)?;
        let op = NameOp::Reveal { record, salt: self.salt(&entry.nonce), commit: position };
        let owned = OwnedName {
            name: name.to_vec(),
            nonce: entry.nonce,
            value: entry.value,
            created: now,
            stage: NameStage::Revealed,
            recovered: entry.recovered,
            start: if entry.recovered { random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8 } else { 0 },
            used: 0,
            pending: None,
            transferring: false,
        };
        let mut t = self.t.clone();
        t.names.insert(name.to_vec(), owned);
        t.commits.remove(&digest_to_bytes(&entry.commit));
        self.commit(t, &[T_COMMITS, T_NAMES])?;
        Ok(op)
    }

    /// Undoes in `t` what [`Wallet::name_commit`], [`Wallet::name_reveal`],
    /// [`Wallet::name_update`] or [`Wallet::name_transfer`] recorded: a
    /// commit is forgotten, a revealed name goes back to its commit, an
    /// update or transfer is no longer signed. A signing leaf an update
    /// used stays used: the signature was made, and a leaf signs once.
    pub(super) fn undo_name_op_in(&self, t: &mut Tables, op: &NameOp) {
        match op {
            NameOp::Commit { commit, .. } => {
                t.commits.remove(&digest_to_bytes(commit));
            }
            NameOp::Reveal { record, .. } => {
                let name = record.name.as_bytes();
                if let Some(entry) = t.names.get(name).filter(|n| n.stage == NameStage::Revealed).cloned()
                    && let Some(commit) = self.commit_of(&entry.name, &entry.nonce)
                {
                    let back = PendingCommit {
                        commit,
                        nonce: entry.nonce,
                        name: Some(entry.name.clone()),
                        value: entry.value,
                        created: entry.created,
                        recovered: entry.recovered,
                    };
                    t.commits.insert(digest_to_bytes(&commit), back);
                    t.names.remove(name);
                }
            }
            NameOp::Update { record, .. } => {
                if let Some(entry) = t.names.get_mut(record.name.as_bytes()) {
                    entry.pending = None;
                    entry.transferring = false;
                }
            }
        }
    }

    /// [`Wallet::undo_name_op_in`], for an operation no transaction could
    /// carry (too few funds, say).
    pub fn undo_name_op(&mut self, op: &NameOp) -> Result<()> {
        let mut t = self.t.clone();
        self.undo_name_op_in(&mut t, op);
        self.commit(t, &[T_COMMITS, T_NAMES])
    }

    /// Signs `record` as the current owner of its name with the key's next
    /// leaf, marking it used in `entry`; also returns whether it was the
    /// key's last.
    fn sign_update(&self, entry: &mut OwnedName, record: Record) -> Result<(NameOp, bool)> {
        if u32::from(entry.used) >= LEAVES_PER_HALF {
            return Err(WalletError::Exhausted);
        }
        let base = if entry.recovered { LEAVES_PER_HALF } else { 0 };
        let leaf = base + (u32::from(entry.start) + u32::from(entry.used)) % LEAVES_PER_HALF;
        entry.used += 1;
        let last = u32::from(entry.used) == LEAVES_PER_HALF;
        let mut key = self.owner_key(&entry.nonce);
        key.set_next_index(u64::from(leaf));
        let op = NameOp::update(record, &mut key).map_err(|e| WalletError::Name(e.to_string()))?;
        Ok((op, last))
    }

    /// The wallet's entry for a name it owns and has nothing signed for.
    fn owned_and_free(&self, name: &[u8]) -> Result<OwnedName> {
        let entry = self
            .owned_name(name)
            .filter(|n| n.stage == NameStage::Owned)
            .ok_or_else(|| WalletError::Name(format!("the wallet does not own {}", said(name))))?;
        if entry.pending.is_some() || entry.transferring {
            return Err(WalletError::Name("an operation on that name is already signed".into()));
        }
        Ok(entry)
    }

    /// Changes `name`'s value, rotating its owner key: an update operation
    /// to carry in a transaction, and whether it took the current key's
    /// last signature (after which it cannot be cancelled and replaced).
    pub fn name_update(&mut self, name: &[u8], value: Commitment) -> Result<(NameOp, bool)> {
        let mut entry = self.owned_and_free(name)?;
        let nonce = fresh_nonce()?;
        let record = self.name_record(name, &nonce, &value)?;
        entry.pending = Some((nonce, value));
        let op = self.sign_update(&mut entry, record)?;
        let mut t = self.t.clone();
        t.names.insert(name.to_vec(), entry);
        self.commit(t, &[T_NAMES])?;
        Ok(op)
    }

    /// Prepares to receive `name` from its owner: a record under a fresh key
    /// of this wallet's, for the owner to sign over ([`Wallet::name_transfer`]).
    pub fn name_offer(&mut self, name: &[u8], value: Commitment, now: u64) -> Result<Record> {
        if self.t.names.contains_key(name) {
            return Err(WalletError::Name("the wallet already holds that name".into()));
        }
        let nonce = fresh_nonce()?;
        let record = self.name_record(name, &nonce, &value)?;
        let entry = OwnedName {
            name: name.to_vec(),
            nonce,
            value,
            created: now,
            stage: NameStage::Offered,
            recovered: false,
            start: 0,
            used: 0,
            pending: None,
            transferring: false,
        };
        let mut t = self.t.clone();
        t.names.insert(name.to_vec(), entry);
        self.commit(t, &[T_NAMES])?;
        Ok(record)
    }

    /// Signs `record`, written by its recipient, over as the owner of its
    /// name: an update operation to carry in a transaction, and whether it
    /// took the key's last signature.
    pub fn name_transfer(&mut self, record: Record) -> Result<(NameOp, bool)> {
        let name = record.name.as_bytes().to_vec();
        let mut entry = self.owned_and_free(&name)?;
        if record.owner == self.owner_hash(&entry.nonce) {
            return Err(WalletError::Name("the record keeps the current owner".into()));
        }
        entry.transferring = true;
        let op = self.sign_update(&mut entry, record)?;
        let mut t = self.t.clone();
        t.names.insert(name, entry);
        self.commit(t, &[T_NAMES])?;
        Ok(op)
    }

    /// Brings the wallet's names in line with the chain's records: a reveal
    /// or a rotation seen on chain settles, an offered name arrives, a
    /// transferred one leaves, and a name whose record names someone else's
    /// key is dropped. A reveal or rotation the wallet cancelled but that
    /// landed anyway is adopted from the record's memo. Returns how many
    /// entries changed.
    pub fn sync_names(&mut self, registry: &impl Registry) -> Result<usize> {
        if self.t.commits.is_empty() && self.t.names.is_empty() {
            return Ok(0);
        }
        let (mut changed, mut gave_up) = (0, false);
        let mut t = self.t.clone();
        // A pending commit whose reveal landed after all.
        for c in self.pending_commits() {
            let Some(name) = &c.name else { continue };
            let Some(record) = registry.record(name)? else { continue };
            if record.owner == self.owner_hash(&c.nonce) && !t.names.contains_key(name) {
                let entry = OwnedName {
                    name: name.clone(),
                    nonce: c.nonce,
                    value: record.value,
                    created: c.created,
                    stage: NameStage::Owned,
                    recovered: c.recovered,
                    start: if c.recovered { random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8 } else { 0 },
                    used: 0,
                    pending: None,
                    transferring: false,
                };
                t.names.insert(name.clone(), entry);
                t.commits.remove(&digest_to_bytes(&c.commit));
                changed += 1;
            }
        }
        for mut entry in t.names.values().cloned().collect::<Vec<_>>() {
            let Some(record) = registry.record(&entry.name)? else { continue };
            let mine = record.owner == self.owner_hash(&entry.nonce);
            let mut rotated = entry.pending.as_ref().is_some_and(|(n, _)| record.owner == self.owner_hash(n));
            if !mine && !rotated && !entry.transferring {
                // A rotation whose pending entry a cancel dropped.
                if let Some(n) = self.open_name_memo(&record.memo).filter(|n| record.owner == self.owner_hash(n)) {
                    entry.pending = Some((n, record.value));
                    rotated = true;
                }
            }
            if rotated {
                let (nonce, value) = entry.pending.take().expect("a rotation has what it rotates to");
                entry.nonce = nonce;
                entry.value = value;
                entry.recovered = false;
                entry.start = 0;
                entry.used = 0;
                entry.stage = NameStage::Owned;
                t.names.insert(entry.name.clone(), entry);
                changed += 1;
            } else if mine {
                if entry.stage != NameStage::Owned || entry.value != record.value {
                    entry.stage = NameStage::Owned;
                    entry.value = record.value;
                    t.names.insert(entry.name.clone(), entry);
                    changed += 1;
                }
            } else if entry.transferring || entry.stage != NameStage::Offered {
                // Signed away, or registered by someone else first. Of
                // the second: this wallet's own reveal of the name, if
                // no block has it, never will be in one, and is given
                // up, so that what it would have spent is free again.
                if entry.stage == NameStage::Revealed && !entry.transferring {
                    let reveals = |sent: &&Sent| {
                        let of_it = |op: &NameOp| matches!(op, NameOp::Reveal { record, .. } if record.name.as_bytes() == &entry.name[..]);
                        sent.tx.ops.iter().any(of_it)
                    };
                    let dead: Vec<Commitment> = t.sent.values().filter(reveals).map(|sent| sent.txid).collect();
                    for txid in dead {
                        gave_up |= Self::unsend_in(&mut t, &txid);
                    }
                }
                t.names.remove(&entry.name);
                changed += 1;
            }
        }
        if changed > 0 {
            let all = &[T_COMMITS, T_NAMES, T_OUTPUTS, T_SENT, super::T_PAYMENTS];
            let tables: &[usize] = if gave_up { all } else { &[T_COMMITS, T_NAMES] };
            self.commit(t, tables)?;
        }
        Ok(changed)
    }

    /// Recovery: finds the wallet's names among the registry's records and
    /// its pending commits among the commit outputs. Returns how many of
    /// each were new.
    pub fn scan_names(&mut self, registry: &impl Registry, now: u64) -> Result<(usize, usize)> {
        let mut t = self.t.clone();
        let (mut names, mut commits) = (0, 0);
        let mut failed: Option<io::Error> = None;
        let mut start = || match random_bytes::<1>() {
            Ok(b) => b[0] % LEAVES_PER_HALF as u8,
            Err(e) => {
                failed.get_or_insert(e);
                0
            }
        };
        registry.each_record(&mut |record| {
            let Some(nonce) = self.open_name_memo(&record.memo) else { return };
            let name = record.name.as_bytes().to_vec();
            if record.owner != self.owner_hash(&nonce) || t.names.contains_key(&name) {
                return;
            }
            let entry = OwnedName {
                name: name.clone(),
                nonce,
                value: record.value,
                created: now,
                stage: NameStage::Owned,
                recovered: true,
                start: start(),
                used: 0,
                pending: None,
                transferring: false,
            };
            t.names.insert(name, entry);
            names += 1;
        })?;
        registry.each_commit(&mut |commit, memo| {
            let Some(nonce) = self.open_memo(memo) else { return };
            let id = digest_to_bytes(commit);
            if t.commits.contains_key(&id) {
                return;
            }
            let entry = PendingCommit {
                commit: *commit,
                nonce,
                name: None,
                value: [0; 32],
                created: now,
                recovered: true,
            };
            t.commits.insert(id, entry);
            commits += 1;
        })?;
        if let Some(e) = failed {
            return Err(e.into());
        }
        if names + commits > 0 {
            self.commit(t, &[T_COMMITS, T_NAMES])?;
        }
        Ok((names, commits))
    }

    /// Forgets pending commits that never reached the chain: not in the
    /// registry, and not among `pooled` (commits carried by pooled
    /// transactions, which may yet land). Returns the names forgotten.
    pub fn prune_commits(&mut self, registry: &impl Registry, pooled: &[Commitment]) -> Result<Vec<String>> {
        let mut t = self.t.clone();
        let mut gone = Vec::new();
        for c in self.pending_commits() {
            if registry.commit(&c.commit)?.is_none() && !pooled.contains(&c.commit) {
                t.commits.remove(&digest_to_bytes(&c.commit));
                gone.push(c.name.as_deref().map_or("(a name not known)".to_string(), said));
            }
        }
        if !gone.is_empty() {
            self.commit(t, &[T_COMMITS])?;
        }
        Ok(gone)
    }

    /// The smallest fee a transaction carrying `ops` from `inputs` inputs
    /// with change may pay.
    pub fn min_carry_fee(inputs: usize, ops: &[NameOp]) -> u64 {
        Policy::MAINNET.min_fee_for(Self::carry_weight(inputs, ops))
    }

    /// The size of a transaction carrying `ops` from `inputs` inputs
    /// with change.
    pub fn carry_weight(inputs: usize, ops: &[NameOp]) -> u64 {
        let weights = crate::mempool::Weights::DEFAULT;
        weights.of(inputs, 1) + ops.iter().map(|op| weights.of_op(op.kind())).sum::<u64>()
    }

    /// Signs a transaction of this wallet's that carries `ops` and pays
    /// `fee` (or the smallest the pool takes): confirmed inputs largest
    /// first, change to a fresh output. Recorded like a payment, so it can
    /// be cancelled while unconfirmed.
    pub fn carry(&mut self, ops: Vec<NameOp>, fee: impl Into<Fee>, chain: &impl Unspent, now: u64) -> Result<Signed> {
        if ops.is_empty() {
            return Err(WalletError::Name("nothing to carry".into()));
        }
        let dust = Policy::MAINNET.dust;
        let coins = self.spendable(chain)?;
        let mut inputs = 1;
        let given: Fee = fee.into();
        given.check(Self::carry_weight(1, &ops))?;
        let fee = loop {
            let fee = given.for_weight(Self::carry_weight(inputs, &ops));
            let mut picked = 0usize;
            let mut total = 0u128;
            for c in &coins {
                if total >= fee as u128 && picked > 0 {
                    break;
                }
                total += c.amount as u128;
                picked += 1;
            }
            if total < fee as u128 || picked == 0 {
                return Err(WalletError::Insufficient { have: total, need: fee as u128 });
            }
            let min = Self::min_carry_fee(picked.max(1), &ops);
            if given.is_total() && fee < min {
                return Err(WalletError::FeeTooLow { min });
            }
            if picked <= inputs {
                break fee;
            }
            inputs = picked;
        };
        let mut picked = Vec::new();
        let mut total = 0u128;
        for c in coins {
            if total >= fee as u128 && !picked.is_empty() {
                break;
            }
            total += c.amount as u128;
            picked.push(c);
        }
        let change_amount = (total - fee as u128) as u64;
        let mut t = self.t.clone();
        let (fee, outputs) = if change_amount >= dust {
            (fee, vec![self.receive_in(&mut t, change_amount, now)?])
        } else {
            (fee + change_amount, vec![])
        };
        let inputs: Vec<(PublicKey, u64)> =
            picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        let commitments: Vec<Commitment> = picked.iter().map(|c| c.commitment).collect();
        let signed = self.sign(&mut t, UnsignedTransaction::with_ops(inputs, outputs, ops), &commitments)?;
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: commitments,
            fee,
            size: signed.tx.size(),
            created: now,
            tx: signed.tx.clone(),
        };
        t.sent.insert(digest_to_bytes(&sent.txid), sent);
        self.commit(t, &[T_OUTPUTS, T_SENT])?;
        Ok(signed)
    }
}

/// The names table's bytes: each name, and its entry.
pub(super) fn put_names<'a>(names: impl Iterator<Item = &'a OwnedName>) -> Vec<u8> {
    let mut w = Writer::default();
    for n in names {
        let bytes = n.to_bytes();
        w.0.push(n.name.len() as u8);
        w.0.extend_from_slice(&n.name);
        w.u32(bytes.len() as u32);
        w.0.extend_from_slice(&bytes);
    }
    w.finish()
}

pub(super) fn get_names(bytes: &[u8]) -> Option<Vec<OwnedName>> {
    let mut r = Reader(bytes);
    let mut out = Vec::new();
    while !r.is_empty() {
        let n = r.take(1)?[0] as usize;
        let name = r.take(n)?.to_vec();
        let len = r.u32()? as usize;
        out.push(OwnedName::from_bytes(name, r.take(len)?)?);
    }
    Some(out)
}
