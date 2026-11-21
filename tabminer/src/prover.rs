//! A block's proof, made: the proofs of [`crate::block_proof`] and the
//! chain's step ([`crate::chain_proof`]) put together for a block of
//! the chain ([`crate::chain`]), and the verifier a node checks the
//! result with.
//!
//! # What a block carries
//!
//! A block's proof is the chain's: one proof that the chain's proof
//! before it verifies and that this block's proofs do, hiding both. It
//! states what [`crate::chain::Chain::statement`] computes from the
//! block and the state, whose digest the block's header names. In a
//! body it is the argument's proof alone: its program and its
//! statement are the verifier's to say.
//!
//! # What is fixed
//!
//! A chain's step takes a block whose proofs are of one of the shapes
//! its plan lists, and names its own program; both are the same for
//! every node of a network. They follow from the circuits and from the
//! sizes of the proofs, so a [`Setup`] finds them by making a block of
//! each shape once: the sizes its proofs come to are the sizes every
//! block's proofs of that shape are made at.
//!
//! # Shapes
//!
//! - **A reward's block**: one run of [`REWARD_ROWS`] rows (the reward,
//!   and sweeps), no signatures, and the work of the header before.
//! - **A block of transactions**: one run of one of the level's sizes,
//!   and the signatures in a tree of one, two or four proofs of a fixed
//!   number of signatures each (a proof not full is filled by saying a
//!   signature again: its entry is in the set once more, to no harm).

use std::collections::HashMap;
use std::time::Duration;

use crate::alg::Shared;
use crate::block_proof::{Beside, PROGRAMS, Runs, Tables, Worked, beside_into, root_into, root_with};
use crate::chain::verify::{BlockStatement, ProofVerifier};
use crate::chain_proof::{Plan, Shape, Stated, Statement, genesis_into, step_into};
use crate::field::F;
use crate::hash::{Digest, EMPTY};
use crate::ledger::{Emission, OUTPUTS_HEIGHT, Record};
use crate::name::{Key, NameOp};
use crate::ntt::Domain;
use crate::output::Output;
use crate::pcs::Params;
use crate::pow::{ItemSource, Nonce};
use crate::proof::{Kind, Proved, program_of, prove_at, prove_hidden, prove_with};
use crate::reading::Deferred;
use crate::segment::{self, Run, closed};
use crate::signature::{Signed, entry, node_into, segment_into};
use crate::signed;
use crate::store::partial::Partial;
use crate::transaction::Transaction;
use crate::xmss::{PublicKey, Signature};

/// Rows of the run of a block that spends nothing by a key: its reward,
/// and the commitments it sweeps.
pub const REWARD_ROWS: usize = 1 << 11;
/// Rows the walks that bring a run's outputs into the root take, at the
/// most: what a run is left room for.
const SETTLE_ROWS: usize = 3 + 2 * 3 * OUTPUTS_HEIGHT;

/// A signature with its key and what it signs.
pub type Signing = (PublicKey, Digest, Signature);

/// The parameters proofs are made under, and the shapes of the blocks
/// of transactions a chain takes.
#[derive(Clone, Copy)]
pub struct Level {
    /// Of the proofs within a block's.
    pub inner: fn(usize) -> Params,
    /// Of the chain's proof, which is the one published.
    pub published: fn(usize) -> Params,
    /// The sizes a run of transactions may have, as logs of its rows,
    /// ascending.
    pub runs: &'static [usize],
    /// Signatures in one proof of them.
    pub per_proof: usize,
    /// The most proofs of signatures a block's tree is over, as a log.
    pub trees: usize,
}

impl Level {
    /// The main network's: 124 bits proven, the published proof ground
    /// more for fewer queries.
    pub const MAINNET: Level = Level {
        inner: |m| Params::proven(m, 2, crate::pcs::SECURITY),
        published: |m| Params::proven_ground(m, 2, crate::pcs::SECURITY, 24),
        runs: &[15, 16],
        per_proof: 64,
        trees: 2,
    };

    /// For tests and the dev networks: proofs of the shapes the main
    /// network's have, small, sound to a few bits and made in a moment.
    pub const SMALL: Level = Level {
        inner: |m| Params::plain(m, 1, 4, 4),
        published: |m| Params::plain(m, 1, 4, 4),
        runs: &[12],
        per_proof: 2,
        trees: 1,
    };

    /// The most signatures a block's proof rests on.
    pub fn signatures(&self) -> usize {
        self.per_proof << self.trees
    }
}

/// A digest of two elements of a statement.
fn digest(x: &[F]) -> Digest {
    [x[0].0.to_le_bytes(), x[1].0.to_le_bytes()].concat().try_into().expect("two elements")
}

/// Rows of a proof's hash table and of its machine.
fn rows_of(proof: &Proved) -> [usize; 2] {
    [proof.rows(Kind::Hashes)[0], proof.rows(Kind::Machine)[0]]
}

/// The sizes the proofs of signatures are made at: a proof of
/// signatures, and the node over two of each level.
#[derive(Clone, Debug, Default)]
struct SignedSizes {
    segment: Option<[usize; 2]>,
    nodes: Vec<[usize; 2]>,
}

/// The sizes a block's last proofs are made at, of one shape, and the
/// program its root then has.
#[derive(Clone, Copy, Debug)]
struct Sized {
    beside: [usize; 2],
    root: [usize; 2],
    program: Digest,
}

/// A block's signatures, proven: one proof over a tree of the proofs of
/// [`Level::per_proof`] signatures each, and where each signature's
/// entry is in the tree.
pub struct SignedProof {
    top: Proved,
    /// What the top states, if it is a node; nothing if it is the one
    /// proof of signatures.
    stated: Vec<F>,
    /// The root of the entries' tree, and the proofs it is over, as a
    /// log.
    root: Digest,
    tree: usize,
    entries: signed::Tree,
    places: HashMap<Digest, usize>,
}

impl SignedProof {
    fn as_signed(&self) -> Signed<'_> {
        match self.stated.is_empty() {
            true => Signed::Segment(&self.top, self.root),
            false => Signed::Node(&self.top, &self.stated),
        }
    }

    /// The level of the entries' tree.
    fn level(&self) -> usize {
        signed::LOG_SLOTS + self.tree
    }

    /// The signed set's root.
    pub fn set(&self) -> Digest {
        signed::lift(&self.root, self.level(), signed::DEPTH)
    }

    /// Where the entry of `key`'s signature of `message` with `leaf` is
    /// in the set, and its path. `None` if it is not there.
    fn place(&self, key: &PublicKey, message: &Digest, leaf: u64) -> Option<segment::Signed> {
        let place = *self.places.get(&entry(key, message, leaf))?;
        let mut siblings = self.entries.path(place).siblings;
        siblings.extend_from_slice(&signed::empty_roots()[self.level()..signed::DEPTH]);
        Some((place as u64, siblings))
    }
}

/// The paths of some names, changed in memory: [`Partial`], of the
/// names' tree.
#[derive(Clone, Default)]
pub struct NamesPart {
    nodes: HashMap<(u8, u128), Digest>,
}

impl NamesPart {
    fn index(key: Key, level: usize) -> u128 {
        key.checked_shr(level as u32).unwrap_or(0)
    }

    /// Takes in the leaf at `key` and its path, as the tree has them
    /// before any change.
    pub fn load(&mut self, key: Key, leaf: &Digest, siblings: &[Digest]) {
        let mut node = *leaf;
        for (level, sibling) in siblings.iter().enumerate() {
            let index = Self::index(key, level);
            self.nodes.entry((level as u8, index)).or_insert(node);
            self.nodes.entry((level as u8, index ^ 1)).or_insert(*sibling);
            node = if index & 1 == 1 { crate::registry::node(sibling, &node) } else { crate::registry::node(&node, sibling) };
        }
    }

    /// The path of the leaf at `key`, which must be one loaded.
    pub fn path(&self, key: Key) -> Vec<Digest> {
        (0..crate::registry::HEIGHT).map(|level| self.nodes[&(level as u8, Self::index(key, level) ^ 1)]).collect()
    }

    /// Makes the leaf at `key`, which must be one loaded, `leaf`.
    pub fn set(&mut self, key: Key, leaf: &Digest) {
        let mut node = *leaf;
        for level in 0..crate::registry::HEIGHT {
            let index = Self::index(key, level);
            self.nodes.insert((level as u8, index), node);
            let sibling = self.nodes[&(level as u8, index ^ 1)];
            node = if index & 1 == 1 { crate::registry::node(&sibling, &node) } else { crate::registry::node(&node, &sibling) };
        }
    }
}

/// What proving a block takes from the state, as it is before the
/// block: the paths of every output the block spends and of the next
/// position, each output spent, the paths of every name it touches, and
/// the records it replaces.
#[derive(Clone, Default)]
pub struct Witness {
    pub outputs: Partial<OUTPUTS_HEIGHT>,
    pub spent: HashMap<u64, crate::store::outputs::Record>,
    pub names: NamesPart,
    pub records: HashMap<Key, crate::name::Record>,
}

impl Witness {
    /// The witness of a block of `txs` and `sweeps` on the state of
    /// `snap`. An error if the block cannot be: it spends what is not
    /// there.
    pub fn collect<B: crate::store::Backend + 'static>(
        snap: &crate::store::state::Snapshot<'_, B>,
        txs: &[Transaction],
        sweeps: &[u64],
    ) -> Result<Witness, crate::error::Error> {
        let mut witness = Witness::default();
        let reveals = |tx: &Transaction| -> Vec<u64> {
            let commits = tx.ops.iter().filter_map(|op| match op {
                NameOp::Reveal { commit, .. } => Some(*commit),
                _ => None,
            });
            commits.collect()
        };
        let spent = txs.iter().flat_map(|tx| tx.spent_positions().into_iter().chain(reveals(tx)));
        for position in spent.chain(sweeps.iter().copied()) {
            let record = match snap.output(position)? {
                Some((record, true)) => record,
                _ => return Err(crate::error::Error::NoSuchOutput(position)),
            };
            let (leaf, path) = snap.prove(position)?;
            witness.outputs.load(position, &leaf, path[..OUTPUTS_HEIGHT].try_into().expect("the outputs' levels"));
            witness.spent.insert(position, record);
        }
        let next = snap.outputs().next;
        let (leaf, path) = snap.prove(next)?;
        witness.outputs.load(next, &leaf, path[..OUTPUTS_HEIGHT].try_into().expect("the outputs' levels"));
        for op in txs.iter().flat_map(|tx| &tx.ops) {
            let Some(record) = op.record() else { continue };
            let key = record.key();
            let (proof, _) = snap.prove_name(key)?;
            witness.names.load(key, &proof.leaf, &proof.siblings);
            if let Some(old) = snap.name(key)? {
                witness.records.insert(key, old);
            }
        }
        Ok(witness)
    }
}

/// What a network's proofs are made with: the circuits, the plan of
/// the blocks a chain takes, the step's own program, and the proof of
/// where a chain begins.
pub struct Setup {
    pub level: Level,
    tables: Tables,
    pub plan: Plan,
    /// The program of the chain's step: every block's statement names
    /// it ([`crate::chain::params::ChainParams::program`]).
    pub own: Digest,
    /// Rows the chain's proof's hash table and machine are filled to, at
    /// the least.
    pub rows: [usize; 2],
    genesis: Proved,
    began: Vec<F>,
    /// The work's proof's sizes; a reward's block's; those of the
    /// proofs of signatures; and those of a block of transactions, by
    /// its run's size and its tree of signatures.
    work: [usize; 2],
    reward: Sized,
    signed: SignedSizes,
    blocks: Vec<Sized>,
}

/// A chain's proof and what it states: the proof of where a chain
/// begins, or the one a block carried.
pub struct Before {
    proof: Proved,
    stated: Vec<F>,
    first: bool,
}

/// A block to prove: its transactions in order, the commitments it
/// sweeps, and the output that pays its maker (the subsidy and the
/// fees), which is the block's first.
pub struct Contents<'a> {
    pub txs: &'a [Transaction],
    pub sweeps: &'a [u64],
    pub reward: &'a Output,
}

/// The proofs of signatures joined into one over `2^tree` of them:
/// `signings` filled to that many proofs' worth with its first. `sizes`
/// are the sizes to make them at; those not yet known are found.
fn sign(level: &Level, tables: &Tables, sizes: &mut SignedSizes, signings: &[Signing], tree: usize) -> Option<SignedProof> {
    let per = level.per_proof;
    assert!(!signings.is_empty() && signings.len() <= per << tree && per <= signed::SLOTS);
    let mut all = signings.to_vec();
    all.resize(per << tree, signings[0].clone());
    // Each proof's entries are its slots, one proof after another.
    let mut slots = vec![EMPTY; signed::SLOTS << tree];
    let mut places = HashMap::new();
    for (i, (key, message, signature)) in all.iter().enumerate() {
        let place = i / per * signed::SLOTS + i % per;
        slots[place] = entry(key, message, signature.index);
        places.entry(slots[place]).or_insert(place);
    }
    let mut proofs: Vec<(Proved, Vec<F>, Digest)> = Vec::new();
    for some in all.chunks(per) {
        let cx = Shared::new();
        let mut chains = Vec::new();
        let root = segment_into(&cx, &mut chains, some, per)?;
        let proof = prove_at(cx, chains, level.inner, sizes.segment.unwrap_or([128, 128]));
        if !proof.holds {
            return None;
        }
        sizes.segment.get_or_insert(rows_of(&proof));
        proofs.push((proof, Vec::new(), root));
    }
    for depth in 0..tree {
        let mut above = Vec::new();
        for pair in proofs.chunks(2) {
            let (a, b) = (as_signed(&pair[0]), as_signed(&pair[1]));
            let cx = Shared::new();
            let mut reader = Deferred::new(&cx);
            let stated = node_into(&cx, &tables.compiled, &mut reader, [&a, &b])?;
            reader.settle(&tables.all());
            let proof = prove_at(cx, vec![], level.inner, sizes.nodes.get(depth).copied().unwrap_or([128, 128]));
            if !proof.holds {
                return None;
            }
            if sizes.nodes.len() == depth {
                sizes.nodes.push(rows_of(&proof));
            }
            let root = Signed::Node(&proof, &stated).root().0;
            above.push((proof, stated, root));
        }
        proofs = above;
    }
    let (top, stated, root) = proofs.pop()?;
    let entries = signed::Tree::new(&slots);
    (entries.root() == root).then_some(SignedProof { top, stated, root, tree, entries, places })
}

fn as_signed(p: &(Proved, Vec<F>, Digest)) -> Signed<'_> {
    match p.1.is_empty() {
        true => Signed::Segment(&p.0, p.2),
        false => Signed::Node(&p.0, &p.1),
    }
}

impl Setup {
    /// The setup of a network that pays by `emission`, with proofs made
    /// at `level`. `source` is any table of the network's work: the
    /// shapes are found by proving a block of each, whose header's
    /// work is part of it.
    pub fn new(level: Level, emission: Emission, source: &impl ItemSource) -> Setup {
        let tables = Tables::new();
        let rested = |stated: &[F]| -> [Digest; PROGRAMS] { std::array::from_fn(|i| digest(&stated[2 * i..])) };
        let work = {
            let cx = Shared::new();
            let (work, stated) = crate::work::work_into(&cx, source, &[1; 32], &[0; 32]);
            (prove_with(cx, vec![], Some(work), level.inner, [128, 128]), stated)
        };
        let shown = Worked { proof: &work.0, stated: &work.1 };
        let (record, pay) = (Record::block(&crate::ledger::Outputs::default(), 1, 1), Output::to_key_hash(&[7; 32], 1));
        let sample = |set: &Digest, rows: usize| {
            let run = Self::run_of(&record, set, &mut Witness::default(), &Contents { txs: &[], sweeps: &[], reward: &pay }, None);
            segment::prove(run.expect("a run"), rows, level.inner)
        };

        // A block of each shape, of some header's work: a reward's, and
        // those with signatures, a tree of each size under a run of each
        // size. For the sizes of their proofs and the programs of their
        // roots.
        let mut key = crate::xmss::SecretKey::generate_with_height(&[0x5a; 32], 1);
        let said: Signing = (key.public_key(), [0; 32], key.sign(&[0; 32]).expect("a first signature"));
        let mut sizes = SignedSizes::default();
        let mut samples = vec![(sample(&signed::empty_roots()[signed::DEPTH], REWARD_ROWS), None)];
        for tree in 0..=level.trees {
            let proven = sign(&level, &tables, &mut sizes, std::slice::from_ref(&said), tree).expect("signatures");
            let cx = Shared::new();
            let mut reader = Deferred::new(&cx);
            let both = beside_into(&cx, &tables, &mut reader, &proven.as_signed(), &shown).expect("a join");
            reader.settle(&tables.all());
            let beside = std::rc::Rc::new((prove_at(cx, vec![], level.inner, [128, 128]), both));
            assert!(beside.0.holds, "the sample signatures and work hold");
            for log in level.runs {
                samples.push((sample(&proven.set(), 1 << log), Some(beside.clone())));
            }
        }
        // The roots, all of one size, so that a chain's step verifies a
        // block's root the same way whatever its shape: the largest any
        // of them comes to.
        let root_of = |(run, beside): &(segment::Proved, Option<std::rc::Rc<(Proved, Vec<F>)>>), rows: [usize; 2]| {
            let cx = Shared::new();
            let mut reader = Deferred::new(&cx);
            let stated = match beside {
                None => root_into(&cx, &tables, &mut reader, &Runs::One(run), None, Some(&shown), 1),
                Some(b) => root_with(&cx, &tables, &mut reader, &Runs::One(run), &Beside::Joined(&b.0, &b.1), 1),
            };
            reader.settle(&tables.all());
            let root = prove_at(cx, vec![], level.inner, rows);
            assert!(root.holds, "the sample block's root holds");
            (root, stated.expect("a root"))
        };
        let mut roots: Vec<(Proved, Vec<F>)> = samples.iter().map(|s| root_of(s, [128, 128])).collect();
        let most = roots.iter().map(|r| rows_of(&r.0)).fold([0; 2], |a, b| [a[0].max(b[0]), a[1].max(b[1])]);
        for (root, sample) in roots.iter_mut().zip(&samples) {
            if rows_of(&root.0) != most {
                *root = root_of(sample, most);
                assert_eq!(rows_of(&root.0), most);
            }
        }
        let shapes: Vec<Shape> = roots.iter().map(|(root, stated)| Shape { root: root.program, rested: rested(stated) }).collect();
        let sized: Vec<Sized> = (roots.iter().zip(&samples))
            .map(|((root, _), (_, beside))| Sized {
                beside: beside.as_ref().map_or([0; 2], |b| rows_of(&b.0)),
                root: most,
                program: root.program,
            })
            .collect();
        let (reward, blocks) = (sized[0], sized[1..].to_vec());
        let (first, first_stated) = roots.swap_remove(0);

        // The shape of a chain's proof: rows enough for a step, found by
        // trying, and for the pads of a proof that hides what it is of.
        // The proof of where a chain begins is made to it.
        let mut rows = [1 << 9, 1 << 15];
        loop {
            let cx = Shared::new();
            let began = genesis_into(&cx);
            let genesis = prove_hidden(cx, level.published, rows, seed());
            assert!(genesis.holds);
            let plan = Plan::new(shapes.clone(), genesis.program, emission);
            let cx = Shared::new();
            let mut reader = Deferred::new(&cx);
            let (block, before) =
                (Stated { proof: &first, stated: &first_stated }, Stated { proof: &genesis, stated: &began });
            step_into(&cx, &tables, &mut reader, &plan, 0, &block, &before, true, &[0; 32], &[0; 32]).expect("a step");
            reader.settle(&tables.all());
            let (hash, machine) = cx.with(|c| (c.trace.rows.len(), 2 * c.asm.finish_len()));
            if hash <= rows[0] && machine <= rows[1] {
                let own = program_of(cx, level.published, rows);
                let work = rows_of(&work.0);
                return Setup { level, tables, plan, own, rows, genesis, began, work, reward, signed: sizes, blocks: blocks.clone() };
            }
            rows = [rows[0].max(hash.next_power_of_two()), rows[1].max(machine.next_power_of_two())];
        }
    }

    /// The proofs of `signings` (as many as [`Level::signatures`] at the
    /// most, one at the least), joined: what a block of the
    /// transactions they are of is proven with. They say nothing of any
    /// block, and are made as the transactions come.
    pub fn sign(&self, signings: &[Signing]) -> Option<SignedProof> {
        let proofs = signings.len().div_ceil(self.level.per_proof).next_power_of_two();
        let tree = proofs.trailing_zeros() as usize;
        if signings.is_empty() || tree > self.level.trees {
            return None;
        }
        sign(&self.level, &self.tables, &mut self.signed.clone(), signings, tree)
    }

    /// The run of a block of `contents`, from the state `start` is of,
    /// with the signed set of root `set`: the reward's transaction, the
    /// others, the operations on names they carry, and the sweeps.
    /// `None` if a signature is not in the set, or the witness lacks a
    /// path.
    fn run_of(
        start: &Record,
        set: &Digest,
        witness: &mut Witness,
        contents: &Contents<'_>,
        proven: Option<&SignedProof>,
    ) -> Option<Run> {
        let next = start.next[0];
        let place = |key: &PublicKey, message: &Digest, leaf: u64| proven?.place(key, message, leaf);
        let of = |position: u64| witness.spent.get(&position).map_or(([0; 20], 0), |r| (r.memo, r.height));
        let rules: Vec<crate::ledger::Transaction> = contents.txs.iter().map(|tx| tx.rule(of)).collect();
        // The nodes to the left of the next position's path, once
        // everything the block spends is gone.
        let reveals = contents.txs.iter().flat_map(|tx| &tx.ops).filter_map(|op| match op {
            NameOp::Reveal { commit, .. } => Some(*commit),
            _ => None,
        });
        let gone: Vec<u64> = (contents.txs.iter().flat_map(|tx| tx.spent_positions()))
            .chain(reveals)
            .chain(contents.sweeps.iter().copied())
            .collect();
        let mut run = Run::new(start, closed(), set);
        if next != 0 {
            let mut after = witness.outputs.clone();
            gone.iter().for_each(|p| after.set(*p, &EMPTY));
            let path = after.path(next);
            let frontier: Vec<Digest> = (0..OUTPUTS_HEIGHT).filter(|l| next >> l & 1 == 1).map(|l| path[l]).collect();
            run.frontier(&frontier);
        }
        // The reward's transaction: no input, one output.
        let pay = crate::ledger::Transaction { outputs: vec![contents.reward.listed()], ..Default::default() };
        run.head(&pay);
        run.output(&pay.outputs[0], &contents.reward.key_hash);
        for (tx, rule) in contents.txs.iter().zip(&rules) {
            let id = rule.id();
            run.head(rule);
            for (input, spent) in tx.inputs.iter().zip(&rule.inputs) {
                let at = place(&input.pubkey, &id, input.signature.index)?;
                run.input(spent, &witness.outputs.path(input.position), input.signature.index, &at);
                witness.outputs.set(input.position, &EMPTY);
            }
            for spent in &rule.policy {
                use crate::conditions::{Cond, Shown, rebind_message};
                let mut places = Vec::new();
                for (cond, shown) in spent.conds.iter().zip(&spent.shown) {
                    let Shown::Signers(signers) = shown else { continue };
                    let message = match cond {
                        Cond::Rebind { channel, .. } => rebind_message(channel, &rule.cover()?.1, spent.state),
                        _ => id,
                    };
                    for (key, leaf) in signers.iter().flatten() {
                        places.push(place(key, &message, *leaf)?);
                    }
                }
                run.policy_input(spent, &witness.outputs.path(spent.position), &places);
                witness.outputs.set(spent.position, &EMPTY);
            }
            for (output, listed) in tx.outputs.iter().zip(&rule.outputs) {
                run.output(listed, &output.key_hash);
            }
            tx.ops.iter().for_each(|op| run.carried(&op.digest()));
        }
        // The operations, done after the transactions; then the sweeps.
        for op in contents.txs.iter().flat_map(|tx| &tx.ops) {
            match op {
                NameOp::Commit { commit, memo } => run.commit(commit, memo),
                NameOp::Reveal { record, salt, commit } => {
                    let spent = witness.spent.get(commit)?;
                    let key = record.key();
                    let (outputs, names) = (witness.outputs.path(*commit), witness.names.path(key));
                    run.reveal(&record.rule(), salt, &spent.memo, spent.height, *commit, &outputs, &names);
                    witness.outputs.set(*commit, &EMPTY);
                    witness.names.set(key, &crate::store::names::leaf_of(record));
                    witness.records.insert(key, *record);
                }
                NameOp::Update { record, pubkey, signature } => {
                    let key = record.key();
                    let old = *witness.records.get(&key)?;
                    let at = place(pubkey, &crate::name::update_message(record), signature.index)?;
                    run.update(&record.rule(), &old.rule(), pubkey, signature.index, &at, &witness.names.path(key));
                    witness.names.set(key, &crate::store::names::leaf_of(record));
                    witness.records.insert(key, *record);
                }
            }
        }
        for position in contents.sweeps {
            let spent = witness.spent.get(position)?;
            run.sweep(&spent.commitment, &spent.memo, spent.height, *position, &witness.outputs.path(*position));
            witness.outputs.set(*position, &EMPTY);
        }
        Some(run)
    }

    /// Whether a block of `txs`, with its reward and `sweeps` sweeps, is
    /// one whose rows a run holds, whatever the state: for whoever
    /// chooses a block's transactions.
    pub fn fits(&self, txs: &[Transaction], sweeps: usize) -> bool {
        // A commitment made, a reveal and an update, at the most; and a
        // sweep.
        let done = |op: &NameOp| match op {
            NameOp::Commit { .. } => 4 + 2 * OUTPUTS_HEIGHT,
            NameOp::Reveal { .. } => 12 + 2 * OUTPUTS_HEIGHT + 2 * crate::registry::HEIGHT,
            NameOp::Update { .. } => 14 + signed::DEPTH + 2 * crate::registry::HEIGHT,
        };
        let of = |tx: &Transaction| {
            segment::rows_bound(&tx.rule(|_| ([0; 20], 0))) + tx.ops.iter().map(done).sum::<usize>()
        };
        let rows = 16 + txs.iter().map(of).sum::<usize>() + sweeps * (2 + 2 * OUTPUTS_HEIGHT) + SETTLE_ROWS;
        let most = if txs.is_empty() { REWARD_ROWS } else { 1 << self.level.runs[self.level.runs.len() - 1] };
        rows <= most && txs.iter().map(|tx| tx.signings().len()).sum::<usize>() <= self.level.signatures()
    }

    /// The proof of where a chain begins, as the chain's proof before
    /// its first block.
    pub fn beginning(&self) -> Before {
        let proof = Proved { program: self.genesis.program, ..self.shell() };
        Before { proof, stated: self.began.clone(), first: true }
    }

    /// The chain's proof a block carried, which states `statement`
    /// ([`crate::chain::Chain::statement`]), as the proof before the
    /// next block's. `None` if the bytes are no proof.
    pub fn carried(&self, proof: &[u8], statement: &Statement) -> Option<Before> {
        let proof = Proved {
            proof: crate::argument::Proof::from_bytes(proof)?,
            public: crate::blake3::words::<8>(&statement.digest()).to_vec(),
            program: self.own,
            ..self.shell()
        };
        Some(Before { proof, stated: statement.elements(), first: false })
    }

    /// A chain's proof without its argument: the parameters and the
    /// tables every one of them has.
    fn shell(&self) -> Proved {
        Proved {
            params: self.genesis.params,
            program: self.own,
            proof: self.genesis.proof.clone(),
            tables: self.genesis.tables.clone(),
            public: self.genesis.public.clone(),
            holds: true,
            used: 0,
            proving: Duration::ZERO,
        }
    }

    /// The proof of the work of a header: `work_hash` its work's hash
    /// ([`crate::block::Header::pow_hash`]), `nonce` its nonce, `source`
    /// the table of its height.
    fn work(&self, source: &impl ItemSource, work_hash: &Digest, nonce: &Nonce) -> (Proved, Vec<F>) {
        let cx = Shared::new();
        let (work, stated) = crate::work::work_into(&cx, source, work_hash, nonce);
        (prove_with(cx, vec![], Some(work), self.level.inner, self.work), stated)
    }

    /// The proof a block of `contents` carries: a block at
    /// `start.height` on the state `start` is of ([`Record::block`]: its
    /// subsidy counted in) and `witness` was taken from. `parent` is the
    /// header before the block's, `source` the table of that header's
    /// height, `before` the chain's proof that header's block carried,
    /// and `proven` the proofs of every signature the transactions rest
    /// on ([`Setup::sign`]; none for a block that has none). `None` if
    /// the block is not one a chain takes: its rows are more than a run
    /// holds, a signature is not among those proven, or what it does
    /// does not hold.
    pub fn block(
        &self,
        source: &impl ItemSource,
        parent: &crate::block::Header,
        before: &Before,
        start: &Record,
        mut witness: Witness,
        contents: &Contents<'_>,
        proven: Option<&SignedProof>,
    ) -> Option<Vec<u8>> {
        let set = proven.map_or(signed::empty_roots()[signed::DEPTH], SignedProof::set);
        let run = Self::run_of(start, &set, &mut witness, contents, proven)?;
        let rows = run.len() + SETTLE_ROWS;
        let work = self.work(source, &parent.pow_hash(), &parent.nonce);
        let shown = Worked { proof: &work.0, stated: &work.1 };
        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        let (shape, sized, stated) = match proven {
            None => {
                if rows > REWARD_ROWS {
                    return None;
                }
                let run = segment::prove(run, REWARD_ROWS, self.level.inner);
                let stated =
                    root_into(&cx, &self.tables, &mut reader, &Runs::One(&run), None, Some(&shown), start.height)?;
                (0, self.reward, stated)
            }
            Some(proven) => {
                let size = self.level.runs.iter().position(|log| rows <= 1 << log)?;
                let shape = proven.tree * self.level.runs.len() + size;
                let sized = self.blocks[shape];
                let run = segment::prove(run, 1 << self.level.runs[size], self.level.inner);
                let beside = {
                    let cx = Shared::new();
                    let mut reader = Deferred::new(&cx);
                    let both = beside_into(&cx, &self.tables, &mut reader, &proven.as_signed(), &shown)?;
                    reader.settle(&self.tables.all());
                    (prove_at(cx, vec![], self.level.inner, sized.beside), both)
                };
                if !beside.0.holds {
                    return None;
                }
                let with = Beside::Joined(&beside.0, &beside.1);
                let stated = root_with(&cx, &self.tables, &mut reader, &Runs::One(&run), &with, start.height)?;
                (1 + shape, sized, stated)
            }
        };
        reader.settle(&self.tables.all());
        let root = prove_at(cx, vec![], self.level.inner, sized.root);
        if !root.holds || root.program != sized.program {
            return None;
        }
        self.step(shape, &root, &stated, before, &parent.rest())
    }

    /// The chain's step over a block's root, of the plan's shape
    /// `shape`: the proof a block carries.
    fn step(&self, shape: usize, root: &Proved, stated: &[F], before: &Before, rest: &Digest) -> Option<Vec<u8>> {
        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        let (block, chain) = (Stated { proof: root, stated }, Stated { proof: &before.proof, stated: &before.stated });
        step_into(&cx, &self.tables, &mut reader, &self.plan, shape, &block, &chain, before.first, &self.own, rest)?;
        reader.settle(&self.tables.all());
        let step = prove_hidden(cx, self.level.published, self.rows, seed());
        (step.holds && step.program == self.own).then(|| step.proof.to_bytes())
    }

    /// The verifier of the chain's proofs this setup makes.
    pub fn verifier(&self) -> ChainVerifier {
        ChainVerifier::new(self.genesis.params, self.own, rows_of(&self.genesis))
    }
}

/// What a proof that hides is made random by: the system's randomness.
fn seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    crate::random::fill(&mut seed).expect("the system's randomness");
    seed
}

/// The verifier of a block's proof: the chain's proof, of the step's
/// program, stating what the chain computes of the block.
pub struct ChainVerifier {
    params: Params,
    program: Digest,
    rows: [usize; 2],
    hashes: crate::circuit::Circuit,
    machine: crate::circuit::Circuit,
    domain: Domain,
}

impl ChainVerifier {
    /// The verifier of chain proofs made under `params`, of the step
    /// of program `program`, with `rows` in the hash table and the
    /// machine (as the proofs have them, which may be more than they
    /// were asked to be filled to).
    pub fn new(params: Params, program: Digest, rows: [usize; 2]) -> ChainVerifier {
        let (hashes, machine) = (crate::recursion::circuit(), crate::machine::circuit());
        ChainVerifier { params, program, rows, hashes, machine, domain: Domain::new(params.k(), false) }
    }
}

impl ProofVerifier for ChainVerifier {
    fn verify(&self, statement: &BlockStatement<'_>, proof: &[u8]) -> bool {
        if statement.chain.program != self.program || statement.digest == EMPTY {
            return false;
        }
        let Some(proof) = crate::argument::Proof::from_bytes(proof) else { return false };
        let public = crate::blake3::words::<8>(&statement.digest);
        let tables = [
            crate::argument::Table { circuit: &self.hashes, rows: self.rows[0], public: &[] },
            crate::argument::Table { circuit: &self.machine, rows: self.rows[1], public: &public },
        ];
        crate::argument::verify_tables(&self.params, &self.domain, &tables, Some(&self.program), &proof).is_some()
    }

    /// The chain's proof shows each header's mix to be its work's.
    fn attests_work(&self) -> bool {
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::block::{Block, BlockRef, Body, BodyRef, Header};
    use crate::chain::Chain;
    use crate::chain::apply::Applied;
    use crate::chain::headers::tests::{NOW, easy, seed, table};
    use crate::chain::params::ChainParams;
    use crate::error::Error;
    use crate::pow::hashimoto;
    use crate::store::testing::MemBackend;

    /// A network of small proofs, on the dev table, whose every header
    /// meets its target: its setup, made once for every test, and its
    /// parameters.
    pub(crate) fn network() -> (&'static Setup, ChainParams) {
        static SETUP: std::sync::OnceLock<Setup> = std::sync::OnceLock::new();
        let setup = SETUP.get_or_init(|| Setup::new(Level::SMALL, Emission(easy().emission), &*table()));
        let params = ChainParams { program: setup.own, ..easy() };
        (setup, ChainParams { genesis_mix: params.genesis_work(&seed()), ..params })
    }

    /// The header of a block of `body` on the chain's last, its work
    /// found.
    fn header_for(chain: &Chain<MemBackend, ChainVerifier>, body: &Body) -> Header {
        let parent = chain.tip().unwrap();
        let bytes = body.to_bytes();
        let (state_root, stated) = chain.header_after(&BodyRef::from_bytes(&bytes).unwrap()).unwrap();
        let mut header = Header {
            prev_hash: parent.hash(),
            height: parent.height + 1,
            timestamp: parent.timestamp + 600,
            body_commitment: body.commitment(),
            state_root,
            statement: stated.digest(),
            aux: [0; 32],
            mix: EMPTY,
            nonce: [0; 32],
        };
        let target = chain.expected_target(&parent).unwrap();
        loop {
            header.mix = hashimoto(&*table(), &header.pow_hash(), &header.nonce).mix;
            if header.quick_pow_check(&target) {
                return header;
            }
            header.nonce[0] = header.nonce[0].wrapping_add(1);
        }
    }

    /// The proof of the next block of the chain, which pays `reward` and
    /// nothing else.
    fn prove_next(setup: &Setup, chain: &Chain<MemBackend, ChainVerifier>, reward: &crate::output::Output) -> Vec<u8> {
        prove_with(setup, chain, reward, &[], None).expect("a proof")
    }

    /// The proof of the next block of the chain, of `txs` and `reward`,
    /// if there is one.
    fn prove_with(
        setup: &Setup,
        chain: &Chain<MemBackend, ChainVerifier>,
        reward: &crate::output::Output,
        txs: &[Transaction],
        proven: Option<&SignedProof>,
    ) -> Option<Vec<u8>> {
        let parent = chain.tip().unwrap();
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        let (roots, next) = ((snap.outputs().hash(), snap.names().hash()), snap.outputs().next);
        // The chain's proof before: where a chain begins, or the one the
        // last block carried, which states what the chain says of it.
        let before = match parent.height {
            0 => setup.beginning(),
            _ => {
                let bytes = chain.body(&parent.hash()).unwrap().expect("the last block's body is kept");
                let body = BodyRef::from_bytes(&bytes).unwrap();
                let stated = chain.statement(parent.height, &parent.prev_hash, &body, &roots, next);
                assert_eq!(stated.digest(), parent.statement);
                setup.carried(body.proof(), &stated).unwrap()
            }
        };
        let height = parent.height + 1;
        let start = Record {
            root: [roots.0; 2],
            inputs: [EMPTY; 2],
            outputs: [EMPTY; 2],
            next: [next; 2],
            sum_in: chain.params().subsidy(height) as u128,
            sum_out: 0,
            height,
            names: [roots.1; 2],
            ops: [EMPTY; 2],
            done: [EMPTY; 2],
        };
        let witness = Witness::collect(&snap, txs, &[]).unwrap();
        let contents = Contents { txs, sweeps: &[], reward };
        setup.block(&*table(), &parent, &before, &start, witness, &contents, proven)
    }

    /// Blocks that pay their reward, each carrying the chain's proof,
    /// are taken by a chain that checks it: from the first block, whose
    /// proof rests on where a chain begins, on.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow unoptimized")]
    fn a_chain_takes_blocks_by_their_proofs() {
        let (setup, params) = network();
        let chain = Chain::open(MemBackend::new(), 8, params, seed(), setup.verifier()).unwrap();
        chain.set_dataset(table());
        let pay = |height: u32| crate::output::Output::to_key_hash(&[height as u8; 32], params.subsidy(height));
        let mut last = Vec::new();
        for height in 1..=3 {
            let reward = pay(height);
            let proof = prove_next(setup, &chain, &reward);
            let body = Body { outputs: vec![reward.block_output()], proof, ..Body::default() };
            let block = Block { header: header_for(&chain, &body), body };
            // With another proof, or the proof of the block before, it
            // is not taken; the block is not held to that.
            let mut other = block.clone();
            let at = other.body.proof.len() / 2;
            other.body.proof[at] ^= 1;
            let view = other.to_bytes();
            assert_eq!(chain.apply_block(&BlockRef::from_bytes(&view).unwrap(), NOW), Err(Error::BadProof));
            if !last.is_empty() {
                other.body.proof = std::mem::take(&mut last);
                let view = other.to_bytes();
                assert_eq!(chain.apply_block(&BlockRef::from_bytes(&view).unwrap(), NOW), Err(Error::BadProof));
            }
            let bytes = block.to_bytes();
            assert_eq!(chain.apply_block(&BlockRef::from_bytes(&bytes).unwrap(), NOW), Ok(Applied::Extended));
            assert_eq!(chain.tip().unwrap(), block.header);
            last = block.body.proof;
        }
        // A reward that is more than the block may pay has no proof.
        let greedy = crate::output::Output::to_key_hash(&[9; 32], params.subsidy(4) + 1);
        let parent = chain.tip().unwrap();
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        let (roots, next) = ((snap.outputs().hash(), snap.names().hash()), snap.outputs().next);
        let bytes = chain.body(&parent.hash()).unwrap().unwrap();
        let body = BodyRef::from_bytes(&bytes).unwrap();
        let stated = chain.statement(parent.height, &parent.prev_hash, &body, &roots, next);
        let before = setup.carried(body.proof(), &stated).unwrap();
        let start = Record {
            root: [roots.0; 2],
            inputs: [EMPTY; 2],
            outputs: [EMPTY; 2],
            next: [next; 2],
            sum_in: params.subsidy(4) as u128,
            sum_out: 0,
            height: 4,
            names: [roots.1; 2],
            ops: [EMPTY; 2],
            done: [EMPTY; 2],
        };
        let witness = Witness::collect(&snap, &[], &[]).unwrap();
        let contents = Contents { txs: &[], sweeps: &[], reward: &greedy };
        assert!(setup.block(&*table(), &parent, &before, &start, witness, &contents, None).is_none());
    }

    /// A block of a payment: its signature proven beforehand, its input
    /// found in the signed set, its outputs made after the reward's. The
    /// chain takes it by its proof, and takes no other body with it.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow unoptimized")]
    fn a_chain_takes_a_block_of_payments() {
        use crate::output::{Key, Output};
        use crate::transaction::UnsignedTransaction;
        let (setup, params) = network();
        let chain = Chain::open(MemBackend::new(), 8, params, seed(), setup.verifier()).unwrap();
        chain.set_dataset(table());
        let extend = |body: Body| {
            let block = Block { header: header_for(&chain, &body), body };
            let bytes = block.to_bytes();
            chain.apply_block(&BlockRef::from_bytes(&bytes).unwrap(), NOW)
        };
        // The first block pays a key, which the second block's payment
        // spends: half to one, the rest less a fee to another.
        let mut key = Key::generate(&[3; 32]);
        let first = Output::new(&key.public_key(), params.subsidy(1));
        let proof = prove_next(setup, &chain, &first);
        assert_eq!(extend(Body { outputs: vec![first.block_output()], proof, ..Body::default() }), Ok(Applied::Extended));
        let (half, fee) = (first.amount / 2, 1000);
        let outputs = vec![Output::to_key_hash(&[1; 32], half), Output::to_key_hash(&[2; 32], first.amount - half - fee)];
        let mut tx = UnsignedTransaction::new(vec![(key.public_key(), first.amount)], outputs).sign_with(&mut key).unwrap();
        tx.set_positions(&[0]);
        let txs = [tx];
        // The signature is proven with no block in mind.
        let proven = setup.sign(&txs[0].signings()).unwrap();
        let reward = Output::to_key_hash(&[4; 32], params.subsidy(2) + fee);
        // A reward of more than the subsidy and the fee has no proof;
        // nor has the payment without its signature's proof.
        let greedy = Output::to_key_hash(&[4; 32], reward.amount + 1);
        assert!(prove_with(setup, &chain, &greedy, &txs, Some(&proven)).is_none());
        let other = setup.sign(&[(key.public_key(), [9; 32], key.sign(&[9; 32]).unwrap())]).unwrap();
        assert!(prove_with(setup, &chain, &reward, &txs, Some(&other)).is_none());
        let proof = prove_with(setup, &chain, &reward, &txs, Some(&proven)).unwrap();
        let listed: Vec<_> = [&reward].into_iter().chain(&txs[0].outputs).map(Output::block_output).collect();
        let body = Body { inputs: vec![0], outputs: listed, proof, ..Body::default() };
        // The proof is of this body: with its outputs in another order
        // it is another block's.
        let mut swapped = body.clone();
        swapped.outputs.swap(1, 2);
        assert_eq!(extend(swapped), Err(Error::BadProof));
        assert_eq!(extend(body), Ok(Applied::Extended));
        let state = chain.state();
        let snap = state.snapshot().unwrap();
        assert_eq!((snap.outputs().next, snap.is_unspent(0).unwrap(), snap.is_unspent(2).unwrap()), (4, false, true));
    }
}
