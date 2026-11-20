//! The ledger's rules for plain payments, as the field-free facts a
//! node and a prover both compute: what an output is, what a
//! transaction's id is of, how the state changes, and what a run of
//! transactions leaves for the proofs of a block to be joined by.
//!
//! # Outputs
//!
//! An output pays an amount to a key. On the chain it is a
//! **commitment** (the hash of the key's hash and the amount), a memo
//! and the amount; whose it is stays off the chain. In the state it is a
//! leaf: the hash of all of that and the height of the block that made
//! it, at a position that is never used again. Spending it empties the
//! leaf.
//!
//! # Transactions
//!
//! A transaction spends outputs and makes outputs. Its **id** is a hash
//! of its body: how many inputs and outputs it has, each input's
//! commitment (so its key and amount), each output as the chain lists
//! it. Every input's key signs the id. Positions and signatures are not
//! in it: a transaction is the same wherever its inputs lie.
//!
//! There are no fees as such: a transaction's inputs may come to more
//! than its outputs or to less, and over a block the inputs and the
//! subsidy come to the outputs exactly.
//!
//! # What ties a proof to a block
//!
//! A block lists the positions it spends and the outputs it makes, not
//! its transactions. Two running hashes, of the positions and of the
//! outputs in the block's order, are what a proof says it applied
//! ([`Record`]), and a node computes the same from the block.
//!
//! Every hash here is one block of Blake3 in a domain of its own
//! ([`crate::hash`]), so that a circuit pays one row for it.

use crate::hash::{
    DOM_BODY, DOM_BODY_IN, DOM_BODY_OP, DOM_BODY_OUT, DOM_COMMITMENT, DOM_INPUTS, DOM_OPS, DOM_OUT_ITEM, DOM_OUTPUTS,
    DOM_PUBKEY, DOM_STATE_LEAF, DOM_STATE_NODE, Digest, EMPTY, hash_domain,
};
use crate::name::{self, Names, Op};
use crate::xmss::PublicKey;
use std::collections::HashMap;

/// Bytes of a memo.
pub const MEMO: usize = 20;
pub type Memo = [u8; MEMO];
/// Levels of the state's tree of outputs: positions are below `2^41`.
pub const OUTPUTS_HEIGHT: usize = 41;

fn block(parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut at = 0;
    for p in parts {
        out[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    out
}

/// A key's hash: of its root, its seed and its tree's height.
pub fn key_hash(pk: &PublicKey) -> Digest {
    hash_domain(DOM_PUBKEY, &block(&[&pk.root, &pk.pub_seed, &(pk.height as u32).to_le_bytes()]))
}

/// An output's commitment: to whose it is and how much.
pub fn commitment(key_hash: &Digest, amount: u64) -> Digest {
    hash_domain(DOM_COMMITMENT, &block(&[key_hash, &amount.to_le_bytes()]))
}

/// An output as the chain lists it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output {
    pub commitment: Digest,
    pub memo: Memo,
    pub amount: u64,
}

impl Output {
    /// An output of `amount` to the key of `key_hash`.
    pub fn to(key_hash: &Digest, amount: u64, memo: Memo) -> Output {
        Output { commitment: commitment(key_hash, amount), memo, amount }
    }

    /// The output as a transaction's id and a block's list take it in.
    pub fn item(&self) -> Digest {
        hash_domain(DOM_OUT_ITEM, &block(&[&self.commitment, &self.memo, &self.amount.to_le_bytes()]))
    }

    /// Its leaf in the state, made at `height`.
    pub fn leaf(&self, height: u32) -> Digest {
        let parts: [&[u8]; 4] = [&self.commitment, &self.memo, &self.amount.to_le_bytes(), &height.to_le_bytes()];
        hash_domain(DOM_STATE_LEAF, &block(&parts))
    }
}

/// An input: the key, and the output it spends (its amount, its memo,
/// the height it was made at, where it lies). The position is not
/// signed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub key: PublicKey,
    pub amount: u64,
    pub memo: Memo,
    pub created: u32,
    pub position: u64,
}

impl Input {
    pub fn output(&self) -> Output {
        Output::to(&key_hash(&self.key), self.amount, self.memo)
    }
}

/// A transaction: outputs spent, outputs made, and operations on names.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub ops: Vec<Op>,
    /// Inputs that spend policies' outputs, after the keys'.
    pub policy: Vec<crate::policy::PolicyInput>,
    /// How many of the outputs, from the first, policies' conditions
    /// are on ([`Transaction::cover`]).
    pub covered: u32,
}

/// A hash that takes digests in one after another: `next = H(so far,
/// digest)` in a domain.
pub fn absorb(domain: u32, so_far: &Digest, x: &Digest) -> Digest {
    hash_domain(domain, &block(&[so_far, x]))
}

/// What a transaction's id starts from: how many inputs it has, how
/// many things it makes (outputs, and operations on names), and how
/// many of its outputs conditions are on.
pub fn body_head(inputs: usize, outputs: usize, covered: u32) -> Digest {
    let counts: [&[u8]; 3] = [&(inputs as u32).to_le_bytes(), &(outputs as u32).to_le_bytes(), &covered.to_le_bytes()];
    hash_domain(DOM_BODY, &block(&counts))
}

impl Transaction {
    /// The outputs conditions are on: how many, and their hash; none if
    /// there are none.
    pub fn cover(&self) -> Option<(u32, Digest)> {
        let outputs = self.outputs.get(..self.covered as usize).filter(|o| !o.is_empty())?;
        Some((self.covered, crate::policy::covered(outputs)))
    }

    /// The id: the hash every input's key signs.
    pub fn id(&self) -> Digest {
        let mut id =
            body_head(self.inputs.len() + self.policy.len(), self.outputs.len() + self.ops.len(), self.covered);
        for input in &self.inputs {
            id = absorb(DOM_BODY_IN, &id, &input.output().commitment);
        }
        for input in &self.policy {
            id = absorb(DOM_BODY_IN, &id, &input.output().commitment);
        }
        for output in &self.outputs {
            id = absorb(DOM_BODY_OUT, &id, &output.item());
        }
        for op in &self.ops {
            id = absorb(DOM_BODY_OP, &id, &op.digest());
        }
        id
    }
}

/// A position as a running hash takes it in.
fn position_digest(position: u64) -> Digest {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&position.to_le_bytes());
    d
}

/// The running hash of the positions a block spends, one more taken in.
pub fn inputs_next(so_far: &Digest, position: u64) -> Digest {
    absorb(DOM_INPUTS, so_far, &position_digest(position))
}

/// The running hash of what a block makes, an output more taken in.
pub fn outputs_next(so_far: &Digest, output: &Output) -> Digest {
    absorb(DOM_OUTPUTS, so_far, &output.item())
}

/// The same running hash, an operation on names more taken in.
pub fn ops_next(so_far: &Digest, op: &Op) -> Digest {
    absorb(DOM_OPS, so_far, &op.digest())
}

/// A node of the state's tree.
pub fn state_node(left: &Digest, right: &Digest) -> Digest {
    hash_domain(DOM_STATE_NODE, &block(&[left, right]))
}

/// The roots of empty subtrees: `[h]` of `2^h` empty leaves.
pub fn empty_roots() -> &'static [Digest; OUTPUTS_HEIGHT + 1] {
    static ROOTS: std::sync::OnceLock<[Digest; OUTPUTS_HEIGHT + 1]> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = [EMPTY; OUTPUTS_HEIGHT + 1];
        for h in 0..OUTPUTS_HEIGHT {
            roots[h + 1] = state_node(&roots[h], &roots[h]);
        }
        roots
    })
}

/// The tree of outputs, in memory, holding only what is not empty: for
/// provers and tests. (A node's own store is another matter.)
#[derive(Clone, Default)]
pub struct Outputs {
    /// Nodes that are not an empty subtree's root, by level and index.
    nodes: HashMap<(u8, u64), Digest>,
    /// What was made at each position still held, and at what height.
    made: HashMap<u64, (Output, u32)>,
    /// The next position to give out.
    pub next: u64,
}

impl Outputs {
    fn node(&self, level: usize, index: u64) -> Digest {
        self.nodes.get(&(level as u8, index)).copied().unwrap_or(empty_roots()[level])
    }

    pub fn root(&self) -> Digest {
        self.node(OUTPUTS_HEIGHT, 0)
    }

    pub fn leaf(&self, position: u64) -> Digest {
        self.node(0, position)
    }

    /// The output at `position` and the height it was made at, if it is
    /// still there.
    pub fn made(&self, position: u64) -> Option<&(Output, u32)> {
        self.made.get(&position).filter(|(output, height)| self.leaf(position) == output.leaf(*height))
    }

    /// The siblings of `position`'s path, the lowest first.
    pub fn path(&self, position: u64) -> Vec<Digest> {
        (0..OUTPUTS_HEIGHT).map(|level| self.node(level, (position >> level) ^ 1)).collect()
    }

    /// Sets the leaf at `position`, and every node above it.
    pub fn set(&mut self, position: u64, leaf: Digest) {
        assert!(position >> OUTPUTS_HEIGHT == 0);
        let mut node = leaf;
        for level in 0..=OUTPUTS_HEIGHT {
            let index = position >> level;
            if node == empty_roots()[level] {
                self.nodes.remove(&(level as u8, index));
            } else {
                self.nodes.insert((level as u8, index), node);
            }
            if level < OUTPUTS_HEIGHT {
                let sibling = self.node(level, index ^ 1);
                node = if index & 1 == 0 { state_node(&node, &sibling) } else { state_node(&sibling, &node) };
            }
        }
    }

    /// Makes `output` at the next position, at `height`: the position.
    pub fn insert(&mut self, output: &Output, height: u32) -> u64 {
        let position = self.next;
        self.set(position, output.leaf(height));
        self.made.insert(position, (*output, height));
        self.next += 1;
        position
    }
}

/// The root a path reaches from `leaf` at `position`.
pub fn path_root(leaf: &Digest, position: u64, siblings: &[Digest]) -> Digest {
    let mut node = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        node = if position >> level & 1 == 0 { state_node(&node, sibling) } else { state_node(sibling, &node) };
    }
    node
}

/// What a run of transactions did, for whoever joins the proofs of a
/// block's runs: the state before and after, the running hashes of the
/// positions spent and the outputs made, the positions given out, and
/// what the inputs and the outputs came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record {
    pub root: [Digest; 2],
    pub inputs: [Digest; 2],
    pub outputs: [Digest; 2],
    pub next: [u64; 2],
    pub sum_in: u128,
    pub sum_out: u128,
    pub height: u32,
    /// The registry's root before and after.
    pub names: [Digest; 2],
}

/// Why a transaction cannot be applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// An input's output is not in the state where it says.
    NotThere,
    /// The state has no room for another output.
    Full,
    /// An operation on names that the names' rules refuse.
    Name(name::Refused),
    /// A policy's conditions do not hold (but for the signatures, which
    /// are not this module's to say).
    Policy,
}

/// The chain's emission: eras one after another from block 1, each so
/// many blocks at so much a block. The genesis pays nothing, and after
/// the last era nothing is paid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Emission(pub &'static [(u32, u64)]);

/// Base units of a coin.
pub const COIN: u64 = 10_000_000_000;
const BLOCKS_PER_YEAR: u32 = 144 * 365;
/// Mainnet's: 1500 coins a block for three and a half years, 500 for as
/// long again, then 7 for a thousand years.
pub const MAINNET_EMISSION: Emission = Emission(&[
    (BLOCKS_PER_YEAR * 7 / 2, 1500 * COIN),
    (BLOCKS_PER_YEAR * 7 / 2, 500 * COIN),
    (BLOCKS_PER_YEAR * 1000, 7 * COIN),
]);

impl Emission {
    /// What the block at `height` pays.
    pub fn subsidy(&self, height: u32) -> u64 {
        let mut end = 0u64;
        for (blocks, subsidy) in self.0 {
            end += *blocks as u64;
            if height >= 1 && height as u64 <= end {
                return *subsidy;
            }
        }
        0
    }
}

impl Record {
    /// A record of a block not yet begun, on `state` at `height`, that
    /// pays `subsidy`: the inputs' sum begins from it, so that a block
    /// whose inputs and subsidy come to its outputs is one whose two
    /// sums end equal.
    pub fn block(state: &Outputs, height: u32, subsidy: u64) -> Record {
        Record { sum_in: subsidy as u128, ..Record::start(state, EMPTY, EMPTY, height) }
    }

    /// A record of nothing done yet, from `state` at `height` and the
    /// running hashes so far.
    pub fn start(state: &Outputs, inputs: Digest, outputs: Digest, height: u32) -> Record {
        let (root, next) = (state.root(), state.next);
        Record {
            root: [root; 2],
            inputs: [inputs; 2],
            outputs: [outputs; 2],
            next: [next; 2],
            sum_in: 0,
            sum_out: 0,
            height,
            names: [name::empty_roots()[name::HEIGHT]; 2],
        }
    }

    /// The same record, of a block on the registry `names`.
    pub fn on(self, names: &Names) -> Record {
        Record { names: [names.root(); 2], ..self }
    }

    /// Applies a transaction with no operation on names to `state` and
    /// to the record.
    pub fn apply(&mut self, state: &mut Outputs, tx: &Transaction) -> Result<(), Refused> {
        assert!(tx.ops.is_empty(), "operations on names need the registry");
        self.apply_with(state, &mut Names::default(), tx)
    }

    /// Applies `tx` to the outputs, the registry and the record: its
    /// inputs emptied in order, its outputs made, then its operations.
    /// Whether the inputs' keys signed, and an updated name's owner, is
    /// not this function's to say.
    pub fn apply_with(&mut self, state: &mut Outputs, names: &mut Names, tx: &Transaction) -> Result<(), Refused> {
        // Nothing is changed unless all of it can be: an output made in
        // this block is not there to spend.
        for (i, input) in tx.inputs.iter().enumerate() {
            let there = state.leaf(input.position) == input.output().leaf(input.created);
            let again = tx.inputs[..i].iter().any(|other| other.position == input.position);
            if !there || again || input.position >= self.next[0] {
                return Err(Refused::NotThere);
            }
        }
        if tx.covered as usize > tx.outputs.len() {
            return Err(Refused::Policy);
        }
        let id = tx.id();
        for (i, input) in tx.policy.iter().enumerate() {
            let there = state.leaf(input.position) == input.output().leaf(input.created);
            let again = tx.policy[..i].iter().any(|other| other.position == input.position)
                || tx.inputs.iter().any(|other| other.position == input.position);
            if !there || again || input.position >= self.next[0] {
                return Err(Refused::NotThere);
            }
            if !input.holds(self.height, &id, tx.cover(), &|_, _, _| true) {
                return Err(Refused::Policy);
            }
        }
        let commits = tx.ops.iter().filter(|op| matches!(op, Op::Commit { .. })).count();
        if (state.next + (tx.outputs.len() + commits) as u64) >> OUTPUTS_HEIGHT != 0 {
            return Err(Refused::Full);
        }
        // The operations, each against the registry as the ones before
        // leave it.
        let mut trial = names.clone();
        for op in &tx.ops {
            match op {
                Op::Commit { .. } => {}
                Op::Reveal { record, salt, position } => {
                    trial.can_reveal(record).map_err(Refused::Name)?;
                    let commit = name::commit(&name::name_hash(&record.name), salt, &record.owner);
                    let found =
                        state.made(*position).filter(|(output, _)| output.commitment == commit && output.amount == 0);
                    let (_, made) =
                        found.filter(|_| *position < self.next[0]).ok_or(Refused::Name(name::Refused::NoCommitment))?;
                    if !name::in_window(*made, self.height) {
                        return Err(Refused::Name(name::Refused::Window));
                    }
                    trial.set(record.clone());
                }
                Op::Update { record } => {
                    trial.can_update(record).map_err(Refused::Name)?;
                    trial.set(record.clone());
                }
            }
        }
        for input in &tx.inputs {
            state.set(input.position, EMPTY);
            self.inputs[1] = inputs_next(&self.inputs[1], input.position);
            self.sum_in += input.amount as u128;
        }
        for input in &tx.policy {
            state.set(input.position, EMPTY);
            self.inputs[1] = inputs_next(&self.inputs[1], input.position);
            self.sum_in += input.amount as u128;
        }
        for output in &tx.outputs {
            state.insert(output, self.height);
            self.outputs[1] = outputs_next(&self.outputs[1], output);
            self.sum_out += output.amount as u128;
        }
        for op in &tx.ops {
            match op {
                Op::Commit { commit, memo } => {
                    state.insert(&name::commit_output(commit, *memo), self.height);
                }
                Op::Reveal { position, .. } => {
                    state.set(*position, EMPTY);
                    self.inputs[1] = inputs_next(&self.inputs[1], *position);
                }
                Op::Update { .. } => {}
            }
            self.outputs[1] = ops_next(&self.outputs[1], op);
        }
        *names = trial;
        (self.root[1], self.next[1], self.names[1]) = (state.root(), state.next, names.root());
        Ok(())
    }

    /// Sweeps the commitment at `position`: an output of no amount, made
    /// more than [`name::MAX_REVEAL`] blocks ago and not revealed.
    pub fn sweep(&mut self, state: &mut Outputs, position: u64) -> Result<(), Refused> {
        let found = state.made(position).filter(|(output, _)| output.amount == 0 && position < self.next[0]);
        let (_, made) = found.ok_or(Refused::NotThere)?;
        if self.height <= *made || self.height - *made <= name::MAX_REVEAL {
            return Err(Refused::Name(name::Refused::Window));
        }
        state.set(position, EMPTY);
        self.inputs[1] = inputs_next(&self.inputs[1], position);
        self.root[1] = state.root();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::SecretKey;

    fn key(i: u8) -> PublicKey {
        SecretKey::generate_with_height(&[i; 32], 1).public_key()
    }

    #[test]
    fn an_output_is_its_commitment_s_and_a_leaf_its_height_s() {
        let (a, b) = (key_hash(&key(1)), key_hash(&key(2)));
        assert_ne!(a, b);
        let out = Output::to(&a, 50, [7; MEMO]);
        assert_eq!(out.commitment, commitment(&a, 50));
        // Another key, amount, memo or height: another commitment, item
        // or leaf.
        assert_ne!(out.commitment, commitment(&b, 50));
        assert_ne!(out.commitment, commitment(&a, 51));
        assert_ne!(out.item(), Output { memo: [8; MEMO], ..out }.item());
        assert_ne!(out.item(), Output { amount: 51, ..out }.item());
        assert_ne!(out.leaf(3), out.leaf(4));
        assert_ne!(out.leaf(3), out.item());
        // A key of another height is another key.
        let mut taller = key(1);
        taller.height += 1;
        assert_ne!(key_hash(&taller), a);
    }

    #[test]
    fn the_tree_is_its_paths() {
        let mut state = Outputs::default();
        assert_eq!(state.root(), empty_roots()[OUTPUTS_HEIGHT]);
        let outs: Vec<Output> = (0..5).map(|i| Output::to(&key_hash(&key(i)), 10 + i as u64, [i; MEMO])).collect();
        for (i, out) in outs.iter().enumerate() {
            assert_eq!(state.insert(out, 9), i as u64);
        }
        for (i, out) in outs.iter().enumerate() {
            let path = state.path(i as u64);
            assert_eq!(path_root(&out.leaf(9), i as u64, &path), state.root());
            assert_ne!(path_root(&out.leaf(8), i as u64, &path), state.root());
        }
        // Emptying a leaf: the same path from nothing is the new root;
        // emptying them all is the empty tree again.
        let (path, before) = (state.path(2), state.root());
        state.set(2, EMPTY);
        assert_eq!(path_root(&EMPTY, 2, &path), state.root());
        assert_ne!(state.root(), before);
        for i in [0, 1, 3, 4] {
            state.set(i, EMPTY);
        }
        assert_eq!((state.root(), state.nodes.len()), (empty_roots()[OUTPUTS_HEIGHT], 0));
    }

    #[test]
    fn a_transaction_is_its_body_and_no_more() {
        let input = |i: u8, position: u64| Input { key: key(i), amount: 40, memo: [i; MEMO], created: 2, position };
        let out = Output::to(&key_hash(&key(9)), 70, [0; MEMO]);
        let tx = Transaction {
            inputs: vec![input(1, 5), input(2, 6)],
            outputs: vec![out],
            ops: vec![],
            policy: vec![],
            covered: 0,
        };
        let id = tx.id();
        // Where the inputs lie, when they were made and their memos are
        // not the transaction's.
        let mut moved = tx.clone();
        (moved.inputs[0].position, moved.inputs[0].created, moved.inputs[0].memo) = (77, 3, [5; MEMO]);
        assert_eq!(moved.id(), id);
        // Everything else is.
        let changes: [&dyn Fn(&mut Transaction); 6] = [
            &|t| t.inputs[0].amount += 1,
            &|t| t.inputs[1].key = key(3),
            &|t| t.inputs.swap(0, 1),
            &|t| t.outputs[0].amount += 1,
            &|t| t.outputs[0].memo[0] ^= 1,
            &|t| t.outputs.push(out),
        ];
        for (i, change) in changes.iter().enumerate() {
            let mut other = tx.clone();
            change(&mut other);
            assert_ne!(other.id(), id, "change {i}");
        }
        // An output is not an input of the same commitment.
        let as_input =
            Transaction { inputs: vec![input(1, 5)], outputs: vec![], ops: vec![], policy: vec![], covered: 0 };
        let as_output = Transaction {
            inputs: vec![],
            outputs: vec![Output { commitment: input(1, 5).output().commitment, ..out }],
            ops: vec![],
            policy: vec![],
            covered: 0,
        };
        assert_ne!(as_input.id(), as_output.id());
    }

    #[test]
    fn a_run_of_transactions_is_recorded() {
        let mut state = Outputs::default();
        let owned: Vec<Input> = (0..4u8)
            .map(|i| {
                let out = Output::to(&key_hash(&key(i)), 100, [i; MEMO]);
                let position = state.insert(&out, 1);
                Input { key: key(i), amount: 100, memo: [i; MEMO], created: 1, position }
            })
            .collect();
        let pay = |inputs: &[usize], amounts: &[u64]| Transaction {
            inputs: inputs.iter().map(|i| owned[*i].clone()).collect(),
            outputs: amounts.iter().map(|a| Output::to(&key_hash(&key(9)), *a, [0; MEMO])).collect(),
            ops: vec![],
            policy: vec![],
            covered: 0,
        };
        let mut record = Record::start(&state, EMPTY, EMPTY, 2);
        let before = record;
        let (first, second) = (pay(&[0, 2], &[150, 40]), pay(&[1], &[130]));
        record.apply(&mut state, &first).unwrap();
        record.apply(&mut state, &second).unwrap();
        assert_eq!((record.sum_in, record.sum_out, record.next), (300, 320, [4, 7]));
        assert_eq!((record.root[0], record.root[1]), (before.root[0], state.root()));
        // The running hashes are of the positions and the outputs, in
        // the block's order.
        let positions = [0, 2, 1].iter().fold(EMPTY, |h, p| inputs_next(&h, *p));
        let outputs = first.outputs.iter().chain(&second.outputs).fold(EMPTY, |h, o| outputs_next(&h, o));
        assert_eq!((record.inputs[1], record.outputs[1]), (positions, outputs));
        // Spent is spent; what this block made is not there to spend;
        // and a refusal changes nothing.
        let (root, kept) = (state.root(), record);
        assert_eq!(record.apply(&mut state, &pay(&[0], &[1])), Err(Refused::NotThere));
        let mut fresh = owned[3].clone();
        (fresh.position, fresh.created) = (4, 2);
        (fresh.key, fresh.amount, fresh.memo) = (key(9), 150, [0; MEMO]);
        assert_eq!(state.leaf(4), fresh.output().leaf(2));
        assert_eq!(
            record.apply(
                &mut state,
                &Transaction { inputs: vec![fresh], outputs: vec![], ops: vec![], policy: vec![], covered: 0 }
            ),
            Err(Refused::NotThere)
        );
        let twice = Transaction {
            inputs: vec![owned[3].clone(), owned[3].clone()],
            outputs: vec![],
            ops: vec![],
            policy: vec![],
            covered: 0,
        };
        assert_eq!(record.apply(&mut state, &twice), Err(Refused::NotThere));
        assert_eq!((state.root(), record), (root, kept));
    }
}
