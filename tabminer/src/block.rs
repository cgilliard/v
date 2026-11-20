//! A block's proof: the proofs of its parts, joined into one that says
//! what the block did.
//!
//! | part | proves | by |
//! |---|---|---|
//! | runs of transactions | the state's change, given a signed set | [`crate::segment`] |
//! | signatures | the signed set | [`crate::signature`], [`crate::signed`] |
//! | joins | two runs, one after the other, are one run | [`join_into`] |
//! | nodes of signatures | two signed sets are one | [`crate::signature::node_into`] |
//! | work | the work of the header before the block's | [`crate::work`] |
//! | the root | the runs are the whole block's, of this signed set, after that work | [`root_into`] |
//!
//! Each join and the root are compiled computations
//! ([`crate::alg`]): they verify their children's proofs by rows of the
//! hash table and the machine, and state what the children were of.
//!
//! # What a block's proof is of
//!
//! [`Statement`]: the state's root before and after, the running hashes
//! of the positions spent and of the outputs made (which a node
//! computes from the block's lists), the positions given out, the
//! height, and what the inputs and the outputs came to. The root finds
//! the runs to begin from nothing (no transaction in hand, the running
//! hashes at their start, the sums at zero) and to end with every
//! transaction whole.
//!
//! The root also states which programs the proofs under it were of
//! ([`PROGRAMS`]), for a chain to hold against the shapes it takes
//! ([`crate::chain::Plan`]), and the header whose work it was shown
//! ([`crate::header`]), for a chain's step to find to be its own.

use crate::alg::{Alg, Shared, Sym, halves};
use crate::circuit::Circuit;
use crate::field::F;
use crate::hash::{DOM_RESTED, Digest};
use crate::ledger::Record;
use crate::proof::{Circuits, Proved};
use crate::reading::Reader;
use crate::segment::{self, CHAINED, FIXED};
use crate::signature::Signed;
use crate::signed;

/// The circuits a block's proofs are of.
pub struct Tables {
    pub compiled: Circuits,
    pub segment: Circuit,
}

impl Default for Tables {
    fn default() -> Tables {
        Tables::new()
    }
}

impl Tables {
    pub fn new() -> Tables {
        Tables { compiled: Circuits::new(), segment: segment::circuit() }
    }

    pub fn all(&self) -> Vec<&Circuit> {
        self.compiled.all().into_iter().chain([&self.segment]).collect()
    }
}

/// A proof of runs: of one run, or of two joined, with what that proof
/// states (the run table's program, what the join rested on, then the
/// record).
pub enum Runs<'a> {
    One(&'a segment::Proved),
    Joined(&'a Proved, &'a [F]),
}

/// The elements public words are.
pub fn elements(words: &[u32]) -> Vec<F> {
    words.chunks(4).map(|w| F(w.iter().rev().fold(0, |x, w| x << 32 | *w as u128))).collect()
}

/// What a proof of runs rests on, as a circuit that verified it holds
/// it: the run table's program; the proof's own program if it is a
/// join's (zeros if not); and what that join rested on in turn.
struct Rested {
    table: Vec<Sym>,
    own: Vec<Sym>,
    below: Vec<Sym>,
}

impl Runs<'_> {
    /// The proof's verification, made rows of `cx`: what it rests on,
    /// and the record.
    fn verify_into(&self, cx: &Shared, tables: &Tables, reader: &mut impl Reader<Sym>) -> Option<(Rested, Vec<Sym>)> {
        let zeros = || vec![cx.constant(F::ZERO), cx.constant(F::ZERO)];
        match self {
            Runs::One(p) => {
                let (table, record) = p.verify_into(cx, &tables.segment, reader)?;
                Some((Rested { table, own: zeros(), below: zeros() }, record))
            }
            Runs::Joined(p, stated) => {
                let of = p.verify_into(cx, &tables.compiled, reader)?;
                let mut said = cx.stated(&[of[2].clone(), of[3].clone()], stated);
                let record = said.split_off(4);
                let below = said.split_off(2);
                Some((Rested { table: said, own: of[..2].to_vec(), below }, record))
            }
        }
    }
}

/// A computation, in `cx`, that verifies two proofs of runs and states
/// them to be one run: what it states, by the field. That is the run
/// table's program, the hash of what its two children were proofs of
/// (their own programs, and what those rested on), and the record.
pub fn join_into(cx: &Shared, tables: &Tables, reader: &mut impl Reader<Sym>, children: [&Runs; 2]) -> Option<Vec<F>> {
    let (a, first) = children[0].verify_into(cx, tables, reader)?;
    let (b, second) = children[1].verify_into(cx, tables, reader)?;
    // Both rest on the one run table.
    assert!(a.table[0].is(&b.table[0]) && a.table[1].is(&b.table[1]));
    let below = cx.hashed(DOM_RESTED, &[a.own, a.below, b.own, b.below].concat());
    let stated = [a.table, below.to_vec(), segment::join(&first, &second)].concat();
    cx.state(&stated);
    Some(stated.iter().map(Sym::value).collect())
}

/// Digests of programs a block's root states before the statement.
pub const PROGRAMS: usize = 6;
/// Elements of a [`Statement`].
pub const STATEMENT: usize = 27;

/// What a block's proof is of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Statement {
    /// The outputs' root before the block and after.
    pub root: [Digest; 2],
    /// The running hashes of the positions spent and of the outputs
    /// made, each from [`EMPTY`].
    pub inputs: Digest,
    pub outputs: Digest,
    /// The first position given out, and the one after the last.
    pub next: [u64; 2],
    pub height: u32,
    /// What the inputs and the subsidy came to, and the outputs: the
    /// same, which is the rule.
    pub sum_in: u128,
    pub sum_out: u128,
    /// What the block pays its maker.
    pub subsidy: u64,
    /// The registry's root before the block and after.
    pub names: [Digest; 2],
    /// The signed set the inputs' keys are found to have signed in.
    pub signed: Digest,
    /// The work shown of the header before this block's: that header's
    /// work's hash, its nonce and its mix. Zeros if none is shown.
    pub work: [Digest; 3],
}

impl Statement {
    /// The statement of a block that is `record` ([`Record::block`]),
    /// from the ledger's rules, paying `subsidy`, with the signed set of
    /// root `signed`.
    pub fn of(record: &Record, subsidy: u64, signed: &Digest) -> Statement {
        Statement {
            root: record.root,
            inputs: record.inputs[1],
            outputs: record.outputs[1],
            next: record.next,
            height: record.height,
            sum_in: record.sum_in,
            sum_out: record.sum_out,
            subsidy,
            names: record.names,
            signed: *signed,
            work: [[0; 32]; 3],
        }
    }

    /// The statement as the elements a proof states.
    pub fn elements(&self) -> Vec<F> {
        let pairs = [&self.root[0], &self.root[1], &self.inputs, &self.outputs, &self.signed];
        let mut out: Vec<F> = pairs.into_iter().flat_map(halves).collect();
        out.extend([
            F(self.next[0] as u128),
            F(self.next[1] as u128),
            F(self.height as u128),
            F(self.sum_in),
            F(self.sum_out),
            // The height before, which a chain's step finds to be the
            // block before's.
            F(self.height.wrapping_sub(1) as u128),
            F(self.subsidy as u128),
        ]);
        out.extend(self.names.iter().flat_map(halves));
        out.extend(self.work.iter().flat_map(halves));
        out
    }
}

/// A proof of a header's work ([`crate::work::work_into`]), with what it
/// states: the header's work's hash, the nonce, the mix and the result.
pub struct Worked<'a> {
    pub proof: &'a Proved,
    pub stated: &'a [F],
}

/// A computation, in `cx`, that verifies the proof of a block's runs,
/// of its signatures (none for a block that spends nothing) and of the
/// work of the header before it (none only for a block no chain takes),
/// and states what the block did: the statement, as elements, after the
/// programs the proofs were verified against: [`PROGRAMS`] digests, the
/// run table's, the join's and what it rested on (zeros if the runs are
/// one), the signatures' proof's and what that rested on (zeros if
/// there are none; the second zeros if it is of one run of signatures),
/// and the work's (zeros if none is shown).
pub fn root_into(
    cx: &Shared,
    tables: &Tables,
    reader: &mut impl Reader<Sym>,
    runs: &Runs,
    signatures: Option<&Signed>,
    work: Option<&Worked>,
    height: u32,
) -> Option<Vec<F>> {
    let (rested, r) = runs.verify_into(cx, tables, reader)?;
    let (ins, outs) = r.split_at(CHAINED + FIXED);
    // The signed set: the signatures' proof's, lifted to the set's
    // height; or the set of nothing.
    let mut programs = [rested.table, rested.own, rested.below].concat();
    let set = match signatures {
        Some(s) => {
            let level = s.root().1;
            let v = s.verify_into(cx, &tables.compiled, reader)?;
            // The level its root is said to be of is the one lifted from.
            assert!(level <= signed::DEPTH && v.level.is(&cx.constant(crate::signature::level_element(level))));
            programs.extend(v.own.into_iter().chain(v.below));
            signed::lift_into(cx, &v.root, level, signed::DEPTH)
        }
        None => {
            programs.extend((0..4).map(|_| cx.constant(F::ZERO)));
            halves(&signed::empty_roots()[signed::DEPTH]).map(|x| cx.constant(x))
        }
    };
    assert!(ins[CHAINED].is(&set[0]) && ins[CHAINED + 1].is(&set[1]));
    // The work of the header before: what its proof states it is of.
    let worked: Vec<Sym> = match work {
        Some(w) => {
            let of = w.proof.verify_into(cx, &tables.compiled, reader)?;
            let said = cx.stated(&[of[2].clone(), of[3].clone()], w.stated);
            programs.extend(of[..2].iter().cloned());
            said[..6].to_vec()
        }
        None => {
            programs.extend((0..2).map(|_| cx.constant(F::ZERO)));
            (0..6).map(|_| cx.constant(F::ZERO)).collect()
        }
    };
    // The runs begin from nothing: the running hashes at their start,
    // no transaction in hand, no outputs yet; the inputs' sum begins
    // from the subsidy, and ends as the outputs': the block's inputs
    // and what it pays come to what it makes.
    let zero = cx.constant(F::ZERO);
    for x in ins[2..10].iter().chain(&ins[13..14]) {
        assert!(x.is(&zero));
    }
    assert!(outs[12].is(&outs[13]));
    // No operation on names yet: each count's bit at its start.
    assert!(ins[16].is(&cx.constant(F(1 | 1 << 32 | 1 << 64 | 1 << 96))));
    // And end with every transaction whole: its body's hash its id, and
    // nothing left. The height is the element above the two counters.
    let h = cx.input(F(height as u128));
    let counts = h.clone() * cx.constant(F(1 << 64));
    assert!(ins[10].is(&counts) && outs[10].is(&counts));
    assert!(outs[6].is(&outs[8]) && outs[7].is(&outs[9]));
    let mut stated = programs;
    stated.extend(ins[..2].iter().chain(&outs[..2]).chain(&outs[2..6]).chain(&set).cloned());
    let before = ins[CHAINED + 2].clone();
    stated.extend([ins[11].clone(), outs[11].clone(), h, outs[12].clone(), outs[13].clone(), before, ins[12].clone()]);
    stated.extend(ins[14..16].iter().chain(&outs[14..16]).cloned());
    stated.extend(worked);
    cx.state(&stated);
    Some(stated.iter().map(Sym::value).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::statement;
    use crate::hash::EMPTY;
    use crate::ledger::{Input, MEMO, Output, Outputs, Transaction, key_hash};
    use crate::pcs::Params;
    use crate::reading::Deferred;
    use crate::segment::{Run, closed};
    use crate::xmss::{SecretKey, Signature};

    fn params(m: usize) -> Params {
        Params::plain(m, 1, 4, 4)
    }

    /// The signed set over a signature proof's entries, the rest empty:
    /// an entry's siblings to the set's root.
    fn path(entries: &[Digest], place: usize) -> Vec<Digest> {
        let mut leaves = entries.to_vec();
        leaves.resize(signed::SLOTS, EMPTY);
        let mut siblings = signed::Tree::new(&leaves).path(place).siblings;
        siblings.extend_from_slice(&signed::empty_roots()[signed::LOG_SLOTS..signed::DEPTH]);
        siblings
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow unoptimized")]
    fn a_block_of_payments_is_proven_from_its_signatures_up() {
        // Three keys own an output each; two payments spend them, each
        // input signed by its key over the payment's id.
        let mut keys: Vec<SecretKey> = (0..3u8).map(|i| SecretKey::generate_with_height(&[i + 1; 32], 2)).collect();
        let mut state = Outputs::default();
        let owned: Vec<Input> = (keys.iter().enumerate())
            .map(|(i, sk)| {
                let (key, memo) = (sk.public_key(), [i as u8; MEMO]);
                let position = state.insert(&Output::to(&key_hash(&key), 100, memo), 1);
                Input { key, amount: 100, memo, created: 1, position }
            })
            .collect();
        let to = key_hash(&owned[0].key);
        let pay = |inputs: &[usize], amounts: &[u64]| Transaction {
            inputs: inputs.iter().map(|i| owned[*i].clone()).collect(),
            outputs: amounts.iter().map(|a| Output::to(&to, *a, [9; MEMO])).collect(),
            ops: vec![],
            policy: vec![],
            covered: 0,
        };
        let txs = [pay(&[0, 2], &[150, 50]), pay(&[1], &[130])];
        let height = 2;

        // The signatures, and the proof of them: its entries' root.
        let mut signatures: Vec<(crate::xmss::PublicKey, Digest, Signature)> = Vec::new();
        for (tx, spends) in txs.iter().zip([vec![0usize, 2], vec![1]]) {
            for k in spends {
                let sig = keys[k].sign(&tx.id()).unwrap();
                signatures.push((keys[k].public_key(), tx.id(), sig));
            }
        }
        let entries: Vec<Digest> =
            signatures.iter().map(|(pk, msg, sig)| crate::signature::entry(pk, msg, sig.index)).collect();
        let cx = Shared::new();
        let mut chains = Vec::new();
        let entries_root = crate::signature::segment_into(&cx, &mut chains, &signatures, 4).unwrap();
        let signed_proof = crate::proof::prove(cx, chains, params);
        assert!(signed_proof.holds && signed_proof.verifies());
        let set = signed::lift(&entries_root, signed::LOG_SLOTS, signed::DEPTH);

        // The runs: the first payment, then the second, each its proof.
        // The block pays 30: its outputs come to its inputs and that.
        let start = Record::block(&state, height, 30);
        let mut record = start;
        let mut run = Run::new(&start, closed(), &set);
        let mut runs = Vec::new();
        let mut entry = 0;
        let mut applied = state.clone();
        for (t, tx) in txs.iter().enumerate() {
            if t == 1 {
                let next = Run::after(&run);
                runs.push(std::mem::replace(&mut run, next));
            }
            run.head(tx);
            for input in &tx.inputs {
                run.input(
                    input,
                    &state.path(input.position),
                    signatures[entry].2.index,
                    &(entry as u64, path(&entries, entry)),
                );
                state.set(input.position, EMPTY);
                entry += 1;
            }
            for output in &tx.outputs {
                run.output(output, &to, &state.path(state.next));
                state.insert(output, height);
            }
            record.apply(&mut applied, tx).unwrap();
        }
        runs.push(run);
        let proved: Vec<segment::Proved> = runs.into_iter().map(|r| segment::prove(r, 512, params)).collect();
        assert!(proved.iter().all(segment::Proved::verifies));

        // The join of the two runs, and the root over it and the
        // signatures.
        let tables = Tables::new();
        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        let joined = join_into(&cx, &tables, &mut reader, [&Runs::One(&proved[0]), &Runs::One(&proved[1])]).unwrap();
        reader.settle(&tables.all());
        let join = crate::proof::prove(cx, vec![], params);
        assert!(join.holds && join.verifies());
        assert_eq!(join.statement(), statement(&joined));

        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        let signatures = Signed::Segment(&signed_proof, entries_root);
        let stated =
            root_into(&cx, &tables, &mut reader, &Runs::Joined(&join, &joined), Some(&signatures), None, height)
                .unwrap();
        reader.settle(&tables.all());
        let root = crate::proof::prove(cx, vec![], params);
        assert!(root.holds && root.verifies());
        assert_eq!(root.statement(), statement(&stated));
        // What the block's proof is of is what the ledger's rules make of
        // the block: after the programs, the statement.
        let expect = Statement::of(&record, 30, &set);
        assert_eq!((record.sum_in, record.sum_out), (330, 330));
        assert_eq!((stated.len(), expect.elements().len()), (2 * PROGRAMS + STATEMENT, STATEMENT));
        assert_eq!(stated[2 * PROGRAMS..], expect.elements()[..]);
        assert_eq!(stated[..2], halves(&proved[0].program));
        assert_eq!(stated[2..4], halves(&join.program));

        // A root at another height, or over runs that leave a
        // transaction in hand, does not hold.
        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        root_into(&cx, &tables, &mut reader, &Runs::Joined(&join, &joined), Some(&signatures), None, height + 1);
        assert!(!cx.finish().asm.finish(128).holds);
        let cx = Shared::new();
        let mut reader = Deferred::new(&cx);
        root_into(&cx, &tables, &mut reader, &Runs::One(&proved[1]), Some(&signatures), None, height);
        assert!(!cx.finish().asm.finish(128).holds);
    }
}
