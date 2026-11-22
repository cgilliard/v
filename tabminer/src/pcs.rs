//! The commitment of a multilinear polynomial over the field, and the
//! proof of a sum over it (BaseFold's way, on the code and the folding of
//! [`crate::ntt`], as in Diamond and Posen's FRI-Binius).
//!
//! The polynomial is its `2^m` values on the cube, bit `i` of an index
//! the variable `i`. Its commitment is the Merkle root of the codeword of
//! those values as a message.
//!
//! # The opening
//!
//! The prover shows `sum_b f(b) w(b) = v` for weights `w` the verifier
//! can work out at any point: with `w = eq(z, .)` that is `f(z) = v`
//! ([`open`]); an argument above this one brings its own
//! ([`open_weighted`]). It is a sumcheck, a variable a round, lowest
//! first. A round's polynomial is of degree two and is sent as its
//! constant and leading coefficients: the middle one follows from the
//! claim, since in characteristic two `g(0) + g(1)` is their sum.
//!
//! With each round's challenge the prover also folds the codeword, and
//! every [`Params::arity`] rounds commits to what it has become. After
//! `m` rounds the codeword is a constant `c`, the polynomial at the
//! challenges `r`, and the sumcheck's last claim must be `c w(r)`.
//!
//! The queries tie the committed codewords together: each opens one leaf
//! of the first, folds it with the rounds' challenges to a single value,
//! finds that value in a leaf of the next, and so on down to `c`.
//!
//! # Soundness
//!
//! The level aimed at is proven, not conjectured: every Fiat-Shamir round
//! is to err with probability below `2^-(s + 1)` for `s` bits of
//! security ([`Params::proven`]), counted as follows.
//!
//! - **Queries, in the unique-decoding regime.** A codeword that is not
//!   within half the code's distance of a codeword that folds rightly
//!   passes one query with probability at most `(1 + rate) / 2`. So a
//!   query is worth `1 - log2(1 + rate)` bits, never a whole one
//!   ([`QUERY_MICROBITS`]), and [`Params::query_grinding`] bits of
//!   grinding before the queries are sampled add to them.
//! - **A folding round** errs with probability about `n / 2^128` for a
//!   codeword of `n` entries: a bad challenge is one that brings a far
//!   word near. The prover grinds before the challenge for as many bits
//!   as that falls short ([`Params::fold_grinding`]).
//! - **A smaller polynomial joining** ([`Joiner`]) adds its sum to the
//!   first's under a challenge, and from there the one sumcheck is of
//!   both. Its codeword is not added to the first's: it is folded
//!   beside it, with the same challenges, in the same leaves, to a
//!   last value of its own. The sumcheck's last claim is a sum of the
//!   polynomials' last values, each times its weights, and the weights
//!   differ: one codeword of them all would fold to one value, their
//!   sum under the challenges, and a prover could say any last values
//!   with that sum and so make the last claim what it liked. Where it
//!   joins, a query finds the joiner's own committed entry in the leaf:
//!   a query that lands where the two differ fails, as one does that
//!   lands where a codeword is not what it folds from. The polynomial
//!   that blinds is added, under a challenge: it is weighed as the
//!   first is, and the two have one last value between them, which a
//!   sum that is near a codeword when one of the two was far gives
//!   away as rarely as a bad fold. Each is ground as a fold.
//! - **A sumcheck round** errs with probability `2 / 2^128`.
//! - **The hash**: 256-bit digests, collisions at 128 bits.
//!
//! `docs/SOUNDNESS.md` has the theorems these counts are from. No count
//! is taken of conjectures that would allow fewer queries.
//!
//! # Hiding
//!
//! An opening of a commitment made with [`commit_blind`] shows the sum
//! and nothing else of the polynomial, given three things of whoever
//! commits ([`crate::hidden`] says what the argument above makes of them
//! and why they are enough):
//!
//! - **The first codeword's leaves.** A query opens a leaf of the
//!   polynomial's own codeword. Some of the polynomial's values must be
//!   random and placed so that the leaves the queries open are, to
//!   whoever sees them, uniform; the prover takes a nonce before the
//!   queries under which they are ([`Blind::good`]).
//! - **Everything after the first leaf's folding.** A second
//!   polynomial, random and the size the first is once its first
//!   codeword has been folded, is committed with it: its codeword's
//!   entry is one more element of each leaf. It joins the opening where
//!   the second codeword is committed, as a [`Joiner`] does, under the
//!   first's own weights: what it sums to under them is sent
//!   (`Proof::blind_sum`), then a challenge adds it. Every codeword
//!   after the first, every round after it and the last value are then
//!   of a sum with a random polynomial, and the last value sent is that
//!   sum's. The pads' polynomial has such a one of its own, a fourth
//!   in the commitment, for the same reason: its codeword is folded
//!   beside the first's and opened where the first's is.
//! - **The rounds before that**, which are the polynomial's own, must
//!   be hidden by the sum's weights on values that are random
//!   ([`crate::hidden`]'s corners).
//!
//! # Pads
//!
//! A hiding commitment holds a third polynomial, the size of the
//! second: values the argument above adds to what it sends
//! ([`crate::hidden`]), which the opening's sum must weigh too. Its
//! codeword's entry is each leaf's last element. As a polynomial of the
//! first's variables it is its values where the first leaf's variables
//! are all zero, and zero elsewhere, and so are its weights: over the
//! first rounds its part of each coefficient sent is its whole sum
//! times the squares of one and each challenge so far, and where the
//! second codeword is committed it joins as a [`Joiner`] does, its
//! weights times those squares, with the polynomial that blinds it
//! added under a challenge. No sum of its own is sent, only that of
//! the one that blinds it: the opening is of the one sum, of the first
//! under its weights and of this under its. Its last value is sent
//! with the blinding one's in it (`Proof::pad_final`). Its own entries
//! the queries open, in the first leaves, are as they are: it must be
//! random enough for those.

use crate::alg::{Alg, Transcript, halves};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::field::F;
use crate::hash::Digest;
use crate::merkle::{self, MerkleTree};
use crate::ntt::Domain;
use crate::parallel::{par_fill, par_map_min};

/// Bits of the field: what caps every algebraic round.
const FIELD_BITS: usize = 128;

/// The security the chain's proofs are made to, in bits, proven: every
/// Fiat-Shamir round of every proof errs with probability `2^-125` at
/// most. The one place it is said.
///
/// The field allows 126 at most (a sumcheck round is 127 bits and every
/// round would be ground), and so do 256-bit digests. A bit more is
/// twice the grinding; at 124 a block of a reward alone grinds for
/// about two seconds.
pub const SECURITY: usize = 124;

/// Bits to grind before a challenge whose round errs with probability
/// `numerator / 2^128`, so that it errs with probability `2^-round_bits`
/// at most. Zero for `round_bits` of zero: no grinding at all.
pub fn grinding(round_bits: usize, numerator: usize) -> usize {
    let log = (usize::BITS - (numerator.max(1) - 1).leading_zeros()) as usize;
    (round_bits + log).saturating_sub(FIELD_BITS)
}

/// What a query is worth at rate `2^-(i + 1)`, in millionths of a bit,
/// rounded down: `1 - log2(1 + rate)`. A table, so that no machine's
/// logarithm decides a parameter of consensus.
pub const QUERY_MICROBITS: [u64; 8] = [415_037, 678_071, 830_074, 912_537, 955_605, 977_632, 988_772, 994_375];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Variables of the polynomial.
    pub m: usize,
    /// The code's rate is `2^-log_inv_rate`.
    pub log_inv_rate: usize,
    pub queries: usize,
    /// Rounds folded between commitments: a leaf is `2^arity` elements.
    pub arity: usize,
    /// Bits ground before the queries are sampled.
    pub query_grinding: usize,
    /// Every folding round is ground until its error is below
    /// `2^-round_bits`; zero for no grinding.
    pub round_bits: usize,
    /// Whether the commitment hides the polynomial ([`commit_blind`]),
    /// and the argument above it everything it says of it.
    pub blind: bool,
    /// Once the polynomial has this many variables left or fewer where a
    /// codeword would be committed, it is sent as it is and no more
    /// codewords are: zero for one that is folded to a constant.
    pub last: usize,
}

impl Params {
    /// Grinding before the queries at every proven level: 2^20 hashes,
    /// some milliseconds, for 29 queries fewer at rate 1/4. A proof
    /// that is published may grind more ([`Params::ground`]).
    pub const QUERY_GRINDING: usize = 20;

    /// Parameters for `security` bits, proven: every round errs with
    /// probability below `2^-(security + 1)`.
    pub fn proven(m: usize, log_inv_rate: usize, security: usize) -> Params {
        Params::proven_ground(m, log_inv_rate, security, Self::QUERY_GRINDING)
    }

    /// [`Params::proven`], with `grinding` bits ground before the
    /// queries: each bit is twice the hashing, once a proof, and about
    /// a query and a half fewer at rate 1/4. For a proof whose size
    /// matters more than a second of proving.
    pub fn proven_ground(m: usize, log_inv_rate: usize, security: usize, grinding: usize) -> Params {
        assert!((1..=QUERY_MICROBITS.len()).contains(&log_inv_rate));
        // A sumcheck round is 127 bits, and is not ground.
        assert!(security + 1 < FIELD_BITS);
        let from_queries = (security + 1).saturating_sub(grinding) as u64 * 1_000_000;
        let queries = from_queries.div_ceil(QUERY_MICROBITS[log_inv_rate - 1]) as usize;
        Params {
            m,
            log_inv_rate,
            queries,
            arity: 4,
            query_grinding: grinding,
            round_bits: security + 1,
            blind: false,
            last: 8,
        }
    }

    /// Parameters with no grinding and `queries` queries: for tests, and
    /// for measuring what the parts cost.
    pub fn plain(m: usize, log_inv_rate: usize, queries: usize, arity: usize) -> Params {
        Params { m, log_inv_rate, queries, arity, query_grinding: 0, round_bits: 0, blind: false, last: 0 }
    }

    /// The same, for proofs that hide what they are of. The queries are
    /// ground for a bit at least: the prover chooses among nonces.
    pub fn hiding(self) -> Params {
        Params { blind: true, query_grinding: self.query_grinding.max(1), ..self }
    }

    /// Variables of the code's domain.
    pub fn k(&self) -> usize {
        self.m + self.log_inv_rate
    }

    /// Rounds each committed codeword is folded before the next: `arity`
    /// each, and what is left over for the last.
    pub fn steps(&self) -> Vec<usize> {
        let mut steps = vec![self.arity; self.m / self.arity];
        if !self.m.is_multiple_of(self.arity) {
            steps.push(self.m % self.arity);
        }
        steps
    }

    /// The round after which the polynomial is sent as it is
    /// ([`Params::last`]), and how many codewords are committed before:
    /// the first, and one where each step before that round ends.
    pub fn sent(&self) -> (usize, usize) {
        let (mut round, mut trees) = (0, 0);
        for step in self.steps() {
            if round > 0 && self.m - round <= self.last {
                break;
            }
            (round, trees) = (round + step, trees + 1);
        }
        (round, trees)
    }

    /// Bits ground before the challenge of folding round `round`, which
    /// folds a codeword of `2^(k - round)` entries.
    pub fn fold_grinding(&self, round: usize) -> usize {
        grinding(self.round_bits, 1 << (self.k() - round))
    }

    /// Bits the queries and their grinding come to, rounded down.
    pub fn query_bits(&self) -> usize {
        (self.queries as u64 * QUERY_MICROBITS[self.log_inv_rate - 1] / 1_000_000) as usize + self.query_grinding
    }
}

pub struct Committed {
    pub codeword: Vec<F>,
    pub tree: MerkleTree,
    /// The codewords of the polynomial that blinds this one, of the
    /// pads' and of the one that blinds the pads', if this is a
    /// commitment that hides: an entry each for each leaf.
    pub blind: Option<[Vec<F>; 3]>,
    /// The codewords folded beside this one, of a codeword committed
    /// while an opening is made: the polynomials that joined it, each
    /// as many entries a leaf as this.
    pub beside: Vec<Vec<F>>,
}

/// The queries' part of one committed codeword: the leaves they open,
/// each once and in the order of their indices, and the siblings their
/// paths need between them ([`MerkleTree::open_batch`]).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Batch {
    pub leaves: Vec<Vec<F>>,
    pub siblings: Vec<Digest>,
}

impl Batch {
    fn of(com: &Committed, indices: &[usize], leaf: usize) -> Batch {
        let distinct = distinct(indices);
        Batch {
            leaves: (distinct.iter())
                .map(|i| {
                    let own = com.codeword[i * leaf..(i + 1) * leaf].iter();
                    let beside = com.beside.iter().flat_map(|b| &b[i * leaf..(i + 1) * leaf]);
                    own.chain(beside).chain(com.blind.iter().flatten().map(|b| &b[*i])).copied().collect()
                })
                .collect(),
            siblings: com.tree.open_batch(&distinct),
        }
    }

    /// The leaves by their indices, if the batch is of the leaves at
    /// `indices` of the tree of `root`: leaves of `leaf` elements, in a
    /// tree of `height`. With them, the compressions it took.
    fn check(&self, root: &Digest, indices: &[usize], leaf: usize, height: usize) -> Option<(Vec<usize>, usize)> {
        let distinct = distinct(indices);
        if self.leaves.len() != distinct.len() || self.leaves.iter().any(|l| l.len() != leaf) {
            return None;
        }
        let hashes: Vec<Digest> = self.leaves.iter().map(|l| merkle::leaf_hash(l)).collect();
        let (found, nodes) = merkle::batch_root(&distinct, &hashes, height, &self.siblings)?;
        let work = distinct.len() * crate::blake3::compressions(leaf * F::BYTES) + nodes;
        (found == *root).then_some((distinct, work))
    }

    fn write(&self, w: &mut Writer) {
        w.len(self.leaves.len());
        self.leaves.iter().for_each(|l| w.fs(l));
        w.digests(&self.siblings);
    }

    fn read(r: &mut Reader) -> Option<Batch> {
        let n = r.len(4)?;
        Some(Batch { leaves: (0..n).map(|_| r.fs()).collect::<Option<_>>()?, siblings: r.digests()? })
    }
}

/// Indices in order, each once.
fn distinct(indices: &[usize]) -> Vec<usize> {
    let mut d = indices.to_vec();
    d.sort_unstable();
    d.dedup();
    d
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Roots of the folded codewords, the second committed codeword first.
    pub roots: Vec<Digest>,
    /// Each sumcheck round's constant and leading coefficients.
    pub rounds: Vec<(F, F)>,
    /// Each round's nonce, ground before its challenge; zero where the
    /// round needs none.
    pub fold_nonces: Vec<u64>,
    /// The polynomial folded so far, where no more codewords are
    /// committed ([`Params::last`]): its values on what is left of the
    /// cube. After it each joiner's the same, and then the pads'
    /// polynomial's in an opening that hides. Empty if the folding goes
    /// on to constants.
    pub last: Vec<F>,
    /// The polynomial at the challenges: what its codeword folds to.
    pub final_value: F,
    /// Each joiner at its challenges.
    pub joined_finals: Vec<F>,
    /// The nonce ground before each joiner joins; zero where the round
    /// needs none.
    pub join_nonces: Vec<u64>,
    /// What the blinding polynomial sums to under the first's weights
    /// where it joins, and what the one that blinds the pads' sums to
    /// under theirs; the nonces ground before each of the two joins;
    /// and the pads' polynomial with the one that blinds it, at the
    /// challenges. Zero for an opening that hides nothing.
    pub blind_sum: F,
    pub pad_blind_sum: F,
    pub blind_nonces: [u64; 2],
    pub pad_final: F,
    /// The nonce ground before the queries.
    pub query_nonce: u64,
    /// The queries' openings of each committed codeword.
    pub openings: Vec<Batch>,
    /// Their openings of each joiner's codeword.
    pub joined_openings: Vec<Batch>,
}

/// What [`verify_weighted`] leaves: the challenges, the sumcheck's last
/// claim, the challenges that joined the smaller polynomials, and the
/// queries' leaves in the first committed codeword. For an opening
/// that hides, the claim is to be the first polynomial's last value
/// times its weights, the joiners' as ever, and the pads' polynomial's
/// last value times its weights at the challenges after the first
/// leaf's, times the squares of one and each of the first leaf's.
pub struct Opening<A> {
    pub r: Vec<A>,
    pub claim: A,
    pub thetas: Vec<A>,
    pub indices: Vec<usize>,
    /// The proof's last values, as the transcript took them in.
    pub final_value: A,
    pub joined_finals: Vec<A>,
    /// The pads' polynomial at the challenges, for an opening that
    /// hides.
    pub pad_final: Option<A>,
}

/// What a verifier hashed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Work {
    pub compressions: usize,
}

/// `eq(z, b)` for every `b` of the cube.
pub fn eq_table(z: &[F]) -> Vec<F> {
    let mut e = vec![F::ZERO; 1 << z.len()];
    e[0] = F::ONE;
    for (i, zi) in z.iter().enumerate() {
        let (lo, hi) = e.split_at_mut(1 << i);
        for (a, b) in lo.iter_mut().zip(hi) {
            *b = *a * *zi;
            *a += *b;
        }
    }
    e
}

/// `eq(a, b)`: in characteristic two, the product of `1 + a_i + b_i`.
pub fn eq(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::ONE, |p, (x, y)| p * (F::ONE + *x + *y))
}

/// Pairs a thread sums before it looks for more work.
const RUN: usize = 1 << 13;

/// The sum over the runs of `0..n` of what `f` gives for each.
fn sum_runs(n: usize, f: impl Fn(std::ops::Range<usize>) -> (F, F) + Sync) -> (F, F) {
    let parts = par_map_min(n.div_ceil(RUN), 1, |i| f(i * RUN..n.min((i + 1) * RUN)));
    parts.into_iter().fold((F::ZERO, F::ZERO), |a, b| (a.0 + b.0, a.1 + b.1))
}

/// The polynomial of values `f` at `z`.
pub fn evaluate(f: &[F], z: &[F]) -> F {
    let e = eq_table(z);
    sum_runs(f.len(), |r| (r.fold(F::ZERO, |a, i| a + f[i] * e[i]), F::ZERO)).0
}

/// A table of values with its lowest variable set to `r`.
fn fold_table(t: &[F], r: F) -> Vec<F> {
    let mut out = vec![F::ZERO; t.len() / 2];
    par_fill(&mut out, |b| t[2 * b] + r * (t[2 * b] + t[2 * b + 1]));
    out
}

pub fn commit(params: &Params, domain: &Domain, f: &[F]) -> Committed {
    assert_eq!(f.len(), 1 << params.m);
    assert_eq!(domain.k, params.k());
    let codeword = domain.encode(f);
    let tree = MerkleTree::new(&codeword, 1 << params.steps()[0]);
    Committed { codeword, tree, blind: None, beside: Vec::new() }
}

/// The commitment of `f` that an opening hides, with the random
/// polynomial `g` that blinds it, the pads `pads` and the random
/// polynomial `g_pads` that blinds those: each `params.m` less the
/// first step's variables. Each leaf ends with their codewords'
/// entries there.
pub fn commit_blind(params: &Params, domain: &Domain, f: &[F], g: &[F], pads: &[F], g_pads: &[F]) -> Committed {
    let step = params.steps()[0];
    assert!(params.blind && step < params.m, "a polynomial larger than a leaf");
    assert_eq!((f.len(), domain.k), (1 << params.m, params.k()));
    let small = 1 << (params.m - step);
    assert_eq!((g.len(), pads.len(), g_pads.len()), (small, small, small));
    let codeword = domain.encode(f);
    let blind = [domain.encode_up(g, step), domain.encode_up(pads, step), domain.encode_up(g_pads, step)];
    let tree = MerkleTree::with_more(&codeword, 1 << step, &[&blind[0], &blind[1], &blind[2]]);
    Committed { codeword, tree, blind: Some(blind), beside: Vec::new() }
}

/// What a prover hides an opening with: the polynomial that blinds the
/// first and the pads ([`commit_blind`]), the pads' weights in the sum,
/// and whether the leaves a set of queries would open are hidden by
/// what is random in the first.
pub struct Blind<'a> {
    pub g: &'a [F],
    pub pads: &'a [F],
    /// The polynomial that blinds the pads'.
    pub g_pads: &'a [F],
    pub weights: Vec<F>,
    pub good: &'a dyn Fn(&[usize]) -> bool,
}

/// The transcript as both sides of [`open`] begin it.
fn begin(root: &Digest, z: &[F], v: F) -> Challenger {
    let mut tr = Challenger::new(b"tabminer pcs");
    tr.absorb(root);
    tr.absorb_fs(z);
    tr.absorb_fs(&[v]);
    tr
}

/// The proof that the committed polynomial `f` is `v` at `z`.
pub fn open(params: &Params, domain: &Domain, com: &Committed, f: &[F], z: &[F], v: F) -> Proof {
    let mut tr = begin(&com.tree.root(), z, v);
    open_weighted(params, domain, com, f, eq_table(z), vec![], None, &mut tr)
}

/// A smaller polynomial opened with the first: `round` variables fewer,
/// `round` a multiple of [`Params::arity`] and not zero, committed by
/// [`commit_at`]. It joins the opening at that round.
pub struct Joiner<'a> {
    pub com: &'a Committed,
    pub f: &'a [F],
    pub weights: Vec<F>,
    pub round: usize,
}

/// The committed codeword whose folding begins at `round`, if one does:
/// which of the opening's commitments a polynomial joining at `round`
/// is opened beside.
fn oracle_at(steps: &[usize], round: usize) -> Option<usize> {
    let mut at = 0;
    steps.iter().position(|s| {
        let here = at == round;
        at += s;
        here
    })
}

/// The commitment of a polynomial to be opened as a [`Joiner`] at
/// `round` under `params`: `params.m - round` variables, its codeword on
/// the domain where the first polynomial's is once it has been folded
/// `round` times and is next committed.
pub fn commit_at(params: &Params, domain: &Domain, f: &[F], round: usize) -> Committed {
    let steps = params.steps();
    let t = oracle_at(&steps, round).filter(|t| *t > 0).expect("a polynomial joins where a codeword is committed");
    assert_eq!(f.len(), 1 << (params.m - round));
    let codeword = domain.encode_up(f, round);
    // Its leaves are single entries: a query needs one of them, not
    // the sixteen a codeword that is folded on is opened by.
    let _ = steps[t];
    let tree = MerkleTree::new(&codeword, 1);
    Committed { codeword, tree, blind: None, beside: Vec::new() }
}

/// The proof that `sum_b f(b) weights(b)` is what the transcript `tr`
/// already holds it to be: the root, and whatever fixes the weights and
/// the sum, must have been absorbed.
///
/// With `joiners`, the proof is of that and of the same for each of
/// them, whose roots, weights and sums the transcript must hold too, in
/// the order of their rounds. Once the first polynomial has been folded
/// to a joiner's size, a challenge `theta` makes one sum of the two,
/// and the rounds go on for both; the joiner's codeword is folded
/// beside the first's from there, in the leaves of every codeword
/// committed after. A query opens the joiner's own tree where it opens
/// the codeword committed next, and finds that entry in the leaf, in
/// the joiner's part of it.
#[allow(clippy::too_many_arguments)]
pub fn open_weighted(
    params: &Params,
    domain: &Domain,
    com: &Committed,
    f: &[F],
    weights: Vec<F>,
    joiners: Vec<Joiner>,
    blind: Option<Blind>,
    tr: &mut Challenger,
) -> Proof {
    let m = params.m;
    assert_eq!((blind.is_some(), blind.is_some()), (params.blind, com.blind.is_some()));
    let steps = params.steps();
    assert!(joiners.windows(2).all(|w| w[0].round <= w[1].round), "joiners come in the order of their rounds");
    let mut f = f.to_vec();
    let mut e = weights;
    // The joiners' tables and challenges, from the rounds they join at.
    let mut joined: Vec<(Vec<F>, Vec<F>, F)> = Vec::with_capacity(joiners.len());
    let mut join_nonces = Vec::with_capacity(joiners.len());
    // The committed codewords after the first, and the one being folded
    // when it is none of them.
    let mut oracles: Vec<Committed> = Vec::new();
    let (stop, trees) = params.sent();
    let mut last: Vec<F> = Vec::new();
    let mut current: Vec<F> = Vec::new();
    let mut committed = true;
    let mut boundary = steps[0];
    let (mut rounds, mut fold_nonces) = (Vec::with_capacity(m), Vec::with_capacity(m));
    // The polynomial that blinds, once it has joined: as a joiner, under
    // the first's weights as they were then. And the pads', under its
    // own.
    let mut blinder: Option<(Vec<F>, Vec<F>, F)> = None;
    let mut padded: Option<(Vec<F>, Vec<F>, F)> = None;
    let (mut blind_sum, mut pad_blind_sum, mut blind_nonces) = (F::ZERO, F::ZERO, [0; 2]);
    // The codewords of what joined, each folded beside the first's and
    // never added to it: every polynomial folds to a value of its own.
    let mut beside: Vec<Vec<F>> = Vec::with_capacity(joiners.len());
    let mut pad_beside: Option<Vec<F>> = None;
    #[allow(unused_assignments, unused_mut, unused_variables)]
    let mut pad_theta = F::ZERO;
    // Before they join, the pads' part of a round: their whole sum,
    // times the squares of one and each challenge so far.
    let pad_sum = blind.as_ref().map_or(F::ZERO, |b| inner_product(b.pads, &b.weights));
    let mut early = F::ONE;
    for i in 0..m {
        let (mut c0, mut c2) = sum_products(&f, &e);
        if i < steps[0] {
            (c0, c2) = (c0 + early * pad_sum, c2 + early * pad_sum);
        }
        for (g, w, theta) in joined.iter().chain(&blinder).chain(&padded) {
            let (d0, d2) = sum_products(g, w);
            (c0, c2) = (c0 + *theta * d0, c2 + *theta * d2);
        }
        tr.absorb_fs(&[c0, c2]);
        rounds.push((c0, c2));
        fold_nonces.push(tr.grind(params.fold_grinding(i)));
        let r = tr.challenge();
        f = fold_table(&f, r);
        e = fold_table(&e, r);
        for (g, w, _) in joined.iter_mut().chain(&mut blinder).chain(&mut padded) {
            *g = fold_table(g, r);
            *w = fold_table(w, r);
        }
        early *= (F::ONE + r).square();
        let source: &[F] = match (committed, oracles.last()) {
            (true, Some(o)) => &o.codeword,
            (true, None) => &com.codeword,
            (false, _) => &current,
        };
        current = domain.fold(source, i, r);
        committed = false;
        for code in beside.iter_mut().chain(&mut pad_beside) {
            *code = domain.fold(code, i, r);
        }
        if let (Some(blind), true) = (&blind, i + 1 == steps[0]) {
            // What is folded from here is the first and a random one;
            // and beside it the pads' and a random one. The pads'
            // weights from here are scaled as their sum was.
            let pad_weights: Vec<F> = blind.weights.iter().map(|w| early * *w).collect();
            blind_sum = inner_product(blind.g, &e);
            pad_blind_sum = inner_product(blind.g_pads, &pad_weights);
            tr.absorb_fs(&[blind_sum, pad_blind_sum]);
            blind_nonces[0] = tr.grind(params.fold_grinding(i + 1));
            let theta = tr.challenge();
            blind_nonces[1] = tr.grind(params.fold_grinding(i + 1));
            let theta_pads = tr.challenge();
            let [add, pads, add_pads] = com.blind.as_ref().expect("a blinded commitment");
            crate::parallel::par_chunks_mut(&mut current, RUN, |c, run| {
                for (x, y) in run.iter_mut().zip(&add[c * RUN..]) {
                    *x += theta * *y;
                }
            });
            let mut code = pads.clone();
            crate::parallel::par_chunks_mut(&mut code, RUN, |c, run| {
                for (x, y) in run.iter_mut().zip(&add_pads[c * RUN..]) {
                    *x += theta_pads * *y;
                }
            });
            pad_beside = Some(code);
            pad_theta = theta_pads;
            blinder = Some((blind.g.to_vec(), e.clone(), theta));
            let both = blind.pads.iter().zip(blind.g_pads).map(|(p, g)| *p + theta_pads * *g).collect();
            padded = Some((both, pad_weights, F::ONE));
        }
        for joiner in joiners.iter().filter(|j| j.round == i + 1) {
            // The first is this one's size from here. Adding the
            // codewords is a round like a fold: ground like one.
            assert!(
                (i + 1 == boundary || i + 1 == stop) && i + 1 < m,
                "a polynomial joins where a codeword is committed"
            );
            join_nonces.push(tr.grind(params.fold_grinding(i + 1)));
            let theta = tr.challenge();
            beside.push(joiner.com.codeword.clone());
            joined.push((joiner.f.to_vec(), joiner.weights.clone(), theta));
        }
        if i + 1 == stop && i + 1 < m {
            // No more codewords: the polynomial (with the one that
            // blinds it), then each that joined it, then the pads'.
            last = f.clone();
            if let Some((g, _, theta)) = &blinder {
                last.iter_mut().zip(g).for_each(|(x, y)| *x += *theta * *y);
            }
            for (g, ..) in joined.iter().chain(&padded) {
                last.extend_from_slice(g);
            }
            tr.absorb_fs(&last);
            boundary = m + 1;
        }
        if i + 1 == boundary && i + 1 < m {
            // A leaf is the codeword's entries and then those of each
            // codeword folded beside it.
            let leaf = 1 << steps[oracles.len() + 1];
            let with: Vec<Vec<F>> = beside.iter().chain(&pad_beside).cloned().collect();
            let tree = match with.is_empty() {
                true => MerkleTree::new(&current, leaf),
                false => {
                    let whole = leaf * (1 + with.len());
                    let mut all = vec![F::ZERO; current.len() * (1 + with.len())];
                    crate::parallel::par_chunks_mut(&mut all, whole * 256, |run, out| {
                        for (at, out) in out.chunks_exact_mut(whole).enumerate() {
                            let range = (run * 256 + at) * leaf..(run * 256 + at + 1) * leaf;
                            let codes = std::iter::once(&current).chain(&with);
                            for (part, code) in out.chunks_exact_mut(leaf).zip(codes) {
                                part.copy_from_slice(&code[range.clone()]);
                            }
                        }
                    });
                    MerkleTree::new(&all, whole)
                }
            };
            tr.absorb(&tree.root());
            oracles.push(Committed { codeword: std::mem::take(&mut current), tree, blind: None, beside: with });
            committed = true;
            boundary += steps[oracles.len()];
        }
    }
    assert_eq!(joined.len(), joiners.len(), "every joiner joined");
    // With a blinding polynomial the last value is of the two together.
    let final_value = blinder.iter().fold(f[0], |v, (g, _, theta)| v + *theta * g[0]);
    let joined_finals: Vec<F> = joined.iter().map(|(g, ..)| g[0]).collect();
    let pad_final = padded.as_ref().map_or(F::ZERO, |(p, ..)| p[0]);
    // (Tests: a prover that says other last values than these, before
    // the queries are drawn.)
    #[cfg(test)]
    let (final_value, joined_finals, pad_final) = {
        let thetas: Vec<F> = joined.iter().map(|(.., theta)| *theta).collect();
        let mut said = (final_value, joined_finals, pad_final);
        if let Some(lie) = tests::LIE.get() {
            lie(&mut said.0, &mut said.1, &thetas, &mut said.2, pad_theta);
        }
        said
    };
    tr.absorb_fs(&[final_value]);
    if blind.is_some() {
        tr.absorb_fs(&[pad_final]);
    }
    tr.absorb_fs(&joined_finals);
    let sample =
        |tr: &mut Challenger| -> Vec<usize> { (0..params.queries).map(|_| tr.index(params.k() - steps[0])).collect() };
    let (query_nonce, mut indices) = match &blind {
        None => {
            let nonce = tr.grind(params.query_grinding);
            (nonce, sample(tr))
        }
        Some(blind) => {
            // The first nonce whose queries open leaves that are hidden.
            assert!(params.query_grinding > 0, "nonces to choose among");
            let mut from = 0;
            loop {
                let mut tried = tr.clone();
                let nonce = tried.grind_from(params.query_grinding, from);
                let indices = sample(&mut tried);
                if (blind.good)(&indices) {
                    *tr = tried;
                    break (nonce, indices);
                }
                from = nonce + 1;
            }
        }
    };
    let mut openings = Vec::with_capacity(steps.len());
    let mut joined_openings = Vec::with_capacity(joiners.len());
    let mut round = 0;
    for (t, s) in steps.iter().enumerate() {
        // A query's entry in this codeword is its leaf in the one before.
        for joiner in joiners.iter().filter(|j| j.round == round) {
            joined_openings.push(Batch::of(joiner.com, &indices, 1));
        }
        if t == trees {
            break;
        }
        if t > 0 {
            indices.iter_mut().for_each(|i| *i >>= s);
        }
        openings.push(Batch::of(if t == 0 { com } else { &oracles[t - 1] }, &indices, 1 << s));
        round += s;
    }
    Proof {
        roots: oracles.iter().map(|o| o.tree.root()).collect(),
        rounds,
        fold_nonces,
        last,
        final_value,
        joined_finals,
        join_nonces,
        blind_sum,
        pad_blind_sum,
        blind_nonces,
        pad_final,
        query_nonce,
        openings,
        joined_openings,
    }
}

/// The sum of the products of `f` and `e`, entry by entry.
pub fn inner_product(f: &[F], e: &[F]) -> F {
    sum_runs(f.len(), |range| (range.fold(F::ZERO, |s, i| s + f[i] * e[i]), F::ZERO)).0
}

/// The sums a round sends for one polynomial: of the products of the
/// values and the weights at the pairs' even entries, and of the
/// products of their differences.
fn sum_products(f: &[F], e: &[F]) -> (F, F) {
    sum_runs(f.len() / 2, |range| {
        let (mut c0, mut c2) = (F::ZERO, F::ZERO);
        for b in range {
            let (f0, f1, e0, e1) = (f[2 * b], f[2 * b + 1], e[2 * b], e[2 * b + 1]);
            c0 += f0 * e0;
            c2 += (f0 + f1) * (e0 + e1);
        }
        (c0, c2)
    })
}

/// Whether `proof` shows that the polynomial committed as `root` is `v`
/// at `z`. `domain` needs no tables.
pub fn verify(params: &Params, domain: &Domain, root: &Digest, z: &[F], v: F, proof: &Proof) -> Option<Work> {
    if z.len() != params.m {
        return None;
    }
    let mut tr = begin(root, z, v);
    let mut opens = Batched::default();
    let o = verify_weighted(params, domain, (root, halves(root)), v, proof, &[], &mut tr, &mut opens)?;
    (o.claim == proof.final_value * eq(z, &o.r)).then_some(Work { compressions: opens.compressions + tr.compressions })
}

/// A polynomial that joined an opening, as the verifier knows it: its
/// root (and the root as the two elements the verifier's arithmetic
/// holds it as), the sum it is shown to have, and the round it joined
/// at.
#[derive(Clone)]
pub struct Joined<'a, A> {
    pub root: &'a Digest,
    pub at: [A; 2],
    pub target: A,
    pub round: usize,
}

/// A tree the queries open, to whoever opens it: its root both ways,
/// the proof's batch of leaves and siblings, and which of the opening's
/// codewords its leaves are beside (its own, or the one it joined).
pub struct Tree<'a, A> {
    pub root: &'a Digest,
    pub at: [A; 2],
    pub batch: &'a Batch,
    pub codeword: usize,
}

/// What one query opened, as values of the verifier's arithmetic.
pub struct Query<A> {
    /// The index of its leaf in the first codeword, as the element whose
    /// bits are the index's.
    pub point: A,
    /// Its leaf in each committed codeword, and in each joiner's.
    pub leaves: Vec<Vec<A>>,
    pub joined: Vec<Vec<A>>,
    /// For each codeword after the first, where in its leaf the value
    /// folded so far lies: the bits of that place, lowest first, each
    /// zero or one.
    pub bits: Vec<Vec<A>>,
}

/// Whoever checks the queries' leaves against the trees' roots: all of
/// a tree's together and by the field's own hashing ([`Batched`]), or
/// each by itself as rows of a circuit.
pub trait Opens<A: Alg> {
    /// Every query's leaves, if they are under the roots. `indices` are
    /// the queries' leaves in the first codeword, each with the element
    /// the transcript gave it as (its bits and others above them).
    fn open(
        &mut self,
        params: &Params,
        trees: &[Tree<A>],
        joined: &[Tree<A>],
        indices: &[(usize, A)],
    ) -> Option<Vec<Query<A>>>;
}

/// The field's own [`Opens`]: a tree's leaves checked all together, the
/// siblings shared between them.
#[derive(Default)]
pub struct Batched {
    pub compressions: usize,
}

/// A tree's height and the size of its leaves, as bits, for each of an
/// opening's codewords.
pub fn shapes(params: &Params) -> Vec<(usize, usize)> {
    let mut layer = 0;
    let shape = |s: &usize| {
        layer += s;
        (params.k() - layer, *s)
    };
    params.steps().iter().map(shape).collect()
}

/// Elements in a leaf of an opening's codeword `codeword`, where the
/// joiners joined at the codewords `places`. The first's has three
/// more in a commitment that hides ([`commit_blind`]); one after it has
/// as many again for each polynomial that has joined by then, the
/// pads' among them. A joiner's own leaf is one entry, in a tree as
/// much higher.
pub fn leaf_len(params: &Params, codeword: usize, joined: bool, places: &[usize]) -> usize {
    if joined {
        return 1;
    }
    let own = 1 << params.steps()[codeword];
    match codeword {
        0 => own + if params.blind { 3 } else { 0 },
        t => own * (1 + beside_at(params, places, t)),
    }
}

/// How many polynomials are folded beside the first in its codeword
/// `t`, after the first: the joiners that joined there or before, and
/// the pads' in an opening that hides.
fn beside_at(params: &Params, places: &[usize], t: usize) -> usize {
    places.iter().filter(|place| **place <= t).count() + params.blind as usize
}

impl Opens<F> for Batched {
    fn open(
        &mut self,
        params: &Params,
        trees: &[Tree<F>],
        joined: &[Tree<F>],
        indices: &[(usize, F)],
    ) -> Option<Vec<Query<F>>> {
        let shapes = shapes(params);
        // A query's leaf in each codeword: the last one's index with the
        // bits of the place in the leaf taken off.
        let mut at: Vec<Vec<usize>> = vec![indices.iter().map(|(i, _)| *i).collect()];
        for (_, s) in &shapes[1..] {
            at.push(at[at.len() - 1].iter().map(|i| i >> s).collect());
        }
        let places: Vec<usize> = joined.iter().map(|t| t.codeword).collect();
        let mut leaves = |tree: &Tree<F>, joined: bool| -> Option<Vec<Vec<F>>> {
            // A joiner's tree has a leaf for each entry of the codeword
            // it joined: a query's is its leaf in the codeword before.
            let (height, s) = shapes[tree.codeword];
            let (height, indices) =
                if joined { (height + s, &at[tree.codeword - 1]) } else { (height, &at[tree.codeword]) };
            let leaf = leaf_len(params, tree.codeword, joined, &places);
            let (distinct, hashed) = tree.batch.check(tree.root, indices, leaf, height)?;
            self.compressions += hashed;
            Some(
                indices.iter().map(|i| tree.batch.leaves[distinct.binary_search(i).expect("opened")].clone()).collect(),
            )
        };
        let opened: Vec<Vec<Vec<F>>> = trees.iter().map(|t| leaves(t, false)).collect::<Option<_>>()?;
        let joined_opened: Vec<Vec<Vec<F>>> = joined.iter().map(|t| leaves(t, true)).collect::<Option<_>>()?;
        let query = |q: usize| Query {
            point: F(at[0][q] as u128),
            leaves: opened.iter().map(|t| t[q].clone()).collect(),
            joined: joined_opened.iter().map(|t| t[q].clone()).collect(),
            bits: (0..shapes.len())
                .map(|t| {
                    if t == 0 { vec![] } else { (0..shapes[t].1).map(|b| F((at[t - 1][q] >> b & 1) as u128)).collect() }
                })
                .collect(),
        };
        Some((0..indices.len()).map(query).collect())
    }
}

/// The entry of `leaf` at the place whose bits are `bits`, lowest first.
fn select<A: Alg>(leaf: &[A], bits: &[A]) -> A {
    let mut vals = leaf.to_vec();
    for bit in bits {
        vals = vals.chunks_exact(2).map(|v| (v[0].clone() + v[1].clone()) * bit.clone() + v[0].clone()).collect();
    }
    vals.swap_remove(0)
}

/// What folding needs of each layer, the same for every query.
///
/// With `r` a layer's challenge and `t` its twiddle for a pair
/// `(y0, y1)`, the pair folds to `(1 + r)(y0 + (t + r / (1 + r))(y0 + y1))`
/// ([`crate::ntt::fold_pair`], regrouped). So a leaf is folded without
/// the factors `1 + r`, a product a pair, and what it folds to is scaled
/// by them all at once. The twiddle is `Ŵ_i` at the pair's point, linear
/// over the point's bits, so it is a sum of parts: these.
struct Layers<A> {
    /// `1 / W_i(x^i)`: what `W_i` at a query's point is scaled by.
    scale: Vec<A>,
    /// `r / (1 + r) + Ŵ_i(pair)`, for each pair of a leaf: its place in
    /// the leaf is bits of its point.
    pair: Vec<Vec<A>>,
    /// `Ŵ_i(x^l)` for each bit `l` of the point between `i` and the end
    /// of the leaf: bits a query's point has, which the leaf's own point
    /// has not.
    over: Vec<Vec<A>>,
    /// For each codeword, the product of `1 + r` over its leaf's layers.
    whole: Vec<A>,
}

impl<A: Alg> Layers<A> {
    /// `None` if a challenge is one: no proof is taken then.
    fn new(domain: &Domain, steps: &[usize], rs: &[A]) -> Option<Layers<A>> {
        let lift = |c: F| rs[0].lift(c);
        let (mut scale, mut pair, mut over, mut whole) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut layer = 0;
        for s in steps {
            let mut all = lift(F::ONE);
            for j in 0..*s {
                let i = layer + j;
                let one_r = (rs[i].clone() + lift(F::ONE)).kept();
                let rho = (rs[i].clone() * one_r.inv()?).kept();
                all = all * one_r;
                scale.push(lift(domain.norm(i).inv()));
                let pairs = 1 << (s - 1 - j);
                pair.push((0..pairs).map(|p| (rho.clone() + lift(domain.twiddle_slow(i, p))).kept()).collect());
                over.push((i..layer + s).map(|l| lift(domain.what(i, l))).collect());
            }
            whole.push(all.kept());
            layer += s;
        }
        Some(Layers { scale, pair, over, whole })
    }
}

/// Where a query's folding ends: after the committed codewords, at the
/// polynomial that was sent if one was, or at the constant.
struct Ends<'a, A> {
    trees: usize,
    /// The polynomials sent, one after another: the first's, each
    /// joiner's, the pads'.
    last: &'a [A],
    /// What each folds to, in that order.
    ends: &'a [A],
}

/// Whether a query's leaves fold rightly. Each codeword's leaf holds,
/// for the first polynomial and for each that has joined, what the
/// leaf before folded to for that polynomial; or, for one that joins
/// here, its own entry where it was committed. The last folds, for
/// each, to the polynomial sent at the query's point, or to its
/// constant.
fn fold_query<A: Alg>(
    domain: &Domain,
    steps: &[usize],
    layers: &Layers<A>,
    places: &[usize],
    blind: Option<&[A; 2]>,
    ends: &Ends<A>,
    query: &Query<A>,
) -> Option<()> {
    let lift = |c: F| query.point.lift(c);
    // `W_i` at the query's point in the whole domain, for every layer:
    // `W_(i+1)(y) = W_i(y) (W_i(y) + W_i(x^i))`. The point of a leaf of
    // a later codeword is this one with its low bits cleared, and `W_i`
    // is linear over the bits.
    let mut w = Vec::with_capacity(layers.scale.len());
    let mut wi = query.point.clone() * lift(F(1 << steps[0]));
    for i in 0..layers.scale.len() {
        let kept = wi.kept();
        wi = (kept.clone() + lift(domain.norm(i))) * kept.clone();
        w.push(kept);
    }
    // What is folded: the first polynomial, each joiner, the pads' in
    // an opening that hides. What each has come to so far, once it has
    // joined.
    let pads = places.len() + 1;
    let mut carried: Vec<Option<A>> = vec![None; pads + blind.is_some() as usize];
    // What joins at the codeword `t`, at the query's entry of it: the
    // polynomial that blinds, added to the first; a joiner's own entry;
    // the pads' with the one that blinds it. All but the first's own
    // are in the first leaf's last three, or a joiner's leaf.
    let join = |t: usize, carried: &mut Vec<Option<A>>| {
        for j in (0..places.len()).filter(|j| places[*j] == t) {
            carried[1 + j] = Some(query.joined[j][0].clone());
        }
        if let (Some([theta, theta_pads]), 1) = (blind, t) {
            let more = &query.leaves[0][1 << steps[0]..];
            carried[0] = carried[0].take().map(|c| theta.clone() * more[0].clone() + c);
            carried[pads] = Some(theta_pads.clone() * more[2].clone() + more[1].clone());
        }
    };
    let mut layer = 0;
    for (t, s) in steps.iter().enumerate().take(ends.trees) {
        let bits = &query.bits[t];
        join(t, &mut carried);
        // The leaf's parts, one for each polynomial there is by now, in
        // their order; and each is what that polynomial had come to.
        let there: Vec<usize> = (0..carried.len()).filter(|k| t == 0 && *k == 0 || carried[*k].is_some()).collect();
        let mut parts: Vec<Vec<A>> = query.leaves[t].chunks(1 << s).take(there.len()).map(<[A]>::to_vec).collect();
        if parts.len() != there.len() || parts.iter().any(|part| part.len() != 1 << s) {
            return None;
        }
        for (k, part) in there.iter().zip(&parts) {
            if let Some(c) = carried[*k].take()
                && !c.is(&select(part, bits))
            {
                return None;
            }
        }
        for j in 0..*s {
            let i = layer + j;
            // The twiddle's part that is the leaf's own.
            let mut own = w[i].clone() * layers.scale[i].clone();
            for (bit, over) in bits.iter().skip(j).zip(&layers.over[i]) {
                own = bit.clone() * over.clone() + own;
            }
            let own = own.kept();
            for vals in &mut parts {
                *vals = vals
                    .chunks_exact(2)
                    .zip(&layers.pair[i])
                    .map(|(y, pair)| (y[0].clone() + y[1].clone()) * (own.clone() + pair.clone()) + y[0].clone())
                    .collect();
            }
        }
        for (k, mut vals) in there.into_iter().zip(parts) {
            carried[k] = Some(vals.swap_remove(0) * layers.whole[t].clone());
        }
        layer += s;
    }
    join(ends.trees, &mut carried);
    let carried: Vec<A> = carried.into_iter().collect::<Option<_>>()?;
    if ends.last.is_empty() {
        return carried.iter().zip(ends.ends).all(|(c, end)| c.is(end)).then_some(());
    }
    // The codeword of each polynomial sent, at the point folded to: its
    // values are coefficients, of the products of the layers' twiddles
    // there. A twiddle past the leaves is the query's point's alone.
    let twiddles: Vec<A> =
        w.iter().zip(&layers.scale).skip(layer).map(|(w, scale)| (w.clone() * scale.clone()).kept()).collect();
    for (c, values) in carried.iter().zip(ends.last.chunks_exact(ends.last.len() / carried.len())) {
        let mut values = values.to_vec();
        for twiddle in &twiddles {
            values = values.chunks_exact(2).map(|p| p[1].clone() * twiddle.clone() + p[0].clone()).collect();
        }
        if !c.is(&values[0]) {
            return None;
        }
    }
    Some(())
}

/// [`verify`] for [`open_weighted`], all but the last check. The caller
/// must find the claim to be `proof.final_value` times the first
/// polynomial's weights at `r`, and for each joiner its `theta` times
/// its `proof.joined_finals` times its weights at `r` past the
/// challenges before its round.
///
/// It is written over any arithmetic and any transcript: the field's and
/// a [`Challenger`], to verify; a machine's and the rows of a hash
/// table, to make a circuit that verifies ([`crate::alg`]). `root` is
/// the commitment, as bytes and as the transcript gave it to the
/// arithmetic.
#[allow(clippy::too_many_arguments)]
pub fn verify_weighted<A: Alg, T: Transcript<A>, O: Opens<A>>(
    params: &Params,
    domain: &Domain,
    root: (&Digest, [A; 2]),
    target: A,
    proof: &Proof,
    joiners: &[Joined<A>],
    tr: &mut T,
    opens: &mut O,
) -> Option<Opening<A>> {
    let m = params.m;
    let steps = params.steps();
    let (stop, trees) = params.sent();
    if domain.k != params.k()
        || proof.rounds.len() != m
        || proof.fold_nonces.len() != m
        || proof.roots.len() != trees - 1
        || proof.openings.len() != trees
        || proof.last.len() != if stop < m { (1 + joiners.len() + params.blind as usize) << (m - stop) } else { 0 }
        || [proof.joined_finals.len(), proof.join_nonces.len(), proof.joined_openings.len()] != [joiners.len(); 3]
        || (params.blind && steps.len() < 2)
        || (!params.blind
            && (proof.blind_sum, proof.pad_blind_sum, proof.blind_nonces, proof.pad_final)
                != (F::ZERO, F::ZERO, [0; 2], F::ZERO))
    {
        return None;
    }
    // A joiner joins where a codeword is committed, after the first; and
    // they come in the order of their rounds.
    let places: Vec<usize> =
        joiners.iter().map(|j| oracle_at(&steps, j.round).filter(|t| *t > 0)).collect::<Option<_>>()?;
    // (And before the last codeword is done with: a polynomial that
    // joined after would be held to nothing.)
    if !places.windows(2).all(|w| w[0] <= w[1]) || places.iter().any(|place| *place > trees) {
        return None;
    }
    let mut claim = target;
    let mut blind_thetas: Option<[A; 2]> = None;
    let mut last: Vec<A> = Vec::new();
    let mut thetas = Vec::with_capacity(joiners.len());
    let mut rs = Vec::with_capacity(m);
    let mut roots = vec![root];
    let mut boundary = steps[0];
    for (i, (c0, c2)) in proof.rounds.iter().enumerate() {
        let c = tr.elements(&[*c0, *c2]);
        if !tr.ground(params.fold_grinding(i), proof.fold_nonces[i]) {
            return None;
        }
        let r = tr.challenge();
        // g(0) + g(1) is the middle coefficient and the leading one.
        claim = ((claim + c[1].clone()) + c[1].clone() * r.clone()) * r.clone() + c[0].clone();
        rs.push(r);
        if params.blind && i + 1 == steps[0] {
            // The polynomial that blinds joins: its sum under the
            // weights, as the prover says it. The pads' polynomial
            // joins too, whose sum is in the claim already, with the
            // one that blinds it, whose sum the prover says.
            let mut sums = tr.elements(&[proof.blind_sum, proof.pad_blind_sum]);
            if !tr.ground(params.fold_grinding(i + 1), proof.blind_nonces[0]) {
                return None;
            }
            let theta = tr.challenge();
            if !tr.ground(params.fold_grinding(i + 1), proof.blind_nonces[1]) {
                return None;
            }
            let theta_pads = tr.challenge();
            claim = theta_pads.clone() * sums.swap_remove(1) + claim;
            claim = theta.clone() * sums.swap_remove(0) + claim;
            blind_thetas = Some([theta, theta_pads]);
        }
        for joiner in joiners.iter().filter(|j| j.round == i + 1) {
            if !tr.ground(params.fold_grinding(i + 1), proof.join_nonces[thetas.len()]) {
                return None;
            }
            let theta = tr.challenge();
            claim = theta.clone() * joiner.target.clone() + claim;
            thetas.push(theta);
        }
        if i + 1 == stop && i + 1 < m {
            last = tr.elements(&proof.last);
            boundary = m + 1;
        }
        if i + 1 == boundary && i + 1 < m {
            let next = &proof.roots[roots.len() - 1];
            roots.push((next, tr.digest(next)));
            boundary += steps[roots.len() - 1];
        }
    }
    let final_value = tr.elements(&[proof.final_value]).swap_remove(0);
    let pad_final = params.blind.then(|| tr.elements(&[proof.pad_final]).swap_remove(0));
    let joined_finals = tr.elements(&proof.joined_finals);
    if !tr.ground(params.query_grinding, proof.query_nonce) {
        return None;
    }
    // Every query's index in the first committed codeword, and the
    // leaves it opens there and in every codeword after; the joiners'
    // the same, beside the codeword they joined into.
    let indices: Vec<(usize, A)> = (0..params.queries).map(|_| tr.index(params.k() - steps[0])).collect();
    let trees: Vec<Tree<A>> = (roots.iter().zip(&proof.openings).enumerate())
        .map(|(t, ((root, at), batch))| Tree { root, at: at.clone(), batch, codeword: t })
        .collect();
    let joined: Vec<Tree<A>> = (joiners.iter().zip(&proof.joined_openings).zip(&places))
        .map(|((j, batch), t)| Tree { root: j.root, at: j.at.clone(), batch, codeword: *t })
        .collect();
    let queries = opens.open(params, &trees, &joined, &indices)?;
    // What each polynomial's codeword folds to: the first's, each
    // joiner's, the pads'. Each by itself: were they one codeword's,
    // the prover would be free in all of them but their sum.
    let mut ends: Vec<A> = vec![final_value.clone()];
    ends.extend(joined_finals.iter().cloned());
    ends.extend(pad_final.clone());
    let ends: Vec<A> = ends.into_iter().map(|end| end.kept()).collect();
    // The polynomials sent, at the challenges after: what all of each
    // folds to.
    if !last.is_empty() {
        for (values, end) in last.chunks_exact(1 << (m - stop)).zip(&ends) {
            let mut values = values.to_vec();
            for r in &rs[stop..] {
                values =
                    values.chunks_exact(2).map(|p| (p[0].clone() + p[1].clone()) * r.clone() + p[0].clone()).collect();
            }
            if !values[0].is(end) {
                return None;
            }
        }
    }
    let layers = Layers::new(domain, &steps, &rs)?;
    let ends = Ends { trees: trees.len(), last: &last, ends: &ends };
    for query in &queries {
        fold_query(domain, &steps, &layers, &places, blind_thetas.as_ref(), &ends, query)?;
    }
    let indices = indices.into_iter().map(|(i, _)| i).collect();
    Some(Opening { r: rs, claim, thetas, indices, final_value, joined_finals, pad_final })
}

impl Proof {
    /// A proof of nothing: what stands where one is still to be made.
    pub(crate) fn empty() -> Proof {
        Proof {
            roots: Vec::new(),
            rounds: Vec::new(),
            fold_nonces: Vec::new(),
            last: Vec::new(),
            final_value: F::ZERO,
            joined_finals: Vec::new(),
            join_nonces: Vec::new(),
            blind_sum: F::ZERO,
            pad_blind_sum: F::ZERO,
            blind_nonces: [0; 2],
            pad_final: F::ZERO,
            query_nonce: 0,
            openings: Vec::new(),
            joined_openings: Vec::new(),
        }
    }

    /// The proof as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w);
        w.0
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        w.digests(&self.roots);
        w.len(self.rounds.len());
        for ((c0, c2), nonce) in self.rounds.iter().zip(&self.fold_nonces) {
            w.f(*c0);
            w.f(*c2);
            w.u64(*nonce);
        }
        w.fs(&self.last);
        w.f(self.final_value);
        w.fs(&self.joined_finals);
        w.len(self.join_nonces.len());
        self.join_nonces.iter().for_each(|n| w.u64(*n));
        w.f(self.blind_sum);
        self.blind_nonces.iter().for_each(|n| w.u64(*n));
        w.f(self.pad_blind_sum);
        w.f(self.pad_final);
        w.u64(self.query_nonce);
        for batches in [&self.openings, &self.joined_openings] {
            w.len(batches.len());
            batches.iter().for_each(|b| b.write(w));
        }
    }

    /// The proof `bytes` are, if they are one and nothing more.
    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let mut r = Reader(bytes);
        let proof = Proof::read(&mut r)?;
        r.end().then_some(proof)
    }

    pub(crate) fn read(r: &mut Reader) -> Option<Proof> {
        let roots = r.digests()?;
        let n = r.len(40)?;
        let (mut rounds, mut fold_nonces) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for _ in 0..n {
            rounds.push((r.f()?, r.f()?));
            fold_nonces.push(r.u64()?);
        }
        let last = r.fs()?;
        let (final_value, joined_finals) = (r.f()?, r.fs()?);
        let n = r.len(8)?;
        let join_nonces = (0..n).map(|_| r.u64()).collect::<Option<_>>()?;
        let (blind_sum, blind_nonces) = (r.f()?, [r.u64()?, r.u64()?]);
        let (pad_blind_sum, pad_final) = (r.f()?, r.f()?);
        let query_nonce = r.u64()?;
        let batches = |r: &mut Reader| {
            let n = r.len(8)?;
            (0..n).map(|_| Batch::read(r)).collect::<Option<Vec<Batch>>>()
        };
        let (openings, joined_openings) = (batches(r)?, batches(r)?);
        Some(Proof {
            roots,
            rounds,
            fold_nonces,
            last,
            final_value,
            joined_finals,
            join_nonces,
            blind_sum,
            pad_blind_sum,
            blind_nonces,
            pad_final,
            query_nonce,
            openings,
            joined_openings,
        })
    }

    /// Bytes of the proof.
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a prover that lies about the last values makes of them:
    /// the first's, the joiners' (and the challenges they joined
    /// under), the pads' (and the challenge of the one that blinds it).
    pub(super) type Lie = fn(&mut F, &mut [F], &[F], &mut F, F);
    thread_local! {
        pub(super) static LIE: std::cell::Cell<Option<Lie>> = const { std::cell::Cell::new(None) };
    }
    use crate::test_util::Rng;

    fn setup(params: &Params, seed: u64) -> (Domain, Vec<F>, Vec<F>, F) {
        let mut rng = Rng(seed);
        let domain = Domain::new(params.k(), true);
        let f = rng.fs(1 << params.m);
        let z = rng.fs(params.m);
        let v = evaluate(&f, &z);
        (domain, f, z, v)
    }

    #[test]
    fn the_value_on_the_cube_is_the_table_s() {
        let mut rng = Rng(7);
        let f = rng.fs(16);
        for b in 0..16 {
            let z: Vec<F> = (0..4).map(|i| F((b >> i & 1) as u128)).collect();
            assert_eq!(evaluate(&f, &z), f[b]);
        }
        let (a, b) = (rng.fs(5), rng.fs(5));
        assert_eq!(eq(&a, &b), evaluate(&eq_table(&a), &b));
    }

    #[test]
    fn proven_parameters() {
        // 105 bits from the queries and 20 from grinding: 125, for 124.
        let p = Params::proven(22, 2, SECURITY);
        assert_eq!((p.queries, p.query_grinding, p.round_bits, p.arity), (155, 20, 125, 4));
        assert!(p.query_bits() >= 125);
        assert_eq!(Params::proven(20, 5, SECURITY).queries, 110);
        assert_eq!(Params::proven(20, 3, 100).queries, 98);
        // A round folding a codeword of 2^24 is 104 bits by the field,
        // so 21 are ground; each round after, a bit fewer.
        assert_eq!(p.k(), 24);
        assert_eq!((p.fold_grinding(0), p.fold_grinding(1), p.fold_grinding(20), p.fold_grinding(21)), (21, 20, 1, 0));
        // An error of n / 2^128 for n that is not a power of two is
        // ground as for the next one; none for a round already under.
        assert_eq!(
            (grinding(125, 31), grinding(125, 32), grinding(125, 33), grinding(125, 8), grinding(125, 1)),
            (2, 2, 3, 0, 0)
        );
        assert_eq!(grinding(0, 1 << 30), 0);
        assert_eq!(Params::plain(22, 2, 10, 4).fold_grinding(0), 0);
    }

    #[test]
    fn an_opening_that_hides_verifies() {
        // A sum of the polynomial under weights and of the pads' under
        // theirs, opened with a polynomial that blinds.
        let mut rng = Rng(31);
        // Folded to a constant; sent with five variables left, after two
        // codewords; and sent where the blinding polynomial joins, after
        // the one.
        for (m, rate, last) in [(10, 1, 0), (13, 2, 0), (13, 2, 5), (10, 1, 8)] {
            let params = Params { last, ..Params::plain(m, rate, 8, 4).hiding() };
            assert_eq!(
                params.sent(),
                [(10, 3), (13, 4), (8, 2), (4, 1)]
                    [[(10, 0), (13, 0), (13, 5), (10, 8)].iter().position(|x| *x == (m, last)).unwrap()]
            );
            let domain = Domain::new(params.k(), true);
            let (f, weights) = (rng.fs(1 << m), rng.fs(1 << m));
            let (g, pads, pad_weights) = (rng.fs(1 << (m - 4)), rng.fs(1 << (m - 4)), rng.fs(1 << (m - 4)));
            let g_pads = rng.fs(1 << (m - 4));
            let com = commit_blind(&params, &domain, &f, &g, &pads, &g_pads);
            let sum = inner_product(&f, &weights) + inner_product(&pads, &pad_weights);
            let run = |sum: F, change: &dyn Fn(&mut Proof)| {
                let begin = || {
                    let mut tr = Challenger::new(b"hides");
                    tr.absorb(&com.tree.root());
                    tr
                };
                let blind =
                    Blind { g: &g, pads: &pads, g_pads: &g_pads, weights: pad_weights.clone(), good: &|_| true };
                let mut proof =
                    open_weighted(&params, &domain, &com, &f, weights.clone(), vec![], Some(blind), &mut begin());
                change(&mut proof);
                let root = com.tree.root();
                let (mut tr, mut opens) = (begin(), Batched::default());
                let plain = Domain::new(params.k(), false);
                let o =
                    verify_weighted(&params, &plain, (&root, halves(&root)), sum, &proof, &[], &mut tr, &mut opens)?;
                // The caller's part: the weights at the challenges.
                let scale = o.r[..4].iter().fold(F::ONE, |s, x| s * (F::ONE + *x)).square();
                let expect =
                    o.final_value * evaluate(&weights, &o.r) + o.pad_final? * scale * evaluate(&pad_weights, &o.r[4..]);
                // The last values sent are not the polynomials'.
                assert_ne!(o.final_value, evaluate(&f, &o.r));
                assert_ne!(o.pad_final?, evaluate(&pads, &o.r[4..]));
                (o.claim == expect).then_some(())
            };
            assert!(run(sum, &|_| {}).is_some(), "{m} variables");
            assert!(run(sum + F::ONE, &|_| {}).is_none());
            assert!(run(sum, &|p| p.blind_sum += F::ONE).is_none());
            assert!(run(sum, &|p| p.pad_blind_sum += F::ONE).is_none());
            assert!(run(sum, &|p| p.pad_final += F::ONE).is_none());
            assert!(run(sum, &|p| p.final_value += F::ONE).is_none());
            // (Moved from the one to the other, in any measure: each
            // is what its own codeword folds to.)
            for part in [F::ONE, F(2), F(0x1234_5678_9abc_def0)] {
                assert!(
                    run(sum, &|p| {
                        p.final_value += F::ONE;
                        p.pad_final += part;
                    })
                    .is_none()
                );
            }
            // The same of a prover that says so before the queries are
            // drawn.
            LIE.set(Some(|first, _, _, pads, theta| {
                *first += F(77);
                *pads += F(77) * theta.inv();
            }));
            let lied = run(sum, &|_| {});
            LIE.set(None);
            assert!(lied.is_none());
            assert!(run(sum, &|p| p.openings[0].leaves[0][16] += F::ONE).is_none());
            assert!(run(sum, &|p| p.openings[0].leaves[0][17] += F::ONE).is_none());
            assert!(run(sum, &|p| p.openings[0].leaves[0][18] += F::ONE).is_none());
            assert!(run(sum, &|p| p.openings[0].leaves[0][3] += F::ONE).is_none());
            if last > 0 {
                assert!(run(sum, &|p| p.last[1] += F::ONE).is_none());
                assert!(run(sum, &|p| _ = p.last.pop()).is_none());
            }
        }
    }

    #[test]
    fn a_proof_verifies() {
        for (m, rate, arity, last) in
            [(10, 2, 4, 0), (12, 5, 4, 0), (9, 1, 3, 0), (7, 3, 1, 0), (11, 2, 6, 0), (12, 2, 4, 5), (9, 1, 3, 9)]
        {
            let params = Params { last, ..Params::plain(m, rate, 12, arity) };
            let (domain, f, z, v) = setup(&params, 8 + m as u64);
            let com = commit(&params, &domain, &f);
            let proof = open(&params, &domain, &com, &f, &z, v);
            let plain = Domain::new(params.k(), false);
            let work = verify(&params, &plain, &com.tree.root(), &z, v, &proof);
            assert!(work.is_some(), "{params:?}");
            // Its bytes are it, and nothing less or more is.
            let bytes = proof.to_bytes();
            assert_eq!(Proof::from_bytes(&bytes).as_ref(), Some(&proof));
            assert_eq!(bytes.len(), proof.size());
            assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_none());
            assert!(Proof::from_bytes(&[&bytes[..], &[0]].concat()).is_none());
        }
    }

    #[test]
    fn a_ground_proof_verifies_and_an_unground_one_does_not() {
        // Grinding as the proven parameters have it, at a size a test
        // can afford: 20 bits a round where the field gives 108.
        let params = Params { queries: 12, query_grinding: 10, round_bits: 118, ..Params::plain(8, 2, 12, 4) };
        assert_eq!((params.fold_grinding(0), params.fold_grinding(7)), (0, 0));
        let params = Params { round_bits: 126, ..params };
        assert_eq!((params.fold_grinding(0), params.fold_grinding(7)), (8, 1));
        let (domain, f, z, v) = setup(&params, 12);
        let com = commit(&params, &domain, &f);
        let root = com.tree.root();
        let proof = open(&params, &domain, &com, &f, &z, v);
        assert!(verify(&params, &domain, &root, &z, v, &proof).is_some());
        assert!(proof.fold_nonces.iter().any(|n| *n != 0));
        // A nonce changed: the round is not ground, or every challenge
        // after it is another.
        let mut p = proof.clone();
        p.fold_nonces[0] ^= 1;
        assert!(verify(&params, &domain, &root, &z, v, &p).is_none());
        let mut p = proof.clone();
        p.query_nonce ^= 1;
        assert!(verify(&params, &domain, &root, &z, v, &p).is_none());
        // The same proof made without grinding does not pass for ground.
        let plain = Params { query_grinding: 0, round_bits: 0, ..params };
        let unground = open(&plain, &domain, &com, &f, &z, v);
        assert!(verify(&plain, &domain, &root, &z, v, &unground).is_some());
        assert!(verify(&params, &domain, &root, &z, v, &unground).is_none());
        assert!(verify(&plain, &domain, &root, &z, v, &proof).is_none());
    }

    #[test]
    fn a_wrong_proof_does_not() {
        let params = Params::plain(10, 2, 12, 4);
        let (domain, f, z, v) = setup(&params, 9);
        let com = commit(&params, &domain, &f);
        let root = com.tree.root();
        let good = open(&params, &domain, &com, &f, &z, v);
        let check = |z: &[F], v: F, p: &Proof| verify(&params, &domain, &root, z, v, p).is_some();
        assert!(check(&z, v, &good));
        // Another value, another point, another root.
        assert!(!check(&z, v + F::ONE, &good));
        let mut z2 = z.clone();
        z2[3] += F::ONE;
        assert!(!check(&z2, v, &good));
        assert!(!check(&z[..9], v, &good));
        let mut other = root;
        other[0] ^= 1;
        assert!(verify(&params, &domain, &other, &z, v, &good).is_none());
        // A proof made for another value.
        assert!(!check(&z, v + F::ONE, &open(&params, &domain, &com, &f, &z, v + F::ONE)));
        // Each part of the proof changed.
        let changed = |change: &dyn Fn(&mut Proof)| {
            let mut p = good.clone();
            change(&mut p);
            assert_ne!(p, good);
            check(&z, v, &p)
        };
        assert!(!changed(&|p| p.rounds[4].0 += F::ONE));
        assert!(!changed(&|p| p.rounds[9].1 += F::ONE));
        assert!(!changed(&|p| p.final_value += F::ONE));
        assert!(!changed(&|p| p.roots[0][0] ^= 1));
        assert!(!changed(&|p| p.fold_nonces[2] = 1));
        assert!(!changed(&|p| p.query_nonce = 1));
        assert!(!changed(&|p| p.openings.truncate(2)));
        assert!(!changed(&|p| _ = p.openings[0].leaves.pop()));
        assert!(!changed(&|p| p.rounds.truncate(9)));
        for t in 0..3 {
            assert!(!changed(&|p| p.openings[t].leaves[1][1] += F::ONE));
            if good.openings[t].siblings.len() > 1 {
                assert!(!changed(&|p| p.openings[t].siblings[0][0] ^= 1));
                assert!(!changed(&|p| p.openings[t].siblings.truncate(1)));
            }
            assert!(!changed(&|p| p.openings[t].leaves.swap(0, 1)));
        }
        // Parameters the proof was not made for.
        for other in [Params { queries: 11, ..params }, Params { arity: 2, ..params }, Params { m: 9, ..params }] {
            assert!(verify(&other, &domain, &root, &z[..other.m], v, &good).is_none());
        }
    }

    /// What a commitment, its opening and its verification cost at the
    /// proven parameters, the grinding among them.
    #[test]
    #[ignore = "timing; run with --release --nocapture"]
    fn proven_timing() {
        for (m, rate) in [(20, 2), (22, 2), (24, 2)] {
            // `SECURITY=126` to see what another level costs.
            let security = std::env::var("SECURITY").ok().and_then(|x| x.parse().ok()).unwrap_or(SECURITY);
            let params = Params::proven(m, rate, security);
            let (domain, f, z, v) = setup(&params, 13);
            let t = std::time::Instant::now();
            let com = commit(&params, &domain, &f);
            let committed = t.elapsed();
            let t = std::time::Instant::now();
            let proof = open(&params, &domain, &com, &f, &z, v);
            let opened = t.elapsed();
            // The same with nothing ground: the difference is the grinding.
            let plain = Params { query_grinding: 0, round_bits: 0, ..params };
            let t = std::time::Instant::now();
            let unground = open(&plain, &domain, &com, &f, &z, v);
            let opened_plain = t.elapsed();
            let t = std::time::Instant::now();
            let work = verify(&params, &domain, &com.tree.root(), &z, v, &proof).expect("the proof verifies");
            let verified = t.elapsed();
            let ground: usize = (0..m).map(|i| params.fold_grinding(i)).filter(|b| *b > 0).count();
            println!(
                "2^{m} elements, rate 1/{}, {} queries: commit {committed:.2?}, open {opened:.2?} \
                 ({:.2?} of it grinding, {ground} rounds and the queries), verify {verified:.2?}, \
                 {} KB (within {} bytes of unground), {} compressions",
                1 << rate,
                params.queries,
                opened.saturating_sub(opened_plain),
                proof.size() / 1000,
                proof.size().abs_diff(unground.size()),
                work.compressions,
            );
        }
    }

    /// Polynomials opened together, each at a point of its own: the
    /// first, and one joining at each of `rounds`.
    struct Together {
        params: Params,
        domain: Domain,
        rounds: Vec<usize>,
        f: Vec<Vec<F>>,
        z: Vec<Vec<F>>,
        v: Vec<F>,
        coms: Vec<Committed>,
    }

    impl Together {
        fn new(params: Params, rounds: &[usize], seed: u64) -> Together {
            let mut rng = Rng(seed);
            let domain = Domain::new(params.k(), true);
            let (mut f, mut z, mut v, mut coms) = (vec![], vec![], vec![], vec![]);
            for round in std::iter::once(0).chain(rounds.iter().copied()) {
                let g = rng.fs(1 << (params.m - round));
                let y = rng.fs(params.m - round);
                v.push(evaluate(&g, &y));
                coms.push(if round == 0 {
                    commit(&params, &domain, &g)
                } else {
                    commit_at(&params, &domain, &g, round)
                });
                f.push(g);
                z.push(y);
            }
            Together { params, domain, rounds: rounds.to_vec(), f, z, v, coms }
        }

        fn roots(&self) -> Vec<Digest> {
            self.coms.iter().map(|c| c.tree.root()).collect()
        }

        /// The opening, the prover answering with the polynomials `f`.
        fn open(&self, f: &[Vec<F>]) -> Proof {
            let mut tr = Challenger::new(b"together");
            let joiners = (1..f.len())
                .map(|i| Joiner {
                    com: &self.coms[i],
                    f: &f[i],
                    weights: eq_table(&self.z[i]),
                    round: self.rounds[i - 1],
                })
                .collect();
            open_weighted(
                &self.params,
                &self.domain,
                &self.coms[0],
                &f[0],
                eq_table(&self.z[0]),
                joiners,
                None,
                &mut tr,
            )
        }

        fn verify(&self, roots: &[Digest], v: &[F], proof: &Proof) -> bool {
            let mut tr = Challenger::new(b"together");
            let joined: Vec<Joined<F>> = (1..roots.len())
                .map(|i| Joined { root: &roots[i], at: halves(&roots[i]), target: v[i], round: self.rounds[i - 1] })
                .collect();
            let root = (&roots[0], halves(&roots[0]));
            let mut opens = Batched::default();
            let Some(Opening { r: rs, claim, thetas, .. }) =
                verify_weighted(&self.params, &self.domain, root, v[0], proof, &joined, &mut tr, &mut opens)
            else {
                return false;
            };
            let mut expect = proof.final_value * eq(&self.z[0], &rs);
            for (i, theta) in thetas.iter().enumerate() {
                expect += *theta * proof.joined_finals[i] * eq(&self.z[i + 1], &rs[self.rounds[i]..]);
            }
            claim == expect
        }
    }

    #[test]
    fn polynomials_are_opened_together() {
        for (m, rate, arity, rounds) in [
            (10, 2, 4, vec![4]),
            (9, 1, 3, vec![3]),
            (6, 2, 2, vec![2]),
            (13, 2, 4, vec![4, 4, 8]),
            (12, 1, 4, vec![8]),
            (9, 2, 2, vec![2, 4, 4, 6]),
        ] {
            let t = Together::new(Params::plain(m, rate, 12, arity), &rounds, 30 + m as u64);
            let roots = t.roots();
            let proof = t.open(&t.f);
            assert!(t.verify(&roots, &t.v, &proof), "{m} {rounds:?}");
            assert_eq!(Proof::from_bytes(&proof.to_bytes()).as_ref(), Some(&proof));
            // Any value wrong, any two roots traded.
            for i in 0..t.v.len() {
                let mut v = t.v.clone();
                v[i] += F::ONE;
                assert!(!t.verify(&roots, &v, &proof), "{m} {rounds:?} value {i}");
                let mut traded = roots.clone();
                traded.swap(i, (i + 1) % roots.len());
                assert!(!t.verify(&traded, &t.v, &proof), "{m} {rounds:?} root {i}");
            }
            // A proof with joiners is not one without, nor the other way.
            let mut tr = Challenger::new(b"together");
            let root = (&roots[0], halves(&roots[0]));
            let mut opens = Batched::default();
            assert!(verify_weighted(&t.params, &t.domain, root, t.v[0], &proof, &[], &mut tr, &mut opens).is_none());
            let alone = Together::new(t.params, &[], 30 + m as u64);
            assert!(!t.verify(&roots, &t.v, &alone.open(&alone.f)));
        }
    }

    #[test]
    fn a_wrong_joiner_is_caught() {
        let t = Together::new(Params::plain(13, 2, 4, 4), &[4, 4, 8], 31);
        let roots = t.roots();
        let good = t.open(&t.f);
        let changed = |change: &dyn Fn(&mut Proof)| {
            let mut p = good.clone();
            change(&mut p);
            assert_ne!(p, good);
            t.verify(&roots, &t.v, &p)
        };
        for j in 0..3 {
            assert!(!changed(&|p| p.joined_finals[j] += F::ONE), "joiner {j}");
            assert!(!changed(&|p| {
                // Moved from one polynomial to another: the constant the
                // codewords fold to is no longer theirs.
                p.final_value += F::ONE;
                p.joined_finals[j] += F::ONE;
            }));
            assert!(!changed(&|p| p.joined_openings[j].leaves[3][0] += F::ONE));
            assert!(!changed(&|p| p.joined_openings[j].siblings[0][0] ^= 1));
            assert!(!changed(&|p| _ = p.joined_openings[j].leaves.pop()));
            assert!(!changed(&|p| p.joined_openings[j].leaves.swap(0, 1)));
            assert!(!changed(&|p| p.joined_openings[j] = Batch::default()));
            // The prover answers for another polynomial than the one
            // committed: its sumcheck is honest, its codeword is not.
            let mut f = t.f.clone();
            f[j + 1][5] += F::ONE;
            let mut v = t.v.clone();
            v[j + 1] = evaluate(&f[j + 1], &t.z[j + 1]);
            assert!(!t.verify(&roots, &v, &t.open(&f)), "joiner {j} lied about");
        }
        assert!(!changed(&|p| p.joined_openings.swap(0, 1)));
        // A prover that moves something from the first polynomial's
        // last value to a joiner's, so that the two together are what
        // they were under the challenge that joined them: one codeword
        // of the two would fold to that all the same, whatever the
        // queries. The opening refuses it, before anything is made of
        // the claim. (All of them joiner 0: a function has no `j`.)
        let opened = |p: &Proof| {
            let mut tr = Challenger::new(b"together");
            let joined: Vec<Joined<F>> = (1..roots.len())
                .map(|i| Joined { root: &roots[i], at: halves(&roots[i]), target: t.v[i], round: t.rounds[i - 1] })
                .collect();
            let root = (&roots[0], halves(&roots[0]));
            verify_weighted(&t.params, &t.domain, root, t.v[0], p, &joined, &mut tr, &mut Batched::default())
        };
        assert!(opened(&good).is_some());
        LIE.set(Some(|first, joined, thetas, _, _| {
            *first += F(77);
            joined[0] += F(77) * thetas[0].inv();
        }));
        let lied = t.open(&t.f);
        LIE.set(None);
        assert_ne!(lied, good);
        assert!(opened(&lied).is_none());
        assert!(!changed(&|p| p.joined_finals.swap(0, 1)));
        assert!(!changed(&|p| _ = p.joined_finals.pop()));
        assert!(!changed(&|p| p.join_nonces[0] = 1));
    }

    #[test]
    fn a_codeword_of_another_polynomial_is_caught() {
        // The prover commits to f, then answers for g: the sumcheck is
        // g's and honest, the codeword is not g's.
        let params = Params::plain(10, 2, 12, 4);
        let (domain, f, z, _) = setup(&params, 10);
        let com = commit(&params, &domain, &f);
        let mut g = f.clone();
        g[77] += F::ONE;
        let v = evaluate(&g, &z);
        let proof = open(&params, &domain, &com, &g, &z, v);
        assert!(verify(&params, &domain, &com.tree.root(), &z, v, &proof).is_none());
    }
}
