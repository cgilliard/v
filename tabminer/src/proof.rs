//! A proof of a compiled computation, whole: the tables it is of, what
//! a verifier needs beside it, and its verification, by the field or as
//! rows of another computation.
//!
//! A computation is rows of the hash table ([`crate::recursion`]) and of
//! the machine ([`crate::machine`]), and may have tables of chains
//! beside them ([`crate::wots`]). They are proven together
//! ([`crate::argument`]), in the order of their sizes; the machine's
//! public value is what the proof is of ([`crate::alg::Shared::state`]).

use crate::alg::{Compiler, Hashed, HashedOpens, Shared, Sym, halves};
use crate::argument::{self, Layout, Part, Program, Proof, Table, prove_hiding, prove_tables, verify_tables};
use crate::circuit::{Circuit, Fixed, Witness};
use crate::field::F;
use crate::hash::Digest;
use crate::ntt::Domain;
use crate::pcs::Params;
use crate::reading::Reader;
use crate::wots::Chains;
use crate::{machine, recursion, wots};

/// What a table is of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Chains,
    Hashes,
    Machine,
    Numbers,
    /// The proof of work's two tables ([`crate::work`]).
    Steps,
    Mix,
}

/// The circuits, made once: whoever reads them for several proofs
/// ([`crate::reading`]) knows a circuit by where it lies.
pub struct Circuits {
    pub chains: Circuit,
    pub hashes: Circuit,
    pub machine: Circuit,
    pub numbers: Circuit,
    pub steps: Circuit,
    pub mix: Circuit,
}

impl Default for Circuits {
    fn default() -> Circuits {
        Circuits::new()
    }
}

impl Circuits {
    pub fn new() -> Circuits {
        Circuits {
            chains: wots::circuit(),
            hashes: recursion::circuit(),
            machine: machine::circuit(),
            numbers: crate::arith::circuit(),
            steps: crate::work::circuit(),
            mix: crate::work::mix::circuit(),
        }
    }

    pub fn of(&self, kind: Kind) -> &Circuit {
        match kind {
            Kind::Chains => &self.chains,
            Kind::Hashes => &self.hashes,
            Kind::Machine => &self.machine,
            Kind::Numbers => &self.numbers,
            Kind::Steps => &self.steps,
            Kind::Mix => &self.mix,
        }
    }

    pub fn all(&self) -> [&Circuit; 6] {
        [&self.chains, &self.hashes, &self.machine, &self.numbers, &self.steps, &self.mix]
    }
}

/// A proof, with what a verifier needs beside it.
pub struct Proved {
    pub params: Params,
    /// The root of the tables' programs.
    pub program: Digest,
    pub proof: Proof,
    /// The tables, in the proof's order: what each is and its rows.
    pub tables: Vec<(Kind, usize)>,
    /// The machine's public values: the statement's digest, as words.
    pub public: Vec<u32>,
    /// Whether the machine's assertions held when the rows were made: a
    /// proof of rows that do not hold does not verify.
    pub holds: bool,
    /// The machine's rows that are not there to fill it.
    pub used: usize,
    pub proving: std::time::Duration,
}

/// The proof of what was compiled in `cx`, with the chains' tables
/// beside it (the largest first), under the parameters `params` gives
/// for the size of the whole.
pub fn prove(cx: Shared, chains: Vec<Chains>, params: impl Fn(usize) -> Params) -> Proved {
    prove_at(cx, chains, params, [128, 128])
}

/// The root of the programs of what was compiled in `cx`, were it
/// proven by [`prove_at`]: for a computation that names its own
/// program, which is the same whatever values it is run on.
pub fn program_of(cx: Shared, params: impl Fn(usize) -> Params, at_least: [usize; 2]) -> Digest {
    let circuits = Circuits::new();
    let Compiler { asm, trace, arith, .. } = cx.finish();
    assert!(arith.is_empty(), "a computation with numbers has a table more");
    let machine_rows = asm.finish(at_least[1]);
    let (hash_rows, hash_program) = trace.finish(at_least[0].max(machine_rows.inputs.len() / 8));
    let tables = [(&circuits.hashes, hash_rows.len()), (&circuits.machine, machine_rows.inputs.len())];
    let layout = Layout::of(tables.iter().copied()).expect("the hash table is the larger");
    let params = params(layout.total);
    let domain = Domain::new(params.k(), true);
    Program::of(&params, &domain, &tables, vec![hash_program, machine_rows.program]).root()
}

/// [`prove`], with the hash table and the machine filled to `at_least`
/// rows: for proofs that are to be of one shape whatever they hold.
pub fn prove_at(cx: Shared, chains: Vec<Chains>, params: impl Fn(usize) -> Params, at_least: [usize; 2]) -> Proved {
    prove_with(cx, chains, None, params, at_least)
}

/// [`prove_at`], with the tables of a header's work beside the rest.
pub fn prove_with(
    cx: Shared,
    chains: Vec<Chains>,
    work: Option<crate::work::Work>,
    params: impl Fn(usize) -> Params,
    at_least: [usize; 2],
) -> Proved {
    prove_all(cx, chains, work, params, at_least, None)
}

/// [`prove_at`], for a proof that says nothing of the computation but
/// its statement ([`crate::hidden`]): the parameters are `params`' made
/// hiding, and `seed` is where what is random in the proof comes from,
/// to be random itself and used for nothing else. The machine's rows
/// must be enough for the pads: 2^15 are.
pub fn prove_hidden(cx: Shared, params: impl Fn(usize) -> Params, at_least: [usize; 2], seed: [u8; 32]) -> Proved {
    prove_all(cx, Vec::new(), None, |m| params(m).hiding(), at_least, Some(seed))
}

fn prove_all(
    cx: Shared,
    chains: Vec<Chains>,
    work: Option<crate::work::Work>,
    params: impl Fn(usize) -> Params,
    at_least: [usize; 2],
    seed: Option<[u8; 32]>,
) -> Proved {
    let circuits = Circuits::new();
    let Compiler { asm, trace, arith, .. } = cx.finish();
    let numbers = (!arith.is_empty()).then(|| arith.finish(128));
    let machine_rows = asm.finish(at_least[1]);
    let used = machine_rows.program.chunks(machine::PROGRAM).filter(|p| p[3] & 4 == 0).count();
    let chains: Vec<_> = chains.into_iter().map(|c| c.finish(128)).collect();
    // The hash table is not smaller than the machine: its rows are
    // eight of the machine's.
    let (hash_rows, hash_program) = trace.finish(at_least[0].max(machine_rows.inputs.len() / 8));
    let k = chains.len();
    let mut kinds: Vec<Kind> = (0..k).map(|_| Kind::Chains).chain([Kind::Hashes, Kind::Machine]).collect();
    let rows: Vec<usize> =
        chains.iter().map(|c| c.0.len()).chain([hash_rows.len(), machine_rows.inputs.len()]).collect();
    let mut rows = rows;
    if let Some((number_rows, _)) = &numbers {
        kinds.push(Kind::Numbers);
        rows.push(number_rows.len());
    }
    if let Some(work) = &work {
        kinds.extend([Kind::Steps, Kind::Mix]);
        rows.extend([work.steps.0.len(), work.mix.0.len()]);
    }
    // Largest first.
    let mut order: Vec<usize> = (0..kinds.len()).collect();
    order.sort_by_key(|i| std::cmp::Reverse(rows[*i] << circuits.of(kinds[*i]).log_cols));
    let tables: Vec<(&Circuit, usize)> = order.iter().map(|i| (circuits.of(kinds[*i]), rows[*i])).collect();
    let layout = Layout::of(tables.iter().copied()).expect("tables in the order of their sizes");
    let params = params(layout.total);
    let domain = Domain::new(params.k(), true);
    let program_of = |i: usize| match kinds[i] {
        Kind::Chains => chains[i].1.clone(),
        Kind::Hashes => hash_program.clone(),
        Kind::Machine => machine_rows.program.clone(),
        Kind::Numbers => numbers.as_ref().expect("a table of numbers").1.clone(),
        Kind::Steps => work.as_ref().expect("the work's tables").steps.1.clone(),
        Kind::Mix => work.as_ref().expect("the work's tables").mix.1.clone(),
    };
    let program = Program::of(&params, &domain, &tables, order.iter().map(|i| program_of(*i)).collect());
    let public = |i: usize| -> &[u32] { if kinds[i] == Kind::Machine { &machine_rows.public } else { &[] } };
    let fixed: Vec<Fixed> =
        order.iter().enumerate().map(|(at, i)| Fixed { program: &program.words[at], public: public(*i) }).collect();
    let t = std::time::Instant::now();
    let parts: Vec<Part> = (order.iter().enumerate())
        .map(|(at, i)| {
            let (i, n) = (*i, rows[*i]);
            let circuit = circuits.of(kinds[i]);
            let witness = match kinds[i] {
                Kind::Chains => Witness::new(circuit, n, |c| wots::run(c), |r| chains[i].0[r], &fixed[at]),
                Kind::Hashes => Witness::new(circuit, n, |c| _ = recursion::row(c), |r| hash_rows[r], &fixed[at]),
                Kind::Machine => Witness::new(circuit, n, |c| machine::run(c), |r| machine_rows.inputs[r], &fixed[at]),
                Kind::Numbers => {
                    let number_rows = &numbers.as_ref().expect("a table of numbers").0;
                    Witness::new(circuit, n, |c| crate::arith::run(c), |r| number_rows[r], &fixed[at])
                }
                Kind::Steps => {
                    let step_rows = &work.as_ref().expect("the work's tables").steps.0;
                    Witness::new(circuit, n, |c| crate::work::run(c), |r| step_rows[r], &fixed[at])
                }
                Kind::Mix => {
                    let mix_rows = &work.as_ref().expect("the work's tables").mix.0;
                    Witness::new(circuit, n, |c| crate::work::mix::run(c), |r| mix_rows[r], &fixed[at])
                }
            };
            Part { circuit, witness, public: public(i) }
        })
        .collect();
    let (proof, _) = match seed {
        Some(seed) => prove_hiding(&params, &domain, parts, Some(&program), seed),
        None => prove_tables(&params, &domain, parts, Some(&program)),
    };
    Proved {
        params,
        program: program.root(),
        proof,
        tables: order.iter().map(|i| (kinds[*i], rows[*i])).collect(),
        public: machine_rows.public.clone(),
        holds: machine_rows.holds,
        used,
        proving: t.elapsed(),
    }
}

impl Proved {
    fn tables<'a>(&'a self, circuits: &'a Circuits) -> Vec<Table<'a>> {
        let public = |kind: Kind| -> &[u32] { if kind == Kind::Machine { &self.public } else { &[] } };
        self.tables
            .iter()
            .map(|(kind, rows)| Table { circuit: circuits.of(*kind), rows: *rows, public: public(*kind) })
            .collect()
    }

    /// Whether the proof verifies, for its program and its statement.
    pub fn verifies(&self) -> bool {
        let circuits = Circuits::new();
        let domain = Domain::new(self.params.k(), false);
        verify_tables(&self.params, &domain, &self.tables(&circuits), Some(&self.program), &self.proof).is_some()
    }

    /// The proof's verification, made rows of `cx`: what it was verified
    /// against and what it was of, as the arithmetic holds them (the
    /// programs' root, then the statement's digest). `reader` reads
    /// `circuits`. `None` if the verifier turns the proof away before
    /// it has made its rows.
    pub fn verify_into(&self, cx: &Shared, circuits: &Circuits, reader: &mut impl Reader<Sym>) -> Option<Vec<Sym>> {
        let domain = Domain::new(self.params.k(), false);
        let (mut tr, mut opens) = (Hashed::new(argument::LABEL, cx), HashedOpens::new(cx));
        let tables = self.tables(circuits);
        let program = Some(&self.program);
        let taken = argument::check_with::<Sym, _, _, _>(
            &self.params,
            &domain,
            &tables,
            program,
            &self.proof,
            &mut tr,
            &mut opens,
            reader,
        )?;
        let publics = taken.publics.into_iter().flatten().flatten();
        Some(taken.program.into_iter().flatten().chain(publics).collect())
    }

    /// What [`Proved::verify_into`] gives, by the field.
    pub fn verified(&self) -> Vec<F> {
        halves(&self.program).into_iter().chain(halves(&self.statement())).collect()
    }

    /// The statement's digest: the machine's public value.
    pub fn statement(&self) -> Digest {
        crate::blake3::bytes(&std::array::from_fn::<u32, 8, _>(|i| self.public[i]))
    }

    /// Rows of the tables of `kind`.
    pub fn rows(&self, kind: Kind) -> Vec<usize> {
        self.tables.iter().filter(|(k, _)| *k == kind).map(|(_, rows)| *rows).collect()
    }

    /// Bytes of the proof.
    pub fn size(&self) -> usize {
        self.proof.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reading::Direct;

    /// A computation with something to hide: a value, hashed; the hash
    /// is what it states.
    fn secret(value: u128) -> Shared {
        let cx = Shared::new();
        let x = cx.input(F(value));
        let square = x.clone() * x.clone() + x.clone();
        let digest = cx.hashed(crate::hash::DOM_STATEMENT, &[x, square]);
        cx.state(&digest);
        cx
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow unoptimized")]
    fn a_proof_that_hides_is_verified_by_a_computation() {
        let params = |m: usize| Params::plain(m, 1, 4, 4);
        let hidden = prove_hidden(secret(77), params, [1 << 11, 1 << 15], [9; 32]);
        assert!(hidden.params.blind && hidden.holds && hidden.verifies());
        // Another value's proof states another hash; the same value's,
        // from another seed, is another proof of the same statement.
        let other = prove_hidden(secret(78), params, [1 << 11, 1 << 15], [9; 32]);
        let again = prove_hidden(secret(77), params, [1 << 11, 1 << 15], [10; 32]);
        assert_ne!(hidden.statement(), other.statement());
        assert_eq!(hidden.statement(), again.statement());
        assert_ne!(hidden.proof, again.proof);
        // Its verification, as rows: proven in turn, of the same program
        // and statement.
        let circuits = Circuits::new();
        let cx = Shared::new();
        let of = hidden.verify_into(&cx, &circuits, &mut Direct).expect("the verifier takes it");
        assert_eq!(of.iter().map(Sym::value).collect::<Vec<F>>(), hidden.verified());
        cx.state(&of);
        let outer = prove(cx, vec![], params);
        assert!(outer.holds && outer.verifies());
        assert_eq!(outer.statement(), crate::alg::statement(&hidden.verified()));
        // A proof changed is not verified by rows that hold.
        let mut bad = Proved {
            proof: hidden.proof.clone(),
            tables: hidden.tables.clone(),
            public: hidden.public.clone(),
            ..hidden
        };
        bad.proof.hidden.extra[40] += F::ONE;
        assert!(!bad.verifies());
        let cx = Shared::new();
        let held = match bad.verify_into(&cx, &circuits, &mut Direct) {
            None => false,
            Some(of) => {
                cx.state(&of);
                prove(cx, vec![], params).holds
            }
        };
        assert!(!held);
    }
}
