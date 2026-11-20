# Soundness

What the proofs of this crate are claimed to show, what each claim rests
on, and how far each has been checked. It is written to be reviewed:
every statement carries one of four marks.

| mark | means |
|---|---|
| **[T]** | a published theorem, whose statement was read in the source for this document |
| **[t]** | a published theorem relied on from memory of the paper: the source could not be fetched here |
| **[D]** | derived in this document or in the code's comments: short enough to check by hand |
| **[N]** | checked numerically by a test in the crate, not proven |
| **[A]** | an assumption |

Zero knowledge has a document of its own, `ZK.md`. The signature scheme
is at the end of this one.

## 1. The claim

A proof is non-interactive: the challenges are hashes of the transcript
(Fiat-Shamir). The claim is in the random oracle model **[A]**, with
Blake3 for the oracle, in the form usual for hash-based proofs:

> Every round of the interactive protocol is *round-by-round sound*
> with error at most `2^-125`: whatever the transcript so far, if the
> claim it carries is false, the next challenge makes it true with
> probability at most `2^-125`, or `2^-125` after the grinding counted
> for that round.

From this a prover that makes `2^t` hash calls convinces the verifier of
a false statement with probability at most about `2^(t - 125)`, plus
`2^(2t - 256)` for a collision of 256-bit digests **[t]** (the
transformation of Ben-Sasson, Chiesa and Spooner, and its
round-by-round form by Chiesa, Manohar and Spooner). That is what "124
bits" means here: `pcs::SECURITY = 124`, `round_bits = 125`.

Two things are part of that convention and should be read as such.

- **Grinding counts as security.** Where a round's error is
  `n / 2^128` for an `n` that grows with the table, the prover must
  find a nonce whose hash has `b` zero bits before the challenge is
  drawn, and the round is counted as `2^-b` times better. This is an
  argument about work, not probability **[A]**: a cheating prover pays
  `2^b` hashes for each fresh challenge it wants to try.
- **Classical.** Against a quantum attacker the hash's collision
  resistance is lower (about `2^85` by the best known algorithm, which
  needs memory nobody has) and Grover halves the bits of each search.
  No quantum figure is claimed for the proofs.

## 2. The commitment and its opening (`pcs.rs`)

The polynomial's `2^m` values are the message of a Reed-Solomon code
in the additive (novel polynomial) basis of Lin, Chung and Han, rate
`2^-R`; the commitment is the Merkle root of the codeword. The opening
is BaseFold's: a sumcheck of `sum f w` whose challenges also fold the
codeword, as in Diamond and Posen's FRI-Binius.

| round | error | basis |
|---|---|---|
| a sumcheck round, degree 2 | `2 / 2^128` | **[D]** Schwartz-Zippel |
| a folding round, on a codeword of `n` entries | `n / 2^128`, ground to `2^-125` | below |
| a smaller polynomial joining | `n / 2^128`, ground | below |
| the queries | `((1 + rho) / 2)^q`, with `q` queries and their grinding | below |
| the Merkle trees | binding, by collision resistance | **[A]** |

**Folding.** What is needed is a proximity gap: if the folded word is
within the unique-decoding radius of the code, then, except with small
probability over the challenge, the word folded was too, and agrees
with its codeword where the fold does.

- For one challenge on a line `u_0 + z u_1`, and distance below half
  the minimum, the exceptional probability is at most `n / q` for a
  Reed-Solomon code of length `n` over a field of `q` elements **[T]**
  (Ben-Sasson, Carmon, Ishai, Kopparty and Saraf, *Proximity Gaps for
  Reed-Solomon Codes*, Theorem 1.2, the unique decoding bound, and
  Theorem 1.4 for the agreement; ECCC TR20-083).
- The fold here is not a line in one challenge. Between two committed
  codewords there are four rounds, each with its own challenge: the
  fold is the *tensor* combination of sixteen rows. Diamond and Posen
  introduced the gap for tensor combinations (*Proximity Testing with
  Logarithmic Randomness*, Theorem 2: for any code, up to a third of
  the minimum distance, with twice the line's error a challenge)
  **[T]**. Diamond and Gruen, with an argument of Angeris, Evans and
  Roh, sharpen it to what is needed here: a Reed-Solomon code of
  length `n` over any domain has the gap for tensor combinations of
  `2^l` rows up to *half* the minimum distance, with error `l n / q`
  **[T]** (*Proximity Gaps in Interleaved Codes*, Corollary 1, from
  its Theorems 1 to 3; the induction of Theorem 3 charges `n / q` for
  each challenge).
- That folding four times with no codeword committed between reduces
  to this gap is the FRI-Binius paper's (Diamond and Posen,
  *Polylogarithmic Proofs for Multilinears over Binary Towers*,
  Theorem 3.16 as the paper above cites it) **[t]**. I could not fetch
  that paper to read the reduction itself.

What the code counts is one round at a time: round `i` folds a codeword
of `n_i = 2^(k - i)` entries, is charged `n_i / 2^128`, and is ground
for the bits that falls short of 125. Against the bound above: the rows
of a step are words of the code it folds *to*, of length `n' = n / 16`,
so each of the step's four challenges errs with at most `n' / q`. The
code charges them `n/q`, `n/(2q)`, `n/(4q)` and `n/(8q)`: each at
least twice what the bound asks **[D]**. The grinding could be a bit
or more less; it is left as it is.

**Joining.** A polynomial that joins has its codeword added to the
folded one under a fresh challenge: a line, with the error `n / q`
above **[T]**, ground as a fold. The programs' polynomial, the blinding
polynomial and the pads' join this way.

**Queries.** If the first codeword is farther than half the minimum
distance from every codeword that folds rightly, a query finds it out
with probability at least `(1 - rho) / 2` **[D]** from the gap, so
passes with at most `(1 + rho) / 2`: `1 - log2(1 + rho)` bits a query,
tabulated as `QUERY_MICROBITS` so that no floating point decides a
parameter. At rate 1/4: 155 queries are 105.1 bits, and 20 bits are
ground before they are drawn, for 125.

**The polynomial sent.** Once 256 values are left the folded polynomial
is sent, not committed. The verifier checks that it is what the
sumcheck's challenges make of it, and that each query's last leaf folds
to its codeword at the query's point. A polynomial sent is its own
codeword exactly, so this replaces the last trees with nothing lost
**[D]**.

**The sum.** With the folding and the queries, the first codeword is
within unique decoding of one polynomial `f`, and the value the
verifier ends with is `f` at the challenges; the sumcheck then shows
the sum **[t]** (BaseFold; FRI-Binius for this code).

## 3. The argument (`argument.rs`, `grand.rs`, `structure.rs`)

Its rounds and their errors are tabulated in `argument.rs`. Each is one
of the following.

| step | statement | error | basis |
|---|---|---|---|
| zerocheck | `A & B = C` on every bit: `sum eq(tau, x)(A B + C)(x) = 0` | `n / 2^128` for `tau` (ground); `2 / 2^128` a round | **[D]** Schwartz-Zippel on a multilinear in `tau`; sumcheck |
| multiplications | `x y = z` in the field, the same way | as above | **[D]** |
| bus | the multiset sent is the multiset received | `(elements in all tuples) / 2^128`, ground | **[D]** two different multisets of tuples give products that differ as polynomials in the two challenges |
| grand product | each product is the leaves' | `2 / 2^128` a round, `1 / 2^128` a batching and a line | **[t]** GKR on a product tree, as in Thaler |
| claims to one point | every claim about the words, at one point | `2 / 2^128` a round, `8 / 2^128` for the batching | **[D]** |
| ring switching | the words' bits at a point, from the packed elements | `(126 + 2 tables) / 2^128`, ground | below |

**Ring switching** is Diamond and Posen's idea **[t]** in a form of our
own **[D]**. The prover sends 128 sums `s_b`; their bits read the other
way are 128 claims about the packed polynomial, which a challenge
batches. Theirs batches in the tensor algebra. Ours batches with the
map `phi(y) = sum_t omega^t y^(2^t)`, chosen because a circuit can
compute it without reading a bit. The lemma needed is that if the 128
claims are not all true, the weighted sum of what they are off by is a
nonzero polynomial in `omega` of degree at most 127: the matrix of the
powers `(x^c)^(2^t)` is invertible (a Moore matrix of a basis). It is
stated in `argument.rs` at `phi` and is short, but it is ours and has
been checked by nobody else.

**Several tables** share the bus's challenges and one opening; each
table's part of the opening is scaled by a power of a challenge inside
the map, counted in the ring switching's error.

**The statement** (the commitment, the programs' root, the public
values) begins the transcript, so every challenge depends on it.

## 4. A verifier that is a circuit (`alg.rs`, `machine.rs`, `recursion.rs`)

A proof that verifies another runs the *same* verifier code over
values of a machine, each operation a row. Two things are claimed.

- **The rows compute what the code computes** **[D]**, by construction:
  there is one verifier, generic over its arithmetic. What differs is
  hashing (rows of the hash table, tied to the machine by the bus) and
  reading the circuits' constraints (`reading.rs`: a sparse sumcheck
  inside the circuit, error `2 / 2^128` a round).
- **Composition** needs more than soundness. A proof that a verifier
  accepted says there *is* an inner proof, so one needs to extract it:
  knowledge soundness, which these protocols have in the random oracle
  model **[t]**. But the inner verifier's hash is then computed by a
  circuit, which an oracle cannot be. This is the standard gap of every
  recursive hash-based proof and is an assumption here too **[A]**.

**A step that names its own program** (`chain.rs`): the step takes its
program's root as an input, states it, and requires the step before to
have stated the same. Whoever verifies the last proof checks that the
root stated is the root verified against. By induction every step was
of that program or of the genesis program **[D]**.

## 5. Hiding proofs

`ZK.md`. For soundness the changes are: every value is defined as what
was sent plus a committed pad, so it is fixed when sent **[D]**; the
checks become equations, batched with error `n / 2^128` (ground)
**[D]**; a product of two unknown values is shown by an identity in a
challenge of degree 2, error `2 / 2^128` a product (ground for their
number) **[D]**; the ring switching's 128 terms are sent and batched,
error `127 / 2^128` (ground) **[D]**; and two more polynomials join the
opening, each a line **[T]**.

## 6. The circuits

A proof shows that rows satisfy a circuit. That the circuit says what
is meant is a separate matter, and the weakest kind of evidence here:

- Each table has tests that prove honest rows and reject changed ones,
  and that compare what a proof states with the rules computed natively
  (`ledger.rs`, `name.rs`, `policy.rs`, `pow.rs`, `xmss.rs`) **[N]**.
- No circuit has a written proof that its constraints imply the rule,
  and a test cannot show that nothing else satisfies them. The
  transaction table (64 kinds of row, 1,565 constraints) is the largest
  such risk.

## 7. The signature scheme (`xmss.rs`)

XMSS with WOTS+ at `w = 16`, over Blake3, with two departures from the
published scheme. Security is existential unforgeability under chosen
messages, for a signer that never uses a leaf twice.

| part | what a forger must do | rests on |
|---|---|---|
| message digest: `H(seed, leaf, height, randomizer, message)` | for a message not signed, hit the digest of one that was, under a randomizer it sees only with the signature | second-preimage resistance **[A]** |
| WOTS chains: each step a keyed hash whose key is its place (seed, leaf, chain, step) | go *backwards* along a chain: the checksum makes any other digest need at least one such step | preimage resistance of each step, each under a key of its own, so many keys are not many chances **[t]** (the tweakable-hash analysis of SPHINCS+) |
| leaf: three hashes of the 67 chain ends, each after the seed, the leaf's index and the tree's height | other chain ends with the same leaf | second-preimage resistance **[A]** |
| tree nodes: the hash of two children, nothing else | another pair of children for a node of an honest tree | second-preimage resistance with as many targets as there are nodes in all trees **[D]** |
| secret chain starts, randomizer: keyed hashes of the secret seed under public keys | tell them from random | Blake3 as a random function of its input **[A]** |

**The departures.**

1. *Chain steps are tweaked, not masked* (as SPHINCS+, not as RFC 8391):
   a published variant.
2. *Tree nodes are not tweaked.* In the published scheme a node is
   hashed with its place in its tree, so that a forger aiming at any of
   `T` nodes gains nothing. Here it gains a factor `T`: with `2^60`
   nodes in existence, a second preimage costs `2^196` and not `2^256`.
   What the place also did was keep one tree's inner node from passing
   as another key's root or leaf. That is restored by the leaf's hash,
   which begins with the seed, the leaf's index and the height: a
   signature verifies for one leaf of one key of one height **[D]**.
   The reason for the departure is cost: an untweaked node is one
   compression in the circuit.

**In the circuit** (`wots.rs`, `signature.rs`) the same hashes are
recomputed, and tests compare the two **[N]**.

**Not claimed:** security if a leaf is reused (the scheme is stateful);
a quantum figure (Grover gives about `2^128` for the preimages, less by
the targets for tree nodes).

## 8. Open

1. The reduction from four folds without a codeword between to the
   tensor gap (**[t]** in section 2) is the FRI-Binius paper's, which
   I could not fetch. The gap itself, at half the distance, was read
   in its source.
2. The ring-switching lemma in its `phi` form is ours.
3. The sumcheck-and-fold soundness of the opening is cited, not
   re-derived for this code's arrangement (four rounds a step, joiners,
   the polynomial sent early).
4. No circuit has a proof that it says what is meant.
5. The recursion's random-oracle gap is the usual one, and is assumed.
6. `ZK.md` is a new construction.
