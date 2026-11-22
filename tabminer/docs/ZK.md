# Zero knowledge

A chain's proof is published. It is a proof of a computation that
verified two other proofs (the block's and the chain's before), and
those came of proofs of signatures and transactions. So it must say
nothing of what it verified beyond its statement: `prove_hidden` in
`src/proof.rs`, by `src/hidden.rs`, `src/argument.rs` and `src/pcs.rs`.
Only the published proof pays for it. The proofs beneath are verified
inside it and never seen.

This is a construction made for this argument, not one taken from a
paper. Its parts are standard (one-time pads on a transcript whose
checks are linear, a sigma protocol for products, a random polynomial
added before a low-degree test), but the arrangement is ours, and so are
two things forced by the code and the field: where the randomness can
live, and how the ring switching is hidden.

## What is claimed

Honest-verifier zero knowledge, statistical, for the interactive
protocol; so zero knowledge in the random oracle model once the
challenges are hashes, as they are. The simulator is given the statement
(the tables' sizes, the programs' root, the public values) and nothing
of the witness, and makes a transcript distributed as a real one, up to
a distance of about `2^-100` (the terms are counted below).

Soundness is the argument's as before, with a few rounds more
(`src/argument.rs`, the table of rounds).

## Where a prover can put randomness

Three facts decide everything.

**A second polynomial costs little.** Beside the witness's polynomial
the prover commits to two random ones, each a sixteenth its size: one
that blinds the opening, and the *pads*. Neither has a tree of its own:
their codewords' entries are a seventeenth and an eighteenth element of
each leaf of the first tree.

**The witness has spare room, and it is not for pads.** A row is
`2^log_cols` words and a circuit seldom uses them all: the hash table
uses 511 of 512. No constraint reads a row's last word, so packed, bit
`j` of that word over 128 rows is a field element the prover may set as
it likes. But such an element is still bits of a table, and a table's
own sums run over all its bits: the 128 sums of the ring switching, the
later rounds over a row's bits, the words' value at the point. A pad
kept there would be a part of the values that pads are added to. What
is sent would be the pads under a map that is the identity plus
something random, and such a map fails to be onto about as often as
not: a few bits about the witness would show. So the spare word holds
only what is added to nothing: the corners and the leaves' cover,
below.

**The code is triangular.** The codeword's entry `i` depends only on the
polynomial's values at places up to about `i`: the basis polynomial of
place `j` vanishes on the first `2^t` points of the domain whenever `j`
has a bit at or above `t`. So what hides a leaf of the witness's
codeword must lie *before* it in the polynomial, in the first table.
This is why the leaves' cover needs the rule below.

## The parts

### 1. Pads on everything sent before the opening

Every field element the prover sends before the opening is sent with a
pad added, each pad used once: the rounds of every sumcheck, the
operands at their points, the grand products' values, the claims' sums,
the 128 sums of the ring switching. What is sent is then uniform and
independent of the witness, for the pads are in no table.

The verifier never learns a value. It holds each as *what was sent plus
a pad*: an affine form over pads it does not know (`Masked`). The
verifier's code is written over any arithmetic, so it runs unchanged on
these forms: adding two, or multiplying one by a challenge or a constant,
gives a form. Where it would check `a = b`, it now keeps the equation
`a - b = 0` over the pads. One thing is sent as it is: the programs'
part of the opening's sum, which anyone can work out.

At the end a challenge `xi` batches every equation, together with what
the ring switching leaves the opening to show (itself a form), into one
claim: a sum of the witness's polynomial under the ring switching's
weights and of the pads' polynomial under what the equations make its
weights. The opening shows that one sum, and so all the equations.

*Soundness.* The pads are committed before any challenge, so a value
defined as "sent plus pad" is fixed at the moment it is sent, as a value
sent in the clear would be. The protocol is the old one with every check
postponed. A false equation survives the batching with probability
`n / 2^128` for `n` equations, which is ground.

### 2. Products

A few checks multiply two values the verifier does not know: each
zerocheck's `a b + c`, the two children at every level of a grand
product, the bus's products multiplied over the tables, and the
squarings in the ring switching. For `sum_t s_t a_t b_t = c`, with
`s_t` known:

1. Three committed elements for each term: pads `alpha_t`, `beta_t`, and
   `gamma_t`, which an honest prover sets to `alpha_t beta_t`.
2. The prover sends the cross terms
   `sum_t s_t (a_t beta_t + b_t alpha_t)` under a pad.
3. A challenge `e`.
4. The prover sends `z_t = e a_t + alpha_t` and `w_t = e b_t + beta_t`
   in the clear.
5. Equations: `e a_t + alpha_t = z_t`, `e b_t + beta_t = w_t`, and
   `e^2 c + e cross + sum_t s_t gamma_t = sum_t s_t z_t w_t`.

Everything in the last equation but `e` and the `z`, `w` was fixed
before `e`, and the `z`, `w` are pinned by the first two. As a
polynomial in `e` the two sides agree only if their `e^2` coefficients
do, which is `sum s_t a_t b_t = c`. Nothing is asked of `gamma_t`: a
prover that commits a wrong one only makes the equation fail. The error
is `2 / 2^128` a product. A square needs no cross term in characteristic
two: `(e a + alpha)^2 = e^2 a^2 + alpha^2`, with `alpha^2` committed.

All the products of a proof are queued and shown under one `e`, drawn
when every value in them has been sent.

*Hiding.* `z_t` and `w_t` are uniform by `alpha_t`, `beta_t`, which are
used nowhere else; the cross terms by their pad.

### 3. The ring switching

The 128 sums `s_b` are sent under pads, and the check that they come to
the words' value at the point is linear in them. What the opening must
then show is `switched(s)`: a chain of 128 squarings, each adding a term
that is a sum of all the `s_b` under constants. Done on forms, every
term would carry every sum's pad through every squaring.

So the prover sends the 128 terms themselves, each under one pad. A
challenge `chi` batches the 128 claims "this term is that sum of the
`s_b`" into one equation. The 127 squarings are then of forms with two
pads, each by the square protocol above.

This is the one place the hiding costs the verifying circuit real work:
the batched equation needs, for each `s_b`, the sum over the terms of
its constant there, about 32,000 rows of the machine.

### 4. The opening

The opening shows one sum of two polynomials. The pads' polynomial has
four variables fewer than the witness's. It is taken as the polynomial
of all the variables that is its own values where the first four are
zero and zero elsewhere, and its weights the same way. Over the first
four rounds its part of each coefficient sent is then its whole sum
times `(1 + r_1)^2 ... (1 + r_i)^2`; after them it joins as any smaller
polynomial does, its codeword added under a challenge and its weights
scaled by those squares. No sum of its own is ever sent: only the two
together are claimed.

Four things in an opening depend on what is committed.

**After the first leaf's folding.** The random polynomial `g` joins
where the second codeword is committed: the prover sends what `g` sums
to under the weights as they then are, a challenge `theta` is drawn,
and `theta g` is added to the folded polynomial and its codeword. Every
round after that, every codeword after the first, and the last value
are of a sum with `theta g`: uniform, for a uniform `g`. The last value
sent is that sum's; the witness's polynomial's own is never sent. A
query opens `g`'s entry and the pads' beside the first leaf and adds
them, under their challenges, to what the leaf folds to.

**The four rounds before that** are of the two polynomials themselves.
They are hidden by 32 random elements that are two whole leaves' places
in the witness's polynomial: the last word of the first table's last
128 rows. The prover sends the sum of four of them (the *corners*), a
challenge `chi` is drawn, and the opening's sum weighs those four by
`chi` and is of that much more. What the prover sends in those rounds
is then, as a function of the 32, onto all nine values it can take: the
corners' sum and two coefficients a round. Why 32 and not 16: with one
leaf's place, what its elements sum to under the weights is determined
by what the rounds say, and one value in nine is left bare. With two,
weighed differently, it is not. That it is onto with the corners'
weights alone is checked by a test
(`the_corners_hide_the_first_rounds`); with any other weights on those
elements beside (the ring switching's are there, they being part of a
table), the determinant that says so is a polynomial in `chi` whose
leading coefficient is the one without them, so it is zero for eight
`chi` at most.

**The leaves the queries open** are sixteen entries each of the
witness's own codeword. They are hidden by the rest of the first
table's last word, all of it random. A leaf is the values, at one point
`y` of the codeword folded four times, of sixteen polynomials (the
coefficients alike modulo sixteen). The last word gives each of them
the part

```text
X(y) (p_0(q) + y' p_1(q))
```

where `q` is `y` folded on until a group of 128 rows is one
coefficient, `p_0`, `p_1` are random of degree below the number of
groups, and `X` is the basis polynomial of the first of the word's
coefficients, zero at the lowest `C / 32` leaves (`C` the bits of a
row) and nowhere else. So the opened leaves are uniform if

- none is among those lowest leaves,
- no more than two have the same `q`, and
- no more different `q` are met than the table has such groups.

The prover checks this of the queries' places (`Places::good`) and, if
it fails, takes the next nonce that grinds: the queries are ground for
a bit at least, and any nonce that grinds is one the verifier takes.
For a chain's proof the rule holds for about nineteen nonces in twenty.
Which nonces fail depends on the transcript alone, which is public, so
the choice says nothing. That the rule is enough is checked against the
code itself by a test that computes the rank
(`the_last_word_hides_the_leaves_it_is_said_to`).

**The pads' polynomial.** A query opens one entry of its codeword, and
its last value is sent as it is. It begins with random elements that
are no pads, more than there are queries: polynomials of that degree
take every set of values at that many points, so the entries and the
last value are uniform, whatever the pads.

**The opening at the point.** The sum's rounds fold nothing: their
challenges `r` are a point, and the prover then sends the witness's
polynomial at it, `g` at it, the pads' polynomial at it (its last
value, as above) and a second random polynomial `g'` at it, and opens
all of them there together (`docs/SOUNDNESS.md` says why: one codeword
holds a prover to one value). That opening is the same thing over
again with `eq(r, .)` for weights and new challenges, and what it shows
is hidden the same way, in two parts.

*Its first four rounds*, and the value of the witness's polynomial at
`r`, are of that polynomial alone. A round's polynomial under `eq` is
`eq` in its variable times a line, so its leading coefficient follows
from its constant one and the claim for anyone: there are five values
here, not nine. They are functions of the same last word that hides
the sum's first rounds and the leaves, and they are uniform with all
of those together: the test that builds the whole map computes its
rank with these five rows in it
(`the_corners_and_the_cover_hide_together`). The value at `r` is not
new to whoever has the sum's rounds and `g` at `r`, which is why `g`
alone would not do for what follows.

*After them* `g`, the pads' polynomial and `g'` join, each under a
challenge, and every round, codeword, polynomial sent and last value
is of a sum with `g'` in it under a challenge: uniform, for a uniform
`g'`, which is in nothing before. A query opens `g'`'s entry beside
the first leaf as it does `g`'s and the pads'. What is seen of `g'`
itself is those entries and its value at `r`.

**The trees.** No leaf is salted. An unopened leaf of the first tree
holds an entry of `g`'s codeword, and those of later trees are of the
blinded sum, so each has 128 bits that the view does not fix, and its
hash says nothing in the random oracle model.

### 5. That these hold together

Each of the three coverings above was argued by itself, and they are
not independent of one another: the first four rounds read the leaves'
cover as well as the corners (the ring switching weighs every element
of a table), and a leaf's elements depend on the corners as well as on
the cover (the corners are coefficients like any others). So what must
be shown is that the corners' sum, the eight coefficients of the first
rounds and every element of every opened leaf are uniform *together*,
as one map from the whole of the first table's last word.

Write the map as two blocks of rows, the rounds' `(M_c | M_v)` and the
leaves' `(L_c | L_v)`, over the corners' group `c` and the cover `v`.
The leaves' rule gives `L_v` full row rank. A dependence between the
rows is an `a` and a `b`, not both zero, with `a M_v = b L_v` and
`a M_c = b L_c`. Since `L_v` has full row rank, `b` is a linear
function of `a`, say `b = a B`, and `a` is not zero. So a dependence is
a nonzero `a` with `a (M_c - B L_c) = 0`. Now `M_c` is the rounds'
matrix on the corners' group for the weights there, which are whatever
the ring switching put plus `chi` on the four corners: `M_c = N + chi
M`, with `M` the matrix for the corners' weights alone, of full row
rank nine (section 4). Nothing else in the condition depends on `chi`.
So `(N - B L_c) + chi M` has a nine-by-nine minor that is a polynomial
in `chi` with a nonzero leading coefficient, and has full row rank for
all but nine values of `chi`: then there is no such `a`. A test builds
the whole map for one case and computes its rank
(`the_corners_and_the_cover_hide_together`).

The pads' polynomial is apart from this: it is no part of a table, and
what is seen of it (an entry a query, and its last value) is hidden by
its own first elements. Those are one more than the queries at least.
The entries are a polynomial's values at as many points as there are
queries, onto for coefficients of that many low degrees; the last
value is the first elements under `eq` at the challenges, which lies
in the span of those evaluations only if a nonzero multilinear
polynomial vanishes at the challenges.

## The simulator

Given the statement and the challenges (it programs the oracle):

1. Every element sent under a pad: uniform.
2. The products' `z`, `w` and cross terms: uniform.
3. The programs' part of the sum: computed, the programs being public.
4. The equations, and what the opening is to show, follow from 1 to 3:
   the opening's claim is public.
5. The corners' sum and the first four rounds: uniform.
6. A uniform polynomial for `f + theta g` from the fifth round on, with
   what it sums to under the weights; `g`'s sum is then what makes the
   claim after four rounds agree. Everything after is computed from it.
7. The pads' polynomial's last value and its entries at the queries:
   uniform.
8. The opened leaves of the first tree: uniform; `g`'s entry at each is
   what the fold and the blinded codeword leave it to be.
9. Unopened siblings: random digests.

Real and simulated differ only where one of the maps of the opening is
not onto for the challenges drawn (the corners', the pads' prefix with
its last value), where a challenge that is divided by is zero, or where
a hash is guessed: each far below `2^-100`.

## What it costs

- **The proof.** Per query, two elements more in the first leaf. Per
  product, three to five elements. The 128 terms and 254 elements of
  the ring switching's squarings. Some kilobytes in all on a proof of
  about 460.
- **The prover.** Two more encodings, each a sixteenth the size; one
  more block to hash in each first leaf; and running the verifier's
  checks once on its own proof, to learn the pads' weights.
- **The verifying circuit.** One compression more a query; the forms'
  arithmetic; the pads' weights at a point; and the ring switching's
  batching above.

Measured at the chain's parameters, on a laptop: the chain's step is
proven in 13 to 15 seconds and 4.2 GB, its proof is 420 KB, and it
uses 83% of the machine's rows and 55% of the hash table's.

## What a prover must supply

A seed of 32 bytes, random and used for one proof only. Every pad, the
corners, the leaves' cover and `g` come of it. A seed used twice gives two proofs
with the same pads, and their difference is the difference of two
witnesses' messages.

## Limits

- The construction is honest-verifier with the Fiat-Shamir transform;
  nothing is claimed against a verifier that could choose challenges.
- The rule for the leaves asks more than is needed (it is sufficient,
  not tight), which costs a prover a nonce in twenty.
- The first table must have a word to spare and more than 128 rows, and
  the polynomial be large enough for the pads (about 2^17 elements).
  The chain's proof is far past both; small proofs cannot hide.

## What it rests on

1. Blake3 as a random oracle, for the challenges and for the hashes of
   unopened leaves.
2. The challenges are honest ones (they are hashes).
3. The seed is random and used for one proof.
4. Three statements of the form "this map is onto unless a challenge
   is one of a few values": the corners' nine values, the leaves'
   rule, and the two together. Each has its argument above and a test
   that computes the rank for one case.
5. Nothing is claimed about what timing or memory use reveal.
