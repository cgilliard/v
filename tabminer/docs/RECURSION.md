# The recursive verifier: where it stands

A block carries one proof that verifies the block's proof and the
chain's proof before it. That needs a verifier written as a circuit.
This is a working note: what is built, what it measures, what is left.
It will be replaced by the modules' own documentation once the chain
proof is whole.

## Built: a proof that verifies a proof

All in `src/`, tested.

The verifier is written once (`argument::check`, `pcs::verify_weighted`,
`grand::verify`, `structure::tables_at`), over three things it does not
name:

| | to verify | to make a circuit that verifies |
|---|---|---|
| the arithmetic (`alg::Alg`) | the field | `alg::Sym`: rows of the machine |
| the transcript (`alg::Transcript`) | `Challenger` | `alg::Hashed`: rows of the hash table |
| the openings (`pcs::Opens`) | `pcs::Batched`: a tree's leaves together | `alg::HashedOpens`: each path its own rows |

Running it over the second column on a proof is compiling it: the rows
carry that proof's values, every check is an assertion of the machine,
and the two tables are proven together like any other two.

- **The hash table** (`recursion.rs`): a row a Blake3 compression. It
  shows the transcript's chain and every Merkle path, and sends what the
  arithmetic computes with (what was absorbed, the challenges, the
  leaves, the roots reached, the queries' indices and their shifts).
- **The machine** (`machine.rs`): a row one `out = (a + d) b + c` on
  field elements, operands by address on the bus, a result sent up to
  four times.
- **Nothing reads a bit of a field element.** The ring switching batches
  its 128 sums with a map that is a sum of powers `2^t`
  (`argument::phi`), so reading the sums the other way is products
  (`argument::switched`). A query's place in a leaf comes as bits from
  the hash table (an index less twice the index shifted). So there is no
  third table.

Tests: `alg::tests::a_proof_is_verified_by_rows` (a proof, its
verification compiled and proven, verified by the field's verifier;
five proofs with a value changed are each turned away or leave rows
that do not hold) and `the_verifier_s_program_is_the_same_for_every_proof`.

## Measured

`alg::tests::fixed_point_timing`, 124 bits proven (rate 1/4, 155
queries), on the laptop (Ryzen 5 7530U). Each is the fixed point: a
proof that verifies proofs of its own shape, whose program is the same
at every level from there on (the test asserts it).

| | verifying one proof | verifying two (`PROOFS=2`): a step of the chain |
|---|---|---|
| hash rows | 2^15 (19,233 used) | 2^16 (41,242 used, 63%) |
| machine rows | 2^18 (213,053 used, 81%) | 2^19 (443,315 used, 85%) |
| packed elements | 2^23 | 2^24 |
| proving | 4.3 to 4.5 s | 9.0 to 9.4 s |
| proof | 422 to 426 KB | 457 to 462 KB |
| verifying | 3.4 to 3.6 ms | 3.6 to 4.2 ms |

Where one verification's 169,474 operations go:

| part | operations |
|---|---|
| the two circuits' tables at a point (the hash circuit's 46,000 terms are nearly all of it) | 55,000 |
| the 128 sums read the other way, once for all tables | 18,000 |
| reading what the openings send | 28,000 |
| folding the queries' leaves | 52,000 |
| the opening's weights | 12,000 |
| the sumchecks, grand products and the rest | 4,500 |

## The statement

A proof of a compiled computation is of a digest, the machine's public
value (`machine::PUBLIC`, two elements): the hash, in its own domain, of
the elements the computation names (`alg::Shared::state`,
`alg::statement`). The hash table hashes them, the machine reads them
and finds them to be the values it computed with.

A compiled verifier names what `argument::check` leaves it
(`argument::Taken`): the root of the programs it verified against, and
the inner proof's own statement. So the proof says "a proof of that
statement, for that program, verifies", and whoever takes it must check
the program's root to be the one meant. For a chain step that is its
own program's root: the same at every level.

## Not built

1. **Zero knowledge** for the proof a wallet makes (step 4).
2. **The circuits** of the chain (step 5), and **aggregation and the
   chain's own statement** (step 6): what a step's statement holds
   beyond what it verified.
3. A written proof of the assembled protocol's soundness, for review.

## Ways to bring it down further

None is built.

- The hash circuit's terms: 46,000, long because the state is
  checkpointed once a round. They are a third of the verifier.
- Fewer queries at the chain step alone (a lower rate there).
- A machine row has 21 spare words: an operation with more addends
  would shorten the long sums.
