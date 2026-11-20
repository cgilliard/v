# The chain's circuits: plan and open points

A working note for step 5 (the circuits) and step 6 (aggregation). What
the reference does is summarised from a survey of `tmp/u/miner`; what is
decided here is marked so. Nothing below is built except `src/xmss.rs`.

## What the reference proves, and how it will map

The miner proves everything; a wallet only signs. A block's proof is a
tree:

| reference | here |
|---|---|
| signature segments (`sig_air`): up to 128 XMSS checks each, block-independent, publish an entry per signature | a signature table: a row a compression, proven as its own proof |
| the signed set: a Merkle tree over the entries, looked up by path | the same, over Blake3 (to decide: see below) |
| transaction segments (`block_air`): spend, insert, policies, sums | tables to design: state-tree walks are compressions, amounts and policies are words |
| the name segment (`name_air`) | the same |
| the work segment (`pow_air`) for the parent header | needs the proof of work redesigned first (below) |
| nodes, root, wrap: verifier programs on a VM | the compiled verifier (`alg`, `machine`, `recursion`): built and measured |
| chain step: verifies the wrap and the previous chain proof | the two-proof fixed point: measured, 9.0 to 9.4 s, about 460 KB |

## XMSS over Blake3 (built: `src/xmss.rs`)

A chain step is Blake3's keyed hash under its tweak: one compression.
The message digest and the leaf are hashes in domains of `hash.rs` that
begin with the seed, the leaf's index and the tree's height; the tree's
nodes are a plain Merkle path (decided with the user: not XMSS as
published; the height in the leaf keeps half a tree from being a key).
A height-4 signature is 1,047 compressions to verify, 2,312 bytes.

## The chain table (built: `src/wots.rs`)

A row a chain step: 506 words, 487 constraints, 7 products, 41,033
terms. It takes the digest's halves off the bus and sends each chain's
end, the seed and the leaf's index. Tested beside a stand-in for the
other end of the bus. Not yet: the hash table's rows for the digest,
the leaf and the path with the machine tying them to the chains; the
entry a signature publishes; a measurement at 2^17 rows.

## A signature's check (built: `src/signature.rs`)

`check_into` makes the rows of one signature's check in three tables
proven together: the chains (`wots`), the hashes of the digest, the
leaf, the path and the entry (`recursion`), and the machine that finds
them to be of one signature. It leaves the signature's **entry**: the
hash of the root reached, the seed, the height, the message and the
leaf's index. A check says nothing of any block.

Measured at 124 bits (`signature::tests::signatures_timing`, `TABLES`
the chain tables' sizes):

| chain tables (rows) | signatures | elements | proving | a signature | proof | peak memory |
|---|---|---|---|---|---|---|
| 2^16, 2^15 | 97 | 2^24 | 8.8 s | 90 ms | 479 KB | 3.1 GB |
| 2^15 x 3 | 96 | 2^24 | 8.8 s | 92 ms | 498 KB | 2.9 GB |
| 2^17, 2^16, 2^15 | 227 | 2^25 | 19.5 s | 86 ms | 546 KB | 6.5 GB |

(The reference: about 115 ms a signature.) A table is a power of two
of rows and the tables together a power of two of words, so the chains
are split over tables of unlike sizes to fill the proof: one chain
table of 2^17 rows would be half of a proof of 2^25 elements with the
other half nearly empty (measured: 130 signatures in 14.5 s).

## The signed set (built: `src/signed.rs`) and what joining proofs costs

The set is a tree of pairs over the entries, every node a hash in its
own domain: `SLOTS = 128` entries a signature proof, four roots a node,
seven levels of nodes. A signature proof states its entries' root
(`segment_root_into`, a hash row a pair that is not of two empty
subtrees); `signature::tests::a_proof_of_signatures_is_verified_by_rows`
compiles the verification of such a proof and proves it.

**Measured (`signature::tests::verifying_costs`): verifying one
signature proof in a circuit is 230,000 operations with one chain
table, 285,000 with two, and about 21,000 hash rows.** A proof of the
hash table and the machine alone is 170,000. The difference is reading
the chain circuit (41,000 terms) for each chain table.

So a node that verifies four signature proofs as they are would be
over a million operations: 2^26 elements, some 40 s and 13 GB. Too
much. Built instead:

1. **Each circuit is read once for all the proofs a node verifies**
   (`src/reading.rs`). The verifier takes each table's reading on the
   prover's word (`Deferred`) and settles them together: a sumcheck
   over the table of the circuit's terms, its challenges from the
   node's own hash rows, leaves one reading at one point.
2. **Two children a node.**
3. **A machine row sends its result eight times** (was four): fewer
   rows that only copy. It makes the machine's bus and products twice
   as large, which costs the chain step about two seconds.

**Measured (`signature::tests::joining_timing`, 124 bits): a node that
joins two proofs of 65 signatures each is 400,000 operations, 421,586
machine rows (80% of 2^19) and 42,319 hash rows: 2^24 elements, proven
in 10.9 s, 459 KB, 3.8 GB peak.** With the same machine the chain step
(two proofs of its own kind) is 11.1 s (was 9.0 to 9.4), and 97
signatures are 9.1 s (94 ms each).

## The signature table as first designed (superseded by the two tables above)

A row is one compression with the tweak as its chaining value. Per
signature: the message digest, 67 chains of 15 steps, the leaf's hash,
the path.

- The public seed and the leaf's index are the first five words of
  every row's chaining value, held equal from row to row; on the
  path's rows the index word shifts right, and its low bit says which
  half of the block is the last row's output (as `recursion.rs` does).
- A chain's rows have a word `active` (all ones or none, never falling
  within a chain): an active row's block is the last row's output if
  that row was active, and is free otherwise (the signature's value, at
  the first active row). A counter of the active rows is `15 - digit`;
  the same count over the message's chains is the checksum.
- The digit is four bits of the message digest: the digest's words
  reach the chains' rows over the bus (sent by the digest's row, taken
  by the first row of every eighth chain) and rotate by four bits a
  chain.
- The chain's end is the last row's output if it was active, its block
  if not (digit 15: no step).

**Open: the row does not fit 512 words and 512 constraints.** The
compression alone is 480 words and 456 constraints (`recursion.rs`'s
row is 511 and 494). Hashing the 67 ends into the leaf in the same
table needs the ends carried or bussed: about 30 words and 90
constraints more. Options, none measured:

1. A row of 1,024 words and constraints: twice the cost a signature.
2. Two tables: this one for the chains only (1,005 rows a signature),
   and the leaf's hash, the path and the message digest as rows of the
   general hash table, the ends going over the bus. The chain table
   then needs only the mux for the end and its gated copy to send.
3. Fewer constraints in the compression (its 112 checkpoint
   constraints are equalities, which could ride on other constraints).

Option 2 is the likely one. At one row a compression and the measured
2^17 rows in about 8 s, a signature costs about 65 ms of proving: 125
signatures a 2^17-row proof (the reference: 100 in 11.5 s).

## Decided (2026-11-19)

1. **Zero knowledge comes after the circuits.** It is a new
   construction for this argument (masking for the sumchecks, a hiding
   opening, a simulation argument); it touches only `argument.rs` and
   `pcs.rs`, and only the published chain-step proof needs it.
2. **The proof of work keeps hashimoto's structure**, over Blake3 and
   words. What it must keep: the work needs a dataset that is harder to
   make than the hashing is to do; verifying without the dataset costs
   time; the dataset is made from the seed text, which the work thereby
   preserves.
3. **The signed set stays a Merkle set**, as the reference's: a
   signature is proven before the block it will be in is known, which
   is what lets a pool prove ahead and fill blocks.

## The chain table in more detail

Budget: 512 words and 512 constraints a row; the compression is 469
words here (the tweak's last three words and the block's second half
are constants or program, not committed) and 456 constraints.

- `active` is one bit in every place; its bit is the carry out of
  `digit + (15 - step)`, the step a program word: three words, four
  constraints.
- The digest reaches the rows as two elements of four words, taken off
  the bus into a register of four words; the first rotates by four bits
  a chain, and the register moves a word every eighth chain.
- The checksum is a running sum of `15 - digit` over the message's
  chains, which the last three chains read their digits from.
- The chain's end, and every copy sent or taken, is a product of field
  elements with a bit (of `active`, or of the program), not `AND`
  constraints: those do not count against the 512.
- Estimated: 506 words, 491 constraints, about 8 products.

## How the two tables meet (found while laying the chain table out)

- Every tuple on the bus is an address and one element, as the hash
  table's and the machine's are: the chain table sends a chain's end as
  two tuples and its seed and leaf as two, and takes the digest's
  halves as two.
- The hash table sends a block's elements and does not take them. So
  the leaf's hash rows send their blocks, the chain table sends the
  ends, and the machine reads both and asserts them equal: about 400
  machine rows a signature, some 5% on top of the chains.
- **The hash table starts every hash from a domain's key** (a tag and
  zeros), so it cannot hash under XMSS's tweak as a key. The chain
  steps keep the tweak as their key, in the chain table. The message
  digest, the leaf's hash and the tree are to be hashes in domains of
  `hash.rs` with the seed and the leaf's index in their first block
  (the leaf, the digest) or without them (the tree's nodes, which then
  are a Merkle path the hash table already climbs). `xmss.rs` has to
  change to that before the table is built. To confirm with the user:
  tree nodes without a tweak of their own (256-bit digests leave a wide
  margin against many-target attacks; the chains keep their tweaks).

## The chain table: the row, as it is to be written

Inputs in order: the seed's four words and the leaf (the tweak's
first five words); the block's first eight words; `active`, the digit,
the link flag; the digest register (four words) and its taken copy;
the checksum's two masked words; the mux's difference (eight words);
the end's sent copy (eight); the seed's and leaf's sent copy (five).
Program: the tweak's extra word, `15 - step`, masks (not first of a
chain; same signature; register holds, rotates, shifts, loads from the
checksum; checksum keeps, counts), a word of bits (send the end, take
the digest, send the seed) and five addresses.

Constraints beyond the compression's 456 (about 30): the tweak's
continuity (5), the digit (1), `active` (2 and an addition), the link
(1 and 8), the register (9), the checksum (2, an addition, a
checkpoint). Products: the mux (2), the end's copies (2), the
digest's (1), the seed's and leaf's (2).

## The proof of work (built natively: `src/pow.rs`) and its circuit (planned)

Hashimoto over Blake3 and 32-bit words; the text in 2^15 overlapping
windows of 64 bytes. Measured: one header's check from the file reads
at least 76.8% of the file, eleven headers all of it (decided with the
user: enough; the parameters stay).

The work segment has to show the 128 items a header's work reads to be
made from the text, and the 64 accesses folded. Notes for its design:

- **A read of the text is a lookup with a count that is the
  prover's.** The bus is a multiset of tuples with no counts, and sums
  of inverses (the usual lookup argument) are unsound in characteristic
  two, where two equal terms cancel. So the text is to be read as a
  memory is checked offline: a table of the 2^15 windows, each sent
  with a counter of one and taken back with its last counter; a read
  takes a window with a counter and sends it with the counter times a
  generator.
- **A table of steps**: a row a keyed hash whose key is the last row's
  output and whose block is the window read, with the read's two
  tuples. Every row is a read, the rows that fill the table too, so
  nothing needs gating. 128 items of 254 steps are 32,512 rows: 2^15.
- For that, an item should begin from its index as the key itself (no
  hash before the first step) and be its last two states (no hash
  after the last): a change to `pow.rs` to make with the circuit.
- The 64 accesses (FNV on 32 words: five additions a multiplication by
  the prime) are a small table of their own, taking items and windows
  off the bus.

## The transaction segment: the design question

What it must enforce is recorded from the reference (key ownership,
commitment openings, removal from and insertion into the state tree,
the body hash that is the txid, the signed-set lookups, the running
hashes that tie it to the block's body, sums, a carry between
segments; policies and names beside).

How to build it here is not settled. The signature check could be a
compiled computation because its shape is fixed: the same hashes in
the same order for every signature. A segment's is not: which row is
an input, an output or the end of a transaction is the block's to say.
In this system a compiled computation's program is committed and the
same for every proof, so it cannot follow the data.

Options:

1. **A table of its own with rows the witness chooses the kind of**
   (as the reference's): a compression a row, registers, and flags
   that say what the row is. The compression leaves no room in 512
   words, so the row is 1,024: twice the cost a row. An input is about
   110 rows (two walks of the 42-level path, the signed set's path, a
   few hashes), an output about 15.
2. **Fixed slots**: a program of slots in a fixed order, each to be
   used or skipped. Simple, but a slot costs what its largest use
   does, and the order of a transaction's items would have to be let
   go of.
3. **A small machine of the witness's choosing over a pool of plain
   hash rows**, joined by tuples whose addresses are the witness's.
   Narrow rows, but the pool's mix of domains is fixed by the program.

Signatures are ten times an input's hashing, so the segment's cost is
the smaller part of a block either way. The likely choice is (1): it
follows the reference's rules as they are and wastes nothing; its cost
is that the verifier of a segment reads a 1,024-word circuit.

## The transaction table (decided: rows that choose their kind; design, not built)

Native rules are built: `src/ledger.rs` (outputs, ids, the tree of
outputs, `Record`). The table is to prove a `Record` for a run of
plain payments.

**A row**: one compression (chaining value: a domain's tag and zeros,
or the last row's output where a hash goes on; block: 16 witness
words; length and flags by kind), a word `kind` with one bit set, a
flag word for each kind (one bit in every place, its bit `kind`'s),
and registers, each held from the row before or set as the kind says.
Which kind may follow which is one constraint a kind: the row
before's flags, over the kinds allowed, come to all ones. 1,024 words;
a program of two masks, the first row and the last.

**Registers**: the outputs' root (8); the running hashes of inputs and
of outputs (8, 8); the signed set's root (8, never changes); the
transaction's claimed id and its body hash so far (8, 8); inputs and
outputs left (2); the sums (4, 4); the next position (2); the height;
and for the item in hand: a held digest (8), the amount (2), a
position being walked and as it was (2, 2), a counter, the two walks'
nodes (8, 8).

**An input**, 110 rows: `KEY` (the key's block: its hash) · `ENT1`
(the same block, in the entry's domain) · `ENT2` (goes on with the id
and the leaf's index: the entry) · 21 × `SN` (up the signed set, by
the bits of a place the prover names; reaches the set's root) ·
`COMMIT` (key hash, amount) · `BODYIN` (the body takes the commitment;
one input fewer left) · `LEAF` (commitment, memo, amount, the height
it was made at) · 41 × (`OLD`, `NEW`) (the leaf's path, and the same
path from nothing, a level a pair, by the position's bits) · `ISP`
(the old path reached the root, the root is now the new path's; the
position goes into the inputs' hash; the sum grows).

**An output**, 87 rows: `OUTC` (commitment of a key hash and the
amount) · `OLEAF` (with the block's height) · `OITEM` (the same block
without the height: the item) · `BODYOUT` · 41 × (`OLD`, `NEW`) (from
nothing, and from the leaf, at the next position) · `OSP` (root, next
position, the outputs' hash, the sum, one output fewer left).

**A transaction**: `HEAD` (its counts: the body hash's start, the
counters, the id it claims), allowed only when the one before is
whole: its counters at zero and its body hash its id. Inputs come
before outputs. `START` is the first row, `PAD` fills.

**Public values** (elements, bound by products with the program's
masks): the registers a run is joined by, as they are in the first
row and in the last: root, the two running hashes, next position, the
transaction in hand (id, body hash, counters) so that a transaction
may lie across two runs; the sums and the height; the signed set's
root.

**Arithmetic**: counters and sums by full adders written out (a
carry word a 32-bit addition, the carry out of a word a bit for the
next).

**Cost**: a payment of two inputs and two outputs is 394 rows of 1,024
words; 2^16 rows (a proof of 2^24 elements) hold about 166 of them.
Later: the reference's stack of outputs, which sets down a whole
subtree with one path, makes an output about 20 rows.

## Names: built natively (`src/name.rs`), their rows planned

Rules as the reference's, restated over Blake3: commit, reveal (1 to
288 blocks later), update (signed by the owner's key over the new
record), sweep. The registry is a plain tree of 128 levels, a name at
the place its hash's first 128 bits say (the reference's is a
compressed trie; a plain tree is two walks of 128 rows and nothing
else to prove). `state_root = H(outputs' root, registry's root)`.

**Decided while planning: name operations are more kinds of row in the
transaction table, not a table and a proof of their own.** A
transaction's operations are applied where the transaction has them,
so nothing has to tie a list of operations in one proof to the same
list in another. With that:

- What a block spends is one ordered list of positions (payments'
  inputs, revealed commitments, sweeps), the running hash a run
  already keeps; what it makes is one ordered list of outputs and
  operations, the other. No third and fourth running hash.
- A name's characters are for the node to check (the block lists the
  record); the rows take the name's hash as given. So is "the new
  owner is another": the node has the old record.
- The caps (1 commit, 5 reveals, 8 updates, 16 sweeps a block) are
  counters a run keeps as one bit moving up a word; a row of the kind
  is refused when its bit is at the cap.
- The windows (`height - made` in 1..288, or above 288 for a sweep)
  are full adders in the row, as the sums are.

Rows, each one compression (kinds to add to `segment.rs`):

- **Commit**: `OPC` (the operation's hash) · `CLEAF` (the
  commitment's output leaf, at the block's height) · `OPBODY` (the
  body takes the operation) · the outputs' walk · `OPSP` (as `OSP`,
  in the operations' domain).
- **Reveal**: `REC1`, `REC2` (the record's hash) · `COM1`, `COM2` (the
  commitment, of the same name's hash and owner) · `RLEAF` (the
  commitment's leaf; the window) · the outputs' walk · `ISP` · `NLEAFR`
  (the name's leaf; nothing there before) · the registry's walk, 128
  of (`NOLD`, `NNEW`) · `NEND` · `OPX` (the operation's hash, its tag
  the flow's) · `OPBODY` · `OPABS`.
- **Update**: `REC1`, `REC2` · `UMSG` (what the owner signs) · `KEY`,
  `ENT1`, `ENT2U`, 21 × `SN` (the owner's entry in the signed set) ·
  `OREC1`, `OREC2` (the old record's hash, its owner the key's hash) ·
  `NLEAFO`, `NLEAFN` · the registry's walk · `NEND` · `OPX` · `OPBODY`
  · `OPABS`.
- **Sweep** (between transactions): `SLEAF` (the window) · the
  outputs' walk · `ISP`.

More than 32 kinds: the kind is two words with one bit between them.
New registers: the registry's root, the name's hash, the owner, the
record's hash, the name's place being walked (four words), the flow's
tag, the caps. The row stays within 1,024 words but needs 2,048
constraints (about 1,400): to trim later.

Also built on the way: `src/arith.rs`, a table of 64-bit additions and
subtractions for compiled computations (`Shared::number`), since the
machine cannot count.

## The header, the work, and the signatures' tree (added with the chain's last pieces)

**The header** (`src/header.rs`) is, to the proofs, five digests: the id
of the header before, the digest of what the chain's proof states with
this header's block in, everything else a node keeps in a header hashed
(`rest`: a time, a target), the nonce and the mix. The work's hash is of
the first three; the id is of that hash, the nonce and the mix.

**The work.** A block's root verifies a proof of the work of the header
*before* the block's (`block::Worked`), and states that header's work's
hash, nonce and mix. A header's own work cannot be in the proof the
header names. The chain's step then computes the work's hash of the
header that names the id the chain was at and states what the chain's
proof before stated (its public digest, which the step has from
verifying it), with a `rest` the prover gives, finds it to be the one
the root stated, and states that header's id as where the chain now is
(`chain::Statement::tip`). Which work program the proof may be of is
part of the block's shape in the plan, like the other programs under a
root: a shape for each size of the table. Whether the result meets a
target stays a node's check, as in the reference.

Putting the work under the root, not in the step, follows the
reference. Its cost is to be measured: a root that verifies runs,
signatures and work verifies three proofs.

**Signatures' nodes** (`signature::node_into`, `signature::Signed`) join
two proofs of signatures of one level into the tree over both, and
state the hash of what they rested on, the root, and its level. The
level is held as a power of `x`, a level up being a product: the
field's sums are not the numbers'. Nodes join pairs, so one program
serves every level; the reference joined four. The block's root takes a
run of signatures or a node, and states the program of whichever and
what it rested on.

## Zero knowledge

See `docs/ZK.md`. The chain's step proofs are made hiding
(`proof::prove_hidden`); everything beneath them is not, and is never
published.
