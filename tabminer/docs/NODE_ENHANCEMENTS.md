# Node enhancements

Things seen while running the node that we want to change before the
code is called complete. The entries are numbered as they were added;
the plan below says in what order they are taken.

Each entry says what was seen, where, and what the change would be.

## Plan

Ordered by what makes a step slow. Only a change to a circuit wants
the setups made again (about an hour); everything else wants the tests
alone, which are long too. So: the entries are taken in batches by
kind, the tests run once a batch, and what touches a circuit is all in
one batch, last.

| batch | entries | why together | what is slow |
|---|---|---|---|
| **A. Small and well defined** | 1, 2, 3, 5, 7, 10 (what `status` says), 12, 18, 23 | a few lines each, each plainly defined; nothing kept or sent changes its form | the tests, once |
| **B. Find and prove** | 20, 22, 6, 19 (the timing) | to be looked into; the new tests of 22 may find faults, which are put right here | the tests, once |
| **C. The wallet** | 8, 9, 24 | 9 is checked against what 8 makes of the wallet; all three change what the wallet or the store keeps | the tests, once |
| **D. The network** | 11, 17, 15, 10 (memory of a fixed size), 4, 21, 13 | they change what nodes say to each other: one upgrade of every node. 13 is run on the live network once they are in | the tests, once; every node started again |
| **E. The proof** | 14, and what of 19 touches a circuit | the only work on circuits | the setups, once; the tests, once |
| **Open** | 16 | to be thought about further; with D, if it is settled by then | |

In that order, because:

1. **A** is quick, makes the live network pleasanter to try at once,
   and 12 puts the lists of peers right.
2. **B** has the one entry that may be a fault of a live network (20).
   Looking into it does not get in the way of A, and can begin beside
   it; if it is found soon, A and B share one run of the tests.
3. **C** before D: the wallet is what is used most, and no other node
   has to change for it.
4. **D** as one upgrade, since every node must have it together.
5. **E** last: it has the hour, and is the last thing to hurry. What
   19 measures in B says what is worth doing here. What 19 finds that
   is the prover's alone (parts done side by side, work kept from one
   proof to the next) touches no circuit, and moves up into B.

Two entries are in two places:

- **3**: raised to 450 KB in A; looked at once more after E, when the
  size of the proof is what it will be.
- **10**: what `status` says is in A; memory of a fixed size is in D,
  since the sizes of 15 say most of what is to be allocated.

## Open

### 4. Blocks reach one seed a chunk at a time

- **Seen:** same test. The RISC-V seed asked the miner for each block in
  requests of one chunk, about one every 1.3 seconds: 312 such requests
  over 23 blocks. It kept up, a block or two behind at the worst.
- **Effect:** none at a ten-minute block time. At the test's 34 seconds
  a block it is close to the limit.
- **Change:** look at why the transfer window to that node stays at one
  chunk (a slow or lossy path, or pacing that does not recover), and
  whether it should grow again sooner.

### 6. A mining node starts with twenty or thirty seconds of nothing

- **Seen:** same test. A node that mines says nothing and gives no
  prompt for 20 to 30 seconds after it is started.
- **What it most likely is:** the node rebuilding what it proves blocks
  with from the setup that is built in (`Setup::from_parts`, called
  from `main.rs` before the server starts). That proves the chain's
  first statement once and compiles the circuits' tables. The setup
  workflow timed the same step at 15.3 s on a four-core runner
  (`the setup, from its file`). A node that does not mine skips it,
  which fits what was seen. To be confirmed by timing the steps of a
  start.
- **Change, in order of preference:**
  1. Do it after the prompt is up: the server starts and answers at
     once, and mining begins when the setup is ready.
  2. If part of it cannot be moved or kept from one run to the next,
     say what is being done and how far it has got, as the table of
     the proof of work does.
- **Done so far:** a node that mines with a setup that is built in (the main network's, the dev networks') gets ready to make blocks behind its start: it listens and answers at once, says `Getting ready to make blocks` and then `Ready to make blocks, after N s` in its log, and whatever makes blocks waits for that. If the setup built in is not the build's, the node says so and stops, as before. To be seen on the live network: that the prompt is there at once, and how long getting ready takes.

### 7. The command that shows the recovery phrase is hard to find

- **Seen:** same test. It looked as if there were no command to show
  the wallet's recovery phrase. There is one, `seed`: it shows the
  twelve words, and asks for the wallet's password first if it has one.
- **What is wrong:** the name does not say what it is (the phrase is
  called "twelve words" when a wallet is made, and will be
  `Recovery phrase:` after entry 5), and what it prints is the twelve
  words among twenty-five others.
- **Change (decided):** its answer is one line, `Recovery phrase:`
  and the twelve words, the same line as when the wallet is made.
  The password is asked for as now.
- **Still to decide:** the command's name. One name for the thing
  everywhere would be a command named for it (`recovery-phrase`, say),
  listed in `help` under that name, with `seed` kept as another name
  for it or dropped.
- **Done so far:** `seed` answers with the one line, and `help` calls it the recovery phrase. The command's name is as it was.

### 8. The wallet by two commands, `txs` and `outputs`, and one `cancel`

- **Seen:** using the wallet. Cancelling is hard to follow, more so
  with names. What the wallet has done is shown by stage, each stage a
  command of its own: `slates` (begun), `sent` (signed, not in a
  block), `payments` (in a block), `mining` (rewards), `names`
  (registrations under way). `cancel` is two things by the stage: of a
  payment begun it frees what was to be spent; of one sent it sends
  another that pays it back, which wants a fee and then `prune` by
  hand. A name is registered by two transactions (a commit, and a
  reveal some blocks later), and which of them is being cancelled is
  not plain.
- **Aim:** as the Grin wallet: to use the wallet by `txs` and
  `outputs`. Names keep the few commands of their own.
- **Proposal:**
  1. `txs`: one list of everything the wallet did or was paid:
     payments sent and received, rewards, burns, each step of a name
     (commit, reveal, update, transfer), what was cancelled. Each with
     a short number that does not change (1, 2, 3, …), its kind, its
     state (begun, pooled, confirmed, cancelled, replaced), amount, fee
     and height. `txs N` says all of one: what it spent and made, its
     note, its id in full, whether its proof is ready.
  2. `outputs`: each output with its state and the number of the
     transaction that made it, and of the one that spent it.
     - Both say how many signatures are left to the key an output is
       under. An address is a key that signs so many times and no
       more, and the wallet refuses to sign when none is left
       (`WalletError::Exhausted`): today nothing at the prompt says
       how many are left, or that they are running out. In `outputs`,
       beside each output (or each address); in `txs`, what a payment
       used up.
  3. `cancel N`: undo this, if it can still be undone. The wallet
     chooses how by the state: frees the outputs of one begun; replaces
     one that is pooled (asking the fee); refuses one confirmed, and
     says why.
  4. No `prune` by hand: after a replacement the wallet sees which of
     the two is in a block and puts itself right. The list says
     "replaced by N".
  5. `bump N` and `resend N` take the same numbers.
  6. A command on a name says the number of the transaction it made;
     `names` shows the number of the last step; `txs` has rows such as
     "name commit @alice". To cancel a step of a name is to cancel that
     row.
  7. The commands there are now become parts of `txs` (`txs pending`,
     `txs mined`, say), their names kept for a while as other names
     for those.
- **Decided:**
  - `prune` goes: it was confusing. What it did is done by the wallet
    itself (4 above).
  - Cancelling a reveal that has been sent: the wallet first warns
    that the name has been said, that taking the reveal back does not
    unsay it, and that another may register the name.
  - A commit that is in a block cannot be cancelled, and `cancel` says
    so: it can only be left unrevealed, and is swept later. The name
    is not marked as given up; nothing else changes.
  - Payments received are listed in `txs`, and one can be given up
    before the sender has signed, as in Grin.
  - The numbers are the wallet's own. A wallet made again from its
    phrase numbers afresh what it finds on the chain.
- **Still to decide:** the exact columns and words of `txs` and
  `outputs`, and which of the present commands stay as other names.

### 9. The wallet through a reorganization

- **Asked for:** to look into how the wallet comes through the chain
  going over to another branch, by tests, and to put right what is
  found. The list of transactions may be less than perfect after one;
  the outputs must always be right: what the wallet says it has is
  what the chain it is now on says it has.
- **What to look at:**
  - Outputs made by blocks that were undone: gone, or back at another
    place if the new branch makes them again. Outputs spent by blocks
    that were undone: spendable again.
  - Rewards of blocks this node won that were undone (`mining` shows
    them as orphaned today).
  - A payment sent whose input lies elsewhere on the new branch. Where
    an output lies is signed now, so such a payment cannot be sent
    again as it was: the wallet says it is to be made again
    (`resend`). Whether that is said clearly, and whether what it was
    to spend is free to be spent.
  - A payment received in a block that was undone, and one that is in
    both branches at different heights.
  - Names: a commit or a reveal in a block that was undone, and a
    reveal whose commit is at another height on the new branch (its
    age is counted from there).
  - The balance at each step, against the outputs.
  - A reorganization deeper than the node can undo, after which the
    node takes the state whole: the wallet then has to find its
    outputs again.
- **Tests there are:** `wallet::tests::what_a_block_undone_took_with_it_is_put_right`,
  and, with real nodes, `a_payment_survives_the_chain_going_over_to_another_branch`
  (`tests/binary.rs`). What they cover of the above is the first thing
  to find out.

### 10. What `status` says of memory and the store; memory of a fixed size

- **Seen:** `status` on a node that does not mine:

  ```
  memory: 14 MB held, 17 MB at the most
  store: 24 MB in use, of a file of 24 MB
  ```

- **What is wrong:** "at the most" is an unusual thing to be told, and
  the store's line says one number twice.
- **Change to what is said:** the memory held, and no more
  (`memory: 14 MB`). The store's line the same way: one number, with
  the file's size only when it is another (to be settled with the
  rest of `status`).
- **Change to the node:** go through the code and allocate at the
  start what can be: the tables, queues, caches and pools that have a
  bound are made at that bound once, and not grown and shrunk as the
  node runs. The aim is memory of a fixed size while the node runs,
  even if that size is somewhat more than is held now; it should
  still be small.
- **To find out first:**
  - What grows and shrinks today, and by how much: the difference
    between "held" and "at the most" above is 3 MB.
  - Which bounds are large against what is used (the pool is allowed
    64 MB; the peers' table, the queues of requests, the objects kept
    to be served, the messages kept for wallets): allocating each at
    its bound may be more than "small", and some bounds may want
    lowering, or the thing left to grow.
  - A node that mines is another matter: proving a block takes
    gigabytes for the seconds it lasts (5.5 GB at the most in the live
    test). Whether that is to be of a fixed size too, kept between
    blocks, or left as it is and said apart in `status`.
- **Done so far:** what `status` says: `memory: N MB`, and the store as one number (the file's length only where it is another). Memory of a fixed size is to come (batch D).

### 11. One node is counted as two peers when it is reached at two addresses

- **Seen:** `peers` on one of two nodes run on one machine, with three
  seeds elsewhere: five nodes in all, so four others, and five peers
  listed. It looked as if the node were its own peer.
- **What it is:** the other node of the machine, twice: once at
  `127.0.0.1:3737`, the address it was given by, and once at the
  router's public address and a port (`74.244.51.185:63474`), which
  the seeds told of and which the router sends back inside. (The
  seeds' logs show which node is behind which port: the block just
  won is announced from the miner's first.) The node is not its own
  peer: it refuses its own address where it knows it.
- **Effect:** a peer's place is taken by the same node again; that
  node is told of each block twice; and what counts peers ("5 of them
  live") says more nodes than there are. It comes about where two
  nodes are behind one router, or a node has more than one address.
- **Change:** a number each node takes at random when it starts, said
  in its pings. A node that hears the number of a peer it has, from
  another address, keeps one of the two (the one it was given, or the
  first); one that hears its own number knows it has reached itself,
  however it did.

### 13. What a live network says to itself: the request logs, read

- **Asked for:** to run the things a node and a wallet do on the live
  network, one at a time, and read `request.log` on each node for
  each: whether what is sent makes sense, how many requests each
  takes, and where more is said than need be.
- **What to run:**
  - A payment, with the message layer in init mode (the seeds stand in
    for relays) and in onion mode (a consensus file with relays in
    force): to an address, to a name, to a name under a name; with a
    note; one that is answered at once, and one whose wallet is not
    there.
  - A payment by file (`send-file`, `receive`, `finalize`), which
    should say nothing to the network before it is pooled.
  - A name: commit, the wait, reveal, update, an offer and a
    transfer; a name under a name given and taken away.
  - Cancelling, bumping and sending again.
  - A burn, and the proofs of a payment and of a burn.
  - A new node joining: block by block when it is near, and by the
    state when it is far (`--sync-behind`).
  - A node stopped and started; a relay stopped while wallets are
    reached through it.
  - Nothing at all, for ten minutes: what an idle node says, and how
    often.
- **What to look for:**
  - How many requests, and how many bytes, each of these takes, on
    each node it touches.
  - The same thing asked or told more than once: a block announced by
    several peers and fetched from more than one; `get-peers` and
    `peers` every few seconds (seen in the first test); a transfer
    that asks a chunk at a time (entry 4).
  - What is asked that the asker has, or could know it does not need.
  - What an idle node costs its peers.
  - Lines of the log that do not say enough to tell what happened.
- **What comes of it:** numbers for each scenario, written down here
  or beside this file, and an entry for each thing found.

### 14. A smaller proof

- **Asked for:** to see whether a block's proof can be made smaller.
  It has grown by degrees, and the aim is to bring it down without
  faults of the kind the reading of the circuits found: nothing that
  rests on an argument nobody has written down and tried.
- **Where it stands:** a block is 421 to 433 KB (mean 428 KB over the
  29 blocks of the live test), nearly all of it the proof. `docs/ZK.md`
  has the proof at 420 KB before the opening was made two parts, which
  added the sum's own rounds and a second random polynomial's entries
  (some 4 KB by count; the rest of the difference is not accounted
  for, and is the first thing to find out).
- **Where the bytes are:** almost all in the queries' openings: about
  149 queries, each opening a leaf of sixteen elements (and three
  more in the first tree) in every committed codeword, with the hashes
  to check them. To be measured part by part before anything is
  changed: leaves, hashes, the polynomial sent at the end, the rounds.
- **What might be tried**, each to be weighed against what it costs
  the prover and the node:
  - More grinding before the queries: each bit is about a query and a
    half fewer at this rate, and twice the hashing once a proof. (The
    published proof grinds 24 bits now.)
  - A lower rate (1/8 for 1/4): fewer queries for the same security,
    against codewords twice as long to make and commit to.
  - The size of a leaf and how many codewords are committed (the
    arity, and where the polynomial is sent whole): fewer, larger
    steps against more, smaller ones.
  - What is sent that follows from the rest: in the opening at the
    point, a round's leading coefficient follows from its constant one
    and the claim (`docs/ZK.md`), so one element a round is enough.
  - How the hashes of the paths are shared and sent.
  - The programs' polynomial: its own tree is opened at every query.
- **What is not to change without an argument:** the security the
  proofs are made to (124 bits, proven, not conjectured), and what
  hides the witness. Every change is argued in `docs/SOUNDNESS.md` (and
  `docs/ZK.md` where it touches what is hidden), and tried by the tests
  that lie about a proof, before it is taken. A change to the proof
  changes the setups (the `setup` workflow), and what the mempool
  keeps of a block for the proof (entry 3).

### 15. A pool that knows of more transactions than it holds

- **Asked for:** to look into the pool. Ours is not the usual one: a
  transaction waiting is far larger than what it leaves on the chain
  (its signatures go into the block's proof and not into the block),
  so the pool is large against the chain. It is 64 MB now and needs to
  be more. The idea: a node that does not mine and has little memory
  keeps the fact of each transaction, and the whole of only some,
  picked at random; then the pool can know of far more than 64 MB of
  transactions without holding them.
- **What a node keeps of a transaction it does not hold whole:** enough
  to do what a node that does not mine does with a pool. Its id, its
  size and what it pays (to say what a payment should pay, and to
  judge one that would take its place), the outputs it spends and the
  names it claims (to refuse another that spends the same), when it
  came. Some hundred bytes, against kilobytes.
- **Decided, of which are held whole:** the most recent, all of them;
  and of the older ones a share, the rest let go at random. A
  transaction is passed on in its first moments, when every node has
  it whole; after that, each node holding its own random share of the
  older ones, any one of them is to be had from some peers.
- **Decided, of its settings:** both are a node's to set.
  - The most recent, held whole: 8 MB of them unless said otherwise.
  - The older ones: a share of them held whole, 35% unless said
    otherwise, in no more than 128 MB unless said otherwise.
  - (A node that mines, or is to hold everything, sets the share to
    all of them and the sizes to what it has.)
- **Why 35% is enough:** while blocks are small, 8 MB of the most
  recent is all there is, and every node holds everything, as now. The
  share only matters once there is regularly more than 8 MB waiting,
  and a network that busy has hundreds of nodes to be had from: any
  transaction is held by many. And nearly all the passing on of a
  transaction is in its first moments, when all hold it whole; the
  older ones are wanted only by whoever comes late.
- **Design notes** (to be thought through further):
  - Both caches hold whole transactions. Beside them is an entry for
    every transaction known. Transactions are told of and asked for by
    id (`Message::Tx { id, len }`, `Object::Tx(id)`), so the id and the
    size are what an entry always has.
  - An entry wants the outputs the transaction spends as well (8 bytes
    an input). A block does not list ids, only what it spends: without
    them a node cannot tell that a transaction it knows of and does not
    hold has gone into a block, and entries would stay until they are
    too old. With them it can also refuse another that spends the
    same, and is not made to pass on a second spend for nothing. So:
    id, size, what it pays, when it came, what it spends; 60 to 80
    bytes. (Decided: an entry is the least a node needs to do its
    part, and that is this, not the transaction.)
  - Which older ones are held whole is said by a hash and not a coin:
    a node takes a secret when it starts and holds a transaction whole
    if the hash of the secret and the id is in the lowest 35%. The
    same even share, each node's its own; but said again the same way
    each time, with no mark to keep, and nobody else can tell or
    arrange which a node holds.
  - One transaction: it comes, is checked whole, and is among the most
    recent. When newer ones have pushed it out of those 8 MB, it is
    held whole among the older ones or only its entry is kept, by the
    rule above. It goes altogether when a block spends what it spends,
    when it is too old, or when there is no room and it pays least.
  - Two bounds: the 128 MB is of the older ones held whole; the
    entries have a bound of their own, by their number.
  - "Not here" is an ordinary answer to being asked for one known and
    not held: whoever asked tries another peer, and holds nothing
    against the first.
  - A miner sets the share to all. One that starts with nothing has
    the older ones from its peers at about one in three from each, and
    asks several at once; a node might say in its status that it holds
    everything, for miners to prefer.
- **What it cannot do without the whole:** give it to a peer that asks;
  make a block of it (it does not mine); look at it again after the
  chain has gone over to another branch.
- **To work out:**
  - A node says it has a transaction only while it holds it whole.
  - A miner that starts, or comes back, wants the older ones too: it
    asks for each of several peers until one has it. Whether that is
    quick enough, and whether it should rather be given a peer that
    holds everything.
  - Whether 35% is enough: with a share `p` held by each of `n` peers,
    one is had from none of them `(1 - p)^n` of the time. At 35% that
    is 3% of the time with eight peers, 12% with five, 1% with eleven.
    A node that finds none of its peers has one asks further, or waits
    for it to come in a block.
  - What the 128 MB is of: the older ones held whole, or those and
    what is kept of the rest. At a hundred bytes each, what is kept of
    a million transactions not held is 100 MB of its own.
  - What goes when the older ones' space is full: more of them at
    random, or the worst paying.
  - A wallet's own are kept by the wallet whatever the pool does.
  - Checking: a transaction is checked whole once, when it comes,
    before anything of it is let go. What is done with one known but
    not held when its outputs move or go (entry 9, and where an output
    lies being signed): forgotten, or fetched again.
  - Whoever asks a node for one it knows of and does not hold: told it
    is not here, in a way that is not taken for a fault of the peer's.
  - How a node says which kind it is, if at all, and whether a miner
    should prefer peers that hold everything.
  - What it does to how the pool is filled and emptied by fee (the
    part of a block kept for the longest waiting, the shelf), which
    are a miner's concerns but share the code.
  - The sizes: how large the pool is to be on a node that holds
    everything, how much a low-memory node keeps whole, and how this
    sits with memory of a fixed size (entry 10).

### 16. A consensus file stays in force until another is voted in

**Open: to be thought about further before anything is built.** The
idea is wanted, and how to do it is not settled.

- **The concern that holds it up:** nodes that mean harm can give
  what is asked to some nodes and not to others. Votes and files a
  long way back are held by fewer nodes and asked for more rarely, so
  the further back the answer lies, the easier it is to keep it from
  some and so to have nodes of one network hold different files to be
  in force. As the rule is now, everything wanted is within the last
  144 to 288 blocks, which every node has just fetched: some node
  always has it.
- **What is known about it so far:** votes are checked against headers
  and a file against its hash, so what is handed over cannot be made
  up, only kept back. A node that has not been given what it needs
  knows that it lacks it, if it does not take "not found" for an
  answer. That leaves: what such a node does meanwhile; how it tells
  being kept from the answer from there being none; and whether what
  must be kept can be held to something recent (a vote said again
  from time to time, a bound on how long a file stands unrenewed), so
  that the last windows always say it.

- **The concern:** init mode (the seeds standing in for relays) is for
  a network that is very small. Once the network is in onion mode and
  has grown, going back to init mode could bring the seeds down. As
  the rule is (`consensus::Current::decide`), a window of 144 blocks
  in which no more than half voted puts the network in init mode,
  whatever was in force. So: two pools, one voting steadily for its
  file and one never voting; the second comes to make most of the
  blocks; and the network goes back to init mode though nobody voted
  for that.
- **The rule to have:**
  - At a boundary, if more than half the window's blocks voted, the
    most voted file that is held and valid is in force: as now.
  - If no more than half voted, the file that was in force stays in
    force.
  - The network is in init mode only before any file was ever voted
    in, or when a file that says `mode init` is itself voted in by
    more than half: then the miners have said so, knowing what it
    means.
- **To settle:**
  1. Every node must come to the same file, and a node that takes its
     state from others has not seen the vote that put the file in
     force, which may be long past. As things are, the votes are kept
     and served only for the last window. **Proposed:**
     - Every node has every header from the first, whether it took
       its state from others or not, and a header commits to its
       block's vote (one of the sixteen values it commits to beside
       it). A vote handed over is checked against a header the node
       has.
     - The *deciding window* is the last window of 144 blocks in which
       more than half voted: the chain alone says which it is, the
       same for everyone. Every node keeps and serves the votes from
       that window on; what is older can go, and never counts again.
     - A new node, its headers in, goes back a window at a time: it
       fetches the window's votes, checks each against its header, and
       counts. The first window with more than half voting says the
       file. None, back to the first block: init mode.
     - What it costs: a block's sixteen values are 549 bytes (seen in
       the live test), so 79 KB a window and 29 MB for a year in which
       nobody voted; one vote by more than half brings it back to one
       window. A new node fetches as much once, which is little beside
       the state.
     - Checked from the headers alone: nothing rests on what recent
       blocks say that they do not vote on, and no rule of a block
       changes.
     - To be seen to: the file in force must be had by its hash for as
       long as it stands (nodes keep and serve consensus files by hash
       now; this one is kept); votes are fetched a block at a time now,
       and are to be had a window at once, and of old blocks; and a
       node that has not yet gone back far enough says that it does
       not know the file yet, and does not take it for init mode.
  2. A file whose relays have gone is not replaced while most do not
     vote: a pool that no longer makes most of the blocks cannot renew
     its own list. That follows from the rule, and is the price of it;
     wallets go round a relay that does not answer.
  3. "More than half" is 73 of 144, as the code has it.
- **It is more than it looked.** The rule is a line; the work is all
  in how a node that was not there finds out what is in force (1
  above): a way to fetch old votes a window at once, a rule for what
  is kept, and a state of not yet knowing. It could be built in two
  steps, the rule first with nodes remembering, the going back after.
- **Another rule, which needs nothing of the past** (to choose between
  the two):
  - Of the last 144 blocks, the file with the most votes is in force,
    if at least some few blocks voted (15, say: a tenth). Only if
    fewer voted is the network in init mode.
  - The two pools: the one that votes has the most votes though it
    makes fewer blocks, and its file stays. No going back to init
    mode.
  - Init mode on purpose: a file that says `mode init` has the most
    votes, as any file would.
  - All of it is said by the last 144 blocks, as now: nothing more to
    keep, nothing to go back for, a few lines to write.
  - What it gives up: not to vote is to leave it to those who do. A
    pool with fewer blocks can change the file whenever the rest say
    nothing, down to the few; with the file that stays, it never can.
    And if nearly nobody votes, it is init mode still, though one pool
    that goes on voting is enough to prevent it.

  | | the file that stays | most votes, of a few at least |
  |---|---|---|
  | most do not vote | nothing changes | those who vote say |
  | fewer blocks can change the file | never | yes, if the rest say nothing |
  | init mode unasked | never | only if nearly nobody votes |
  | a new node needs the past | yes, to the last deciding window | no |
  | to build | a good deal | a few lines |

### 17. Can a consensus file, or the votes for it, be kept from some nodes?

- **Asked for:** to find out whether there is an attack by keeping
  back, as the rule is today: whether nodes can give `consensus.txt`
  to some peers and not to others; and whether a node asks enough
  peers, often enough, to be sure of having each file that is voted
  for, and each block's vote, if anyone has them.
- **What the code does now** (`Worker::follow_votes`, read and not yet
  tried):
  - Every so often (`sync.leaves_retry`) a node asks for the votes of
    the blocks of the window it lacks, a few at a time, each of the
    next of its peers in turn; and for one file voted for that it does
    not hold, of the next peer in turn. What did not come is asked for
    again the next time, of another. So it goes round all its peers,
    for as long as the thing is wanted: one honest peer that has it is
    enough, in time.
  - What is handed over is checked: a vote against its header, a file
    against its hash. It can be kept back, not made up.
  - **While a file is not held, the node does not wait: it counts as
    if that file were not there** (`Current::decide`, `Skip::NotHeld`),
    and takes the next most voted file it does hold, or init mode. A
    block whose vote it lacks is counted as not having voted, which
    can bring the votes cast under the half that is needed, and so
    init mode. So a node kept from a file or from votes does not say
    "I do not know": for as long as it is kept from them it holds
    another file to be in force than the rest do, or none.
- **Decided:** a node waits until it knows what is in force. While a
  file with votes enough to win is not yet held, or votes are missing
  that could change the count, it holds nothing to be in force: it
  says that it does not know yet (`consensus`, `status`), and it sends
  nothing by the message layer, since it does not know by which nodes
  to send. (A payment begun then is refused with that said, or waits;
  to be settled with what `send` says.)
- **It is part of catching up:** a node that is catching up fetches
  what says the consensus as it fetches the rest, and has not caught
  up, and does not begin, until it knows it. The exception is init
  mode. To be worked through; what is clear so far:
  - Whether a block voted at all is said by its header: one that
    commits to no values commits to what is known beforehand (the
    code counts a vote as missing only of a header that commits to
    values not yet had). So, of the last 144 headers:
    - no more than half commit to any values: init mode, for certain,
      with nothing fetched and nothing waited for. This is a network
      that is beginning, where nobody votes.
    - more than half do, and their values and the file with the most
      votes are had: that file.
    - more than half do, and some values or the file cannot be had:
      not known. The only hard case.
  - In the hard case a time after which init mode is taken would bring
    back what entry 16 is about: a node kept waiting would go to init
    mode of itself. Rather: go on waiting and say so (the node follows
    the chain; the message layer is said not to be ready, and why);
    keep to the file last known, of a node that was running; and ask
    more widely, several peers at once and others sought for it,
    before the peers it has are given up on. Leaning: never init mode
    by waiting.
- **A node that is running, as blocks come:** the same must hold
  from block to block, and it is the easier of the two.
  - What it has that a node catching up has not: the file changes
    only at heights that are multiples of 144, by the window ending
    there; a file that may win is seen at its first vote, up to a day
    before it can; both files stand for some blocks after a change
    (`consensus::GRACE`, 6; senders prefer the new from `SWITCH`, 2),
    which is there for nodes that hear of it at different moments;
    and it knows the file in force, which it can keep to.
  - Where it is open: a block's vote is fetched by itself after the
    block has come, and the last blocks before a boundary leave no
    time for that; and a file first voted for late in the window, or
    kept back throughout, may not be held when the boundary comes.
  - Proposed:
    1. A block's sixteen values go with the block (beside it, not in
       it: nothing of a block changes), 549 bytes. Whoever has a
       block has its vote: nothing is left to keep back by itself, and
       nothing to fetch in the last moments before a boundary. And of
       a node catching up: with the headers of the last windows.
    2. A file is fetched at its first vote, of several peers at once.
    3. At a boundary with something still lacking, a running node
       keeps to the file it has and says that it is behind: it neither
       takes a guess nor stops.
    4. The blocks of grace are how long it has. If the new file is
       still not held when the old one is to go, the node does not
       know, as one catching up does not, and says so.
  - The first does most: what was "votes can be kept back" becomes
    "blocks can be kept back", which a node deals with already.
- **Before any of it is built: read what is there, and set the
  times.**
  - The logic as it is written is to be gone through and checked
    against all of the above, not taken from its comments: how a
    header commits to its values, and whether one that commits to
    none is told from its header alone; how votes are counted over
    the window and at a boundary (`Chain::consensus`,
    `Chain::consensus_votes`, `consensus::Current::decide`); how the
    blocks of grace and the switch are kept to by whoever sends and
    whoever is reached; what `follow_votes` asks, of whom, and when
    it stops; what is kept and what is let go
    (`keep_consensus_files`); and what a node that takes its state
    from others has of all this when it is done.
  - The times are to be chosen, not left as they fell: how often
    votes and files are asked for again (2 s now), how many peers at
    once, how long one peer is given to answer, and how long a node
    waits before it says it does not know. Short enough that the
    network is not held up by a peer that says nothing; long enough
    for a slow link, which a satellite hop is (more than half a
    second each way: the times of the message layer were raised for
    that, to 5 s for a delivery and 10 s for a way to answer). Each
    with its reason written beside it.

- **So, to look into:**
  - How long a node can be held in that state by peers that do not
    give: one file is asked for at a time and one peer a turn, at the
    pace of `leaves_retry`; with `n` peers of which one is honest it
    is `n` turns at the worst. Whether to ask several at once.
  - What "could change the count" is, exactly, so that a node does
    not wait for what cannot matter (a file with fewer votes than one
    that is held and sound; votes too few to change which has most).
  - What is done by a node that was running and knew the file, when
    a new window brings a file it does not hold: whether it keeps to
    the file it knew until the new one is had, or stops sending.
  - A node all of whose peers keep the file back is cut off from it,
    as it would be from blocks; whether that is to be said somewhere
    (`consensus` at the prompt says what is skipped and why).
  - Who has the file at all: a miner that votes keeps its own file to
    hand over from the first block that votes for it; whether a file
    voted for by a miner that then does not serve it can be told from
    one that is being kept back, and what the network does then (as it
    is: the file cannot win on a node that does not hold it, which is
    every node, so all agree).
  - The same of the votes: a block's vote is not in the block, and is
    had from whoever has it; a miner that does not hand its own over
    leaves its blocks as not voting for everyone alike.
  - This is where entry 16 comes from: the further back the answer
    lies, the worse each of these is.

### 19. How long a block takes to prove, and more with a transaction in it

- **Seen:** live test, on six threads, with the table of the proof of
  work made. A block of a reward alone: 33 to 35 s. A block with one
  payment of one signature: 81.23 s (block 11) and 78.05 s (block
  146), against 34.62 s for the block before it. So one transaction
  costs about 45 s more.
- **Also seen:** the four-core runner that makes the setups took 32
  to 34 s for a block of a reward alone, the same as six threads
  here: the proving may not be making use of the threads it has.
- **Not known:** what it was before the last changes to the circuits
  on this machine; and what a block of many transactions takes
  (signatures are proven sixty-four at a time, so the second to the
  sixty-fourth should cost far less than the first).
- **To do:** time the parts of proving a block, of a reward alone and
  with one, eight and sixty-four transactions: the runs of
  transactions, the signatures, the work, the block's root, the
  chain's step, each with its threads. Then see what can be had:
  parts done side by side that are done one after another; what is
  proven for one signature that is the same for any (done once and
  kept); threads. Peak memory with each (5.5 GB at the most, in the
  live test).
- **Done so far:** the line that says how long a block took to prove now says where the time went, part by part: the work, the run (or runs, and their joining), the signatures, the signatures and work together, the block's root, the chain's step. To be read off the live network for a block of a reward alone and one with a transaction. What is known from the code: a block of a reward alone has a run of the smallest size made for it; a block with any transaction has a run of 2^15 rows at the least, a proof of signatures made for sixty-four at a time, and one more proof that puts the signatures and the work together. That is where the forty-five seconds are, and a smaller size of run and of signatures' proof for a block of a few transactions is what would take them back (shapes of the setup: batch E).

### 21. Two ways to slow a node down that were left as they are

Neither gives a wrong result; each has a bound. Both could be made
harder.

- **Blocks of a side branch with proofs that do not hold.** A block
  that is not on the chain is kept without its proof being looked at.
  A peer can give copies with bad proofs of the blocks of a branch;
  when that branch comes to have the most work, going over to it is
  held up by one fetch for each bad copy. Each bad copy costs the peer
  a strike and ten minutes of being passed over, and five strikes a
  ban. To make it harder: when a proof on the way does not hold, fetch
  every block of the branch not yet joined again at once.
- **A flood of ways being opened at a relay.** A relay keeps count of
  only so many ways being opened by those it does not know, and lets
  the oldest go: datagrams with made-up senders, enough of them, push
  out the ways wallets are really opening. The count is what keeps the
  flood from filling memory. Wallets go round a relay that does not
  answer. To make it harder: a token to be shown before a relay keeps
  anything of an opening.

### 22. Changes made that nothing tries directly

The code was in, and the tests there were passed with it; none of
these had a test of its own.

- **Tried now**, each by a test that fails with the change taken out:
  - A state being taken that would wait for ever at a step
    (`a_state_being_taken_goes_on_when_what_it_waited_for_is_done`).
  - The work of a header whose block is waited for being confirmed
    over and over (counted in
    `a_header_whose_block_nobody_has_sends_no_node_back`: once in a
    minute).
  - The rule for a fetch that is too slow
    (`a_fetch_is_slow_against_the_others_not_by_itself`; the rule is a
    function of its own now, `too_slow`).
  - A state taken though blocks could be had, let be after three
    rounds of nobody giving it
    (`a_state_nobody_gives_is_let_be_for_the_blocks`).
  - A chain that leaves this one far down and is weighed and found to
    have no more work (`a_chain_far_down_with_no_more_work_is_not_kept`).
  - A node with one peer, after a fetch from it failed (entry 20).
- **Still not tried:**
  - What it costs to make the state as of an earlier block, counted
    for all workers together: wants several workers asked for states
    as of different blocks at once.
  - A block that cannot be read when it is asked for.
  - The short wait of a socket on Windows.
  - The watch on workers that have stopped looking up, on a worker
    that really has.
  - The bound on chains that leave this one far down (one at a time).
  - Two changes to the pool: other announcers of a transaction kept
    while it is fetched; a pooled transaction whose policy input no
    longer holds, dropped.
### 23. The wording of what the node says

- **Asked for:** to go over everything the node says, and put right
  what does not read well or does not say enough: the lines of the
  logs, what is said at start, what each command answers, `help`, and
  what is said when something is refused.
- **What to look for:**
  - The same thing called by one name everywhere (entry 7: the
    recovery phrase).
  - One of a thing and several said rightly (`1 transactions`).
  - A line that can be understood by whoever has not read the code,
    and says what to do where there is something to do.
  - What is refused says why, and what would be taken.
  - No more lines than are needed (entries 5 and 7).
  - What `status` says (entry 10), line by line.
- **Seen so far, and found to be clear enough as they are:**
  `Block 12 carries 1 transactions of the pool (1 signatures)`
  (but for the plural), and `reached at: 2 of 2 nodes` in `status`.
- **Done so far:** one of a thing and several, in the line of a block's transactions. The going over of everything is still to do: as a list of what is said now and what is proposed, to be read through and agreed.

### 24. A `supply` command

- **Asked for:** a command that says what the supply should be at the
  chain's height, by the emission (the sum of what each block so far
  pays), and what the outputs that are unspent come to. The two should
  be the same. It is there to show a fault if there is one.
- **To settle:**
  - Coins burned: a burn makes an output nobody can spend, which is
    among the unspent. Said apart, so that the line reads: expected,
    unspent, of which burned.
  - What it costs: to add up every unspent output is to read the
    whole set, which is millions of outputs on a chain of any age.
    Either the command is slow and says so as it goes, or the sum is
    kept with the state and changed with each block (then the command
    is instant, and adding it all up from the outputs is the check of
    that, asked for by an option).
  - What is said when they differ: both numbers and the difference,
    plainly, as an error.

## Done

### 1. The miner builds a template before the pool has dropped what just confirmed

- **Seen:** live test, 2026-11-22, block 12 on the miner (`main1`).
  Block 11 carried a payment. Right after it was won, the log said
  `Block 12 carries 1 transactions of the pool (1 signatures)`, and a
  quarter of a second later `Proving block 12` again, this time without
  the transaction.
- **Effect:** none on the chain. Block 12 was proven in the usual time
  and does not hold the payment twice. A moment of proving is thrown
  away, and the log line says something that is not so.
- **Change:** update the pool for the block just won before the next
  template is built, so the first template is the right one.
- **Done:** the pool is brought up to a block before whoever waits for the chain to move is told.

### 2. Block and proof sizes are not in the main log

- **Seen:** same test. To learn the sizes of the blocks so far we had to
  read them out of block announcements in `request.log`.
- **Change:** say the block's size (and its proof's) on the `Won block`
  and `Received block` lines.
- **Done:** `Won block` says the block's size and its proof's; `Received block` the block's size.

### 3. The space kept for the proof in a block has a thin margin

- **Seen:** same test. Over 29 blocks, a block was 421 to 433 KB (mean
  428 KB), nearly all of it the proof. The mempool keeps 440 KB of a
  block for the proof (`PROOF_BYTES`), 7 KB over the largest seen.
- **Change:** raise the reserve (450 KB, say), or measure the spread
  over many more blocks and set it from that.
- **Done, for now:** 450 KB. To be looked at once more when the proof is the size it will be (batch E).

### 5. What is said when a wallet is made is too long

- **Seen:** same test, at the miner's first start. After
  `Server is ready!` come a blank line, three lines about the twelve
  words, a blank line, the words indented, a blank line, and then the
  prompt.
- **Change:** `Server is ready!`, then one line, `Recovery phrase:`
  followed by the twelve words, then the prompt. Nothing else.
- **Done:** `Server is ready!`, then `Recovery phrase:` and the words on one line.

### 12. An address of the machine itself is told to other nodes

- **Seen:** a node started with a new directory and no `--peer` had
  `127.0.0.1:3737` among its peers at once.
- **What it is:** a node asked for peers tells of any it has live
  (`Peers::sample`), whatever kind of address each is; and a node told
  of addresses tries each (`Message::Peers`), refusing only port 0 and
  the unspecified, broadcast and multicast addresses. Another node of
  the same machine had `127.0.0.1:3737` live and told of it; the new
  one tried it, and the miner answered there, both being on one
  machine. On another machine it would have been that machine itself,
  or nothing. It is also kept in `peers.txt` and read again at the
  next start.
- **Change:** an address of the machine itself (`127.0.0.0/8`) is
  never told to another node, and never taken from one. Such a peer is
  one given on the command line and no other (two nodes on one
  machine, to try things).
- **To decide:** whether the same holds of the private ranges
  (`10/8`, `172.16/12`, `192.168/16`): they too mean nothing outside
  their own network, but two nodes of one network may rightly be each
  other's peers by them. Taken only if given, perhaps, and never told.
- **Done:** an address of the machine itself is not told, not taken from what a peer tells, and not kept in `peers.txt`. A node that is reached from one directly still answers it and has it as a peer: that is a node of the same machine, and the two-nodes-on-one-machine case needs it. The private ranges are as they were (still to decide).

### 18. A wallet made again says its new address

- **Seen:** a wallet made again from its words has another address
  than it had. That is as it is meant to be, and not what whoever
  restores one expects.
- **Change:** when a wallet is made again, one line:
  `Wallet's restored address: <address> (Note: this is different than the previous address)`.
- **Done:** the line is said after `Server is ready!`.

### 20. A node that stops catching up

- **Seen:** once, in the test `over_real_sockets_with_several_workers`
  on Windows: a node catching up over real sockets with several
  workers had its headers in after 3.1 s and its first block after
  1.9 s, reached block 10 of 25, and had nothing more in the five
  minutes it was given. The same code passed on Windows four times
  before and after. Earlier failures of this test, put down to a slow
  machine, were probably the same.
- **What it is:** not known. Ten blocks in two seconds and then none
  is not slowness: something stopped asking for the blocks after, or
  stopped giving them. It has been seen on Windows only, which does
  not say it is of Windows only: a fault between workers would be
  everywhere, and rarer elsewhere.
- **Where to look first:** a fetch that one worker finished or gave
  up while the list all workers share still has it as under way, so
  that nothing more is asked for; the turns the serving side gives
  among the addresses of a host; the rule for a fetch that is too
  slow.
- **Why it matters:** a node of the live network that stops catching
  up and says nothing is wrong would be this.
- **Found, and done:** a fetch of a block that comes to nothing (given up for silence, or as too slow) has its peer passed over for ten minutes, so that another is asked in its place. A node with one peer that can give the block then asked nobody for ten minutes: ten blocks and then none. Now, where nobody else holds the block, a peer that has been passed over for a little while (`sync.header_wait`) is asked again. Tried by `a_node_with_one_peer_asks_it_again_after_a_fetch_fails`, which stands at block 8 of 40 without the change. Why a fetch should fail at all between two nodes of one machine on the Windows runner is not known (datagrams lost on a machine doing much else, most likely); with the change it costs seconds, and the other test of real sockets no longer asks that no fetch fail.
