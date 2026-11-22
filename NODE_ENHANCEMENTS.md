# Node enhancements

Things seen while running the node that we may want to change. Not
ordered yet: once the list is long enough to be worth it, we prioritize.

Each entry says what was seen, where, and what the change would be.

## Open

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

### 2. Block and proof sizes are not in the main log

- **Seen:** same test. To learn the sizes of the blocks so far we had to
  read them out of block announcements in `request.log`.
- **Change:** say the block's size (and its proof's) on the `Won block`
  and `Received block` lines.

### 3. The space kept for the proof in a block has a thin margin

- **Seen:** same test. Over 29 blocks, a block was 421 to 433 KB (mean
  428 KB), nearly all of it the proof. The mempool keeps 440 KB of a
  block for the proof (`PROOF_BYTES`), 7 KB over the largest seen.
- **Change:** raise the reserve (450 KB, say), or measure the spread
  over many more blocks and set it from that.

### 4. Blocks reach one seed a chunk at a time

- **Seen:** same test. The RISC-V seed asked the miner for each block in
  requests of one chunk, about one every 1.3 seconds: 312 such requests
  over 23 blocks. It kept up, a block or two behind at the worst.
- **Effect:** none at a ten-minute block time. At the test's 34 seconds
  a block it is close to the limit.
- **Change:** look at why the transfer window to that node stays at one
  chunk (a slow or lossy path, or pacing that does not recover), and
  whether it should grow again sooner.

## Done

(Nothing yet.)
