//! Memory-hard proof of work in the style of Ethash, seeded by a text
//! that the chain exists to preserve.
//!
//! The seed is the American King James Bible as the gzip file
//! `resources/akjv.txt.gz` ([`SEED_TEXT_LEN`] bytes), in the binary and
//! used as it is: nothing is decompressed. Its bytes are read in
//! **windows** of 64 bytes, a Blake3 block: [`WINDOWS`] of them, a power
//! of two, spread evenly from the file's first byte to its last, so that
//! each overlaps the next and every byte is in one or two. A window is
//! picked by the low bits of a word, every one as likely as another.
//!
//! Every dataset item is made from the windows: from a key that is the
//! item's index, each of [`PowParams::parents`] steps picks a window by
//! the key and hashes it under the key, which gives the next. Miners keep the items
//! in a table of 64-byte items. The work of a header ([`hashimoto`])
//! seeds a mix of 32 words from the header's hash and a nonce and makes
//! [`PowParams::accesses`] reads, each folding in two adjacent items and
//! one window of the file itself; it then hashes the mix, and that with
//! the seed.
//!
//! # Validating a block requires the seed file, all of it
//!
//! Checking a header's work without the table computes the 128 items it
//! reads from the file: `128 * parents` windows, and 64 more read
//! directly, each picked by a hash, which nobody can foretell or steer.
//! At the parameters here one header's work reads most of the file, and
//! a few headers' all of it ([`tests`] measure both). So neither the
//! table nor any hash of the file stands in for it, no part of it can be
//! left out, and a node missing any window soon meets a block it cannot
//! validate. Every validating node keeps the file.
//!
//! # Verifiers and miners
//!
//! A verifier computes only the items a header's work touches, from the
//! file ([`SeedText::table`]): 128 of them, each the same work whatever
//! the table's size, since an item is made from its index and the text
//! and from no other item. A hash costs three compressions with the
//! table and about `2 * accesses * parents` without it, so a miner keeps
//! the table.
//!
//! # The table grows
//!
//! The chain is divided into epochs of [`PowParams::epoch_blocks`]
//! blocks. The table has `2^log_dataset_items` items in the first and
//! twice as many in each one after, until it has
//! `2^max_log_dataset_items`: on mainnet 1 GB, doubling each year to
//! 32 GB. An item is the same in every epoch, so a table that grows
//! keeps the items it has, and which table a block's work is of depends
//! on its height alone.
//!
//! # The arithmetic
//!
//! Words of 32 bits. The mixing step is Ethash's FNV,
//! `(a * 0x01000193) ^ b`, cheap enough that a hash's cost is its reads
//! of the table; the hashes are Blake3, each a call any Blake3 library
//! makes.

use crate::blake3;
use crate::hash::{DOM_POW_ITEM, DOM_POW_MIX, DOM_POW_RESULT, DOM_POW_SEED, Digest, hash_domain};

/// One dataset item: 16 words, 64 bytes.
pub type Item = [u32; 16];
/// A nonce: 32 bytes, any.
pub type Nonce = [u8; 32];

/// The seed file: the text gzipped, in the binary and used as it is.
pub const SEED_TEXT_GZ: &[u8] = include_bytes!("../resources/akjv.txt.gz");
/// Its size, checked when it is first used.
pub const SEED_TEXT_LEN: usize = 1_291_059;
/// Bytes of a window: a Blake3 block.
pub const WINDOW: usize = 64;
/// Windows, as a power of two.
pub const LOG_WINDOWS: u32 = 15;
pub const WINDOWS: usize = 1 << LOG_WINDOWS;
// Each window overlaps the next: every byte is in one.
const _: () = assert!((SEED_TEXT_LEN - WINDOW) / (WINDOWS - 1) < WINDOW);

const FNV_PRIME: u32 = 0x0100_0193;
/// Words of the mix: two items.
const MIX_WORDS: usize = 32;

/// `(a * FNV_PRIME) ^ b`.
#[inline(always)]
fn fnv(a: u32, b: u32) -> u32 {
    a.wrapping_mul(FNV_PRIME) ^ b
}

/// The proof of work's parameters: how large the table is in each
/// epoch, and how much work an item and a hash are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowParams {
    /// The table has `2^log_dataset_items` items in the first epoch.
    pub log_dataset_items: u32,
    /// It doubles each epoch until it has `2^max_log_dataset_items`.
    pub max_log_dataset_items: u32,
    /// Blocks in an epoch.
    pub epoch_blocks: u32,
    /// Steps of an item, each hashing one window of the text.
    pub parents: usize,
    /// Reads of the table (of two adjacent items each) a hash makes.
    pub accesses: usize,
}

impl PowParams {
    /// A table of 1 GB that doubles each year (52,560 blocks of ten
    /// minutes) to 32 GB.
    pub const MAINNET: PowParams = PowParams {
        log_dataset_items: 24,
        max_log_dataset_items: 29,
        epoch_blocks: 144 * 365,
        parents: 254,
        accesses: 64,
    };

    /// The dev networks': a 64 KB table that does not grow.
    pub const DEV: PowParams = PowParams { log_dataset_items: 10, max_log_dataset_items: 10, ..Self::MAINNET };

    /// The epoch of the block at `height`.
    pub const fn epoch_of(&self, height: u64) -> u32 {
        let e = height / self.epoch_blocks as u64;
        if e > u32::MAX as u64 { u32::MAX } else { e as u32 }
    }

    /// `log2` of the table's items in epoch `epoch`.
    pub const fn log_items(&self, epoch: u32) -> u32 {
        let room = self.max_log_dataset_items - self.log_dataset_items;
        self.log_dataset_items + if epoch < room { epoch } else { room }
    }

    /// `log2` of the items of the table the work of the block at
    /// `height` is of.
    pub const fn log_items_at(&self, height: u64) -> u32 {
        self.log_items(self.epoch_of(height))
    }

    const fn check(&self) {
        assert!(self.log_dataset_items >= 7 && self.log_dataset_items <= self.max_log_dataset_items);
        assert!(self.max_log_dataset_items <= 32, "an item's index is picked by one word");
        assert!(self.epoch_blocks > 0);
    }

    /// Whether a table of `2^log_items` items is one of the schedule's.
    const fn has_table(&self, log_items: u32) -> bool {
        log_items >= self.log_dataset_items && log_items <= self.max_log_dataset_items
    }
}

const _: () = PowParams::MAINNET.check();
const _: () = PowParams::DEV.check();

/// Bytes of a table of `2^log_items` items.
pub const fn table_bytes(log_items: u32) -> u64 {
    64u64 << log_items
}

/// Where window `w` begins: the windows are spread evenly, the first at
/// the text's first byte and the last ending at its last.
pub const fn window_offset(w: usize, len: usize) -> usize {
    ((w as u64 * (len - WINDOW) as u64) / (WINDOWS as u64 - 1)) as usize
}

/// A nonce with the number in its first eight bytes, for a search in
/// order.
pub fn nonce_from_u64(n: u64) -> Nonce {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

/// The key an item's steps begin from: its index, under a mark.
pub fn first_key(index: usize) -> [u32; 8] {
    [index as u32, (index as u64 >> 32) as u32, DOM_POW_ITEM, 0, 0, 0, 0, 0]
}

/// Where a table's items come from: a table, or the text.
pub trait ItemSource {
    fn params(&self) -> &PowParams;
    /// `log2` of the table's items.
    fn log_items(&self) -> u32;
    fn item(&self, index: usize) -> Item;
    fn seed(&self) -> &SeedText<'_>;
}

/// The seed text, with the parameters items are made by.
#[derive(Clone, Copy)]
pub struct SeedText<'a> {
    params: PowParams,
    text: &'a [u8],
}

impl SeedText<'static> {
    /// The file in the binary.
    pub fn new(params: PowParams) -> SeedText<'static> {
        assert_eq!(SEED_TEXT_GZ.len(), SEED_TEXT_LEN, "the seed file is not the one expected");
        SeedText { params, text: SEED_TEXT_GZ }
    }
}

impl<'a> SeedText<'a> {
    /// Another text of the seed file's length: for tests.
    pub fn from_bytes(params: PowParams, text: &'a [u8]) -> SeedText<'a> {
        assert_eq!(text.len(), SEED_TEXT_LEN);
        SeedText { params, text }
    }

    pub fn params(&self) -> &PowParams {
        &self.params
    }

    /// Window `w`'s bytes.
    pub fn window(&self, w: usize) -> &'a [u8] {
        let at = window_offset(w, self.text.len());
        &self.text[at..at + WINDOW]
    }

    /// The windows an item is made of, in order, and the item. Its
    /// first key is its index under a mark; each of `parents` steps picks
    /// a window by the key's first word and hashes it under the key,
    /// which gives the next key. The item is the last key and the one
    /// before it. No other item enters, nor the table's size.
    fn item_and_windows(&self, index: usize, mut read: impl FnMut(usize)) -> Item {
        assert!(index as u64 >> self.params.max_log_dataset_items == 0, "no table has such an item");
        let mut state = first_key(index);
        let mut before = state;
        for _ in 0..self.params.parents {
            let w = state[0] as usize & (WINDOWS - 1);
            read(w);
            before = state;
            state = blake3::words(&blake3::keyed_hash(&blake3::bytes(&state), self.window(w)));
        }
        std::array::from_fn(|i| if i < 8 { state[i] } else { before[i - 8] })
    }

    /// Dataset item `index`.
    pub fn calc_dataset_item(&self, index: usize) -> Item {
        self.item_and_windows(index, |_| {})
    }

    /// The items of the table the block at `height` is mined with, each
    /// made from the file when asked for: what a verifier checks a
    /// header's work with.
    pub fn at(&self, height: u64) -> SeedItems<'a> {
        self.table(self.params.log_items_at(height))
    }

    /// The items of the table of `2^log_items` items, made when asked
    /// for.
    pub fn table(&self, log_items: u32) -> SeedItems<'a> {
        assert!(self.params.has_table(log_items), "no epoch has a table of 2^{log_items} items");
        SeedItems { seed: *self, log_items }
    }
}

/// A table's items made from the seed file as they are asked for: a
/// verifier's source. It holds no item.
#[derive(Clone, Copy)]
pub struct SeedItems<'a> {
    seed: SeedText<'a>,
    log_items: u32,
}

impl ItemSource for SeedItems<'_> {
    fn params(&self) -> &PowParams {
        &self.seed.params
    }

    fn log_items(&self) -> u32 {
        self.log_items
    }

    fn item(&self, index: usize) -> Item {
        self.seed.calc_dataset_item(index)
    }

    fn seed(&self) -> &SeedText<'_> {
        &self.seed
    }
}

/// A table made whole, in memory: for the small ones of tests and the
/// dev networks.
pub struct Dataset<'a> {
    seed: SeedText<'a>,
    log_items: u32,
    items: Vec<Item>,
}

impl<'a> Dataset<'a> {
    pub fn generate(seed: &SeedText<'a>, log_items: u32) -> Dataset<'a> {
        assert!(seed.params.has_table(log_items));
        let mut items = vec![[0u32; 16]; 1 << log_items];
        crate::parallel::par_fill_min(&mut items, 16, |i| seed.calc_dataset_item(i));
        Dataset { seed: *seed, log_items, items }
    }
}

impl ItemSource for Dataset<'_> {
    fn params(&self) -> &PowParams {
        &self.seed.params
    }

    fn log_items(&self) -> u32 {
        self.log_items
    }

    fn item(&self, index: usize) -> Item {
        self.items[index]
    }

    fn seed(&self) -> &SeedText<'_> {
        &self.seed
    }
}

/// The seed of a header's work: a hash of the header's hash and the
/// nonce.
fn seed(header_hash: &Digest, nonce: &Nonce) -> [u32; 8] {
    blake3::words(&hash_domain(DOM_POW_SEED, &[&header_hash[..], nonce].concat()))
}

fn result(mix: &Digest, seed: &[u32; 8]) -> Digest {
    hash_domain(DOM_POW_RESULT, &[&mix[..], &blake3::bytes(seed)].concat())
}

/// The result for a mix a header claims: two compressions and no table.
/// A cheap check before the work is done again.
pub fn result_from_mix(header_hash: &Digest, nonce: &Nonce, mix: &Digest) -> Digest {
    result(mix, &seed(header_hash, nonce))
}

/// What one evaluation of the work gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowOutput {
    /// The mix, folded: kept in the header, for verifiers to check.
    pub mix: Digest,
    /// The hash that is held against the target.
    pub result: Digest,
}

/// What a hash reads, for whoever wants to know: an item's index, or a
/// window read directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    Item(usize),
    Window(usize),
}

fn hashimoto_reading<S: ItemSource>(
    source: &S,
    header_hash: &Digest,
    nonce: &Nonce,
    mut read: impl FnMut(Read),
) -> PowOutput {
    let params = source.params();
    let text = source.seed();
    let seed = seed(header_hash, nonce);
    let mut mix: [u32; MIX_WORDS] = std::array::from_fn(|k| seed[k % 8]);
    let pairs = 1usize << (source.log_items() - 1);
    for i in 0..params.accesses {
        let sel = fnv(i as u32 ^ seed[0], mix[0]);
        let sel2 = fnv(i as u32 ^ seed[1], mix[16]);
        let idx = (sel as usize & (pairs - 1)) * 2;
        let window = sel2 as usize & (WINDOWS - 1);
        read(Read::Item(idx));
        read(Read::Item(idx + 1));
        read(Read::Window(window));
        let x: [u32; 16] = blake3::words(text.window(window));
        let (a, b) = (source.item(idx), source.item(idx + 1));
        for (k, (m, d)) in mix.iter_mut().zip(a.iter().chain(&b)).enumerate() {
            *m = fnv(*m, *d) ^ x[k % 16];
        }
    }
    let mix = hash_domain(DOM_POW_MIX, &mix.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
    PowOutput { mix, result: result(&mix, &seed) }
}

/// The memory-hard hash of a header's hash and a nonce, with `source`
/// for the table's items and the seed file. Each access folds in two
/// adjacent items, picked by `fnv(i ^ seed[0], mix[0])` among the
/// table's pairs, and one window of the file, picked by
/// `fnv(i ^ seed[1], mix[16])`: the window's word `k % 16` is folded
/// into the mix's word `k` after its item's. The mix is then hashed.
pub fn hashimoto<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce) -> PowOutput {
    hashimoto_reading(source, header_hash, nonce, |_| {})
}

/// Whether `mix` is the true mix of the header's work and `meets` takes
/// its result: by a table with the seed file, or by the file alone.
pub fn verify<S: ItemSource>(
    source: &S,
    header_hash: &Digest,
    nonce: &Nonce,
    mix: &Digest,
    meets: impl Fn(&Digest) -> bool,
) -> bool {
    let out = hashimoto(source, header_hash, nonce);
    out.mix == *mix && meets(&out.result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> SeedText<'static> {
        SeedText::new(PowParams::DEV)
    }

    #[test]
    fn the_windows_cover_the_file() {
        let mut covered = vec![0u8; SEED_TEXT_LEN];
        for w in 0..WINDOWS {
            let at = window_offset(w, SEED_TEXT_LEN);
            assert!(at + WINDOW <= SEED_TEXT_LEN);
            covered[at..at + WINDOW].iter_mut().for_each(|c| *c += 1);
        }
        assert_eq!(
            (window_offset(0, SEED_TEXT_LEN), window_offset(WINDOWS - 1, SEED_TEXT_LEN)),
            (0, SEED_TEXT_LEN - WINDOW)
        );
        assert!(covered.iter().all(|c| (1..=2).contains(c)));
        // The file is the one the chain is to keep: a gzip file.
        assert_eq!(SEED_TEXT_GZ[..2], [0x1F, 0x8B]);
    }

    #[test]
    fn a_table_s_items_are_the_text_s() {
        let seed = text();
        let table = Dataset::generate(&seed, 10);
        for i in [0, 1, 513, 1023] {
            assert_eq!(table.item(i), seed.calc_dataset_item(i));
        }
        assert_ne!(table.item(0), table.item(1));
        // And every hash made of them is the same either way.
        let (hash, nonce) = ([7u8; 32], nonce_from_u64(3));
        let out = hashimoto(&table, &hash, &nonce);
        assert_eq!(out, hashimoto(&seed.table(10), &hash, &nonce));
        assert_eq!(out.result, result_from_mix(&hash, &nonce, &out.mix));
        assert!(verify(&seed.table(10), &hash, &nonce, &out.mix, |_| true));
        assert!(!verify(&seed.table(10), &hash, &nonce, &[0; 32], |_| true));
        assert!(!verify(&seed.table(10), &hash, &nonce, &out.mix, |_| false));
        assert_ne!(out, hashimoto(&table, &hash, &nonce_from_u64(4)));
        assert_ne!(out, hashimoto(&table, &[8u8; 32], &nonce));
    }

    #[test]
    fn another_text_is_other_work() {
        // A byte of the file changed, in a window an item reads: that
        // item is another, and an item that reads no window with the
        // byte is as it was.
        let seed = text();
        let windows = |i: usize| {
            let mut read = Vec::new();
            seed.item_and_windows(i, |w| read.push(w));
            read
        };
        let byte = window_offset(windows(0)[100], SEED_TEXT_LEN) + 20;
        let mut other = SEED_TEXT_GZ.to_vec();
        other[byte] ^= 1;
        let changed = SeedText::from_bytes(PowParams::DEV, &other);
        assert_ne!(seed.calc_dataset_item(0), changed.calc_dataset_item(0));
        let reads_it =
            |i: usize| windows(i).iter().any(|w| (window_offset(*w, SEED_TEXT_LEN)..).take(WINDOW).any(|b| b == byte));
        let clear = (1..64).find(|i| !reads_it(*i)).unwrap();
        assert_eq!(seed.calc_dataset_item(clear), changed.calc_dataset_item(clear));
    }

    /// The bytes of the file one header's work reads when it is checked
    /// from the file, marked in `seen`.
    fn reads(seed: &SeedText, header: u64, seen: &mut [bool]) {
        let hash = hash_domain(DOM_POW_SEED, &header.to_le_bytes());
        let mut mark = |w: usize| {
            let at = window_offset(w, SEED_TEXT_LEN);
            seen[at..at + WINDOW].iter_mut().for_each(|s| *s = true);
        };
        let mut items = Vec::new();
        hashimoto_reading(&seed.table(seed.params.log_dataset_items), &hash, &nonce_from_u64(header), |r| match r {
            Read::Item(i) => items.push(i),
            Read::Window(w) => mark(w),
        });
        for i in items {
            seed.item_and_windows(i, &mut mark);
        }
    }

    #[test]
    fn checking_work_needs_the_file() {
        // One header's work, checked from the file, reads most of it, at
        // places its hash picks; a few headers' read all of it.
        let seed = SeedText::new(PowParams::MAINNET);
        let mut all = vec![false; SEED_TEXT_LEN];
        let mut blocks_to_all = 0;
        let mut least = 1.0f64;
        for header in 0..40 {
            let mut one = vec![false; SEED_TEXT_LEN];
            reads(&seed, header, &mut one);
            let part = one.iter().filter(|s| **s).count() as f64 / SEED_TEXT_LEN as f64;
            least = least.min(part);
            all.iter_mut().zip(&one).for_each(|(a, o)| *a |= *o);
            if blocks_to_all == 0 && all.iter().all(|s| *s) {
                blocks_to_all = header + 1;
            }
        }
        println!(
            "a header's work reads at least {:.1}% of the file; {blocks_to_all} headers read all of it",
            100.0 * least
        );
        assert!(least > 0.7, "{least}");
        assert!((1..=30).contains(&blocks_to_all), "{blocks_to_all}");
    }
}
