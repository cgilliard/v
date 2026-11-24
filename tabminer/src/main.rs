//! `tabminer [options]`: a node of the Tabernacle network.
//!
//! What it is told is read and checked ([`Configuration`]); then
//! everything it needs is opened: the logs, the store, the port. Only
//! when all of that is done does it say how it is configured and, in
//! the next line, that it is ready: from then on it takes requests,
//! until it is ended: nothing is done about being told to stop, since
//! nothing has to be put in order first (`docs/RUNNING.md`).

use std::io::{BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tabminer::chain::Chain;
use tabminer::chain::params::ChainParams;
use tabminer::configuration::{Configuration, Network, hex};
use tabminer::console::{Console, Reply};
use tabminer::logger::Logger;
use tabminer::logger::fmt::{bytes, commas, seconds, short_seconds};
use tabminer::logger::queued::Queued;
use tabminer::logger::stats::{Stats, StatsLog};
use tabminer::miner::{self, HoldOff, Mined, Now};
use tabminer::net::node::{Behind, Event, Handle, Node};
use tabminer::net::socket::{self, Watch};
use tabminer::pow::{Dataset, ItemSource, LazyDataset, SeedText};
use tabminer::prover::{ChainVerifier, Level, Setup};
use tabminer::store::backend::FileBackend;
use tabminer::wallet::follow::follow_when;
use tabminer::wallet::{Ask, Wallet, WalletError};

/// Every allocation of the node is counted: so that it can say how
/// much memory it holds, and the most it has held.
#[global_allocator]
static HEAP: tabminer::heap::Counting = tabminer::heap::Counting;

/// How blocks are made here: what a block may carry, and, for
/// debugging, what it is filled with in place of that.
#[derive(Clone, Copy)]
struct Making {
    /// Signatures a block checks at the most.
    max_signatures: usize,
    /// The height above which no block is made.
    blocks: Option<u64>,
    /// How long is waited after a block made here before the next is
    /// begun.
    delay: Duration,
    /// Debugging: the outputs every block makes, and how many of the
    /// outputs the chain began with it spends.
    fill: Option<(usize, usize)>,
    /// Debugging: the outputs the chain began with, and how far apart.
    filled: Option<(u64, u64)>,
}

impl Making {
    /// Debugging: what a block of `max_block_size` is filled with, if
    /// blocks are filled: as much of what was asked for as fits.
    fn filling(&self, max_block_size: usize) -> Option<(usize, usize)> {
        #[cfg(feature = "dev")]
        return self.fill.map(|(outputs, spends)| miner::fill_plan(max_block_size, outputs, spends));
        #[cfg(not(feature = "dev"))]
        return None.filter(|_: &(usize, usize)| max_block_size > 0 && self.fill.is_some() && self.filled.is_some());
    }
}

/// What the node's proofs are made with: made once, when the node
/// starts, or behind its start where the setup is one that is built
/// in (which is some seconds of work, and a node that is listening
/// and answering meanwhile is better than one that says nothing).
static SETUP: std::sync::OnceLock<Setup> = std::sync::OnceLock::new();

/// The setup: waited for, by whoever makes blocks, if it is still being
/// got ready.
fn setup() -> &'static Setup {
    loop {
        if let Some(setup) = SETUP.get() {
            return setup;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The whole table of a network whose table is small enough to make in
/// a moment (the dev networks'): headers are checked against it.
fn small_table(seed: &SeedText<'static>) -> Option<Dataset<'static>> {
    let params = seed.params();
    (params.max_log_dataset_items <= 12).then(|| Dataset::generate(seed, params.log_dataset_items))
}

/// The node's wallet, as its threads share it.
type Purse = Arc<Mutex<Wallet<FileBackend>>>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let read = |path: &Path| std::fs::read_to_string(path);
    let configuration = match Configuration::read(&args, home.as_deref(), &here, &read) {
        // A thread to a core, unless told how many (a core, not each of
        // the two threads a core may run): and from here on it is that
        // many, so that the log says the number.
        Ok(mut configuration) => {
            if configuration.threads == 0 {
                configuration.threads = tabminer::parallel::cores();
            }
            configuration
        }
        Err(refused) => {
            // The help asked for is what was asked for; the help after
            // something wrong is a failure.
            let (said, code) = refused.said();
            match code {
                0 => print!("{said}"),
                _ => eprint!("{said}"),
            }
            std::process::exit(code);
        }
    };
    let mut main_log = None;
    let Err(what) = run(&configuration, &mut main_log);
    // In the main log too, if it got as far as being opened.
    match &main_log {
        Some(main) => main.log_all(&format!("Error: {what}")),
        None => eprintln!("Error: {what}"),
    }
    std::process::exit(-1);
}

/// What the main log says of something that happened to the node, if
/// anything.
fn said(event: &Event) -> Option<String> {
    let n = |height: u32| commas(height as u64);
    let whose = |from: &Option<std::net::SocketAddrV4>| {
        from.map_or_else(|| "made here".to_string(), |from| format!("from {from}"))
    };
    Some(match event {
        Event::PeerConnected { peer, height } => format!("Peer {peer} connected (height {})", n(*height)),
        Event::PeerLost { peer } => format!("Peer {peer} lost"),
        Event::Banned { peer } => format!("Banned {}: it sent what no honest peer sends, too often", peer.ip()),
        Event::HeadersWanted { from, to, peer } => {
            format!("Syncing headers {} to {} (announced by {peer})", n(*from), n(*to))
        }
        Event::HeadersKept { height } => format!("Headers synced to {}", n(*height)),
        Event::HeadersRefused { peer } => format!("Headers from {peer} refused"),
        Event::FetchMoved { height, from, to, quiet, here, of } => format!(
            "Block {}: nothing more from {from} for {:.1}s, with {} of its {} chunks here; the rest is asked of {to}",
            n(*height),
            *quiet as f64 / 1e6,
            commas(*here as u64),
            commas(*of as u64)
        ),
        // (A block made here that joins the chain was said when won.)
        Event::Block { from: None, undone: 0, .. } => return None,
        Event::Block { header, len, from, undone: 0, .. } => {
            let bytes = tabminer::block::HEADER_SIZE as u64 + *len as u64;
            format!(
                "Received block {} ({}) of {} bytes {}",
                n(header.height),
                short(&header.hash()),
                commas(bytes),
                whose(from)
            )
        }
        // The chain went over to another branch.
        Event::Block { header, from, undone, taken, .. } => {
            let blocks = |k: u32| if k == 1 { "1 block".to_string() } else { format!("{} blocks", n(k)) };
            format!(
                "Reorganized to block {} ({}) {}: {} undone, {} taken, above block {}",
                n(header.height),
                short(&header.hash()),
                whose(from),
                blocks(*undone),
                blocks(*taken),
                n(header.height - taken)
            )
        }
        Event::Side { header, from: None } => {
            format!("Block {} ({}) made here is on a side branch", n(header.height), short(&header.hash()))
        }
        Event::Side { header, from: Some(from) } => {
            format!("Received block {} ({}) from {from}, on a side branch", n(header.height), short(&header.hash()))
        }
        Event::BlockRefused { header, from, why } => {
            format!("Refused block {} ({}) {}: {why}", n(header.height), short(&header.hash()), whose(from))
        }
        Event::Synced { height } => format!("Synced at block {}", n(*height)),
        Event::StateWanted { height, id, again: false } => {
            format!("Taking the state as of block {} ({})", n(*height), short(id))
        }
        Event::StateWanted { height, id, again: true } => {
            format!("Taking the state as of a later block, {} ({})", n(*height), short(id))
        }
        Event::StateTaken { height } => format!("State taken as of block {}", n(*height)),
        Event::Consensus { mode, file: Some(hash) } => format!(
            "The message layer is in {mode} mode: the consensus file {} is in force",
            hash[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        Event::Mail => return None,
        Event::Consensus { mode, file: None } => {
            format!("The message layer is in {mode} mode: no consensus file is in force")
        }
        Event::StateProgress { parts, of } => {
            format!("Taking the state: {} of {} parts ({}%)", commas(*parts), commas(*of), parts * 100 / (*of).max(1))
        }
    })
}

/// The first of a block's id, as the logs say it.
fn short(id: &tabminer::hash::Digest) -> String {
    hex(&tabminer::hash::digest_to_bytes(id)[..4])
}

/// Makes blocks, one after another, on whatever the chain's last block
/// is: begun again whenever that changes, and not while the node is
/// catching up with a chain ahead of its own.
fn make_blocks(
    hold: &Handle<FileBackend, ChainVerifier>,
    seed: SeedText<'static>,
    kept: &Path,
    prebuild: bool,
    making: Making,
    wallet: &Purse,
    main: &Arc<Logger>,
    stats: &Arc<Stats>,
) {
    // The table of the proof of work, for the height blocks are now
    // made at: what a file of it from an earlier run holds, and the
    // rest filled as it is read, and by a thread that does nothing
    // else until it is whole.
    let pow = hold.chain().params().pow;
    let size = |log_items: u32| bytes(tabminer::pow::table_bytes(log_items));
    let next = hold.chain().tip().map_or(1, |tip| tip.height as u64 + 1);
    let table = match LazyDataset::open(&seed, pow.log_items_at(next), kept) {
        Ok(table) => Arc::new(RwLock::new(table)),
        Err(e) => {
            let needed = size(pow.log_items_at(next));
            return main.log(&format!("Error: no blocks are made: the table of the proof of work ({needed}): {e}"));
        }
    };
    // What a file kept from an earlier run gave, if it gave the whole.
    if table.read().unwrap_or_else(|e| e.into_inner()).is_complete() {
        let whole = size(pow.log_items_at(next));
        main.log(&format!("The table of the proof of work ({whole}) was read from '{}'", kept.display()));
    }
    fill_table(&table, kept, main, prebuild);
    // Where this miner's nonces begin: its own, as likely as not.
    let mut start = [0u8; 8];
    let _ = tabminer::random::fill(&mut start);
    let mut start = u64::from_le_bytes(start);
    let mut hold_off = HoldOff::new(hold.chain().params().schedule.block_time.max(1) as u64);
    // Blocks given up that have not yet let go.
    let mut letting_go: std::collections::VecDeque<std::thread::JoinHandle<()>> = Default::default();
    loop {
        let seen = hold.moves();
        // No higher than told to.
        if making.blocks.is_some_and(|most| hold.read().height as u64 >= most) {
            hold.wait_moved(seen, Duration::from_secs(60));
            continue;
        }
        // Not while the state is being taken; and not, for a while,
        // while a chain known to be ahead of ours is coming in.
        let ahead = match hold.behind() {
            Behind::State => {
                hold.wait_moved(seen, Duration::from_secs(1));
                continue;
            }
            Behind::Blocks { best, height } => Some((best, height)),
            Behind::No => None,
        };
        match (hold_off.ask(ahead.map(|(best, _)| best), Instant::now()), ahead) {
            (Now::Wait { first }, Some((best, height))) => {
                if first {
                    main.log(&format!(
                        "Not mining: a chain ahead is coming in, to block {} ({})",
                        commas(height as u64),
                        short(&best)
                    ));
                }
                hold.wait_moved(seen, Duration::from_secs(1));
                continue;
            }
            (Now::MineAnyway { first: true }, Some((best, height))) => main.log(&format!(
                "Mining again: the blocks of the chain ahead, to block {} ({}), have not come in {}",
                commas(height as u64),
                short(&best),
                seconds(hold_off.limit().as_millis() as u64)
            )),
            _ => {}
        }
        start = start.wrapping_add(1 << 32);
        // Two steps, each said as it is begun: the block's proof is
        // made, and then the nonce is looked for.
        let on = hold.chain().tip().ok().map(|tip| (commas(tip.height as u64 + 1), short(&tip.hash())));
        if let Some((height, parent)) = &on {
            main.log(&format!("Proving block {height} on {parent}"));
        }
        // The table grows with the chain, a year at a time: what it
        // has stays, and the rest is filled as the first was.
        let wanted = hold.chain().tip().map_or(0, |tip| pow.log_items_at(tip.height as u64 + 1));
        if table.read().unwrap_or_else(|e| e.into_inner()).log_items() < wanted {
            main.log(&format!("The table of the proof of work grows to {}", size(wanted)));
            if let Err(e) = table.write().unwrap_or_else(|e| e.into_inner()).grow(wanted) {
                return main.log(&format!("Error: no more blocks are made: the table of the proof of work: {e}"));
            }
            fill_table(&table, kept, main, prebuild);
        }
        // The block is made on a thread of its own, which is not
        // waited for when the chain has another last block: the next
        // block is begun at once, and the one given up lets go where
        // it next asks whether to go on, seconds later at the most.
        // One may be letting go beside the one being made, and no
        // more: an older one is waited for.
        letting_go.retain(|attempt| !attempt.is_finished());
        while letting_go.len() > 1 {
            if let Some(old) = letting_go.pop_front() {
                let _ = old.join();
            }
        }
        let (done, ended) = std::sync::mpsc::channel::<bool>();
        let attempt = {
            let (hold, table, main, stats) = (hold.clone(), Arc::clone(&table), Arc::clone(main), Arc::clone(stats));
            let (wallet, watch) = (Arc::clone(wallet), ahead.is_none());
            std::thread::Builder::new().name("block".into()).spawn(move || {
                let finished = make_block(&hold, &table, &wallet, &main, &stats, making, seen, watch, start, on);
                let _ = done.send(finished);
            })
        };
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(e) => return main.log(&format!("Error: no more blocks are made: no thread to make one on: {e}")),
        };
        // Until it has come to its end, or the chain has moved.
        let ended = loop {
            match ended.try_recv() {
                Ok(finished) => break Some(finished),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break Some(false),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if hold.moves() != seen {
                break None;
            }
            hold.wait_moved(seen, Duration::from_millis(250));
        };
        match ended {
            Some(true) => return,
            Some(false) => {
                if attempt.join().is_err() {
                    return main.log("Error: no more blocks are made: making one failed");
                }
            }
            None => letting_go.push_back(attempt),
        }
    }
}

/// Makes one block on the chain's last, which was the last when the
/// chain had moved `seen` times: given up when it has another, or
/// (`watch`) when a chain ahead turns up that is to be waited for.
/// Won, it is handed to the node, and what comes of it waited for.
/// True if the chain has had its last block.
#[allow(clippy::too_many_arguments)]
fn make_block(
    hold: &Handle<FileBackend, ChainVerifier>,
    table: &RwLock<LazyDataset<'static>>,
    wallet: &Purse,
    main: &Logger,
    stats: &Stats,
    making: Making,
    seen: u64,
    watch: bool,
    start: u64,
    on: Option<(String, String)>,
) -> bool {
    // (A chain ahead is looked for a few times a second, not at every
    // hash.)
    let looked = std::sync::Mutex::new(Instant::now());
    // (When the chain was first seen to have another last block: for
    // how long the letting go then took, which `TABMINER_TIMING` has
    // said.)
    let noticed = std::sync::Mutex::new(None::<Instant>);
    let cancel = || {
        if hold.moves() != seen {
            noticed.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(Instant::now);
            return true;
        }
        let mut looked = looked.lock().unwrap_or_else(|e| e.into_inner());
        if !watch || looked.elapsed() < Duration::from_millis(250) {
            return false;
        }
        *looked = Instant::now();
        hold.behind() != Behind::No
    };
    let proved = |took: Duration| {
        if let Some((height, parent)) = &on {
            let took = short_seconds(took.as_millis() as u64);
            // (And where the time went, part by part.)
            let parts: Vec<String> = tabminer::prover::parts_timed()
                .iter()
                .map(|(name, took)| format!("{name} {}", short_seconds(took.as_millis() as u64)))
                .collect();
            let parts = if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) };
            main.log(&format!("Mining block {height} on {parent}: proved in {took}{parts}"));
        }
    };
    // What the block carries of the pool: none, if it cannot be
    // chosen.
    // (Debugging: none, of a block that is filled with what nobody
    // sent.)
    let filling = making.filling(hold.chain().params().max_block_size);
    let chosen = match filling {
        Some(_) => Ok((Vec::new(), Vec::new())),
        None => miner::choose(hold.chain(), setup(), &|f| hold.pool(f), making.max_signatures),
    };
    let (pooled, sweeps) = match chosen {
        Ok(chosen) => chosen,
        Err(e) => {
            main.log(&format!("Error: choosing a block's transactions: {e}"));
            (Vec::new(), Vec::new())
        }
    };
    if let Some((height, _)) = &on
        && !pooled.is_empty()
    {
        let signatures: usize = pooled.iter().map(|tx| tx.weight()).sum();
        let some =
            |n: usize, one: &str, more: &str| format!("{} {}", commas(n as u64), if n == 1 { one } else { more });
        main.log(&format!(
            "Block {height} carries {} of the pool ({})",
            some(pooled.len(), "transaction", "transactions"),
            some(signatures, "signature", "signatures")
        ));
    }
    // What it pays is paid to the wallet: an output made for this
    // block, and forgotten if the block comes to nothing.
    let unix = socket::unix();
    let purse = || wallet.lock().unwrap_or_else(|e| e.into_inner());
    let paid = match miner::reward_due(hold.chain(), &pooled) {
        // (A block that is filled makes an output of one unit for each
        // it is filled with: its reward is less by as many.)
        Ok(Some((height, due))) => {
            let due = due.saturating_sub(filling.map_or(0, |(outputs, _)| outputs as u64));
            purse().reward(due, height, unix).map_err(|e| e.to_string())
        }
        Ok(None) => return true,
        Err(e) => Err(e.to_string()),
    };
    let paid = match paid {
        Ok(paid) => paid,
        Err(e) => {
            main.log(&format!("Error: making a block: its reward: {e}"));
            hold.wait_moved(seen, Duration::from_secs(1));
            return false;
        }
    };
    let dataset = table.read().unwrap_or_else(|e| e.into_inner());
    let made = match filling {
        #[cfg(feature = "dev")]
        Some((outputs, spends)) => {
            let said = |line: &str| main.log(line);
            let (chain, filled) = (hold.chain(), making.filled);
            miner::mine_filled(chain, &*dataset, &paid, unix, start, outputs, spends, filled, &said, &cancel)
        }
        _ => miner::mine_with(hold.chain(), setup(), &*dataset, &paid, unix, start, &pooled, &sweeps, &proved, &cancel),
    };
    // (The table is let go with the work done: what follows waits for
    // the block to be applied, minutes at the worst, and the table
    // could not grow meanwhile, nor anyone begin to read it once it
    // was waiting to.)
    drop(dataset);
    // Kept, with its block's id, before the block is handed over; and
    // forgotten at once if there is no block.
    let kept = match &made {
        Ok(Mined::Block { header, .. }) => {
            purse().reward_found(&paid.commitment, &tabminer::hash::digest_to_bytes(&header.hash()))
        }
        _ => purse().forget(&paid.commitment).map(|_| ()),
    };
    if let Err(e) = kept {
        main.log(&format!("Error: the wallet's record of a block's reward: {e}"));
    }
    match made {
        Ok(Mined::Block { block, header, hashes, solved, .. }) => {
            // (Its size, and its proof's: nearly all of a block that
            // carries little.)
            let proof = tabminer::block::BlockRef::from_bytes(&block).map_or(0, |b| b.body().proof().len());
            main.log(&format!(
                "Won block {} ({}): {} hashes in {}; {} bytes, {} of them its proof",
                commas(header.height as u64),
                short(&header.hash()),
                commas(hashes),
                short_seconds(solved.as_millis() as u64),
                commas(block.len() as u64),
                commas(proof as u64)
            ));
            stats.add(socket::MINED, 1);
            // Until what came of it is heard: it is the chain's
            // last, or another got there first. Either way the next
            // is begun at once, on whatever the last then is. (However
            // long applying it takes, which on a slow disk and a large
            // state is minutes: a block begun meanwhile would be begun
            // on the block before, and be for nothing.)
            let settled = hold.settled();
            hold.mined(block, socket::unix());
            hold.wait_settled(settled, Duration::from_secs(600));
            // Its leaves are the node's own, which nobody else has: kept
            // with it, for whoever asks what its header commits to.
            // (Unless they were set to something else meanwhile, or the
            // block was not taken: then there is nothing to keep.)
            if header.aux != [0u8; 32]
                && let Ok(leaves) = hold.chain().aux_leaves()
            {
                let _ = hold.chain().put_aux_leaves(&header.hash(), &leaves);
            }
            // (And then for as long as it was told to, before the next.)
            std::thread::sleep(making.delay);
        }
        Ok(Mined::Cancelled) => {
            let noticed = *noticed.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(at) = noticed
                && std::env::var_os("TABMINER_TIMING").is_some()
            {
                main.log(&format!("Let go {} ms after the chain was seen to move", at.elapsed().as_millis()));
            }
        }
        // What was chosen no longer applies: again, in a moment, with
        // what is chosen then.
        Ok(Mined::Stale) => hold.wait_moved(seen, Duration::from_millis(200)),
        Ok(Mined::Finished) => return true,
        Err(e) => {
            main.log(&format!("Error: making a block: {e}"));
            hold.wait_moved(seen, Duration::from_secs(1));
        }
    }
    false
}

/// Fills what is missing of the table of the proof of work, on a thread
/// of its own, and keeps it in the file `kept` when it is whole: so
/// that the next run begins with it. (Blocks are made meanwhile: what
/// they read of the table is filled as they read it.)
fn fill_table(table: &Arc<RwLock<LazyDataset<'static>>>, kept: &Path, main: &Arc<Logger>, first: bool) {
    // Said here, before any thread is begun: so that it is always said
    // before what the caller goes on to say.
    {
        let table = table.read().unwrap_or_else(|e| e.into_inner());
        if table.is_complete() {
            return;
        }
        let whole = tabminer::pow::table_bytes(table.log_items());
        let there = whole / table.pairs() as u64 * table.filled() as u64;
        main.log(&format!(
            "Making the table of the proof of work: {} of {} are there. This may take a while{}",
            bytes(there),
            bytes(whole),
            if first { ": no blocks are made until it is whole" } else { "" }
        ));
    }
    let (shared, kept, told) = (Arc::clone(table), kept.to_path_buf(), Arc::clone(main));
    let fill = move || {
        let main = told;
        let table = shared.read().unwrap_or_else(|e| e.into_inner());
        let whole = tabminer::pow::table_bytes(table.log_items());
        let began = Instant::now();
        // How far it has got, at every twentieth.
        miner::fill_table(&table, Duration::from_millis(500), &|percent| {
            let there = bytes(whole / 100 * percent as u64);
            main.log(&format!("The table of the proof of work: {percent}% ({there} of {})", bytes(whole)));
        });
        main.log(&format!(
            "The table of the proof of work is whole: made in {}",
            seconds(began.elapsed().as_millis() as u64)
        ));
        // Kept, for the next run to begin with.
        match table.save(&kept) {
            Ok(()) => main.log(&format!("The table of the proof of work is kept in '{}'", kept.display())),
            Err(e) => main
                .log(&format!("Error: the table of the proof of work could not be kept in '{}': {e}", kept.display())),
        }
    };
    // Before any block is made, if so set; else beside the making of them.
    if first {
        return fill();
    }
    if let Err(e) = std::thread::Builder::new().name("pow table".into()).spawn(fill) {
        main.log(&format!("Error: the table of the proof of work is not being made ahead: {e}"));
    }
}

/// Runs the node: it returns only with why it could not start, or
/// could not go on. Told to stop, the program is ended by the
/// operating system, where it stands.
fn run(c: &Configuration, main_log: &mut Option<Arc<Logger>>) -> Result<std::convert::Infallible, String> {
    if c.network != Network::Mainnet && !cfg!(feature = "dev") {
        return Err(format!("this build has no {} network: it is built with --features dev", c.network.name()));
    }
    tabminer::parallel::set_threads(c.threads);
    let mut net = c.net.clone();
    net.workers = c.threads;

    // Somewhere to keep things, and the logs: the main one first, so
    // that whatever else goes wrong is said there.
    let made = |dir: &Path| {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot make the directory {}: {e}", dir.display()))
    };
    made(&c.data_dir)?;
    let open = |path: &Path| -> Result<Logger, String> {
        if let Some(dir) = path.parent() {
            made(dir)?;
        }
        Logger::open(path, c.rotation).map_err(|e| format!("cannot open the log {}: {e}", path.display()))
    };
    let main = Arc::new(open(&c.main_log)?);
    *main_log = Some(Arc::clone(&main));
    let threads = |e: std::io::Error| format!("cannot start a thread: {e}");
    let requests = open(&c.request_log)?.report_rotations_to(Arc::clone(&main));
    let requests = Queued::start(requests, c.request_log_queue, Arc::clone(&main)).map_err(threads)?;
    let stat_log = open(&c.stat_log)?.report_rotations_to(Arc::clone(&main));

    // The chain.
    #[allow(unused_mut)]
    let (mut params, proofs) = match c.network {
        Network::Mainnet => (ChainParams::MAINNET, Level::MAINNET),
        Network::Dev => (ChainParams::DEV, Level::SMALL),
        Network::DevRecursive => (ChainParams::DEV_RECURSIVE, Level::SMALL),
        Network::DevMainWork => (ChainParams::DEV_MAIN_WORK, Level::SMALL),
    };
    // Debugging: a chain begun with a state filled at once. Its first
    // block says that state's root, which is made from the two numbers
    // given: so it is the first block of every node told the same.
    #[cfg(feature = "dev")]
    let filled = c.debug_outputs.map(|(n, spacing, _)| {
        let began = Instant::now();
        main.log(&format!(
            "debug: making the roots of a state of {} outputs, one every {spacing} positions",
            commas(n)
        ));
        let said = std::sync::atomic::AtomicU64::new(0);
        let (root, roots) = tabminer::chain::debug::root(n, spacing, &|done| {
            // (About every ten million.)
            if said.fetch_max(done / 10_000_000, std::sync::atomic::Ordering::Relaxed) < done / 10_000_000 {
                main.log(&format!(
                    "debug: the roots of {} outputs made in {:.1}s",
                    commas(done),
                    began.elapsed().as_secs_f64()
                ));
            }
        });
        params.genesis_state = Some(root);
        main.log(&format!(
            "debug: the first block of a chain of {} outputs ready in {:.1}s",
            commas(n),
            began.elapsed().as_secs_f64()
        ));
        roots
    });
    let seed = SeedText::new(params.pow);
    // What the proofs are made and checked with: a block of each shape
    // is proven once, for the plan of the shapes and the step's program,
    // which every block's statement names.
    // Its numbers are kept in the data directory from one run to the
    // next: a node that only checks blocks needs no more than those,
    // and one that makes them has the rest back in a moment.
    let emission = tabminer::ledger::Emission(params.emission);
    let kept = c.data_dir.join(format!("proofs-{}.setup", c.network.name()));
    // (The main network's are built in.)
    let read = match c.network {
        Network::Mainnet => Some(tabminer::prover::Parts::mainnet()),
        #[cfg(feature = "dev")]
        Network::Dev | Network::DevRecursive => Some(tabminer::prover::Parts::dev()),
        // (Debugging: where no proof is checked, any network's are
        // those, for want of its own: nothing is made or checked with
        // them, and its nodes are to agree on them.)
        #[cfg(feature = "dev")]
        _ if c.debug_unchecked => Some(tabminer::prover::Parts::dev()),
        _ => std::fs::read(&kept).ok().and_then(|bytes| tabminer::prover::Parts::from_bytes(&bytes)),
    };
    // (Debugging: nor does one whose blocks are filled with what
    // nobody sent, which are not proven.)
    let proves = c.mine && c.debug_fill.is_none();
    // What makes blocks is got ready from the setup's numbers: seconds
    // of work. Of a setup that is built in, behind the node's start:
    // the numbers are all that checking blocks takes, and the node
    // listens and answers while the rest is done. (Of one kept in the
    // data directory, here and now as before: if it is not this
    // build's, another is made, whose numbers the node then starts
    // with.)
    #[cfg(feature = "dev")]
    let built_in = !matches!(c.network, Network::DevMainWork) || c.debug_unchecked;
    #[cfg(not(feature = "dev"))]
    let built_in = true;
    let behind = proves && built_in && read.is_some();
    if let (true, Some(parts)) = (behind, read.clone()) {
        let (main, pow, mainnet) = (Arc::clone(&main), params.pow, matches!(c.network, Network::Mainnet));
        let getting_ready = move || {
            let began = Instant::now();
            main.log("Getting ready to make blocks");
            match Setup::from_parts(proofs, emission, pow, &parts) {
                Some(proving) => {
                    let _ = SETUP.set(proving);
                    main.log(&format!("Ready to make blocks, after {:.1}s", began.elapsed().as_secs_f64()));
                }
                // (Never made here, the main network's least of all: a
                // node with a setup of its own would make blocks nobody
                // takes, and take nobody's.)
                None => {
                    let which = if mainnet { "the main network" } else { "this network" };
                    main.log(&format!(
                        "Error: the proofs' setup built in is not this build's: it makes no block of {which}. Halting!"
                    ));
                    std::process::exit(1);
                }
            }
        };
        std::thread::Builder::new().name("setup".into()).spawn(getting_ready).map_err(threads)?;
    }
    let again = read
        .as_ref()
        .filter(|_| proves && !behind)
        .and_then(|parts| Setup::from_parts(proofs, emission, params.pow, parts));
    let (parts, proving) = match (read, again) {
        (Some(parts), None) if behind => (parts, None),
        (Some(parts), Some(proving)) => (parts, Some(proving)),
        (Some(parts), None) if !proves => (parts, None),
        // (The main network's are never made here: a node with others
        // of its own would make blocks nobody takes, and take nobody's.)
        _ if matches!(c.network, Network::Mainnet) => {
            return Err("the proofs' setup built in is not this build's: it makes no block of the main network".into());
        }
        _ => {
            let began = Instant::now();
            main.log("Making what the proofs are made and checked with: once, for some minutes");
            let proving = Setup::new_said(proofs, emission, &seed.at(0), &|line| main.log(line));
            main.log(&format!("That was made in {:.1}s", began.elapsed().as_secs_f64()));
            let parts = proving.parts();
            if let Err(e) = std::fs::write(&kept, parts.to_bytes()) {
                main.log(&format!("Error: it is not kept for the next run: {}: {e}", kept.display()));
            }
            (parts, Some(proving))
        }
    };
    if matches!(c.network, Network::Mainnet) && parts.own != params.program {
        return Err("the proofs' setup built in is not the main network's".into());
    }
    params.program = parts.own;
    let mut verifier = ChainVerifier::of(&proofs, &parts);
    if let Some(proving) = proving
        && SETUP.set(proving).is_err()
    {
        return Err("the setup was made twice".into());
    }
    // A data directory is of blocks that were checked, or of blocks
    // that were not, for good: blocks nobody checked must never pass
    // for checked ones, nor a chain that was checked take any.
    let marker = c.data_dir.join("unchecked");
    let store = c.data_dir.join("chain.store");
    match (c.debug_unchecked, marker.exists()) {
        (true, false) if store.exists() => {
            return Err(format!(
                "{} holds a chain whose blocks were checked: --debug-no-validate-proofs needs a data directory of its own",
                c.data_dir.display()
            ));
        }
        (true, false) => std::fs::write(&marker, "blocks here were taken without checking their proofs\n")
            .map_err(|e| format!("cannot write {}: {e}", marker.display()))?,
        (false, true) => {
            return Err(format!(
                "{} was run with --debug-no-validate-proofs: its blocks were never checked. Give another --data-dir, \
                 or that option again",
                c.data_dir.display()
            ));
        }
        _ => {}
    }
    if c.debug_unchecked {
        verifier = verifier.unchecked();
    }
    let backend = FileBackend::open(&store).map_err(|e| format!("cannot open the store {}: {e}", store.display()))?;
    // (A file made now is in its directory for good only once the
    // directory is.)
    if let Some(dir) = store.parent() {
        let _ = tabminer::store::backend::sync_dir(dir);
    }
    let chain = Chain::open(backend, c.keep, params, seed, verifier)
        .map_err(|e| format!("cannot open the store {}: {e}", store.display()))?;
    // Debugging: the state the chain begins with, put as a state taken
    // from other nodes is put, unless this node is to have only its
    // first block.
    #[cfg(feature = "dev")]
    if let (Some((n, spacing, false)), Some(roots)) = (c.debug_outputs, &filled) {
        let began = Instant::now();
        let said = std::cell::Cell::new(0);
        let filling = tabminer::chain::debug::fill(&chain, n, spacing, roots, &|done| {
            if done / 10_000_000 > said.get() {
                said.set(done / 10_000_000);
                main.log(&format!("debug: {} outputs filled in {:.1}s", commas(done), began.elapsed().as_secs_f64()));
            }
        });
        filling.map_err(|e| format!("debug: filling the state: {e}"))?;
        main.log(&format!("debug: a state of {} outputs ready in {:.1}s", commas(n), began.elapsed().as_secs_f64()));
        // (What making it held is not what a node holds: the most it
        // holds is counted from here.)
        tabminer::heap::reset_peak();
    }
    // Debugging: a chain made long before the node starts, of empty
    // blocks spaced as far apart as there is time for since its first.
    #[cfg(feature = "dev")]
    if let Some(blocks) = c.debug_blocks {
        let began = Instant::now();
        // (Checked against the table as they are applied, where the
        // network's is small enough to make in a moment, as they are
        // from here on: from the seed's text a header is a hundred
        // times the work.)
        let dataset = small_table(&seed);
        if let Some(table) = small_table(&seed) {
            chain.set_dataset(Arc::new(table));
        }
        let unix = socket::unix();
        // (As far apart as there is time for since the first block,
        // and not so far that the chain would end ahead of now: later
        // than its blocks are meant to be, so that each asks for the
        // least work there is.)
        let most = 500.max(2 * params.schedule.block_time as u64);
        let spacing = (unix.saturating_sub(params.genesis_timestamp) / (blocks as u64 + 1)).clamp(1, most);
        main.log(&format!("debug: making the chain {} blocks long", commas(blocks as u64)));
        let said = |height: u32| {
            main.log(&format!("debug: {} blocks made in {:.1}s", commas(height as u64), began.elapsed().as_secs_f64()))
        };
        miner::extend_empty(&chain, &seed, dataset.as_ref(), blocks, spacing, unix, &said)
            .map_err(|e| format!("debug: making the chain longer: {e}"))?;
        let now = chain.tip().map_or(0, |tip| tip.height);
        main.log(&format!(
            "debug: a chain of {} blocks ready in {:.1}s",
            commas(now as u64),
            began.elapsed().as_secs_f64()
        ));
    }
    // A chain made under other rules than this build's is not gone on
    // with: nothing made here could build on it, and nothing of it
    // would be taken from a peer.
    if matches!(miner::last_proof_holds(&chain), Ok(false)) {
        return Err(format!(
            "the chain in {} was made under other rules than this build's (the proof of its last block is not one \
             this build takes): it cannot be gone on with. Give another --data-dir, or remove that one",
            store.display()
        ));
    }
    // The table of the proof of work, where the network's is built in:
    // headers are checked against it, and blocks made with it.
    if let Some(dataset) = small_table(&seed) {
        chain.set_dataset(Arc::new(dataset));
    }
    // Blocks are made with a table of their own, which fills as it is
    // read and is kept in the data directory from one run to the next.
    // (Where the table is kept may be somewhere of its own, which is
    // made if it is not there.)
    if let Some(dir) = c.pow_table.parent().filter(|_| c.mine) {
        made(dir)?;
    }
    let mining = c.mine.then(|| (seed, c.pow_table.clone()));

    // The port.
    let socket = UdpSocket::bind(c.listen).map_err(|e| format!("cannot listen on {}: {e}", c.listen))?;
    let mut secret = [0u8; 32];
    tabminer::random::fill(&mut secret).map_err(|e| format!("the system gave no random bytes: {e}"))?;
    let clock = Instant::now();
    let now = || clock.elapsed().as_micros() as u64;
    let mut node = Node::new(net, c.network.magic(), Arc::new(chain), secret, now()).threaded();
    for peer in &c.peers {
        node.add_peer(*peer, true, now());
    }
    // The peers that answered when the node last ran: asked again, as
    // any peer it is told of is, and kept only if they answer.
    let peers_kept = c.data_dir.join("peers.txt");
    if let Ok(kept) = std::fs::read_to_string(&peers_kept) {
        let known = kept.lines().filter_map(|line| line.trim().parse::<std::net::SocketAddrV4>().ok());
        let taken = known.filter(|peer| node.add_peer(*peer, false, now())).count();
        if taken > 0 {
            main.log(&format!("{} peers are known from the last run", commas(taken as u64)));
        }
    }
    // A seed that cannot be found now is one fewer to begin from.
    for seed in &c.all_seeds() {
        for found in seed.to_socket_addrs().into_iter().flatten() {
            if let SocketAddr::V4(found) = found {
                node.add_seed(found, now());
            }
        }
    }

    // The stats: how the node stands is read afresh for every line.
    let hold = node.hold();
    let stats = {
        let hold = hold.clone();
        Arc::new(socket::stats().refreshed_by(Box::new(move |stats| socket::set_levels(stats, &hold))))
    };

    // The wallet: opened, or made, before the node says it is ready.
    let (wallet, phrase) = match c.wallet {
        true => {
            let (wallet, phrase) = open_wallet(c, &hold, &main)?;
            (Some(wallet), phrase)
        }
        false => (None, None),
    };

    // The wallet is to be reached: the node says, to the nodes that
    // stand between wallets, that it is there, for as long as it runs.
    if let Some(wallet) = &wallet {
        let identity = wallet.lock().unwrap_or_else(|e| e.into_inner()).identity_key();
        let mut chance = [0u8; 64];
        tabminer::random::fill(&mut chance).map_err(|e| format!("the system gave no random bytes: {e}"))?;
        hold.participate(tabminer::net::sessions::Participant::new(identity, &chance, now()));
    }

    // Everything is open: from here the node can do what it is for.
    let _stats_log = StatsLog::start(stat_log, Arc::clone(&stats), c.stats).map_err(threads)?;
    // (With the network's first block: what every node of it must
    // agree on.)
    let first = tabminer::hash::digest_to_bytes(&params.genesis().header.hash());
    c.announce_with(&main, &[("Genesis", tabminer::configuration::hex(&first))]);
    Configuration::ready(&main);
    // A wallet just made: its words, said here, after everything else
    // the node says as it starts, where whoever is at the terminal
    // sees them; once, and in no log.
    if let Some(phrase) = phrase {
        // (To nobody, if nobody is there to read it: that is no
        // reason for the node to stop.)
        let _ = writeln!(std::io::stderr(), "{phrase}");
    }

    // Blocks are made on a thread of their own, for as long as the
    // node runs.
    {
        let (main, debug) = (Arc::clone(&main), c.debug_unchecked);
        hold.on_event(Box::new(move |event| {
            if let Some(line) = said(event) {
                main.log(&line);
            }
            // Debugging: how long the block took to apply.
            if debug && let Event::Block { header, .. } = event {
                let (height, took) = tabminer::chain::apply::last_applied();
                if height == header.height {
                    main.log(&format!("debug: block {height} applied in {:.3}s", took.as_secs_f64()));
                }
            }
        }));
    }
    // The pool is what it was when the node last ran, as far as the
    // chain still takes it; and is kept, as it changes, for the next
    // run: a node that stops has no say in when.
    {
        let kept = c.data_dir.join("pool.tab");
        if let Ok(saved) = std::fs::read(&kept) {
            let taken = hold.load_pool(&saved, socket::unix());
            if taken > 0 {
                main.log(&format!("The pool has {} transactions kept from the last run", commas(taken as u64)));
            }
        }
        let (hold, main) = (hold.clone(), Arc::clone(&main));
        let keeping = move || {
            // (What the pool was when last kept: how many, their
            // bytes, and the last it took.)
            let mut was = (0, 0, 0);
            let mut peers_were: Vec<std::net::SocketAddrV4> = Vec::new();
            loop {
                std::thread::sleep(Duration::from_secs(30));
                let (mut now, mut saved) = (was, None);
                hold.pool(&mut |pool| {
                    now = (pool.len(), pool.bytes(), pool.entries().map(|e| e.order).max().unwrap_or(0));
                    if now != was {
                        saved = Some(pool.saved());
                    }
                });
                if let Some(saved) = saved {
                    let tmp = kept.with_extension("tmp");
                    match std::fs::write(&tmp, &saved).and_then(|()| std::fs::rename(&tmp, &kept)) {
                        Ok(()) => was = now,
                        Err(e) => main.log(&format!("Error: the pool cannot be kept in {}: {e}", kept.display())),
                    }
                }
                // And the peers that have answered, one to a line. (Not
                // none: a node with nobody to talk to for a while does
                // not forget everybody it knew.)
                let answered = hold.answered();
                if answered != peers_were && !answered.is_empty() {
                    // (But an address of this machine itself, which is
                    // given each time the node is started if it is
                    // wanted, and is not for the next run to find.)
                    let kept = answered.iter().filter(|peer| !peer.ip().is_loopback());
                    let text: String = kept.map(|peer| format!("{peer}\n")).collect();
                    let tmp = peers_kept.with_extension("tmp");
                    match std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &peers_kept)) {
                        Ok(()) => peers_were = answered,
                        Err(e) => {
                            main.log(&format!("Error: the peers cannot be kept in {}: {e}", peers_kept.display()))
                        }
                    }
                }
            }
        };
        std::thread::Builder::new().name("keeper".into()).spawn(keeping).map_err(threads)?;
    }
    // The wallet follows the chain on a thread of its own: woken when
    // the chain has another last block, and once in a while besides.
    if let Some(wallet) = &wallet {
        let (hold, wallet, main) = (hold.clone(), Arc::clone(wallet), Arc::clone(&main));
        let following = move || {
            let began = Instant::now();
            let mut failed = false;
            let mut refused: Vec<tabminer::hash::Digest> = Vec::new();
            loop {
                let seen = hold.moves();
                // (The chain is all here when nothing ahead of it is
                // known of or coming in; and, of a node just started,
                // not before its peers have had time to say how long
                // theirs are.)
                let caught_up = hold.behind() == tabminer::net::node::Behind::No
                    && !hold.syncing()
                    && began.elapsed() >= Duration::from_secs(20);
                let followed = follow_when(
                    hold.chain(),
                    &mut wallet.lock().unwrap_or_else(|e| e.into_inner()),
                    socket::unix(),
                    caught_up,
                );
                // (Said once, not at every block, while it goes on.)
                match &followed {
                    Err(e) if !failed => main.log(&format!("Error: the wallet cannot follow the chain: {e}")),
                    _ => {}
                }
                failed = followed.is_err();
                // (And what it expected and will not have is let go:
                // of payments taken back, say. Nobody has to ask.)
                if followed.is_ok() {
                    let _ = tabminer::console::tidy(&hold, &wallet, false);
                }
                // A wallet made again from its words has looked for
                // what it holds, the chain being all here.
                if let Ok(did) = &followed
                    && did.restored
                {
                    main.log(&format!(
                        "The wallet, made again from its words, has found {} outputs ({}) and {} names",
                        commas(did.found.0 as u64),
                        tabminer::console::coins(did.found.1),
                        commas(did.names as u64)
                    ));
                }
                // A reveal given up because its commit is no longer in
                // the chain is said, once.
                for name in wallet.lock().unwrap_or_else(|e| e.into_inner()).take_failed_reveals() {
                    main.log(&format!(
                        "Error: the reveal of {name} failed: its commit is no longer where it was in the chain. \
                         The name is committed to and not revealed again (see names); it has been said, \
                         and another may commit to it first"
                    ));
                }
                // What a reorganization took from the wallet, and gave
                // back, is said.
                if let Ok(did) = &followed {
                    let c = did.changed;
                    for (n, what) in [
                        (c.undone, "payments sent are in no block any more: they are to be mined again"),
                        (c.lost, "outputs are in no block any more: orphaned, unless a block makes them again"),
                        (c.returned, "outputs that were orphaned are in the chain again"),
                        (c.forgotten, "outputs orphaned for too long are forgotten"),
                        (
                            c.stranded,
                            "payments sent spent what is in no block any more: no block will have them; \
                             to be made again (see txs)",
                        ),
                    ] {
                        if n > 0 {
                            main.log(&format!("The wallet: {n} {what}"));
                        }
                    }
                }
                // A payment sent that no block has is kept in the pool:
                // put back if a reorganization, a restart or a full
                // pool took it out. (Said once for each, if the pool
                // will not have it.)
                let waiting = {
                    let wallet = wallet.lock().unwrap_or_else(|e| e.into_inner());
                    let unconfirmed = hold.chain().whole().ok().and_then(|state| {
                        let snap = state.snapshot().ok()?;
                        wallet.unconfirmed(&snap).ok()
                    });
                    let again =
                        |sent: &tabminer::wallet::Sent| Some((sent.txid, wallet.resend(&sent.txid).ok()?.to_bytes()));
                    unconfirmed.unwrap_or_default().iter().filter_map(again).collect::<Vec<_>>()
                };
                refused.retain(|id| waiting.iter().any(|(txid, _)| txid == id));
                for (txid, bytes) in waiting {
                    if hold.pooled(&txid) {
                        continue;
                    }
                    let id = short(&txid);
                    match hold.submit(&bytes, socket::unix()) {
                        Ok(_) => main.log(&format!(
                            "The wallet: payment sent {id} was in no block and not pooled: pooled again"
                        )),
                        Err(why) if !refused.contains(&txid) => {
                            refused.push(txid);
                            main.log(&format!(
                                "The wallet: payment sent {id} is in no block, and the pool does not take it: {why}"
                            ));
                        }
                        Err(_) => {}
                    }
                }
                // Pooled spends of its outputs: a leaf signed from
                // elsewhere (a copy of this wallet, or its file as it
                // was before) is never signed from again.
                if let Ok(behind @ 1..) = tabminer::console::observe(&hold, &wallet) {
                    main.log(&format!(
                        "The wallet: {behind} outputs were signed from leaves it took for unused (its file is an earlier one?): passed over"
                    ));
                }
                // (Sooner, while a wallet made again waits to look for
                // what it holds.)
                let pending = wallet.lock().unwrap_or_else(|e| e.into_inner()).scan_pending();
                hold.wait_moved(seen, Duration::from_secs(if pending { 5 } else { 60 }));
            }
        };
        std::thread::Builder::new().name("wallet".into()).spawn(following).map_err(threads)?;
    }
    if let (Some((seed, table)), Some(wallet)) = (mining, &wallet) {
        let (hold, main, stats, prebuild) = (hold.clone(), Arc::clone(&main), Arc::clone(&stats), c.prebuild_table);
        let most = Making {
            max_signatures: c.max_block_signatures,
            blocks: c.blocks,
            delay: Duration::from_secs(c.delay_blocks),
            fill: c.debug_fill,
            filled: c.debug_outputs.map(|(n, spacing, _)| (n, spacing)),
        };
        let wallet = Arc::clone(wallet);
        std::thread::Builder::new()
            .name("miner".into())
            .spawn(move || make_blocks(&hold, seed, &table, prebuild, most, &wallet, &main, &stats))
            .map_err(threads)?;
    }
    let names: Arc<Mutex<tabminer::console::Named>> = Arc::default();
    // Commands are taken from the terminal on a thread of their own.
    if c.prompt {
        let said = Arc::clone(&main);
        let log = Arc::new(move |line: &str| said.log(line));
        let debug = cfg!(feature = "dev") && c.network != Network::Mainnet;
        let (wallet, unix, names) = (wallet.clone(), socket::unix, Arc::clone(&names));
        let console = Console { hold: hold.clone(), wallet, unix, log, debug, max_names: c.max_names, names };
        let main = Arc::clone(&main);
        std::thread::Builder::new().name("prompt".into()).spawn(move || prompt(&console, &main)).map_err(threads)?;
    }

    // What comes for the wallet over the message layer is taken as it
    // comes: a payment to it answered, the answer to one of its own
    // signed and pooled. And what became of what it sent is said.
    if let Some(wallet) = &wallet {
        // (What happens to the wallet's payments while nobody asked is
        // said in the log, and to whoever is at the terminal: a line
        // each, and the prompt again after it.)
        let at_terminal = c.prompt && std::io::IsTerminal::is_terminal(&std::io::stderr());
        let aloud = {
            let main = Arc::clone(&main);
            move |line: &str| {
                main.log(line);
                if at_terminal {
                    use std::io::Write;
                    let _ = write!(std::io::stderr(), "\r{line}\n> ");
                }
            }
        };
        let log = Arc::new(aloud.clone());
        let (wallet, debug, names) = (Some(Arc::clone(wallet)), false, Arc::clone(&names));
        let (unix, max_names) = (socket::unix, c.max_names);
        let console = Console { hold: hold.clone(), wallet, unix, log, debug, max_names, names };
        // (The full names the wallet is: reached by them from the
        // start, and looked to now and then while the node runs.)
        if let Err(why) = console.renew_names() {
            main.log(&format!("Error: the wallet's names: {why}"));
        }
        let hold = hold.clone();
        let mut looked = std::time::Instant::now();
        let mut passed: Vec<(tabminer::hash::Digest, [u8; 32], std::time::Instant)> = Vec::new();
        let mut warned: Option<std::time::Instant> = None;
        let taking = move || loop {
            std::thread::sleep(Duration::from_millis(50));
            if looked.elapsed() >= Duration::from_secs(600) {
                looked = std::time::Instant::now();
                if let Err(why) = console.renew_names() {
                    aloud(&format!("Error: the wallet's names: {why}"));
                }
            }
            // (Another node saying it is this wallet: said, and no more
            // than every ten minutes. Nothing is stopped for it.)
            if let Some(node) = hold.take_twin()
                && warned.is_none_or(|at: std::time::Instant| at.elapsed() >= Duration::from_secs(600))
            {
                warned = Some(std::time::Instant::now());
                aloud(&format!(
                    "Warning: another node is running this wallet (seen at {node}). Two copies of one wallet at once \
                     can sign twice with one key, and only one of them is reached: stop one of them"
                ));
            }
            // (Whose a name is, is known before its wallet answers.)
            for (slate, whom) in hold.take_resolved() {
                match console.resolved(&slate, &whom) {
                    Ok(said) if !said.is_empty() => aloud(&format!("P{}", &said[1..])),
                    Ok(_) => {}
                    Err(why) => aloud(&format!("Error: a payment to a name: {why}")),
                }
            }
            for message in hold.take_messages() {
                if let Err(why) = console.take(&message) {
                    aloud(&format!("Error: a message for the wallet: {why}"));
                }
            }
            // (A payment passed on and not answered in a minute is no
            // payment: its wallet is gone, or cannot answer. Given up,
            // so that what it would have spent is free again.)
            let late = |since: &std::time::Instant| since.elapsed() >= Duration::from_secs(60);
            for (to, tag, _) in passed.extract_if(.., |p| late(&p.2)).collect::<Vec<_>>() {
                if console.awaits_answer(&tag) {
                    aloud(&console.undelivered(&to, &tag, "it was passed on, and is not answered"));
                }
            }
            for (to, _, tag, what) in hold.take_posted() {
                use tabminer::net::sessions::Posted;
                match what {
                    Posted::Passed if console.awaits_answer(&tag) => passed.push((to, tag, std::time::Instant::now())),
                    Posted::Passed | Posted::Waiting => {}
                    Posted::Offline => aloud(&console.undelivered(&to, &tag, "that wallet is not there")),
                    Posted::Unsent => aloud(&console.undelivered(&to, &tag, "no node it is reached at took it")),
                }
            }
        };
        std::thread::Builder::new().name("messages".into()).spawn(taking).map_err(threads)?;
    }

    let watch = Watch { requests: Some(&requests), stats: Some(&stats), main: Some(&main) };
    match socket::run_for_ever(&mut node, &socket, clock, &socket::unix, &watch) {
        Ok(()) => Err("the node stopped of itself".into()),
        Err(e) => Err(format!("the port can no longer be listened on: {e}")),
    }
}

/// Opens the wallet in the data directory, or makes one if there is
/// none: its password asked for at the terminal, or read from the file
/// given for it; a new wallet's phrase said on the terminal, once, and
/// nowhere else. Then it is brought up to the chain.
fn open_wallet(
    c: &Configuration,
    hold: &Handle<FileBackend, ChainVerifier>,
    main: &Logger,
) -> Result<(Purse, Option<String>), String> {
    let path = c.data_dir.join("wallet.tab");
    let is_new = !path.exists();
    let whose = |e: WalletError| format!("the wallet {}: {e}", path.display());
    if c.restore && !is_new {
        return Err(format!("--restore: there is a wallet already, {}: it is not made again over", path.display()));
    }
    let backend = FileBackend::open(&path).map_err(|e| format!("cannot open the wallet {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let typed = |asking: &str| -> Result<String, WalletError> {
        eprint!("{asking}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    };
    let mut ask = |ask: Ask| -> Result<String, WalletError> {
        // From the file, if one is given: its first line.
        if let Some(file) = &c.password_file {
            let text = std::fs::read_to_string(file)?;
            return Ok(text.lines().next().unwrap_or("").to_string());
        }
        match (ask, c.prompt) {
            (Ask::Unlock, true) => typed("Wallet password: "),
            (Ask::New, true) => loop {
                let first = typed("A password for the new wallet (none, for no password): ")?;
                if first.is_empty() || typed("The same again: ")? == first {
                    break Ok(first);
                }
                eprintln!("They are not the same.");
            },
            // Nobody to ask: a new wallet has no password, and a locked
            // one cannot be opened.
            (Ask::New, false) => Ok(String::new()),
            (Ask::Unlock, false) => Err(WalletError::WrongPassword),
        }
    };
    // Made again from its words, typed here: or opened, or made new.
    let (mut wallet, phrase) = if c.restore {
        let made = typed("The wallet's twelve words: ").and_then(|words| {
            let words = words.split_whitespace().collect::<Vec<_>>().join(" ");
            Wallet::restore(backend, &words, "", &ask(Ask::New)?)
        });
        match made {
            Ok(wallet) => {
                main.log(&format!("A wallet was made again from its words in '{}'", path.display()));
                let said = tabminer::console::restored(&wallet.address());
                (wallet, Some(said))
            }
            Err(e) => {
                // (Nothing is left of a wallet that was not made.)
                let _ = std::fs::remove_file(&path);
                return Err(format!("--restore: {e}"));
            }
        }
    } else {
        let (wallet, phrase) = Wallet::open_with(backend, &mut ask).map_err(|e| match e {
            WalletError::WrongPassword if c.password_file.is_none() && !c.prompt => {
                format!("the wallet {} has a password: give --password-file", path.display())
            }
            e => whose(e),
        })?;
        let phrase = phrase.filter(|_| is_new).map(|phrase| tabminer::console::made(&phrase));
        if phrase.is_some() {
            main.log(&format!("A wallet was made in '{}'", path.display()));
        }
        (wallet, phrase)
    };
    // Rewards of blocks that were being made when the node last stopped
    // are of no block.
    for (c, _, block) in wallet.rewards() {
        if block == [0; 32] {
            wallet.forget(&c).map_err(whose)?;
        }
    }
    wallet.set_min_confirmations(c.min_confirmations);
    // (What a wallet made again holds is looked for by the thread that
    // follows the chain, once the chain is all here: not now, when the
    // node has not yet heard how long the chain is.)
    follow_when(hold.chain(), &mut wallet, socket::unix(), false).map_err(whose)?;
    Ok((Arc::new(Mutex::new(wallet)), phrase))
}

/// Takes commands from the terminal, one a line, and says what comes of
/// each; until told to stop, or there is no more to read, when the node
/// ends.
fn prompt(console: &Console<FileBackend, FileBackend>, main: &Logger) {
    let mut line = String::new();
    loop {
        print!("> ");
        let _ = std::io::stdout().flush();
        line.clear();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        match console.run(&line) {
            Reply::Said(text) => println!("{text}"),
            Reply::Wrong(text) => println!("error: {text}"),
            Reply::Nothing => {}
            // The wallet's password, asked for and typed here: it is
            // no part of a command, and is kept by nothing.
            Reply::Password => {
                print!("Wallet password: ");
                let _ = std::io::stdout().flush();
                line.clear();
                match std::io::stdin().lock().read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                match console.seed(line.trim_end_matches(['\n', '\r'])) {
                    Ok(text) => println!("{text}"),
                    Err(text) => println!("error: {text}"),
                }
                line.clear();
            }
            // The wallet's password, changed: the one it has, and the
            // new one twice.
            Reply::NewPassword => {
                let ask = |asking: &str| -> Option<String> {
                    print!("{asking}");
                    let _ = std::io::stdout().flush();
                    let mut typed = String::new();
                    match std::io::stdin().lock().read_line(&mut typed) {
                        Ok(0) | Err(_) => None,
                        Ok(_) => Some(typed.trim_end_matches(['\n', '\r']).to_string()),
                    }
                };
                let old = match console.locked() {
                    true => ask("Wallet password: "),
                    false => Some(String::new()),
                };
                let Some(old) = old else { break };
                let Some(new) = ask("A new password (none, for no password): ") else { break };
                let Some(again) = (if new.is_empty() { Some(String::new()) } else { ask("The same again: ") }) else {
                    break;
                };
                match (new == again).then(|| console.set_password(&old, &new)) {
                    Some(Ok(text)) => println!("{text}"),
                    Some(Err(text)) => println!("error: {text}"),
                    None => println!("error: they are not the same"),
                }
            }
            Reply::Quit => break,
        }
    }
    main.log("Told to stop at the prompt, halting!");
    std::process::exit(0);
}
