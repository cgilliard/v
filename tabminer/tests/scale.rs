//! The program at the size of a chain that has run for years: what a
//! node needs, measured.
//!
//! A state of `TABMINER_SCALE_OUTPUTS` unspent outputs is made at once
//! behind a chain's first block (`--debug-fill-outputs`, with blocks'
//! proofs unchecked), and then: full blocks are made and applied on it;
//! and a new node takes the state from the one that has it. The size is
//! 2,000,000 where nothing is said, as every push runs it, and
//! 180,000,000, somewhat more than Bitcoin's, nightly
//! (`.github/workflows/scale.yml`). The data directories are under the
//! system's temporary directory (`TMPDIR`), which needs room for the
//! state: twice, when it is taken by a second node.
//!
//! A third test is of a chain's length, not its state's size: a chain
//! of a year's blocks (`TABMINER_SCALE_BLOCKS`, or 144 x 365 = 52,560)
//! is made in a couple of minutes (`--debug-blocks`: empty blocks, of
//! next to no work), and a new node takes its headers. It is of a
//! network with the main network's work (`--network dev-main-work`):
//! its table, its targets, its times. What a header costs to check is
//! what it costs there.
//!
//! Each test prints what it measured as `SCALE` lines, one fact a line,
//! to be read and compared between runs: `SCALE <test> <what> <value>`.
//! The last of them say what the machine had left, of disk and of
//! memory: so that a run on a machine with little says so.
//!
//! What is not measured here is proving: a node that makes blocks needs
//! what these say and, besides, the memory of a proof and of the table
//! of the proof of work.

#![cfg(feature = "dev")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const TABMINER: &str = env!("CARGO_BIN_EXE_tabminer");
/// The blocks a node of these tests keeps the bodies of, and how far
/// under its last block a new node takes the state.
const KEPT: &str = "8";
const SYNC_POINT: &str = "4";

fn number(name: &str, or: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(or)
}

/// The size of the state: `TABMINER_SCALE_OUTPUTS`, or 2,000,000.
fn outputs() -> u64 {
    number("TABMINER_SCALE_OUTPUTS", 2_000_000)
}

/// One output every this many positions: `TABMINER_SCALE_SPACING`, or 5
/// (the rest as if spent, as on a chain with a history).
fn spacing() -> u64 {
    number("TABMINER_SCALE_SPACING", 5)
}

/// How long a step that grows with the state may take: an hour, and a
/// minute for every million outputs.
fn scaled(n: u64) -> Duration {
    Duration::from_secs(3600 + 60 * (n / 1_000_000))
}

/// A port for the nodes of the test numbered `test` (it and the one
/// after): its own, as likely as not, and under the ports a system
/// gives out of itself. (Windows keeps runs of those for itself, and
/// refuses whoever asks for one by number.)
fn port(test: u32) -> u32 {
    20_000 + test * 9_000 + std::process::id() % 8_990
}

fn report(test: &str, what: &str, value: impl std::fmt::Display) {
    println!("SCALE {test} {what} {value}");
}

/// A node run by a test: ended with the test, however that ends, and
/// its data directory removed.
struct Node {
    name: &'static str,
    child: Child,
    dir: PathBuf,
    listen: String,
    /// The most memory it was seen to have: all of it, and what of it
    /// is its own (not the files it reads), in megabytes.
    resident: Arc<AtomicU64>,
    own: Arc<AtomicU64>,
    /// How many lines of its main log have been shown.
    shown: usize,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Node {
    fn start(name: &'static str, test: &str, port: u32, args: &[&str]) -> Node {
        Node::start_on("dev", name, test, port, args)
    }

    /// A node of the network `network`.
    fn start_on(network: &str, name: &'static str, test: &str, port: u32, args: &[&str]) -> Node {
        let dir = std::env::temp_dir().join(format!("tabminer-scale-{test}-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let listen = format!("127.0.0.1:{port}");
        let child = Command::new(TABMINER)
            .args(["--network", network, "--debug-no-validate-proofs", "--no-prompt"])
            .args(["--max-undo-blocks", KEPT, "--sync-point", SYNC_POINT])
            .args(["--stat-interval-seconds", "1", "--stat-summary-seconds", "60"])
            .args(["--data-dir", &dir.display().to_string(), "--listen", &listen])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // Its memory as the system sees it, looked at every second for
        // as long as it runs (Linux only: elsewhere what the node says
        // of itself is what there is).
        let (resident, own) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let (r, o, path) = (Arc::clone(&resident), Arc::clone(&own), format!("/proc/{}/status", child.id()));
        std::thread::spawn(move || {
            while let Ok(status) = std::fs::read_to_string(&path) {
                let kb = |what: &str| {
                    status
                        .lines()
                        .find(|l| l.starts_with(what))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                };
                let (Some(all), Some(anon)) = (kb("VmHWM:"), kb("RssAnon:")) else { break };
                r.fetch_max(all / 1000, Ordering::Relaxed);
                o.fetch_max(anon / 1000, Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Node { name, child, dir, listen, resident, own, shown: 0 }
    }

    /// The lines of its main log that have `text` in them.
    fn lines(&self, text: &str) -> Vec<String> {
        let log = std::fs::read_to_string(self.dir.join("tabernacle.log")).unwrap_or_default();
        log.lines().filter(|l| l.contains(text)).map(str::to_string).collect()
    }

    /// Shows what its main log has said since it was last shown: each
    /// line as the node wrote it, after the node's name. So that what a
    /// run prints is what whoever ran the two nodes would have read.
    fn show(&mut self) {
        let log = std::fs::read_to_string(self.dir.join("tabernacle.log")).unwrap_or_default();
        // (Not a last line still being written.)
        let whole = log.matches('\n').count();
        for line in log.lines().take(whole).skip(self.shown) {
            println!("{:>6} | {line}", self.name);
        }
        self.shown = self.shown.max(whole);
    }

    /// Waits until its log has `count` lines with `text` in them, and
    /// gives them: the test fails if `within` passes first, or the node
    /// ends, or says of anything that it is an error.
    fn wait(&mut self, text: &str, count: usize, within: Duration) -> Vec<String> {
        let began = Instant::now();
        loop {
            self.show();
            let lines = self.lines(text);
            if lines.len() >= count {
                return lines;
            }
            let errors = self.lines("Error: ");
            assert!(errors.is_empty(), "{}: {errors:?}", self.name);
            assert!(
                !self.lines("Refused block").iter().any(|_| true),
                "{}: {:?}",
                self.name,
                self.lines("Refused block")
            );
            if let Some(ended) = self.child.try_wait().unwrap() {
                panic!("{} ended ({ended}) before its log said '{text}' {count} times", self.name);
            }
            assert!(began.elapsed() < within, "{}: '{text}' {} of {count} times in {within:?}", self.name, lines.len());
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The most memory the node said it held ([`tabminer::heap`]), in
    /// megabytes: from the lines of its stat log.
    fn peak_heap(&self) -> u64 {
        let log = std::fs::read_to_string(self.dir.join("stat.log")).unwrap_or_default();
        let Some(names) = log.lines().find(|l| l.starts_with("Uptime:")) else { return 0 };
        log.lines().filter_map(|l| column(names, l, "PeakHeapMB")).max().unwrap_or(0)
    }

    /// Says what the node used: memory, and disk.
    fn report(&self, test: &str, who: &str) {
        report(test, &format!("{who}_peak_heap_mb"), self.peak_heap());
        for (what, seen) in [("peak_own_memory_mb", &self.own), ("peak_resident_mb", &self.resident)] {
            if seen.load(Ordering::Relaxed) > 0 {
                report(test, &format!("{who}_{what}"), seen.load(Ordering::Relaxed));
            }
        }
        report(test, &format!("{who}_disk_mb"), dir_size(&self.dir) / 1_000_000);
    }
}

/// What a line of the stats log says under the column `name`: the
/// columns' names are the last word of the log's line of names
/// (`header`), and a line's last words are their values.
fn column(header: &str, line: &str, name: &str) -> Option<u64> {
    let names: Vec<&str> = header.split_whitespace().last()?.split('_').filter(|n| !n.is_empty()).collect();
    let at = names.iter().position(|n| *n == name)?;
    let values: Vec<&str> = line.split_whitespace().collect();
    values.get(values.len().checked_sub(names.len())? + at)?.replace(',', "").parse().ok()
}

/// The seconds a line says after `label` (`applied in 0.427s`).
fn secs_after(line: &str, label: &str) -> Option<f64> {
    let rest = &line[line.find(label)? + label.len()..];
    rest.split(|c: char| !(c.is_ascii_digit() || c == '.')).find(|s| !s.is_empty())?.parse().ok()
}

/// The bytes on disk of what is under `dir`.
fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let size = |e: std::fs::DirEntry| match e.metadata() {
        Ok(m) if m.is_dir() => dir_size(&e.path()),
        #[cfg(unix)]
        Ok(m) => std::os::unix::fs::MetadataExt::blocks(&m) * 512,
        #[cfg(not(unix))]
        Ok(m) => m.len(),
        Err(_) => 0,
    };
    entries.flatten().map(size).sum()
}

/// Says what the machine has left, of disk where the data directories
/// were and of memory: so that a run on a machine with little says so.
fn report_left(test: &str) {
    // (Kilobytes free: `df` says, or on Windows the drive itself.)
    #[cfg(unix)]
    let free = Command::new("df").arg("-Pk").arg(std::env::temp_dir()).output().ok().and_then(|o| {
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        text.lines().nth(1)?.split_whitespace().nth(3)?.parse::<u64>().ok()
    });
    #[cfg(not(unix))]
    let free = {
        let ask = format!("(Get-Item '{}').PSDrive.Free", std::env::temp_dir().display());
        let said = Command::new("powershell").args(["-NoProfile", "-Command", &ask]).output().ok();
        said.and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok()).map(|bytes| bytes / 1000)
    };
    if let Some(kb) = free {
        report(test, "machine_disk_available_mb", kb / 1000);
    }
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let kb = |what: &str| {
        meminfo.lines().find(|l| l.starts_with(what)).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
    };
    if let (Some(total), Some(available)) = (kb("MemTotal:"), kb("MemAvailable:")) {
        report(test, "machine_memory_mb", total / 1000);
        report(test, "machine_memory_available_mb", available / 1000);
    }
}

/// A node that has the state of `n` outputs, making full blocks on it
/// up to the height `blocks`: each of as many outputs, and as many
/// spends of the state's outputs chosen at random, as fit a block. How
/// long it took until it was ready.
fn filled(test: &'static str, port: u32, n: u64, blocks: u64) -> (Node, Duration) {
    let began = Instant::now();
    let (state, blocks) = (format!("{n},{}", spacing()), blocks.to_string());
    let args = ["--debug-fill-outputs", &state, "--debug-fill", "100000,100000", "--blocks", &blocks];
    let mut node = Node::start("server", test, port, &args);
    node.wait("Server is ready!", 1, scaled(n));
    (node, began.elapsed())
}

/// Full blocks, each of two million bytes with tens of thousands of
/// spends, are made and applied on a state of `TABMINER_SCALE_OUTPUTS`:
/// how long applying one takes, and what the node needed.
#[test]
#[ignore = "slow: a job of its own in .github/workflows/test.yml, and nightly at full size"]
fn a_full_block_applies_on_a_large_state() {
    const T: &str = "full-block";
    let (n, blocks) = (outputs(), 10);
    let port = port(0);
    let (mut node, ready) = filled(T, port, n, blocks);
    report(T, "outputs", n);
    report(T, "spacing", spacing());
    report(T, "fill_secs", format!("{:.1}", ready.as_secs_f64()));
    report(T, "filled_disk_mb", dir_size(&node.dir) / 1_000_000);
    let applied = node.wait("applied in ", blocks as usize, scaled(n));
    let built = node.lines("debug fill: block ");
    assert_eq!(built.len(), blocks as usize);
    // Every one of them full: within a part in a hundred of the most a
    // block may be, and of spends as of outputs.
    for line in &built {
        let after =
            |label: &str| line[..line.find(label).unwrap()].split_whitespace().last().unwrap().parse::<u64>().unwrap();
        assert!(after(" bytes") > 1_980_000 && after(" spends") > 20_000 && after(" outputs") > 20_000, "{line}");
    }
    report(T, "block_bytes", built[0][..built[0].find(" bytes").unwrap()].split_whitespace().last().unwrap());
    report(T, "block_spends", built[0][..built[0].find(" spends").unwrap()].split_whitespace().last().unwrap());
    for (what, lines, label) in [("build", &built, "built in "), ("apply", &applied, "applied in ")] {
        let mut secs: Vec<f64> = lines.iter().map(|l| secs_after(l, label).unwrap()).collect();
        secs.sort_by(f64::total_cmp);
        report(T, &format!("{what}_median_secs"), format!("{:.3}", secs[secs.len() / 2]));
        report(T, &format!("{what}_max_secs"), format!("{:.3}", secs[secs.len() - 1]));
    }
    node.show();
    node.report(T, "node");
    report_left(T);
}

/// A new node takes a state of `TABMINER_SCALE_OUTPUTS` from the one
/// node that has it, and the full blocks after it: how long it takes,
/// and what both needed. That neither holds the state in memory is what
/// the memory lines say: at full size the state is many times what a
/// node may hold.
#[test]
#[ignore = "slow: a job of its own in .github/workflows/test.yml, and nightly at full size"]
fn a_fresh_node_fast_syncs_a_large_state() {
    const T: &str = "fast-sync";
    // (More blocks than a node keeps: the first of them can no longer
    // be had, and the new node must take the state.)
    let (n, blocks) = (outputs(), 12);
    let port = port(1);
    let (mut server, ready) = filled(T, port, n, blocks);
    report(T, "outputs", n);
    report(T, "spacing", spacing());
    report(T, "fill_secs", format!("{:.1}", ready.as_secs_f64()));
    server.wait("applied in ", blocks as usize, scaled(n));
    let last = server.wait(&format!("Won block {blocks} ("), 1, scaled(n)).pop().unwrap();
    let id = &last[last.find('(').unwrap()..last.find(')').unwrap()];

    let began = Instant::now();
    let state = format!("{n},{}", spacing());
    let args = ["--no-mine", "--debug-genesis-outputs", &state, "--peer", &server.listen];
    let mut new = Node::start("new", T, port + 1, &args);
    new.wait("Server is ready!", 1, scaled(n));
    let ready = began.elapsed();
    new.wait("Headers synced to ", 1, Duration::from_secs(600));
    let headers = began.elapsed();
    let taking = new.wait("Taking the state as of block ", 1, Duration::from_secs(600));
    new.wait("State taken as of block ", 1, scaled(n));
    let taken = began.elapsed();
    // Taken once, and as of the block that far under the last.
    assert_eq!(taking.len(), 1, "{taking:?}");
    assert!(taking[0].contains(&format!("as of block {} ", blocks - SYNC_POINT.parse::<u64>().unwrap())), "{taking:?}");
    // And then the blocks after it, full ones, to the same last block.
    new.wait(&format!("Synced at block {blocks}"), 1, scaled(n));
    let synced = began.elapsed();
    assert_eq!(new.lines(&format!("Received block {blocks} {id}")).len(), 1, "the two are on one block");
    assert_eq!(new.lines("applied in ").len(), SYNC_POINT.parse::<usize>().unwrap());

    // The first is what only a node of these tests does, before it is
    // ready: making the first block of a chain begun with a state. The
    // rest are counted from when it was ready, as a node of a network
    // would be: they are how long joining takes.
    report(T, "first_block_secs", format!("{:.1}", ready.as_secs_f64()));
    report(T, "headers_secs", format!("{:.1}", (headers - ready).as_secs_f64()));
    report(T, "state_taken_secs", format!("{:.1}", (taken - ready).as_secs_f64()));
    report(T, "state_fetch_secs", format!("{:.1}", (taken - headers).as_secs_f64()));
    report(T, "synced_secs", format!("{:.1}", (synced - ready).as_secs_f64()));
    // How long the new node took to apply each of the full blocks it
    // was sent: a node that did not make them, and had read none of
    // what they spend.
    let mut secs: Vec<f64> = new.lines("applied in ").iter().map(|l| secs_after(l, "applied in ").unwrap()).collect();
    secs.sort_by(f64::total_cmp);
    report(T, "apply_median_secs", format!("{:.3}", secs[secs.len() / 2]));
    report(T, "apply_max_secs", format!("{:.3}", secs[secs.len() - 1]));
    server.show();
    new.show();
    server.report(T, "server");
    new.report(T, "new");
    report_left(T);
}

/// A new node takes the headers of a chain a year long (52,560 blocks,
/// or `TABMINER_SCALE_BLOCKS`) from the one node that has it, and then
/// joins it: how long the headers take, and what the node needed.
///
/// The chain is of a network with the main network's work, and the new
/// node, which makes no blocks, has no table of it: so it checks
/// headers as a node of the main network does. The work of each is
/// checked by what the header claims, the rest left to the proof of the
/// block the state is taken as of, and checked in full, from the seed's
/// text, only from that block up. Were every header checked in full the
/// run would fail: all but the last of this chain's headers claim work
/// that was never done (`--debug-blocks`), which is what makes a year
/// of them in minutes. (At tens of milliseconds a header, it would also
/// take most of an hour.)
#[test]
#[ignore = "slow: a job of its own in .github/workflows/test.yml, and nightly"]
fn a_fresh_node_takes_a_years_headers() {
    const T: &str = "headers";
    let blocks = number("TABMINER_SCALE_BLOCKS", 144 * 365);
    let said = |n: u64| {
        // (As the log says a number: in threes.)
        let digits = n.to_string();
        let mut out = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push(',');
            }
            out.push(c);
        }
        out
    };
    let port = port(2);
    let within = Duration::from_secs(3600);
    let began = Instant::now();
    const NETWORK: &str = "dev-main-work";
    let mut server = Node::start_on(NETWORK, "server", T, port, &["--no-mine", "--debug-blocks", &blocks.to_string()]);
    server.wait("Server is ready!", 1, within);
    report(T, "blocks", blocks);
    report(T, "chain_made_secs", format!("{:.1}", began.elapsed().as_secs_f64()));
    report(T, "server_disk_mb", dir_size(&server.dir) / 1_000_000);

    let mut new = Node::start_on(NETWORK, "new", T, port + 1, &["--no-mine", "--peer", &server.listen]);
    new.wait("Server is ready!", 1, within);
    let began = Instant::now();
    new.wait("Syncing headers 1 to ", 1, within);
    let asked = began.elapsed();
    new.wait(&format!("Headers synced to {}", said(blocks)), 1, within);
    let headers = began.elapsed();
    // And then the chain itself: its state, small as it is, and the
    // blocks after it.
    new.wait(&format!("Synced at block {}", said(blocks)), 1, within);
    let synced = began.elapsed();
    // (Its headers were kept with their work pending, and those from
    // the block the state was taken as of checked in full: it says
    // nothing of either, but it could not have joined otherwise.)
    report(T, "network", NETWORK);
    report(T, "headers_secs", format!("{:.1}", (headers - asked).as_secs_f64()));
    report(T, "headers_a_second", format!("{:.0}", blocks as f64 / (headers - asked).as_secs_f64()));
    report(T, "synced_secs", format!("{:.1}", synced.as_secs_f64()));
    server.show();
    new.show();
    server.report(T, "server");
    new.report(T, "new");
    report_left(T);
    // A header is two hundred bytes, and what a node keeps of one
    // somewhat under twice that: the file of a node that has taken a
    // year of them is not many times what they come to.
    let (disk, headers) = (dir_size(&new.dir), blocks * 204);
    assert!(disk < 6 * headers, "{} MB on disk for {} MB of headers", disk / 1_000_000, headers / 1_000_000);
}
