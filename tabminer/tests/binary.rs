//! The program itself, run as whoever keeps a node runs it.

#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

/// What the line of a new wallet's words begins with.
const PHRASE: &str = "Recovery phrase: ";
const TABMINER: &str = env!("CARGO_BIN_EXE_tabminer");

/// A node run by a test: ended with the test, however that ends.
#[cfg(unix)]
struct Running(std::process::Child);

#[cfg(unix)]
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Held by a test whose nodes make blocks: every block is proven, with
/// every core and some gigabytes, so such tests go one at a time
/// however many the harness runs at once.
#[cfg(all(unix, feature = "dev"))]
fn proving() -> std::sync::MutexGuard<'static, ()> {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ONE.lock().unwrap_or_else(|e| e.into_inner())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tabminer-binary-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The help asked for is the help, and no failure; an option that is
/// not one is named, the help follows, and that is a failure. Neither
/// makes anything.
#[test]
fn help_is_no_failure_and_an_unknown_option_is() {
    let dir = scratch("help");
    let data = dir.display().to_string();
    let help = Command::new(TABMINER).args(["--data-dir", &data, "--help"]).output().unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(text.starts_with("tabminer: a node of the Tabernacle network.") && text.contains("\nLogging\n"));
    assert!(help.stderr.is_empty());

    let unknown = Command::new(TABMINER).args(["--data-dir", &data, "--prot", "1"]).output().unwrap();
    let said = String::from_utf8(unknown.stderr).unwrap();
    // (-1, as the system has it: 255 where a code is one byte.)
    assert!(matches!(unknown.status.code(), Some(-1 | 255)), "{:?}", unknown.status);
    assert_eq!(said, format!("Error: unknown configuration option: '--prot'\n\n{text}"));
    assert!(unknown.stdout.is_empty());
    assert!(!dir.exists());

    // Making blocks needs a wallet for their rewards: a node told to
    // have none and to make blocks says so, and does not start.
    let purseless = Command::new(TABMINER).args(["--data-dir", &data, "--no-wallet"]).output().unwrap();
    assert!(matches!(purseless.status.code(), Some(-1 | 255)));
    let said = String::from_utf8(purseless.stderr).unwrap();
    let why = "--no-wallet needs --no-mine: the rewards of blocks made here are paid to the wallet";
    assert_eq!(said, format!("Error: {why}\n\n{text}"));
    assert!(!dir.exists());
}

/// A node that starts says how it is configured and then, in the very
/// next line, that it is ready; and from then it answers. Told to
/// stop, it says so and stops, at once and without failure.
#[cfg(unix)]
#[test]
fn a_node_starts_says_it_is_ready_and_ends_when_told() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};
    let dir = scratch("run");
    let data = dir.display().to_string();
    // (A port of our own, as likely as not.)
    let port = 20_000 + std::process::id() % 20_000;
    let listen = format!("127.0.0.1:{port}");
    let node = Command::new(TABMINER)
        .args(["--no-mine", "--no-wallet", "--no-prompt"])
        .args(["--data-dir", &data, "--listen", &listen, "--max-peers", "2000"])
        .arg("--no-seeds")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut node = Running(node);
    let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
    let mut said = Vec::new();
    for line in lines.by_ref() {
        said.push(line.unwrap());
        if said.last().unwrap().ends_with("Server is ready!") {
            break;
        }
    }
    let rule = "-".repeat(105);
    assert!(said[0][26..].starts_with("Server started ") && said[0].ends_with(" UTC"), "{said:#?}");
    assert_eq!((&said[1], &said[said.len() - 2]), (&rule, &rule));
    assert_eq!(&said[2][26..], format!("UDP Server Listening on: '{listen}'"));
    // (By its end: the lines are not all of one millisecond.)
    assert!(said.iter().any(|l| l.ends_with(&format!("Main Log:                '{data}/tabernacle.log'"))));
    assert!(said.iter().any(|l| l.ends_with("Max Peers:               '2,000'")));
    // How many threads, as a number: one a core, nothing being said.
    let cores = tabminer::parallel::cores();
    assert!(said.iter().any(|l| l.ends_with(&format!("Threads:                 '{cores}'"))), "{said:#?}");

    // It is ready: a datagram that is no message is taken, and has its
    // line in the request log.
    let us = UdpSocket::bind("127.0.0.1:0").unwrap();
    us.send_to(b"is anybody there", &listen).unwrap();
    let start = Instant::now();
    let requests = dir.join("request.log");
    while !std::fs::read_to_string(&requests).unwrap().contains("malformed (16 bytes) -> malformed") {
        assert!(start.elapsed() < Duration::from_secs(20), "{:?}", std::fs::read_to_string(&requests));
        std::thread::sleep(Duration::from_millis(20));
    }

    // Told to stop. (With the signal to end, not an interrupt: a
    // program a shell started in the background, as these tests are
    // when coverage is measured, is started ignoring interrupts, and
    // a node does nothing to change that.)
    let told = Instant::now();
    assert!(Command::new("kill").args(["-TERM", &node.0.id().to_string()]).status().unwrap().success());
    let status = node.0.wait().unwrap();
    // (Ended by the signal itself: the node does nothing about it.)
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(15));
    assert!(told.elapsed() < Duration::from_secs(5));
    // Nothing more was said once it was ready, on the terminal or in
    // the main log.
    assert_eq!(lines.count(), 0);
    let main = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
    let logged: Vec<&str> = main.lines().collect();
    assert_eq!(logged[..said.len()], said.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(logged.len(), said.len());
    assert!(std::fs::read_to_string(dir.join("stat.log")).unwrap().contains("AvgLatency(us)"));

    // A second node on the same port cannot start: it says why, and
    // never that it is ready.
    let first = Command::new(TABMINER)
        .args(["--no-mine", "--no-prompt", "--data-dir", &data, "--listen", &listen])
        .arg("--no-seeds")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let other = scratch("other");
    let mut first = Running(first);
    let mut lines = BufReader::new(first.0.stderr.take().unwrap()).lines();
    assert!(lines.by_ref().any(|l| l.unwrap().ends_with("Server is ready!")));
    let second = Command::new(TABMINER)
        .args(["--no-mine", "--no-prompt", "--data-dir", &other.display().to_string(), "--listen", &listen])
        .arg("--no-seeds")
        .output()
        .unwrap();
    let said = String::from_utf8(second.stderr).unwrap();
    assert!(matches!(second.status.code(), Some(-1 | 255)));
    assert!(
        said.contains(&format!("] Error: cannot listen on {listen}: ")) && !said.contains("Server is ready"),
        "{said}"
    );
    assert_eq!(said.lines().count(), 1);
    assert!(Command::new("kill").args(["-TERM", &first.0.id().to_string()]).status().unwrap().success());
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&first.0.wait().unwrap()), Some(15));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}

/// Two nodes of the dev network, each making blocks and each told of
/// the other: both chains grow, each takes the other's blocks, and
/// they are of one mind. Every block carries the chain's proof, which
/// each node makes, with the dev networks' setup as it is built in, and
/// the other checks: some tens of seconds of every core a block, and
/// they share the cores.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn two_nodes_make_blocks_and_take_each_others() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("mine-a"), scratch("mine-b")];
    let port = 41_000 + std::process::id() % 20_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let start = |i: usize| {
        let node = Command::new(TABMINER)
            .args(["--network", "dev", "--stat-interval-seconds", "1", "--stat-summary-seconds", "2"])
            .args(["--data-dir", &dirs[i].display().to_string(), "--listen", &at(i as u32)])
            .args(["--peer", &at(1 - i as u32), "--no-prompt"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut node = Running(node);
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        assert!(lines.by_ref().any(|l| l.unwrap().ends_with("Server is ready!")));
        node
    };
    let mut nodes = [start(0), start(1)];
    // What the stats log last said of a node: its height, the blocks
    // that joined its chain, and those it made itself.
    let last = |i: usize| -> Option<(u64, u64, u64)> {
        let stats = std::fs::read_to_string(dirs[i].join("stat.log")).ok()?;
        let whole = stats.lines().rev().find(|l| l.starts_with('['))?;
        let n: Vec<u64> = whole[26..].split_whitespace().map(|n| n.replace(',', "").parse().unwrap_or(0)).collect();
        Some((n[n.len() - 3], n[n.len() - 2], n[n.len() - 1]))
    };
    // Until each has made blocks, and holds more than it made.
    let began = Instant::now();
    loop {
        let all: Vec<_> = (0..2).filter_map(last).collect();
        if all.len() == 2 && all.iter().all(|(height, joined, made)| *height >= 2 && *made >= 1 && joined > made) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(2400), "{all:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    for node in &mut nodes {
        assert!(Command::new("kill").args(["-TERM", &node.0.id().to_string()]).status().unwrap().success());
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&node.0.wait().unwrap()), Some(15));
    }
    // Each was told of the other's blocks and asked for them; and
    // nothing went wrong that the main log would say.
    for dir in &dirs {
        let requests = std::fs::read_to_string(dir.join("request.log")).unwrap();
        assert!(requests.contains(" block height ") && requests.contains(" get block, "), "{requests}");
        // The main log says of each block that it was being made, that
        // it was won, or that it came from the other.
        let main = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
        assert!(!main.contains("Error"), "{main}");
        // (Not of the first block, which one of them may have had from the
        // other before its own was proven.)
        let told = ["] Proving block ", "] Mining block ", ": proved in ", "] Won block ", " hashes in "];
        let told = told.into_iter().chain(["] Received block ", " bytes from 127.0.0.1:"]);
        for said in told.chain(["] Peer 127.0.0.1:", " connected (height "]) {
            assert!(main.contains(said), "{said}: {main}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Two nodes of the dev network, each with a wallet and a prompt: one
/// makes blocks, whose rewards are its wallet's, and pays the other by
/// a slate passed between them as a file. The payment is mined, and the
/// other's wallet has it.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_is_made_at_the_prompt_and_mined() {
    let _one = proving();
    use std::io::{Read, Write};
    use std::process::{ChildStdin, ChildStdout};
    use std::time::{Duration, Instant};
    let dirs = [scratch("pay-a"), scratch("pay-b")];
    let port = 43_000 + std::process::id() % 20_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    // What a node says up to its next prompt.
    fn until_prompt(out: &mut ChildStdout) -> String {
        let (mut said, mut byte) = (Vec::new(), [0u8; 1]);
        while !(said.ends_with(b"> ") && (said.len() == 2 || said[said.len() - 3] == b'\n')) {
            assert_eq!(out.read(&mut byte).unwrap(), 1, "the node stopped: {}", String::from_utf8_lossy(&said));
            said.push(byte[0]);
        }
        String::from_utf8(said[..said.len() - 2].to_vec()).unwrap()
    }
    fn ask(node: &mut (Running, ChildStdin, ChildStdout), command: &str) -> String {
        writeln!(node.1, "{command}").unwrap();
        until_prompt(&mut node.2)
    }
    let start = |i: usize, mines: bool| {
        let mut command = Command::new(TABMINER);
        command
            .args(["--network", "dev", "--min-confirmations", "1"])
            .args(["--data-dir", &dirs[i].display().to_string(), "--listen", &at(i as u32)])
            .args(["--peer", &at(1 - i as u32)]);
        if !mines {
            command.arg("--no-mine");
        }
        let node = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut node = Running(node);
        let (mut stdin, mut stdout) = (node.0.stdin.take().unwrap(), node.0.stdout.take().unwrap());
        // A new wallet: no password. The node is ready, and then its
        // words are said, once: the last thing before the prompt.
        writeln!(stdin).unwrap();
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        let before: Vec<String> =
            lines.by_ref().map(|l| l.unwrap()).take_while(|l| !l.ends_with("Server is ready!")).collect();
        assert!(!before.iter().any(|l| l.starts_with(PHRASE)), "{before:#?}");
        // (One line, after the node is ready.)
        let said = lines.by_ref().map(|l| l.unwrap()).find(|l| l.starts_with(PHRASE)).expect("the wallet's words");
        let words = said.strip_prefix(PHRASE).unwrap_or_else(|| panic!("{said}"));
        assert_eq!(words.split_whitespace().count(), 12, "{words}");
        assert!(dirs[i].join("wallet.tab").exists());
        // (What it says on that side from here on is not waited for.)
        std::thread::spawn(move || lines.for_each(drop));
        assert_eq!(until_prompt(&mut stdout), "");
        (node, stdin, stdout)
    };
    let mut maker = start(0, true);
    let mut other = start(1, false);
    let confirmed = |node: &mut (Running, ChildStdin, ChildStdout)| {
        let said = ask(node, "balance");
        said.lines().next().unwrap().trim_start_matches("spendable").trim().to_string()
    };
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(4800), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    assert!(ask(&mut maker, "help").starts_with("commands:"));
    assert_eq!(ask(&mut maker, "nonsense"), "error: nonsense: no such command (see help)\n");
    assert_eq!(confirmed(&mut other), "0");
    // Rewards come to the maker's wallet as its blocks join the chain.
    wait("the maker has no rewards", &mut || confirmed(&mut maker) != "0");
    assert!(ask(&mut maker, "outputs").contains("confirmed"));
    // The payment: begun by the maker, answered by the other, signed by
    // the maker.
    let slate = dirs[0].join("payment.slate").display().to_string();
    let begun = ask(&mut maker, &format!("send-file 12.5 {slate}"));
    assert!(begun.contains("begun: 12.5 and a fee of"), "{begun}");
    let pending = ask(&mut maker, "txs pending");
    assert!(pending.contains(" begun ") && pending.contains("12.5"), "{pending}");
    let answered = ask(&mut other, &format!("receive {slate}"));
    assert!(answered.contains("answered: 12.5 to this wallet"), "{answered}");
    assert!(ask(&mut other, "balance").contains("unverified  12.5"));
    let signed = ask(&mut maker, &format!("finalize {slate}.received"));
    assert!(signed.contains("signed and pooled"), "{signed}");
    assert!(!ask(&mut maker, "txs pending").contains(" begun "));
    // Mined: the other has it, confirmed, and the maker's log says a
    // block carried it.
    wait("the payment is not confirmed", &mut || confirmed(&mut other) == "12.5");
    let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
    assert!(log.contains("carries 1 transaction of the pool (1 signature)"), "{log}");
    // And each node's log says what its own wallet did, and nothing of
    // the other's.
    let theirs = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
    assert!(log.contains("] Payment ") && log.contains(" begun: 12.5 and a fee of "), "{log}");
    assert!(log.contains(" signed and pooled: transaction ") && !log.contains(" answered: "), "{log}");
    assert!(theirs.contains(" answered: 12.5 to this wallet") && !theirs.contains(" begun: "), "{theirs}");
    assert!(!theirs.contains("signed and pooled"), "{theirs}");
    let status = ask(&mut other, "status");
    assert!(status.contains("wallet: 12.5 confirmed") && status.contains("pool: 0 transactions"), "{status}");
    // A second payment, taken back before a block has it: another
    // spend of the same takes its place in both pools, and the other
    // never has it.
    let begun = ask(&mut maker, &format!("send-file 3 {slate}"));
    assert!(begun.contains("begun: 3 and a fee of"), "{begun}");
    assert!(ask(&mut other, &format!("receive {slate}")).contains("answered: 3 to this wallet"));
    let signed = ask(&mut maker, &format!("finalize {slate}.received"));
    let id = signed.split("transaction ").nth(1).unwrap()[..8].to_string();
    let back = ask(&mut maker, &format!("cancel {id}"));
    println!("{}", back.trim_end());
    // (Unless a block had it already: then it is not to be taken back.)
    if back.contains("taken back: transaction") {
        let after = "The transaction has been cancelled, but it could still end up in a block: \
                     `txs` says which of the two did.";
        assert!(back.contains(after), "{back}");
        wait("the payment taken back is not mined", &mut || !ask(&mut maker, "txs pending").contains(" pooled "));
        // (The list says which took the place of which.)
        let listed = ask(&mut maker, "txs");
        assert!(listed.contains(" replaced by ") && listed.contains(" cancel of "), "{listed}");
        // (What it was put in place of may have been mined all the
        // same, between the taking back and the block: which is what
        // the taking back says of itself. Then the other holds it.)
        match ask(&mut other, "prune").starts_with("1 outputs expected") {
            true => assert_eq!(confirmed(&mut other), "12.5"),
            false => assert_eq!(confirmed(&mut other), "15.5"),
        }
        let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
        assert!(log.contains(" taken back: transaction "), "{log}");
    } else {
        assert!(back.contains("a block has it already"), "{back}");
    }
    assert!(ask(&mut maker, "bump 0000000000").starts_with("error: no row with that number"));
    // Told to stop, each does, without failure.
    for mut node in [maker, other] {
        writeln!(node.1, "quit").unwrap();
        assert_eq!(node.0.0.wait().unwrap().code(), Some(0));
    }
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A node of the dev network with a wallet and a prompt, as a test
/// drives it: what is typed to it, and what it says.
#[cfg(all(unix, feature = "dev"))]
struct Prompted {
    node: Running,
    typed: std::process::ChildStdin,
    said: std::process::ChildStdout,
}

#[cfg(all(unix, feature = "dev"))]
impl Prompted {
    /// Starts a node in `dir` listening on `listen`, with these peers,
    /// making blocks or not: `new` if it has no wallet yet, when its
    /// words are looked for.
    fn start(dir: &std::path::Path, listen: &str, peers: &[String], mines: bool, new: bool) -> Prompted {
        Prompted::start_as(dir, listen, peers, mines, new, None).0
    }

    /// The same, and the words of its wallet if it is new; or, with
    /// `restore`, a node whose wallet is made again from those words.
    fn start_as(
        dir: &std::path::Path,
        listen: &str,
        peers: &[String],
        mines: bool,
        new: bool,
        restore: Option<&str>,
    ) -> (Prompted, Option<String>) {
        Prompted::start_with(dir, listen, peers, mines, new, restore, &[])
    }

    /// The same, with these options more.
    fn start_with(
        dir: &std::path::Path,
        listen: &str,
        peers: &[String],
        mines: bool,
        new: bool,
        restore: Option<&str>,
        more: &[&str],
    ) -> (Prompted, Option<String>) {
        use std::io::Write;
        let mut command = Command::new(TABMINER);
        command.args(more);
        if restore.is_some() {
            command.arg("--restore");
        }
        command.args(["--network", "dev", "--data-dir", &dir.display().to_string()]);
        // (Its wallet spends what one block has: these chains are short.)
        command.args(["--min-confirmations", "1"]);
        command.args(["--listen", listen]);
        // (The nodes it is told of are its seeds too: wallets are
        // reached at the seeds, and every node here is given the same.)
        for peer in peers {
            command.args(["--peer", peer, "--seed", peer]);
        }
        if !mines {
            command.arg("--no-mine");
        }
        let node = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut node = Running(node);
        let (mut typed, said) = (node.0.stdin.take().unwrap(), node.0.stdout.take().unwrap());
        // (Its words, of a wallet made again; and of that or a new
        // one, no password.)
        if let Some(words) = restore {
            writeln!(typed, "{words}").unwrap();
        }
        if new || restore.is_some() {
            writeln!(typed).unwrap();
        }
        let mut lines = BufReader::new(node.0.stderr.take().unwrap()).lines();
        let before: Vec<String> =
            lines.by_ref().map(|l| l.unwrap()).take_while(|l| !l.ends_with("Server is ready!")).collect();
        // (A new wallet's words are said after that, and nowhere
        // before.)
        assert!(!before.iter().any(|l| l.starts_with(PHRASE)), "{before:#?}");
        let mut words = None;
        if new {
            let said = lines.by_ref().map(|l| l.unwrap()).find(|l| l.starts_with(PHRASE)).expect("the wallet's words");
            let phrase = said.strip_prefix(PHRASE).unwrap_or_else(|| panic!("{said}"));
            assert_eq!(phrase.split_whitespace().count(), 12, "{said}");
            words = Some(phrase.trim().to_string());
        } else if restore.is_some() {
            // (A wallet made again says its address, which is another.)
            let said = lines
                .by_ref()
                .map(|l| l.unwrap())
                .find(|l| l.starts_with("Wallet's restored"))
                .expect("the wallet's address");
            assert!(said.starts_with("Wallet's restored address: tab1"), "{said}");
            assert!(said.ends_with("(Note: this is different than the previous address)"), "{said}");
        }
        std::thread::spawn(move || lines.for_each(drop));
        let mut node = Prompted { node, typed, said };
        assert_eq!(node.until_prompt(), "");
        (node, words)
    }

    /// What it says up to its next prompt.
    fn until_prompt(&mut self) -> String {
        use std::io::Read;
        let (mut said, mut byte) = (Vec::new(), [0u8; 1]);
        while !(said.ends_with(b"> ") && (said.len() == 2 || said[said.len() - 3] == b'\n')) {
            assert_eq!(self.said.read(&mut byte).unwrap(), 1, "the node stopped: {}", String::from_utf8_lossy(&said));
            said.push(byte[0]);
        }
        String::from_utf8(said[..said.len() - 2].to_vec()).unwrap()
    }

    fn ask(&mut self, command: &str) -> String {
        use std::io::Write;
        writeln!(self.typed, "{command}").unwrap();
        self.until_prompt()
    }

    fn confirmed(&mut self) -> String {
        self.ask("balance").lines().next().unwrap().trim_start_matches("spendable").trim().to_string()
    }

    fn height(&mut self) -> u64 {
        let status = self.ask("status");
        status.split_whitespace().nth(1).unwrap().replace(',', "").parse().unwrap()
    }

    fn stop(mut self) {
        use std::io::Write;
        writeln!(self.typed, "quit").unwrap();
        assert_eq!(self.node.0.wait().unwrap().code(), Some(0));
    }
}

/// The chain goes over to another branch under two wallets, between
/// nodes that are running. A payment mined on the branch given up is
/// in no block: its sender's node says so, as its recipient's does of
/// what it was paid; the payment goes back to the pools, and from them
/// to the node whose branch it is now, which never had it; mined there,
/// each wallet has what it had. A payment that no block has is put back
/// in the pool of a node that was stopped and started; and one that
/// spent what only the branch given up had is never mined.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_survives_the_chain_going_over_to_another_branch() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("reorg-a"), scratch("reorg-b"), scratch("reorg-c")];
    let port = 45_000 + std::process::id() % 15_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(6000), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let log = |i: usize| std::fs::read_to_string(dirs[i].join("tabernacle.log")).unwrap();
    let slate = dirs[0].join("payment.slate").display().to_string();
    let pay = |maker: &mut Prompted, other: &mut Prompted, amount: &str| {
        assert!(maker.ask(&format!("send-file {amount} {slate}")).contains("begun"));
        assert!(other.ask(&format!("receive {slate}")).contains("answered"));
        let signed = maker.ask(&format!("finalize {slate}.received"));
        assert!(signed.contains("signed and pooled"), "{signed}");
    };

    // A makes blocks, and B follows it. C takes the first of them, and
    // is stopped: what it has is where the branches will part.
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], true, true);
    let mut other = Prompted::start(&dirs[1], &at(1), &[at(0)], false, true);
    wait("the maker has made no blocks", &mut || maker.height() >= 4);
    let shared = maker.height();
    let mut third = Prompted::start(&dirs[2], &at(2), &[at(0)], false, true);
    wait("the third has not the first blocks", &mut || third.height() >= shared);
    third.stop();

    // A pays B, in a block of its own branch; and stops making blocks.
    pay(&mut maker, &mut other, "12.5");
    wait("the payment is not confirmed", &mut || other.confirmed() == "12.5");
    maker.stop();
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], false, false);
    let ours = maker.height();
    // A second payment, which no block has, since nobody makes any: it
    // is not in the pool of a node stopped and started, and is put
    // back there.
    pay(&mut maker, &mut other, "3");
    maker.stop();
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], false, false);
    wait("the payment that no block has is not pooled again", &mut || {
        log(0).contains("was in no block and not pooled: pooled again")
    });
    assert!(maker.ask("txs pending").contains(" pooled "));

    // C makes blocks on what it has, where nobody knows of it, until
    // its branch is the longer; then it is where A and B find it.
    let mut third = Prompted::start(&dirs[2], &at(3), &[], true, false);
    wait("the third's branch is not the longer", &mut || third.height() > ours + 3);
    third.stop();
    let mut third = Prompted::start(&dirs[2], &at(3), &[at(0), at(1)], true, false);

    // The first payment is mined again, on that branch: the other has
    // it, where it now is.
    wait("the payment is not mined on the other branch", &mut || {
        log(1).contains("outputs that were orphaned are in the chain again")
    });
    assert_eq!(other.confirmed(), "12.5");
    assert!(third.height() > ours);
    let (a, b) = (log(0), log(1));
    assert!(a.contains("Reorganized to block"), "{a}");
    assert!(a.contains("The wallet: 1 payments sent are in no block any more"), "{a}");
    assert!(b.contains("The wallet: 1 outputs are in no block any more"), "{b}");
    assert!(log(2).contains("carries 1 transaction of the pool"), "{}", log(2));
    // The second spent the reward of a block of the branch given up
    // (the largest the maker had, with the first payment's fee): there
    // is no such output now, and no block will ever have that payment.
    // Its sender has nothing waiting; its recipient has what was never
    // more than expected, until it is pruned.
    assert!(!maker.ask("txs pending").contains(" pooled "), "{}", maker.ask("txs"));
    assert!(other.ask("balance").contains("unverified  3"));
    assert!(other.ask("prune").starts_with("1 outputs expected"));
    assert_eq!(other.ask("balance"), "spendable   12.5\n");
    for node in [maker, other, third] {
        node.stop();
    }
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A name, between running nodes: committed to, revealed when its
/// commit has waited, changed, and given to the wallet of another node;
/// each step a transaction the wallet makes and a block carries.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_name_is_registered_changed_and_given_at_the_prompt() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("name-a"), scratch("name-b")];
    let port = 47_000 + std::process::id() % 15_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(4800), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let mut maker = Prompted::start(&dirs[0], &at(0), &[at(1)], true, true);
    let mut other = Prompted::start(&dirs[1], &at(1), &[at(0)], false, true);
    wait("the maker has no rewards", &mut || maker.confirmed() != "0");
    assert_eq!(maker.ask("names"), "no names\n");
    assert_eq!(maker.ask("name alice"), "alice is not registered\n");
    assert!(maker.ask("name-commit Alice").starts_with("error: Alice is not a valid name"));

    // Committed to: which says nothing of the name. Revealed once the
    // commit has been in the chain for as long as the network asks.
    let committed = maker.ask("name-commit alice -");
    assert!(committed.starts_with("Name alice: committed to: transaction "), "{committed}");
    assert!(maker.ask("names").contains("committed, "));
    assert!(maker.ask("name-commit alice").starts_with("error: the wallet has already committed"));
    let mut early = false;
    wait("the name is not revealed", &mut || {
        let said = maker.ask("name-reveal alice");
        early |= said.contains("not on chain yet") || said.contains("blocks old; wait");
        said.starts_with("Name alice: revealed: transaction ")
    });
    assert!(early, "it was revealed without waiting");
    wait("the name is not registered", &mut || maker.ask("names").contains("  owned  "));
    let nothing = "0".repeat(64);
    assert!(maker.ask("name alice").starts_with(&format!("alice says {nothing}\n")));
    assert_eq!(other.ask("name alice"), maker.ask("name alice"));

    // Changed: what it says, as every node then has it.
    let says = "01000000".repeat(8);
    assert!(maker.ask("name-update alice nonsense").starts_with("error: 'nonsense' is not what a name says"));
    assert!(maker.ask(&format!("name-update alice {says}")).starts_with("Name alice: changed: transaction "));
    assert!(maker.ask("names").contains("owned, a change signed"));
    wait("the name is not changed", &mut || other.ask("name alice").starts_with(&format!("alice says {says}\n")));
    wait("the wallet has not seen the change", &mut || maker.ask("names").contains(&format!("  owned  says {says}")));

    // Given to the other node's wallet: which writes the record, for
    // the owner to sign over.
    let offer = dirs[1].join("alice.offer").display().to_string();
    assert!(other.ask(&format!("name-offer alice {offer} -")).starts_with("Name alice: an offer written"));
    assert!(other.ask("names").contains("offered to this wallet"));
    assert!(maker.ask(&format!("name-transfer {offer}")).starts_with("Name alice: signed over: transaction "));
    assert!(maker.ask("names").contains("being given away"));
    wait("the name has not been given", &mut || other.ask("names").contains("  owned  "));
    wait("the name has not left its giver", &mut || maker.ask("names") == "no names\n");
    assert!(other.ask("name alice").starts_with(&format!("alice says {nothing}\n")));
    let log = std::fs::read_to_string(dirs[0].join("tabernacle.log")).unwrap();
    for step in ["committed to", "revealed", "changed", "signed over"] {
        assert!(log.contains(&format!("] Name alice: {step}: transaction ")), "{step}: {log}");
    }
    maker.stop();
    other.stop();
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A wallet is made again from its twelve words, on another node: it
/// finds, once the chain is there, what the first holds; and says its
/// words as the first does. And a wallet's password is set, asked for,
/// and taken off, at the prompt.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_wallet_is_made_again_from_its_words() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("restore-a"), scratch("restore-b")];
    let port = 35_000 + std::process::id() % 10_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    // One makes blocks, and holds what they pay.
    let (mut first, words) = Prompted::start_as(&dirs[0], &at(0), &[], true, true, None);
    let words = words.unwrap();
    let began = Instant::now();
    while first.height() < 3 {
        assert!(began.elapsed() < Duration::from_secs(2400), "no blocks");
        std::thread::sleep(Duration::from_millis(200));
    }
    // Its password: none, then one, which its words are then kept
    // behind, then none again.
    use std::io::Write;
    assert!(first.ask("seed").contains(&words));
    writeln!(first.typed, "password\nsecret\nsecret").unwrap();
    assert!(first.until_prompt().contains("password is set"));
    writeln!(first.typed, "seed\nnot it").unwrap();
    assert!(first.until_prompt().contains("wrong wallet password"));
    writeln!(first.typed, "seed\nsecret").unwrap();
    assert!(first.until_prompt().contains(&words));
    writeln!(first.typed, "password\nsecret\n").unwrap();
    assert!(first.until_prompt().contains("no password now"));
    assert!(first.ask("seed").contains(&words));
    // Another, of the same words, with nothing but the chain to go by:
    // it comes to hold what the chain says those words hold.
    let (mut second, _) = Prompted::start_as(&dirs[1], &at(1), &[at(0)], false, false, Some(&words));
    assert!(second.ask("seed").contains(&words));
    // (What the first is paid after the second has looked is the
    // first's to know of: the second looks once, and from then on
    // follows what it knows. So: something, and no more than the first
    // holds.)
    let began = Instant::now();
    let found = loop {
        let found = second.confirmed();
        if found != "0" {
            break found;
        }
        assert!(began.elapsed() < Duration::from_secs(3600), "the second has found nothing");
        std::thread::sleep(Duration::from_millis(500));
    };
    let units = |coins: &str| coins.replace(',', "").parse::<f64>().unwrap();
    assert!(units(&found) > 0.0 && units(&found) <= units(&first.confirmed()), "{found}");
    let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
    assert!(log.contains("The wallet, made again from its words, has found "), "{log}");
    // And it is not made again over a wallet that is there.
    second.stop();
    let again = Command::new(TABMINER)
        .args(["--network", "dev", "--no-mine", "--restore", "--data-dir", &dirs[1].display().to_string()])
        // (A port of the test's own: the default may be another node's.)
        .args(["--listen", &at(1)])
        .output()
        .unwrap();
    assert!(!again.status.success() && String::from_utf8_lossy(&again.stderr).contains("there is a wallet already"));
    first.stop();
    for dir in &dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Miners vote for a consensus file, and the network comes to follow
/// it: a node that makes blocks is told to vote for a file that names
/// three relays; a node that makes none, and was told nothing, takes
/// from it the leaves its blocks commit to and then the file itself;
/// and when the votes of the first hundred and forty-four blocks are
/// counted, both say the same file is in force, and the mode it names.
// (A vote is decided over 144 blocks, and every block here is proven:
// an hour and more of every core. Run when asked for.)
#[cfg(all(unix, feature = "dev"))]
#[ignore = "proves 144 blocks; run with --release -- --ignored"]
#[test]
fn a_consensus_file_is_voted_for_and_followed() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("votes-a"), scratch("votes-b")];
    let port = 37_000 + std::process::id() % 10_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let mut first = Prompted::start(&dirs[0], &at(0), &[], true, true);
    let mut second = Prompted::start(&dirs[1], &at(1), &[at(0)], false, true);
    assert!(first.ask("consensus").starts_with("mode init\nnothing is decided before block 144"));
    assert!(first.ask("leaves").starts_with("no leaf is set"));
    // A file that is none is not voted for; one that is, is.
    let file = dirs[0].join("consensus.txt");
    std::fs::write(&file, "mode onion\n").unwrap();
    assert!(first.ask(&format!("set-leaf 0 {}", file.display())).contains("fewer than the 3 needed"));
    let relays: Vec<String> = (1..=3u32).map(|i| tabminer::address::encode(&[i as u8; 32])).collect();
    let text: String = relays.iter().enumerate().map(|(i, id)| format!("relay {id} 10.0.0.{i}:3737\n")).collect();
    std::fs::write(&file, format!("# three relays\nmode onion\n{text}")).unwrap();
    let voted = first.ask(&format!("set-leaf 0 {}", file.display()));
    assert!(voted.contains("vote for") && voted.contains("mode onion"), "{voted}");
    assert!(first.ask("leaves").contains("(the vote for a consensus file)"));
    // Until the first boundary nothing is in force; after it, the file
    // is, on both: the second has it from the first.
    let began = Instant::now();
    loop {
        let (a, b) = (first.ask("consensus"), second.ask("consensus"));
        if a.starts_with("mode onion") && b.starts_with("mode onion") {
            for said in [&a, &b] {
                assert!(said.contains("decided at block 144, of the votes of blocks 1 to 144"), "{said}");
                assert!(said.contains("in force: "), "{said}");
                assert!(relays.iter().all(|id| said.contains(&format!("  relay {id} 10.0.0."))), "{said}");
            }
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(18000), "the first says:\n{a}\nthe second says:\n{b}");
        std::thread::sleep(Duration::from_secs(2));
    }
    // (Each says so in its log when it next looks to the votes: within
    // a few seconds.)
    for dir in &dirs {
        let began = Instant::now();
        loop {
            let log = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
            if log.contains("The message layer is in onion mode: the consensus file ") {
                break;
            }
            assert!(began.elapsed() < Duration::from_secs(600), "{log}");
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    first.stop();
    second.stop();
    for dir in &dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A payment is made to an address: the wallet it is to is told
/// nothing and types nothing. The slate goes to it sealed, through a
/// node both are reached at and neither is otherwise anything to; its
/// wallet answers, the sender's signs the answer, and a block carries
/// the transaction.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_is_sent_to_an_address() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("send-relay"), scratch("send-a"), scratch("send-b")];
    let port = 33_000 + std::process::id() % 10_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    // A node that stands between wallets, and is nobody's wallet here.
    let relay = Command::new(TABMINER)
        .args(["--network", "dev", "--no-mine", "--no-prompt", "--relay"])
        .args(["--data-dir", &dirs[0].display().to_string(), "--listen", &at(0)])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let relay = Running(relay);
    let mut payer = Prompted::start(&dirs[1], &at(1), &[at(0)], true, true);
    let mut paid = Prompted::start(&dirs[2], &at(2), &[at(0)], false, true);
    let to = paid.ask("address").trim().to_string();
    assert!(to.starts_with("tab1") && to.len() == 62, "{to}");
    // Until the payer has something to pay with, and both are reached.
    let began = Instant::now();
    loop {
        let reached = |status: String| status.contains("reached at: 1 of 1 nodes");
        if payer.confirmed() != "0" && reached(payer.ask("status")) && reached(paid.ask("status")) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(3600), "{}\n{}", payer.ask("status"), paid.ask("status"));
        std::thread::sleep(Duration::from_millis(500));
    }
    // Not to nobody, nor to itself.
    assert!(payer.ask("send 5 tab1nothing").starts_with("error: 'tab1nothing' is no address"));
    assert!(payer.ask("send 5 @nobody").starts_with("error: nobody is not registered"));
    // To itself, if it likes: answered, signed and pooled as any.
    let own = payer.ask("address").trim().to_string();
    assert!(payer.ask(&format!("send 1 {own}")).contains(&format!("begun: 1 and a fee of")));
    let began = Instant::now();
    loop {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        if log.contains(&format!(" answered by {own}, signed and pooled: transaction ")) {
            // (Whom it is from is not said: the wallet that is paid is
            // not told, though here it is itself.)
            assert!(log.contains(" answered: 1 to this wallet") && !log.contains(" from tab1"), "{log}");
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(1200), "the wallet does not pay itself: {log}");
        std::thread::sleep(Duration::from_millis(50));
    }
    // (Mined, and what it paid is the wallet's to spend again.)
    while payer.ask("txs pending").contains(" begun ") || payer.confirmed() == "0" {
        assert!(began.elapsed() < Duration::from_secs(2400), "{}", payer.ask("txs"));
        std::thread::sleep(Duration::from_millis(300));
    }
    let sent = Instant::now();
    let begun = payer.ask(&format!("send 5 {to} \"deposit 4821\""));
    assert!(begun.contains("begun: 5 and a fee of") && begun.contains(&to), "{begun}");
    assert!(begun.contains("note: \"deposit 4821\""), "{begun}");
    // Answered, signed and pooled: how long that took is said, for
    // whoever reads the run.
    let pooled = loop {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        if log.contains(&format!(" answered by {to}, signed and pooled: transaction ")) {
            break sent.elapsed();
        }
        assert!(sent.elapsed() < Duration::from_secs(1200), "the answer has not come: {log}");
        std::thread::sleep(Duration::from_millis(20));
    };
    println!("a payment to an address was answered, signed and pooled in {:.2}s", pooled.as_secs_f64());
    let began = Instant::now();
    while paid.confirmed() != "5" {
        assert!(began.elapsed() < Duration::from_secs(3600), "the payment has not come: {}", paid.ask("balance"));
        std::thread::sleep(Duration::from_millis(500));
    }
    // What it was for is said to the wallet that was paid, and kept
    // with what it was paid; who paid is not.
    let log = std::fs::read_to_string(dirs[2].join("tabernacle.log")).unwrap();
    assert!(log.contains(" answered: 5 to this wallet, note: \"deposit 4821\""), "{log}");
    assert!(!log.contains(&own) && paid.ask("outputs").contains("\"deposit 4821\""), "{log}");
    // The payment is proven: kept by the wallet that paid, its proof
    // made when a block had it, and checked by another node against
    // nothing but its chain.
    let began = Instant::now();
    let listed = loop {
        let listed = payer.ask("payments");
        if listed.lines().any(|l| l.contains(&format!("paid to {to} \"deposit 4821\"")) && l.contains("proof ready")) {
            break listed;
        }
        assert!(began.elapsed() < Duration::from_secs(1200), "{listed}");
        std::thread::sleep(Duration::from_millis(300));
    };
    let line = listed.lines().find(|l| l.contains(&format!("paid to {to}"))).unwrap();
    let txid = line.split_whitespace().next().unwrap().to_string();
    let file = dirs[1].join("payment.proof").display().to_string();
    assert!(payer.ask(&format!("payment-proof {txid} {file}")).starts_with("the proof of "));
    assert!(std::fs::read_to_string(&file).unwrap().starts_with("-----BEGIN TAB PAYMENT PROOF-----\n"));
    // (Once the node that checks has the block: it may be a moment
    // behind the one that made the proof.)
    let began = Instant::now();
    let shown = loop {
        let shown = paid.ask(&format!("verify-proof {file}"));
        if !shown.contains("the chain here has no block") || began.elapsed() > Duration::from_secs(1200) {
            break shown;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(
        shown.starts_with(&format!("the proof holds: {own} paid 5 to {to}, note: \"deposit 4821\", in block ")),
        "{shown}"
    );
    // (Changed, it does not hold; and what is no proof is none.)
    let text = std::fs::read_to_string(&file).unwrap();
    let at = text.find('\n').unwrap() + 40;
    let swapped = if &text[at..at + 1] == "A" { "B" } else { "A" };
    std::fs::write(&file, format!("{}{swapped}{}", &text[..at], &text[at + 1..])).unwrap();
    let refused = paid.ask(&format!("verify-proof {file}"));
    assert!(refused.starts_with("error: ") && !refused.contains("holds:"), "{refused}");
    // Coins are burned, to the credit of a name as it is written: and
    // that is proven as a payment is.
    let burned = payer.ask("burn 2 \"a year of hosting\" alice@mailhub");
    assert!(burned.starts_with("Burned: 2 for alice@mailhub, for \"a year of hosting\": transaction "), "{burned}");
    let began = Instant::now();
    let listed = loop {
        let listed = payer.ask("payments");
        if listed.lines().any(|l| l.contains("burned for alice@mailhub") && l.contains("proof ready")) {
            break listed;
        }
        assert!(began.elapsed() < Duration::from_secs(2400), "{listed}");
        std::thread::sleep(Duration::from_millis(300));
    };
    let line = listed.lines().find(|l| l.contains("burned for alice@mailhub")).unwrap();
    let txid = line.split_whitespace().next().unwrap().to_string();
    let file = dirs[1].join("burn.proof").display().to_string();
    assert!(payer.ask(&format!("burn-proof {txid} {file}")).starts_with("the proof of "));
    // (Once the node that checks has the block: it may be a moment
    // behind the one that made the proof.)
    let began = Instant::now();
    let shown = loop {
        let shown = paid.ask(&format!("verify-proof {file}"));
        if !shown.contains("the chain here has no block") || began.elapsed() > Duration::from_secs(1200) {
            break shown;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(
        shown.starts_with("the proof holds: 2 was burned for alice@mailhub, for \"a year of hosting\", in block "),
        "{shown}"
    );
    assert!(payer.ask("burn 1 nothing").starts_with("error: burn: not what it takes"));
    while payer.confirmed() == "0" {
        assert!(began.elapsed() < Duration::from_secs(2400), "{}", payer.ask("balance"));
        std::thread::sleep(Duration::from_millis(300));
    }
    // A payment to a wallet that is not there is no payment: said to be
    // so, given up, and nothing spent.
    let nobody = tabminer::address::encode(&[77; 32]);
    let held = payer.confirmed();
    assert!(payer.ask(&format!("send 1 {nobody}")).contains("begun: 1 and a fee of"));
    let began = Instant::now();
    loop {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        if log.contains(&format!(" to {nobody} was not delivered (that wallet is not there): given up")) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(1800), "{log}");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(!payer.ask("txs pending").contains(" begun "), "{}", payer.ask("txs"));
    assert!(payer.confirmed() >= held);
    // Each wallet's log says its part of it, and whom it was with.
    let logs: Vec<String> = dirs.iter().map(|d| std::fs::read_to_string(d.join("tabernacle.log")).unwrap()).collect();
    assert!(logs[1].contains(&format!(" answered by {to}, signed and pooled: transaction ")), "{}", logs[1]);
    // (The wallet that was paid was not told who paid it.)
    assert!(logs[2].contains(" answered: 5 to this wallet") && !logs[2].contains(&own), "{}", logs[2]);
    // And the node between them saw a message offered, and nothing of
    // what it said or who sent it: neither address is in its logs.
    let between = format!("{}{}", logs[0], std::fs::read_to_string(dirs[0].join("request.log")).unwrap());
    assert!(between.contains(" offer ") && !between.contains(&own) && !between.contains(&to), "{between}");
    payer.stop();
    paid.stop();
    drop(relay);
    for dir in &dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// While relays are in force a payment goes by them: four nodes that
/// ways go through, a wallet that pays and one that is paid, each
/// reached at the end of a way through relays and sending by another.
/// The payment is answered, signed and mined; and neither wallet's
/// node is told where the other is by anything of the message layer.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_payment_goes_by_ways_through_relays() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs: Vec<_> = (0..6).map(|i| scratch(&format!("ways-{i}"))).collect();
    let port = 34_000 + std::process::id() % 10_000;
    let at = |i: usize| format!("127.0.0.1:{}", port + i as u32);
    // (All of one chain: each knows the first, as a node of the chain.)
    let mut relays: Vec<Prompted> = (0..4)
        .map(|i| {
            let peers = if i == 0 { vec![] } else { vec![at(0)] };
            Prompted::start_with(&dirs[i], &at(i), &peers, false, true, None, &["--relay"]).0
        })
        .collect();
    let mut payer = Prompted::start(&dirs[4], &at(4), &[at(0)], true, true);
    let mut paid = Prompted::start(&dirs[5], &at(5), &[at(0)], false, true);
    // The relays, by the addresses of their wallets: a file nobody
    // voted for, put in force at each node.
    let mut file = String::from("mode onion\n");
    for (i, relay) in relays.iter_mut().enumerate() {
        file.push_str(&format!("relay {} {}\n", relay.ask("address").trim(), at(i)));
    }
    let path = dirs[0].join("forced.txt");
    std::fs::write(&path, file).unwrap();
    let force = format!("debug-consensus {}", path.display());
    for node in relays.iter_mut().chain([&mut payer, &mut paid]) {
        let said = node.ask(&force);
        assert!(said.contains("onion mode, of 4 relays"), "{said}");
    }
    let to = paid.ask("address").trim().to_string();
    let began = Instant::now();
    loop {
        let reached = |status: String| status.contains("reached at: 3 of 3 nodes");
        if payer.confirmed() != "0" && reached(payer.ask("status")) && reached(paid.ask("status")) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(3600), "{}\n{}", payer.ask("status"), paid.ask("status"));
        std::thread::sleep(Duration::from_millis(500));
    }
    let sent = Instant::now();
    let begun = payer.ask(&format!("send 5 {to}"));
    assert!(begun.contains("begun: 5 and a fee of") && begun.contains(&to), "{begun}");
    let pooled = loop {
        let log = std::fs::read_to_string(dirs[4].join("tabernacle.log")).unwrap();
        if log.contains(" signed and pooled: transaction ") {
            break sent.elapsed();
        }
        assert!(sent.elapsed() < Duration::from_secs(1200), "the answer has not come: {log}");
        std::thread::sleep(Duration::from_millis(20));
    };
    println!("a payment by ways through relays was answered, signed and pooled in {:.2}s", pooled.as_secs_f64());
    let began = Instant::now();
    while paid.confirmed() != "5" {
        assert!(began.elapsed() < Duration::from_secs(2400), "{}", paid.ask("balance"));
        std::thread::sleep(Duration::from_millis(500));
    }
    // To a wallet that is nowhere: an error, and nothing spent.
    let nobody = tabminer::address::encode(&[78; 32]);
    assert!(payer.ask(&format!("send 1 {nobody}")).contains("begun: 1 and a fee of"));
    let began = Instant::now();
    loop {
        let log = std::fs::read_to_string(dirs[4].join("tabernacle.log")).unwrap();
        if log.contains(&format!(" to {nobody} was not delivered (that wallet is not there): given up")) {
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(1800), "{log}");
        std::thread::sleep(Duration::from_millis(200));
    }
    // The relays held ways, and the nodes wallets are reached at held
    // their sessions.
    let held: Vec<String> = relays.iter_mut().map(|r| r.ask("status")).collect();
    // (Each of the six wallets at three of the four; and for a
    // minute more, whichever the first still holds of before.)
    let here = |s: &String| -> u32 {
        let line = s.lines().find(|l| l.starts_with("sessions: ")).unwrap_or("sessions: 0");
        line.split(' ').nth(1).unwrap().parse().unwrap()
    };
    assert!((18..=24).contains(&held.iter().map(here).sum::<u32>()), "{held:#?}");
}

/// A name under a name: the wallet that holds `mailhub` gives
/// `alice@mailhub` to another wallet, which is then reached by it, and
/// is paid by it; a name nobody was given is nobody's; and only the
/// wallet a name says may give names under it.
#[cfg(all(unix, feature = "dev"))]
#[cfg_attr(debug_assertions, ignore = "proves blocks; run with --release")]
#[test]
fn a_wallet_is_paid_by_a_name_under_a_name() {
    let _one = proving();
    use std::time::{Duration, Instant};
    let dirs = [scratch("sub-relay"), scratch("sub-hub"), scratch("sub-alice")];
    let port = 36_000 + std::process::id() % 10_000;
    let at = |i: u32| format!("127.0.0.1:{}", port + i);
    let wait = |what: &str, done: &mut dyn FnMut() -> bool| {
        let began = Instant::now();
        while !done() {
            assert!(began.elapsed() < Duration::from_secs(4800), "{what}");
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let relay = Command::new(TABMINER)
        .args(["--network", "dev", "--no-mine", "--no-prompt", "--relay"])
        .args(["--data-dir", &dirs[0].display().to_string(), "--listen", &at(0)])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let relay = Running(relay);
    let mut hub = Prompted::start(&dirs[1], &at(1), &[at(0)], true, true);
    let mut alice = Prompted::start(&dirs[2], &at(2), &[at(0)], false, true);
    let (hub_is, alice_is) = (hub.ask("address").trim().to_string(), alice.ask("address").trim().to_string());
    wait("the hub has no rewards", &mut || hub.confirmed() != "0");
    // The hub's wallet registers `mailhub`, and has it say its address.
    assert!(hub.ask("name-commit mailhub").starts_with("Name mailhub: committed to"));
    wait("the name is not revealed", &mut || hub.ask("name-reveal mailhub").starts_with("Name mailhub: revealed"));
    wait("the name is not registered", &mut || hub.ask("names").contains("  owned  "));
    // (Committed to with nothing said of what it is to say, it says the
    // hub's address: a name to be paid by, and to give names under.)
    wait("the name does not say the address", &mut || {
        alice.ask("name mailhub").contains(&format!("as an address: {hub_is}"))
    });
    assert_eq!(hub.ask("subnames"), "no names under names: none given, and this wallet is none\n");
    // What is no name under a name, or not the hub's to give.
    assert!(
        hub.ask(&format!("subname set Alice@mailhub {alice_is}"))
            .starts_with("error: 'Alice@mailhub' is no label@name")
    );
    assert!(hub.ask(&format!("subname set alice@nothing {alice_is}")).starts_with("error: nothing is not registered"));
    assert!(
        alice.ask(&format!("subname set bob@mailhub {alice_is}")).starts_with("error: mailhub is not this wallet's")
    );
    // Given: the other wallet is the name, and is reached by it.
    wait("the wallets are not reached", &mut || {
        hub.ask("status").contains("reached at: 1 of 1") && alice.ask("status").contains("reached at: 1 of 1")
    });
    let given = hub.ask(&format!("subname set alice@mailhub {alice_is}"));
    assert!(given.starts_with(&format!("alice@mailhub is {alice_is}, by a certificate that holds 7 days")), "{given}");
    wait("the name is not reached", &mut || alice.ask("subnames").contains("reached by it at 1 nodes"));
    assert!(alice.ask("subnames").starts_with("this wallet is alice@mailhub, for 7.0 days more"));
    assert!(hub.ask("subnames").starts_with(&format!("given: alice@mailhub is {alice_is}, for 7.0 days more")));
    // Paid by the name.
    let sent = Instant::now();
    let begun = hub.ask("send 5 alice@mailhub");
    assert!(begun.contains("begun: 5 and a fee of") && begun.contains("to alice@mailhub"), "{begun}");
    let pooled = loop {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        if log.contains(" signed and pooled: transaction ") {
            assert!(log.contains(&format!(": alice@mailhub is {alice_is}")), "{log}");
            break sent.elapsed();
        }
        assert!(sent.elapsed() < Duration::from_secs(1200), "the answer has not come: {log}");
        std::thread::sleep(Duration::from_millis(20));
    };
    println!("a payment to a name under a name was answered, signed and pooled in {:.2}s", pooled.as_secs_f64());
    wait("the payment is not confirmed", &mut || alice.confirmed() == "5");
    // To a name nobody was given: an error that names it.
    assert!(hub.ask("send 1 bob@mailhub").contains("to bob@mailhub"));
    wait("nothing is said of the name that is nobody's", &mut || {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        log.contains(" to bob@mailhub was not delivered (that wallet is not there): given up")
    });
    assert!(hub.ask("send 1 bob@nothing").starts_with("error: nothing is not registered"));
    // The hub says that alice's key signs for `mailhub`: alice then
    // gives a name under it, to the hub's wallet, which is paid by it.
    let word = dirs[1].join("mailhub.word").display().to_string();
    let said = hub.ask(&format!("subname delegate mailhub {alice_is} 10 {word}"));
    assert!(said.starts_with(&format!("for 10 days the key of {alice_is} signs for mailhub")), "{said}");
    assert!(hub.ask(&format!("subname signer {word}")).starts_with("error: "), "it names another wallet");
    let taken = alice.ask(&format!("subname signer {word}"));
    assert!(taken.starts_with("this wallet signs for mailhub for 10.0 days more, by the word of"), "{taken}");
    assert!(alice.ask("subnames").contains("signs for mailhub, by the word of"));
    let given = alice.ask(&format!("subname set desk@mailhub {hub_is}"));
    assert!(given.starts_with(&format!("desk@mailhub is {hub_is}")), "{given}");
    wait("the hub is not reached by the name", &mut || hub.ask("subnames").contains("this wallet is desk@mailhub"));
    wait("the hub is not reached by the name", &mut || hub.ask("subnames").contains("reached by it at 1 nodes"));
    // (The hub pays its own name: to itself, by a certificate of
    // another key's, which answers to the hub's word.)
    let held = alice.confirmed();
    assert!(hub.ask("send 2 desk@mailhub").contains("to desk@mailhub"));
    wait("the name signed for by word is not paid", &mut || {
        let log = std::fs::read_to_string(dirs[1].join("tabernacle.log")).unwrap();
        log.contains(&format!(": desk@mailhub is {hub_is}"))
            && log.contains(&format!(" answered by {hub_is}, signed and pooled"))
    });
    assert_eq!(alice.confirmed(), held);
    // The wallet is the name no longer, if it says so: and is not
    // paid by it.
    assert_eq!(alice.ask("subname drop alice@mailhub"), "this wallet is alice@mailhub no longer\n");
    assert!(alice.ask("subname drop alice@mailhub").starts_with("error: this wallet is not alice@mailhub"));
    assert!(hub.ask("subname del alice@mailhub").starts_with("alice@mailhub is given out no longer"));
    hub.stop();
    alice.stop();
    drop(relay);
    dirs.iter().for_each(|d| drop(std::fs::remove_dir_all(d)));
}

/// A node whose blocks' proofs go unchecked, and are not made
/// (`--debug-no-validate-proofs`): for what a node does with blocks,
/// tried in moments. Ended with the test, and its directory removed.
#[cfg(all(unix, feature = "dev"))]
struct Unchecked {
    node: Running,
    typed: std::process::ChildStdin,
    dir: PathBuf,
    listen: String,
}

#[cfg(all(unix, feature = "dev"))]
impl Drop for Unchecked {
    /// Told to stop at its prompt, as whoever keeps a node tells it, and
    /// waited for: a node that ends of itself says what it did (where
    /// what the tests reach is counted, it is then that it is written
    /// down). Ended outright if it has not by then.
    fn drop(&mut self) {
        use std::io::Write;
        let _ = writeln!(self.typed, "quit");
        let began = std::time::Instant::now();
        while began.elapsed() < std::time::Duration::from_secs(20) {
            if matches!(self.node.0.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = self.node.0.kill();
        let _ = self.node.0.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(all(unix, feature = "dev"))]
impl Unchecked {
    fn start(network: &str, name: &str, port: u32, args: &[&str]) -> Unchecked {
        let dir = scratch(name);
        let listen = format!("127.0.0.1:{port}");
        let node = Command::new(TABMINER)
            .args(["--network", network, "--debug-no-validate-proofs"])
            .args(["--stat-interval-seconds", "1", "--stat-summary-seconds", "2"])
            .args(["--data-dir", &dir.display().to_string(), "--listen", &listen])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut node = Running(node);
        // (A new wallet, if it makes one, has no password.)
        let mut typed = node.0.stdin.take().unwrap();
        let _ = std::io::Write::write_all(&mut typed, b"\n");
        Unchecked { node, typed, dir, listen }
    }

    /// The lines of its main log that have `text` in them.
    fn lines(&self, text: &str) -> Vec<String> {
        let log = std::fs::read_to_string(self.dir.join("tabernacle.log")).unwrap_or_default();
        log.lines().filter(|l| l.contains(text)).map(str::to_string).collect()
    }

    /// Waits until its log has `count` lines with `text` in them, and
    /// gives them: the test fails if ten minutes pass first (thirty of
    /// a build not optimized), or the node ends, or says of anything
    /// that it is an error.
    fn wait(&mut self, text: &str, count: usize) -> Vec<String> {
        // (A block is won by chance, at about a million hashes: a
        // build not optimized, on two cores and counting its lines,
        // makes six thousand a second, and one block in thirty is
        // then more than ten minutes in coming.)
        let most = std::time::Duration::from_secs(if cfg!(debug_assertions) { 1_800 } else { 600 });
        let began = std::time::Instant::now();
        loop {
            let lines = self.lines(text);
            if lines.len() >= count {
                return lines;
            }
            let wrong: Vec<String> = self.lines("Error: ").into_iter().chain(self.lines("Refused block")).collect();
            assert!(wrong.is_empty(), "{wrong:?}");
            if let Some(ended) = self.node.0.try_wait().unwrap() {
                panic!("the node ended ({ended}) before its log said '{text}' {count} times");
            }
            let all = std::fs::read_to_string(self.dir.join("tabernacle.log")).unwrap_or_default();
            assert!(began.elapsed() < most, "'{text}' {} of {count}: {all}", lines.len());
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

/// A node begun with a state nobody made fills its blocks with what
/// nobody sent, and a new node takes the state from it and the blocks
/// after: the blocks unproven, so in moments. What a node does with a
/// block and with a state is the same whoever proved the block.
#[cfg(all(unix, feature = "dev"))]
#[test]
fn blocks_filled_and_unproven_are_made_and_taken() {
    let port = 23_000 + std::process::id() % 9_000;
    // (Blocks kept for two back, and a state taken as of the block
    // under the last: with three blocks made the first can no longer
    // be had, and a new node must take the state.)
    let kept = ["--max-undo-blocks", "2", "--sync-point", "1", "--no-seeds"];
    let fill = ["--debug-fill-outputs", "2000,5", "--debug-fill", "200,200", "--blocks", "3"];
    let mut server = Unchecked::start("dev", "filled-server", port, &[&kept[..], &fill[..]].concat());
    server.wait("Server is ready!", 1);
    let built = server.wait("debug fill: block ", 3);
    assert!(built[0].contains("block 1: 200 outputs, 200 spends, "), "{built:?}");
    server.wait("applied in ", 3);
    let last = server.wait("Won block 3 (", 1).pop().unwrap();
    let id = &last[last.find('(').unwrap()..last.find(')').unwrap()];
    // A new node of that chain, with its first block and none of its
    // outputs.
    let join = ["--no-mine", "--no-wallet", "--debug-genesis-outputs", "2000,5", "--peer", &server.listen];
    let mut new = Unchecked::start("dev", "filled-new", port + 1, &[&kept[..], &join[..]].concat());
    new.wait("Server is ready!", 1);
    new.wait("Taking the state as of block 2 ", 1);
    new.wait("State taken as of block 2", 1);
    new.wait("Synced at block 3", 1);
    assert_eq!(new.lines(&format!("Received block 3 {id}")).len(), 1, "the two are on one block");
    // It makes no block above the height it was told, and says how it
    // stands as it goes.
    assert_eq!(server.lines("Won block ").len(), 3);
    let stats = std::fs::read_to_string(server.dir.join("stat.log")).unwrap();
    assert!(stats.contains("AvgLatency(us)"), "{stats}");
}

/// A chain of empty blocks made beforehand, some hundreds long, on the
/// network with the main network's work: a new node takes its headers,
/// then its state as of a block under its last, then the blocks after.
#[cfg(all(unix, feature = "dev"))]
#[test]
fn a_chain_made_beforehand_is_taken_by_its_headers() {
    let port = 32_100 + std::process::id() % 2_800;
    let kept = ["--max-undo-blocks", "8", "--sync-point", "4", "--no-seeds"];
    let made = ["--no-mine", "--debug-blocks", "300"];
    let mut server = Unchecked::start("dev-main-work", "headers-server", port, &[&kept[..], &made[..]].concat());
    server.wait("debug: a chain of 300 blocks ready in ", 1);
    server.wait("Server is ready!", 1);
    let join = ["--no-mine", "--no-wallet", "--peer", &server.listen];
    let mut new = Unchecked::start("dev-main-work", "headers-new", port + 1, &[&kept[..], &join[..]].concat());
    new.wait("Server is ready!", 1);
    new.wait("Headers synced to 300", 1);
    let taking = new.wait("Taking the state as of block 296 ", 1);
    assert_eq!(taking.len(), 1, "{taking:?}");
    new.wait("State taken as of block 296", 1);
    new.wait("Synced at block 300", 1);
    // (The data directory of blocks nobody checked says so, for good.)
    assert!(new.dir.join("unchecked").exists());
}

/// A node that makes no blocks is asked at its prompt how it stands,
/// its wallet's password is set and asked for, and it stops when told;
/// a wallet is then made again from its words in another directory, and
/// has the same words. No block is made: moments.
#[cfg(all(unix, feature = "dev"))]
#[test]
fn a_wallet_is_asked_at_the_prompt_and_made_again_with_no_block() {
    let dirs = [scratch("asked-a"), scratch("asked-b")];
    let port = 28_000 + std::process::id() % 4_000;
    let (mut node, words) = Prompted::start_as(&dirs[0], &format!("127.0.0.1:{port}"), &[], false, true, None);
    let words = words.unwrap();
    assert!(node.ask("help").starts_with("commands:"));
    assert_eq!(node.ask("nonsense"), "error: nonsense: no such command (see help)\n");
    assert!(node.ask("status").starts_with("block 0 ("));
    assert_eq!(node.ask("balance"), "spendable   0\n");
    assert_eq!(node.ask("peers"), "0 peers known, 0 of them live\n");
    for line in ["outputs", "names", "fees", "mempool", "leaves", "consensus", "mining", "txs", "payments"] {
        assert!(!node.ask(line).is_empty(), "{line}");
    }
    let address = node.ask("address");
    assert!(address.starts_with("tab1"), "{address}");
    // Its words are said again when asked for.
    assert!(node.ask("seed").contains(&words));
    node.stop();
    // Made again from its words, where there is no wallet: the same
    // words, and an address of its own (the wallet that was lost may
    // still be somewhere, reached at the one it had).
    let (mut again, _) =
        Prompted::start_as(&dirs[1], &format!("127.0.0.1:{}", port + 1), &[], false, false, Some(&words));
    let other = again.ask("address");
    assert!(other.starts_with("tab1") && other != address, "{other}");
    assert!(again.ask("seed").contains(&words));
    again.stop();
    // And the first starts again on what it kept, with the wallet it had.
    let (mut back, _) = Prompted::start_as(&dirs[0], &format!("127.0.0.1:{port}"), &[], false, false, None);
    assert_eq!(back.ask("address"), address);
    back.stop();
    for dir in &dirs {
        let log = std::fs::read_to_string(dir.join("tabernacle.log")).unwrap();
        assert!(!log.contains("Error"), "{log}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
