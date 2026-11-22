//! How a node is told what to do: its options, the help that lists
//! them, the check of what was given, and the lines a node says of its
//! configuration when it starts.
//!
//! `tabminer [options]` is all there is: no command comes first. Every
//! option is in one list ([`OPTIONS`]), from which the help is written,
//! the command line is read, and the startup lines are laid out, so
//! that the three cannot disagree.
//!
//! * An option that is not one is refused by name:
//!   `Error: unknown configuration option: '--prot'`, and the help
//!   follows.
//! * `--help`, anywhere on the line, is the help and nothing else.
//! * Everything given is checked ([`Configuration::read`]) before
//!   anything is opened, bound or written: a port out of range, a
//!   number that is not one, two limits that cannot both hold.
//!
//! # Where the logs go
//!
//! For each of the three logs, the first of these that was given: its
//! own option, which is the file's whole name (`--main-log`); the
//! directory for logs (`--log-dir`), with the log's usual name in it;
//! the data directory (`--data-dir`), the same. Whatever was given, the
//! names kept are whole paths from the root.

use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};

use crate::logger::fmt::{column, commas};
use crate::logger::stats::Every;
use crate::logger::{Logger, Rotation};
use crate::net::config::Config as Net;
use crate::transport::SECOND;

/// What an option takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Takes {
    /// Nothing: it is given or it is not.
    Nothing,
    /// A value, called this in the help.
    Value(&'static str),
    /// A value, and the option may be given more than once.
    Values(&'static str),
}

struct Opt {
    name: &'static str,
    takes: Takes,
    /// What the help says of it. A line break is a line break there.
    help: &'static str,
}

/// The options, in the sections and the order of the help.
const OPTIONS: &[(&str, &[Opt])] = &[
    (
        "General",
        &[
            Opt { name: "help", takes: Takes::Nothing, help: "print this and exit" },
            Opt { name: "network", takes: Takes::Value("NAME"), help: "mainnet (default), dev or dev-recursive" },
            Opt {
                name: "data-dir",
                takes: Takes::Value("DIR"),
                help: "where the chain, the peers file and the logs are kept\n(default ~/.tabernacle/tabminer)",
            },
            Opt {
                name: "threads",
                takes: Takes::Value("N"),
                help: "threads that handle requests, and threads for hashing and\nchecking proofs (default 0: one a core, counting cores and\nnot the two threads a core may run)",
            },
        ],
    ),
    (
        "Mining",
        &[
            Opt { name: "no-mine", takes: Takes::Nothing, help: "follow the chain without mining" },
            Opt {
                name: "prebuild-table",
                takes: Takes::Nothing,
                help: "make the whole table of the proof of work before any block\nis made, and not while blocks are made (it is kept in the\ndata directory either way, and made only once)",
            },
            Opt {
                name: "pow-table",
                takes: Takes::Value("FILE"),
                help: "where the table of the proof of work is kept (default\npow.table in the data directory): somewhere of its own, it\noutlasts the data directory and is not made again",
            },
            Opt {
                name: "delay-blocks",
                takes: Takes::Value("N"),
                help: "wait N seconds after each block made here before the next\nis begun: slower blocks, for a network of a few nodes far\napart (what blocks ask for in work follows)",
            },
            Opt {
                name: "max-block-signatures",
                takes: Takes::Value("N"),
                help: "signatures a block made here checks at the most: one for\neach input of the transactions it carries (default 256)",
            },
        ],
    ),
    (
        "Wallet",
        &[
            Opt {
                name: "no-wallet",
                takes: Takes::Nothing,
                help: "run without a wallet: with --no-mine, a block's reward\nbeing paid to the wallet",
            },
            Opt {
                name: "restore",
                takes: Takes::Nothing,
                help: "make the wallet again from its twelve words, which are\nasked for: where the data directory has no wallet. What it\nholds is looked for once the chain is here",
            },
            Opt {
                name: "password-file",
                takes: Takes::Value("FILE"),
                help: "the wallet's password is the first line of FILE, and is not\nasked for",
            },
            Opt {
                name: "min-confirmations",
                takes: Takes::Value("N"),
                help: "blocks an output is to have been in before the wallet\nspends it, the one that made it counted (default 6)",
            },
            Opt {
                name: "no-prompt",
                takes: Takes::Nothing,
                help: "take no commands from the terminal, and ask it nothing:\nfor a node run by another program",
            },
        ],
    ),
    (
        "Network",
        &[
            Opt {
                name: "listen",
                takes: Takes::Value("ADDR:PORT"),
                help: "the address datagrams are taken at (default 0.0.0.0:3737)",
            },
            Opt {
                name: "peer",
                takes: Takes::Values("ADDR:PORT"),
                help: "a peer to keep whatever it does; may be repeated",
            },
            Opt {
                name: "seed",
                takes: Takes::Values("HOST:PORT"),
                help: "a seed to look up besides the built-in ones; may be repeated",
            },
            Opt {
                name: "no-seeds",
                takes: Takes::Nothing,
                help: "do not use the built-in seeds (the main network has two;\nthe others none)",
            },
            Opt {
                name: "relay",
                takes: Takes::Nothing,
                help: "stand between wallets on the message layer: hold sessions\nfor those that are reached here, and pass on what is sealed\nto them. A node not told to does neither",
            },
            Opt {
                name: "max-sessions",
                takes: Takes::Value("N"),
                help: "with --relay: wallets a session is held for at the most\n(default 10000)",
            },
            Opt {
                name: "max-names",
                takes: Takes::Value("N"),
                help: "names under names the wallet takes at the most, of those it
is given (default 5)",
            },
            Opt {
                name: "mempool-size",
                takes: Takes::Value("SIZE"),
                help: "bytes of transactions waiting for a block that are kept at\nthe most: what pays least gives way to what pays more\n(default 64m)",
            },
            Opt {
                name: "min-fee",
                takes: Takes::Value("N"),
                help: "base units a unit of weight a transaction pays at the least\nto be kept and passed on here; the smallest output kept\nfollows it. The wallet pays no less (default 25000)",
            },
            Opt {
                name: "weight-input",
                takes: Takes::Value("N"),
                help: "what an input weighs in a transaction's fee, and each\nsignature of an input that spends a policy (default 1)",
            },
            Opt {
                name: "weight-output",
                takes: Takes::Value("N"),
                help: "what an output weighs: more than an input, the outputs\nbeing what every node keeps (default 3)",
            },
            Opt {
                name: "weight-commit",
                takes: Takes::Value("N"),
                help: "what a commitment to a name weighs (default 3)",
            },
            Opt { name: "weight-reveal", takes: Takes::Value("N"), help: "what a name's reveal weighs (default 4)" },
            Opt { name: "weight-update", takes: Takes::Value("N"), help: "what a name's update weighs (default 1)" },
            Opt {
                name: "max-tx-size",
                takes: Takes::Value("SIZE"),
                help: "the largest transaction kept and passed on here, whatever\nit pays (default 2m)",
            },
            Opt {
                name: "fee-half-life",
                takes: Takes::Value("N"),
                help: "what a full pool asks, above the least, falls halfway\nback in N hours (default 12)",
            },
            Opt {
                name: "mempool-expiry",
                takes: Takes::Value("N"),
                help: "a transaction that has waited N days for a block\nis dropped, and refused for as long again (default 14)",
            },
            Opt {
                name: "reserve",
                takes: Takes::Value("N"),
                help: "of the space for transactions of a block mined here, N in\na hundred is for those that have waited longest, oldest first,\nwhatever they pay (default 10; 0: all of it by fee)",
            },
            Opt {
                name: "request-queue-size",
                takes: Takes::Value("N"),
                help: "requests that may wait for one thread; one that comes\nwhen so many do is dropped (default 4096)",
            },
        ],
    ),
    (
        "Peers",
        &[
            Opt { name: "max-peers", takes: Takes::Value("N"), help: "peers kept (default 64)" },
            Opt {
                name: "target-peers",
                takes: Takes::Value("N"),
                help: "live peers below which more are looked for (default 8)",
            },
            Opt {
                name: "max-peers-per-host",
                takes: Takes::Value("N"),
                help: "peers of one host, over all its ports (default 4)",
            },
            Opt {
                name: "max-peers-per-network",
                takes: Takes::Value("N"),
                help: "peers of one /16 network (default 8)",
            },
            Opt { name: "ping-seconds", takes: Takes::Value("TIME"), help: "between pings of a peer (default 30)" },
            Opt {
                name: "peer-live-seconds",
                takes: Takes::Value("TIME"),
                help: "a peer silent this long is not counted live (default 65)",
            },
            Opt {
                name: "peer-drop-seconds",
                takes: Takes::Value("TIME"),
                help: "a peer silent this long is dropped (default 180)",
            },
            Opt {
                name: "ban-strikes",
                takes: Takes::Value("N"),
                help: "wrong answers before a host is refused (default 5)",
            },
            Opt { name: "ban-seconds", takes: Takes::Value("TIME"), help: "how long it is refused (default 3600)" },
        ],
    ),
    (
        "Sync",
        &[
            Opt {
                name: "sync-point",
                takes: Takes::Value("N"),
                help: "take the state whole as of the block N under the best\nheader when blocks cannot be had (default 144; 0: never)",
            },
            Opt {
                name: "sync-behind",
                takes: Takes::Value("N"),
                help: "take the state whole when more than N blocks under the\nbest header, though the blocks could be had (default 1008;\ntwice --sync-point at the least; 0: only when they cannot)",
            },
            Opt {
                name: "max-undo-blocks",
                takes: Takes::Value("N"),
                help: "blocks that can be undone, and whose bodies and states\nare served (default 1008)",
            },
            Opt {
                name: "header-fetches",
                takes: Takes::Value("N"),
                help: "runs of headers fetched at once (default 16)",
            },
            Opt { name: "block-fetches", takes: Takes::Value("N"), help: "blocks fetched at once (default 24)" },
            Opt {
                name: "block-fetches-per-peer",
                takes: Takes::Value("N"),
                help: "of those, from one peer (default 8)",
            },
            Opt {
                name: "part-fetches",
                takes: Takes::Value("N"),
                help: "parts of a state fetched at once (default 32)",
            },
            Opt {
                name: "header-wait-seconds",
                takes: Takes::Value("TIME"),
                help: "how long a peer claiming more work may take to send a\nheader we lack (default 15)",
            },
            Opt {
                name: "pass-over-seconds",
                takes: Takes::Value("TIME"),
                help: "how long a peer that failed us is passed over (default 600)",
            },
        ],
    ),
    (
        "Serving",
        &[
            Opt {
                name: "serve-chunks-per-second",
                takes: Takes::Value("N"),
                help: "chunks sent a second, in all (default 8192)",
            },
            Opt {
                name: "serve-queue",
                takes: Takes::Value("N"),
                help: "requests for chunks that may wait (default 256)",
            },
            Opt {
                name: "serve-queue-per-peer",
                takes: Takes::Value("N"),
                help: "of those, from one host (default 32)",
            },
        ],
    ),
    (
        "Debugging",
        &[
            Opt {
                name: "debug-no-validate-proofs",
                takes: Takes::Nothing,
                help: "take blocks without checking their proofs, and make them\nwithout proving: only on a dev network, in a build that has\nthem, and in a data directory of its own, which is marked as\none whose blocks were never checked",
            },
            Opt {
                name: "debug-fill",
                takes: Takes::Value("N[,S]"),
                help: "with the above: every block made here makes N outputs and\nspends S of those the chain began with, as many as fit a\nblock",
            },
            Opt {
                name: "debug-fill-outputs",
                takes: Takes::Value("N[,K]"),
                help: "with the above: begin the chain with N outputs nobody made,\none every K positions (5 if not said): a state the size of\na chain that has run for years. The same on every node\ntold the same",
            },
            Opt {
                name: "debug-genesis-outputs",
                takes: Takes::Value("N[,K]"),
                help: "with the above: begin with the first block of a chain so\nfilled, and none of its outputs: a new node of that chain,\nto take its state from the others",
            },
            Opt {
                name: "debug-blocks",
                takes: Takes::Value("N"),
                help: "with the above: before anything else, make the chain N blocks\nlong, of empty blocks that take no work to speak of: a chain\nas long as one that has run for years",
            },
            Opt { name: "blocks", takes: Takes::Value("N"), help: "make no block above height N" },
        ],
    ),
    (
        "Logging",
        &[
            Opt {
                name: "log-dir",
                takes: Takes::Value("DIR"),
                help: "where the logs are kept (default: the data directory)",
            },
            Opt {
                name: "main-log",
                takes: Takes::Value("FILE"),
                help: "the main log (default tabernacle.log in the log directory)",
            },
            Opt {
                name: "request-log",
                takes: Takes::Value("FILE"),
                help: "the request log (default request.log there)",
            },
            Opt { name: "stat-log", takes: Takes::Value("FILE"), help: "the stats log (default stat.log there)" },
            Opt {
                name: "log-rotate-seconds",
                takes: Takes::Value("TIME"),
                help: "a log's file is put aside after this long\n(default 3600, which is 60m or 1h)",
            },
            Opt {
                name: "log-rotate-bytes",
                takes: Takes::Value("SIZE"),
                help: "or when it holds this much\n(default 1048576, which is 1024k or 1m)",
            },
            Opt {
                name: "request-log-queue",
                takes: Takes::Value("N"),
                help: "lines that may wait to be written to the request log\n(default 10000)",
            },
            Opt {
                name: "stat-interval-seconds",
                takes: Takes::Value("TIME"),
                help: "between lines of the stats log (default 10)",
            },
            Opt { name: "stat-summary-seconds", takes: Takes::Value("TIME"), help: "between its wholes (default 60)" },
        ],
    ),
];

/// The help: what the options are, by section.
pub fn help() -> String {
    let mut out = String::from(
        "tabminer: a node of the Tabernacle network. It mines unless told not to.\n\nusage: tabminer [options]\n",
    );
    // The widest option, with what it takes, sets where the telling
    // begins.
    let shown = |o: &Opt| match o.takes {
        Takes::Nothing => format!("--{}", o.name),
        Takes::Value(v) | Takes::Values(v) => format!("--{} {v}", o.name),
    };
    let wide = OPTIONS.iter().flat_map(|(_, opts)| opts.iter()).map(|o| shown(o).len()).max().unwrap_or(0) + 2;
    for (section, opts) in OPTIONS {
        out += &format!("\n{section}\n");
        for o in *opts {
            for (k, line) in o.help.lines().enumerate() {
                let first = if k == 0 { shown(o) } else { String::new() };
                out += &format!("  {}{line}\n", column(&first, wide, ' '));
            }
        }
    }
    out += "\nA TIME is so many seconds, or a number and s, m, h or d: 90, 90s, 60m, 1h, 7d.\n";
    out += "A SIZE is so many bytes, or a number and k, m or g, each 1024 of the one before:\n";
    out += "1048576, 1024k, 1m.\n";
    out += "\nOptions can be kept in a file and given as @FILE: one to a line, as they are\n";
    out += "written here, with # before anything that is not one. What is on the command\n";
    out += "line is taken before what is in a file.\n";
    out
}

/// Why a node does not start on what it was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// `--help` was given: the help is what was asked for.
    Help,
    /// Something given is wrong: what, as it is said after `Error: `.
    Wrong(String),
}

impl Refused {
    /// What the node says, and the code it ends with. Asked for, the
    /// help is all there is and nothing is wrong (0); something wrong
    /// is said first, then the help, and that is a failure (-1).
    pub fn said(&self) -> (String, i32) {
        match self {
            Refused::Help => (help(), 0),
            Refused::Wrong(what) => (format!("Error: {what}\n\n{}", help()), -1),
        }
    }
}

/// A number and what it is counted in, as `60m` or `1024k`: the number
/// times what its last letter stands for among `units`, or the number
/// alone. None if it is not that, or too large to count.
fn with_unit(value: &str, units: &[(char, u64)]) -> Option<u64> {
    let last = value.chars().last()?.to_ascii_lowercase();
    let (digits, times) = match units.iter().find(|(letter, _)| *letter == last) {
        Some((_, times)) => (&value[..value.len() - 1], *times),
        None => (value, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(times)
}

/// A network a node can be of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Dev,
    DevRecursive,
    /// A dev network with the main network's work.
    DevMainWork,
}

impl Network {
    pub fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Dev => "dev",
            Network::DevRecursive => "dev-recursive",
            Network::DevMainWork => "dev-main-work",
        }
    }

    /// The four bytes every datagram of the network begins with
    /// (`docs/WIRE.md`, 2.2).
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => *b"TABM",
            Network::Dev => *b"TABD",
            Network::DevRecursive => *b"TABR",
            Network::DevMainWork => *b"TABW",
        }
    }

    /// The data directory's name under `~/.tabernacle`.
    fn directory(&self) -> &'static str {
        match self {
            Network::Mainnet => "tabminer",
            Network::Dev => "tabminer-dev",
            Network::DevRecursive => "tabminer-dev-recursive",
            Network::DevMainWork => "tabminer-dev-main-work",
        }
    }
}

/// The seeds of the main network, built in: the nodes a new node
/// begins from, and, while no consensus file names relays, the nodes
/// every wallet is reached at. All of the network have the same.
pub const SEEDS: [&str; 2] = ["tabernacle1.root.sx:3737", "tabernacle2.root.sx:3737"];

/// How a node is configured: everything it was told, and the default
/// of everything it was not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub network: Network,
    pub data_dir: PathBuf,
    /// Threads that handle requests, and threads for hashing and
    /// checking proofs; zero for one a core.
    pub threads: usize,
    pub mine: bool,
    /// Whether the table of the proof of work is made whole before any
    /// block is.
    pub prebuild_table: bool,
    /// Where the table of the proof of work is kept from one run to
    /// the next.
    pub pow_table: PathBuf,
    /// Signatures a block made here checks at the most: what bounds the
    /// transactions it carries.
    pub max_block_signatures: usize,
    /// Whether the node has a wallet: where the rewards of the blocks
    /// it makes are paid.
    pub wallet: bool,
    /// Where the wallet's password is read from, if not asked for.
    pub password_file: Option<PathBuf>,
    /// Blocks an output is to have been in before the wallet spends it.
    pub min_confirmations: u32,
    /// Whether commands are taken from the terminal.
    pub prompt: bool,
    /// Whether the wallet is to be made again from its words.
    pub restore: bool,
    /// Debugging: whether blocks' proofs go unchecked, and unmade.
    pub debug_unchecked: bool,
    /// Debugging: the outputs every block made here makes, and how
    /// many of those the chain began with it spends.
    pub debug_fill: Option<(usize, usize)>,
    /// Debugging: the outputs the chain begins with and how far apart
    /// they are, and whether this node has only their root.
    pub debug_outputs: Option<(u64, u64, bool)>,
    /// Debugging: how long the chain is made before the node starts.
    pub debug_blocks: Option<u32>,
    /// The height above which no block is made here.
    pub blocks: Option<u64>,
    /// Seconds waited after a block made here before the next is begun.
    pub delay_blocks: u64,
    /// Names under names the wallet takes at the most.
    pub max_names: usize,
    pub listen: SocketAddrV4,
    /// Peers given by hand.
    pub peers: Vec<SocketAddrV4>,
    /// Seeds given, besides the built-in ones: names to look up.
    pub seeds: Vec<String>,
    /// Whether the built-in seeds are used.
    pub built_in_seeds: bool,
    /// Blocks that can be undone.
    pub keep: usize,
    /// The node's own settings among its peers.
    pub net: Net,
    pub main_log: PathBuf,
    pub request_log: PathBuf,
    pub stat_log: PathBuf,
    pub rotation: Rotation,
    pub request_log_queue: usize,
    pub stats: Every,
    /// The files options were read from, in the order given.
    pub files: Vec<PathBuf>,
}

/// What was given, option by option, before it is made sense of: from
/// files, and from the command line, which is taken before them.
#[derive(Default)]
struct Given {
    /// An option's name, its value, and where it was given: the place
    /// of its file among the files, or past them all for the command
    /// line.
    values: Vec<(&'static str, String, usize)>,
    flags: Vec<&'static str>,
}

/// The options of `words` (a command line, or one line of a file),
/// added to `given` as from `source`. `place` is said before what is
/// wrong: nothing for the command line, the file and line for a file.
fn take(given: &mut Given, words: &[&str], source: usize, place: &str) -> Result<(), Refused> {
    let wrong = |what: String| Refused::Wrong(format!("{place}{what}"));
    let mut at = 0;
    while at < words.len() {
        let word = words[at];
        let known = word
            .strip_prefix("--")
            .and_then(|name| OPTIONS.iter().flat_map(|(_, opts)| opts.iter()).find(|o| o.name == name));
        let Some(opt) = known else {
            return Err(wrong(format!("unknown configuration option: '{word}'")));
        };
        match opt.takes {
            Takes::Nothing => {
                // (Given in a file and on the command line is given.)
                if !given.flags.contains(&opt.name) {
                    given.flags.push(opt.name);
                }
            }
            Takes::Value(_) | Takes::Values(_) => {
                let Some(value) = words.get(at + 1).filter(|v| !v.starts_with("--")) else {
                    return Err(wrong(format!("--{} needs a value", opt.name)));
                };
                // Twice in one place is a mistake; in two places, the
                // nearer is taken.
                let twice = given.values.iter().any(|(n, _, from)| *n == opt.name && *from == source);
                if matches!(opt.takes, Takes::Value(_)) && twice {
                    return Err(wrong(format!("--{} was given twice", opt.name)));
                }
                given.values.push((opt.name, value.to_string(), source));
                at += 1;
            }
        }
        at += 1;
    }
    Ok(())
}

impl Given {
    fn flag(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }

    /// Every value of an option that may be given more than once: the
    /// files' and the command line's together.
    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.values.iter().filter(move |(n, _, _)| *n == name).map(|(_, v, _)| v.as_str())
    }

    /// The value of an option: where it was given in more than one
    /// place, the nearest (the command line, then the last file).
    fn one(&self, name: &str) -> Option<&str> {
        self.values.iter().filter(|(n, _, _)| *n == name).max_by_key(|(_, _, from)| *from).map(|(_, v, _)| v.as_str())
    }

    /// A time in seconds, if the option was given: so many seconds, or
    /// a number and `s`, `m`, `h` or `d`. No less than `least`.
    fn time(&self, name: &str, least: u64) -> Result<Option<u64>, Refused> {
        let units = [('s', 1), ('m', 60), ('h', 3600), ('d', 86_400)];
        self.counted(name, least, &units, "a time (as 90, 90s, 60m or 1h)")
    }

    /// A size in bytes, if the option was given: so many bytes, or a
    /// number and `k`, `m` or `g`.
    fn size(&self, name: &str, least: u64) -> Result<Option<u64>, Refused> {
        let units = [('k', 1 << 10), ('m', 1 << 20), ('g', 1 << 30)];
        self.counted(name, least, &units, "a size (as 1048576, 1024k or 1m)")
    }

    fn counted(&self, name: &str, least: u64, units: &[(char, u64)], what: &str) -> Result<Option<u64>, Refused> {
        let Some(value) = self.one(name) else {
            return Ok(None);
        };
        let n = with_unit(value, units).ok_or_else(|| Refused::Wrong(format!("--{name}: '{value}' is not {what}")))?;
        if n < least {
            return Err(Refused::Wrong(format!("--{name}: {value} is under the least it may be ({least})")));
        }
        Ok(Some(n))
    }

    /// A whole number, if the option was given: no less than `least`.
    fn number(&self, name: &str, least: u64) -> Result<Option<u64>, Refused> {
        let Some(value) = self.one(name) else {
            return Ok(None);
        };
        let n: u64 = value.parse().map_err(|_| Refused::Wrong(format!("--{name}: '{value}' is not a number")))?;
        if n < least {
            return Err(Refused::Wrong(format!("--{name}: {value} is under the least it may be ({least})")));
        }
        Ok(Some(n))
    }
}

impl Configuration {
    /// Whether the node listens on this machine alone while it has
    /// seeds or peers that are elsewhere: they will not answer it.
    pub fn listens_alone(&self) -> bool {
        let here = |host: &str| host == "localhost" || host.starts_with("127.");
        let seeds = self.all_seeds();
        let elsewhere = self.peers.iter().any(|peer| !peer.ip().is_loopback())
            || seeds.iter().any(|seed| !here(seed.rsplit_once(':').map_or(seed, |(host, _)| host)));
        elsewhere && self.listen.ip().is_loopback()
    }

    /// The seeds the node begins from: those built in, of the main
    /// network unless told not to, and those it was given.
    pub fn all_seeds(&self) -> Vec<String> {
        let built_in = SEEDS.iter().filter(|_| self.built_in_seeds && self.network == Network::Mainnet);
        built_in.map(|seed| seed.to_string()).chain(self.seeds.iter().cloned()).collect()
    }

    /// The configuration `args` asks for (the command line, without the
    /// program's own name), or why there is none. `home` is the user's
    /// own directory, if there is one, and `here` the directory the
    /// node was started in: paths not from the root are from there.
    ///
    /// A word `@FILE` is a file of options, read with `load`: one
    /// option to a line, written as on the command line, with `#`
    /// before anything that is not one. What the command line says is
    /// taken before what a file says, and a later file before an
    /// earlier; an option that may be given many times has the values
    /// of all of them.
    ///
    /// Beyond reading those files, nothing is opened or made: this
    /// reads and checks only.
    pub fn read(
        args: &[String],
        home: Option<&Path>,
        here: &Path,
        load: &dyn Fn(&Path) -> std::io::Result<String>,
    ) -> Result<Configuration, Refused> {
        // `--help` anywhere is the help, whatever else is there.
        if args.iter().any(|a| a == "--help") {
            return Err(Refused::Help);
        }
        let wrong = |what: String| Refused::Wrong(what);
        // A path as it was given, from the root: one that is not is
        // from where the node was started.
        let whole = |given: &str| {
            let p = Path::new(given);
            if p.is_absolute() { p.to_path_buf() } else { here.join(p) }
        };
        let mut given = Given::default();
        let mut files = Vec::new();
        for file in args.iter().filter_map(|a| a.strip_prefix('@')) {
            if file.is_empty() {
                return Err(wrong("@ needs the name of a file after it".into()));
            }
            let path = whole(file);
            let text = load(&path).map_err(|e| wrong(format!("{} cannot be read: {e}", path.display())))?;
            for (number, line) in text.lines().enumerate() {
                // What comes after a # is for whoever reads the file.
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                // An option, and the rest of the line its value: so
                // that a path may have spaces in it.
                let words: Vec<&str> = line.splitn(2, char::is_whitespace).map(str::trim).collect();
                let place = format!("{} line {}: ", path.display(), number + 1);
                match words[0] {
                    "--help" => return Err(wrong(format!("{place}--help is for the command line"))),
                    word if word.starts_with('@') => {
                        return Err(wrong(format!("{place}a file of options cannot name another")));
                    }
                    _ => take(&mut given, &words, files.len(), &place)?,
                }
            }
            files.push(path);
        }
        let line: Vec<&str> = args.iter().filter(|a| !a.starts_with('@')).map(String::as_str).collect();
        take(&mut given, &line, files.len(), "")?;

        let network = match given.one("network") {
            None | Some("mainnet") => Network::Mainnet,
            Some("dev") => Network::Dev,
            Some("dev-recursive") => Network::DevRecursive,
            Some("dev-main-work") => Network::DevMainWork,
            Some(other) => {
                return Err(wrong(format!("--network: '{other}' is not mainnet, dev, dev-recursive or dev-main-work")));
            }
        };
        let path = |name: &str| -> Result<Option<PathBuf>, Refused> {
            match given.one(name) {
                Some("") => Err(wrong(format!("--{name}: no path was given"))),
                Some(p) => Ok(Some(whole(p))),
                None => Ok(None),
            }
        };
        let data_dir = match path("data-dir")? {
            Some(dir) => dir,
            None => match home {
                Some(home) => home.join(".tabernacle").join(network.directory()),
                None => return Err(wrong("there is no home directory to keep data in: give --data-dir".into())),
            },
        };
        let log_dir = path("log-dir")?.unwrap_or_else(|| data_dir.clone());
        let log = |name: &str, usual: &str| -> Result<PathBuf, Refused> {
            Ok(path(name)?.unwrap_or_else(|| log_dir.join(usual)))
        };
        let pow_table = path("pow-table")?.unwrap_or_else(|| data_dir.join("pow.table"));
        let (main_log, request_log, stat_log) =
            (log("main-log", "tabernacle.log")?, log("request-log", "request.log")?, log("stat-log", "stat.log")?);
        if main_log == request_log || main_log == stat_log || request_log == stat_log {
            return Err(wrong(format!("two logs cannot be one file: {}", main_log.display())));
        }

        let address = |name: &str, value: &str| -> Result<SocketAddrV4, Refused> {
            match value.parse::<SocketAddrV4>() {
                Ok(a) if a.port() != 0 => Ok(a),
                _ => Err(wrong(format!("--{name}: '{value}' is not an address and port (as 203.0.113.7:3737)"))),
            }
        };
        let listen = match given.one("listen") {
            Some(value) => address("listen", value)?,
            None => "0.0.0.0:3737".parse().expect("an address"),
        };
        let peers = given.all("peer").map(|v| address("peer", v)).collect::<Result<Vec<_>, _>>()?;
        let mut seeds = Vec::new();
        for seed in given.all("seed") {
            // A name or an address, and a port that is one.
            let port = seed.rsplit_once(':').filter(|(host, _)| !host.is_empty()).map(|(_, port)| port.parse::<u16>());
            match port {
                Some(Ok(port)) if port != 0 => seeds.push(seed.to_string()),
                _ => return Err(wrong(format!("--seed: '{seed}' is not a host and port (as seed.example.org:3737)"))),
            }
        }

        let mut net = Net::default();
        let seconds = |name: &str, least: u64| given.time(name, least).map(|n| n.map(|n| n.saturating_mul(SECOND)));
        let count = |name: &str, least: u64| given.number(name, least).map(|n| n.map(|n| n as usize));
        let (p, s) = (&mut net.peers, &mut net.sync);
        p.max = count("max-peers", 1)?.unwrap_or(p.max);
        p.target = count("target-peers", 1)?.unwrap_or(p.target);
        p.per_host = count("max-peers-per-host", 1)?.unwrap_or(p.per_host);
        p.per_network = count("max-peers-per-network", 1)?.unwrap_or(p.per_network);
        p.ping = seconds("ping-seconds", 1)?.unwrap_or(p.ping);
        p.live_silence = seconds("peer-live-seconds", 1)?.unwrap_or(p.live_silence);
        p.drop_silence = seconds("peer-drop-seconds", 1)?.unwrap_or(p.drop_silence);
        p.strikes = given.number("ban-strikes", 1)?.map_or(p.strikes, |n| n.min(u32::MAX as u64) as u32);
        p.ban = seconds("ban-seconds", 1)?.unwrap_or(p.ban);
        s.sync_point = given.number("sync-point", 0)?.map_or(s.sync_point, |n| n.min(u32::MAX as u64) as u32);
        s.sync_behind = given.number("sync-behind", 0)?.map_or(s.sync_behind, |n| n.min(u32::MAX as u64) as u32);
        s.header_fetches = count("header-fetches", 1)?.unwrap_or(s.header_fetches);
        s.blocks = count("block-fetches", 1)?.unwrap_or(s.blocks);
        s.blocks_per_peer = count("block-fetches-per-peer", 1)?.unwrap_or(s.blocks_per_peer);
        s.parts = count("part-fetches", 1)?.unwrap_or(s.parts);
        s.header_wait = seconds("header-wait-seconds", 1)?.unwrap_or(s.header_wait);
        s.pass_over = seconds("pass-over-seconds", 1)?.unwrap_or(s.pass_over);
        net.serve.rate =
            given.number("serve-chunks-per-second", 1)?.map_or(net.serve.rate, |n| n.min(u32::MAX as u64) as u32);
        net.serve.waiting = count("serve-queue", 1)?.unwrap_or(net.serve.waiting);
        net.request_queue = count("request-queue-size", 1)?.unwrap_or(net.request_queue);
        net.pool = given.size("mempool-size", 1 << 20)?.map_or(net.pool, |bytes| bytes as usize);
        let was = net.policy;
        let reserve = given.number("reserve", 0)?.map_or(was.reserve_percent as u64, |p| p.min(100));
        net.policy = crate::mempool::Policy::set(
            given.number("min-fee", 0)?.unwrap_or(was.min_fee_per_unit).min(1 << 32),
            given.number("fee-half-life", 1)?.unwrap_or(was.half_life_secs / 3600).min(100_000),
            given.number("mempool-expiry", 1)?.unwrap_or(was.expiry_secs / 86400).min(100_000),
            reserve as usize,
        )
        .with_weights(crate::mempool::Weights {
            input: given.number("weight-input", 1)?.unwrap_or(was.weights.input).min(1 << 16),
            output: given.number("weight-output", 0)?.unwrap_or(was.weights.output).min(1 << 16),
            commit: given.number("weight-commit", 0)?.unwrap_or(was.weights.commit).min(1 << 16),
            reveal: given.number("weight-reveal", 0)?.unwrap_or(was.weights.reveal).min(1 << 16),
            update: given.number("weight-update", 0)?.unwrap_or(was.weights.update).min(1 << 16),
        })
        .with_max_tx_size(given.size("max-tx-size", 1)?.map_or(was.max_tx_size, |bytes| bytes as usize));
        net.relay = given.flag("relay");
        net.sessions.most = count("max-sessions", 1)?.unwrap_or(net.sessions.most);
        if given.one("max-sessions").is_some() && !net.relay {
            return Err(Refused::Wrong("--max-sessions needs --relay".into()));
        }
        net.serve.waiting_each = count("serve-queue-per-peer", 1)?.unwrap_or(net.serve.waiting_each);
        // What cannot both hold, said by the options' own names.
        let (p, s) = (&net.peers, &net.sync);
        let clash = |what: String| Err(wrong(what));
        if p.target > p.max {
            return clash(format!("--target-peers ({}) is over --max-peers ({})", p.target, p.max));
        }
        if p.per_network < p.per_host {
            return clash(format!(
                "--max-peers-per-network ({}) is under --max-peers-per-host ({})",
                p.per_network, p.per_host
            ));
        }
        if p.live_silence < 2 * p.ping {
            return clash(format!(
                "--peer-live-seconds ({}) is under two of --ping-seconds ({})",
                p.live_silence / SECOND,
                p.ping / SECOND
            ));
        }
        if p.drop_silence < p.live_silence {
            return clash(format!(
                "--peer-drop-seconds ({}) is under --peer-live-seconds ({})",
                p.drop_silence / SECOND,
                p.live_silence / SECOND
            ));
        }
        if s.blocks_per_peer > s.blocks {
            return clash(format!(
                "--block-fetches-per-peer ({}) is over --block-fetches ({})",
                s.blocks_per_peer, s.blocks
            ));
        }
        if net.serve.waiting_each > net.serve.waiting {
            return clash(format!(
                "--serve-queue-per-peer ({}) is over --serve-queue ({})",
                net.serve.waiting_each, net.serve.waiting
            ));
        }
        // And whatever else the node itself would not run with.
        if let Err(e) = net.check() {
            return Err(wrong(e.to_string()));
        }

        // The debugging options: a number, and perhaps a second after
        // a comma.
        let pair = |name: &str, second: u64| -> Result<Option<(u64, u64)>, Refused> {
            let Some(text) = given.one(name) else { return Ok(None) };
            let (first, rest) = text.split_once(',').map_or((text, None), |(a, b)| (a, Some(b)));
            let number = |t: &str| t.parse::<u64>().map_err(|_| wrong(format!("--{name}: '{text}' is not N or N,M")));
            Ok(Some((number(first)?, rest.map_or(Ok(second), number)?)))
        };
        let debug_unchecked = given.flag("debug-no-validate-proofs");
        let debug_fill = pair("debug-fill", 0)?.map(|(n, s)| (n as usize, s as usize));
        let (filled, rooted) = (pair("debug-fill-outputs", 5)?, pair("debug-genesis-outputs", 5)?);
        if debug_unchecked && (network == Network::Mainnet || !cfg!(feature = "dev")) {
            return clash(
                "--debug-no-validate-proofs needs --network dev, in a build that has the dev networks".into(),
            );
        }
        for (name, given) in [
            ("debug-fill", debug_fill.is_some()),
            ("debug-blocks", given.one("debug-blocks").is_some()),
            ("debug-fill-outputs", filled.is_some()),
            ("debug-genesis-outputs", rooted.is_some()),
        ] {
            if given && !debug_unchecked {
                return clash(format!("--{name} needs --debug-no-validate-proofs"));
            }
        }
        let debug_outputs = match (filled, rooted) {
            (Some(_), Some(_)) => {
                return clash(
                    "--debug-genesis-outputs needs --debug-fill-outputs not to be given: it is one or the other".into(),
                );
            }
            (Some((n, k)), None) => Some((n, k.max(1), false)),
            (None, Some((n, k))) => Some((n, k.max(1), true)),
            (None, None) => None,
        };
        let (mine, wallet) = (!given.flag("no-mine"), !given.flag("no-wallet"));
        if mine && !wallet {
            return clash("--no-wallet needs --no-mine: the rewards of blocks made here are paid to the wallet".into());
        }
        if given.flag("restore") && !wallet {
            return clash("--restore needs a wallet: not with --no-wallet".into());
        }
        let password_file = path("password-file")?;
        let keep = count("max-undo-blocks", 1)?.unwrap_or(1008);
        if s.sync_point as usize >= keep {
            return clash(format!("--sync-point ({}) is not under --max-undo-blocks ({keep})", s.sync_point));
        }
        let rotation = Rotation {
            max_age: given.time("log-rotate-seconds", 0)?.unwrap_or(Rotation::default().max_age),
            max_size: given.size("log-rotate-bytes", 0)?.unwrap_or(Rotation::default().max_size),
        };
        let stats = Every {
            interval: given
                .time("stat-interval-seconds", 1)?
                .map_or(Every::default().interval, |n| n.saturating_mul(1000)),
            summary: given
                .time("stat-summary-seconds", 1)?
                .map_or(Every::default().summary, |n| n.saturating_mul(1000)),
        };
        if stats.summary < stats.interval {
            return clash(format!(
                "--stat-summary-seconds ({}) is under --stat-interval-seconds ({})",
                stats.summary / 1000,
                stats.interval / 1000
            ));
        }
        Ok(Configuration {
            network,
            data_dir,
            threads: count("threads", 0)?.unwrap_or(0),
            mine,
            prebuild_table: given.flag("prebuild-table"),
            pow_table,
            max_block_signatures: count("max-block-signatures", 0)?.unwrap_or(crate::miner::MAX_SIGNATURES),
            wallet,
            password_file,
            min_confirmations: count("min-confirmations", 1)?
                .map_or(crate::wallet::MIN_CONFIRMATIONS, |n| n.min(u32::MAX as usize) as u32),
            prompt: !given.flag("no-prompt"),
            restore: given.flag("restore"),
            debug_unchecked,
            debug_fill,
            debug_outputs,
            debug_blocks: given.number("debug-blocks", 1)?.map(|n| n.min(u32::MAX as u64) as u32),
            blocks: given.number("blocks", 0)?,
            delay_blocks: given.number("delay-blocks", 0)?.unwrap_or(0),
            max_names: given.number("max-names", 0)?.unwrap_or(5) as usize,
            listen,
            peers,
            seeds,
            built_in_seeds: !given.flag("no-seeds"),
            keep,
            net,
            main_log,
            request_log,
            stat_log,
            rotation,
            request_log_queue: count("request-log-queue", 1)?.unwrap_or(10_000),
            stats,
            files,
        })
    }

    /// What a node says of its configuration when it starts: each thing
    /// by its name, and what it is. Paths are whole, and numbers are
    /// written as in every log.
    pub fn lines(&self) -> Vec<(String, String)> {
        let (p, s) = (&self.net.peers, &self.net.sync);
        let secs = |micros: u64| format!("{} seconds", commas(micros / SECOND));
        let yes = |b: bool| if b { "yes" } else { "no" }.to_string();
        let limit = |n: u64, unit: &str| if n == 0 { "no limit".to_string() } else { format!("{} {unit}", commas(n)) };
        let mut lines: Vec<(&str, String)> = vec![(LISTENING, self.listen.to_string())];
        lines.extend(self.files.iter().map(|file| ("Configuration File", file.display().to_string())));
        lines.extend([
            ("Network", self.network.name().to_string()),
            ("Mining", yes(self.mine)),
            ("Prebuild Table", yes(self.prebuild_table)),
            ("PoW Table", self.pow_table.display().to_string()),
            ("Max Block Signatures", commas(self.max_block_signatures as u64)),
        ]);
        lines.push(("Wallet", yes(self.wallet)));
        lines.push(("Min Confirmations", commas(self.min_confirmations as u64)));
        if self.debug_unchecked {
            lines.push(("Debug", "blocks' proofs are not checked".to_string()));
        }
        lines.extend([
            ("Threads", if self.threads == 0 { "one a core".to_string() } else { commas(self.threads as u64) }),
            ("Request Queue Size", commas(self.net.request_queue as u64)),
            ("Mempool Size", format!("{} bytes", commas(self.net.pool as u64))),
            ("Min Fee", format!("{} a unit of weight", commas(self.net.policy.min_fee_per_unit))),
            ("Fee Half Life", format!("{} hours", commas(self.net.policy.half_life_secs / 3600))),
            ("Mempool Expiry", format!("{} days", commas(self.net.policy.expiry_secs / 86400))),
            ("Block Reserve", format!("{}%", self.net.policy.reserve_percent)),
            (
                "Relay",
                if self.net.relay {
                    format!("yes, {} sessions at the most", commas(self.net.sessions.most as u64))
                } else {
                    "no".to_string()
                },
            ),
            ("Data Directory", self.data_dir.display().to_string()),
            ("Main Log", self.main_log.display().to_string()),
            ("Request Log", self.request_log.display().to_string()),
            ("Stat Log", self.stat_log.display().to_string()),
            ("Log Rotation Time", limit(self.rotation.max_age, "seconds")),
            ("Log Rotation Size", limit(self.rotation.max_size, "bytes")),
            ("Request Log Queue", format!("{} lines", commas(self.request_log_queue as u64))),
            ("Stat Interval", format!("{} seconds", commas(self.stats.interval / 1000))),
            ("Stat Summary", format!("{} seconds", commas(self.stats.summary / 1000))),
            ("Built-in Seeds", yes(self.built_in_seeds)),
        ]);
        lines.extend(self.all_seeds().into_iter().map(|seed| ("Seed", seed)));
        lines.extend(self.peers.iter().map(|peer| ("Peer", peer.to_string())));
        lines.extend([
            ("Max Peers", commas(p.max as u64)),
            ("Target Peers", commas(p.target as u64)),
            ("Max Peers per Host", commas(p.per_host as u64)),
            ("Max Peers per Network", commas(p.per_network as u64)),
            ("Ping Interval", secs(p.ping)),
            ("Peer Live Timeout", secs(p.live_silence)),
            ("Peer Drop Timeout", secs(p.drop_silence)),
            ("Ban Strikes", commas(p.strikes as u64)),
            ("Ban Time", secs(p.ban)),
            (
                "Sync Point",
                if s.sync_point == 0 { "never".to_string() } else { format!("{} blocks", commas(s.sync_point as u64)) },
            ),
            (
                "Sync Behind",
                match (s.sync_point, s.sync_behind) {
                    (0, _) | (_, 0) => "never".to_string(),
                    (_, behind) => format!("{} blocks", commas(behind as u64)),
                },
            ),
            ("Max Undo Blocks", commas(self.keep as u64)),
            ("Header Fetches", commas(s.header_fetches as u64)),
            ("Block Fetches", commas(s.blocks as u64)),
            ("Block Fetches per Peer", commas(s.blocks_per_peer as u64)),
            ("Part Fetches", commas(s.parts as u64)),
            ("Header Wait", secs(s.header_wait)),
            ("Pass Over Time", secs(s.pass_over)),
            ("Serve Rate", format!("{} chunks per second", commas(self.net.serve.rate as u64))),
            ("Serve Queue", commas(self.net.serve.waiting as u64)),
            ("Serve Queue per Peer", commas(self.net.serve.waiting_each as u64)),
        ]);
        lines.into_iter().map(|(name, value)| (name.to_string(), value)).collect()
    }

    /// Says, in the main log and on the terminal alike, when the node
    /// started and how it is configured:
    ///
    /// ```text
    /// [2026-10-17 19:30:44:000] Server started 10-17-2026 19:30:44 UTC
    /// -----------------------------------------------------------------
    /// [2026-10-17 19:30:44:000] UDP Server Listening on: '0.0.0.0:3737'
    /// [2026-10-17 19:30:44:000] Main Log:                '/srv/tab/tabernacle.log'
    /// -----------------------------------------------------------------
    /// ```
    pub fn announce(&self, main: &Logger) {
        self.announce_with(main, &[])
    }

    /// [`Configuration::announce`], with `more` said after the network:
    /// what is not configured but follows from it (the id of the
    /// network's first block).
    pub fn announce_with(&self, main: &Logger, more: &[(&str, String)]) {
        let mut lines = self.lines();
        let after = lines.iter().position(|(name, _)| name == "Network").map_or(lines.len(), |i| i + 1);
        lines.splice(after..after, more.iter().map(|(name, value)| (name.to_string(), value.clone())));
        let wide = lines.iter().map(|(name, _)| name.chars().count()).max().unwrap_or(0) + 2;
        main.log_all(&format!("Server started {}", crate::logger::Moment::of(main.now()).started()));
        main.log_all_no_header(&RULE);
        for (name, value) in &lines {
            // (A node that listens on this machine alone hears nothing
            // from any other: said beside it, since what follows looks
            // like peers that do not answer.)
            let note = if *name == LISTENING && self.listens_alone() { LOOPBACK } else { "" };
            main.log_all(&format!("{}'{value}'{note}", column(&format!("{name}:"), wide, ' ')));
        }
        main.log_all_no_header(&RULE);
    }

    /// Says that the node is up, straight after its configuration. This
    /// line is the mark that a node is running, for whoever reads the
    /// log, or a program that does: it is to be said only when the
    /// port is bound and requests can be taken, and by nothing else.
    ///
    /// It is the last thing said on the terminal: from here the main
    /// log is written to its file alone, and the terminal is left to
    /// whoever is at it.
    pub fn ready(main: &Logger) {
        main.log_all(READY);
        main.file_only();
    }
}

/// Bytes as hex digits.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const LISTENING: &str = "UDP Server Listening on";
/// What is said beside the address a node listens on, when that is
/// this machine alone and its seeds or peers are elsewhere.
pub const LOOPBACK: &str = " WARNING: Binding to loopback. Probably not what you want!";

/// What a node says when it can take requests.
pub const READY: &str = "Server is ready!";

/// The rule drawn above and below the configuration.
static RULE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| "-".repeat(105));

#[cfg(test)]
mod tests {
    use super::*;

    /// The files there are, for the tests.
    fn load(path: &Path) -> std::io::Result<String> {
        // (Whichever way the system writes the line between a
        // directory and what is in it.)
        match path.to_str().unwrap().replace('\\', "/").as_str() {
            "/work/here/my_config" => Ok("# a seed\n\n--max-peers 2000   # many\n--no-mine\n--peer 203.0.113.7:3737\n\
                 --data-dir /srv/my tab\n--log-rotate-seconds 2h\n"
                .into()),
            "/etc/tab/second" => Ok("--max-peers 300\n--target-peers 20\n--peer 198.51.100.20:3738\n".into()),
            "/bad/unknown" => Ok("--max-peers 5\n--prot 3737\n".into()),
            "/bad/twice" => Ok("--max-peers 5\n--max-peers 6\n".into()),
            "/bad/help" => Ok("--help\n".into()),
            "/bad/nested" => Ok("@/etc/tab/second\n".into()),
            "/bad/value" => Ok("--max-peers\n".into()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file")),
        }
    }

    fn read(args: &[&str]) -> Result<Configuration, Refused> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        Configuration::read(&args, Some(Path::new("/home/chris")), Path::new("/work/here"), &load)
    }

    fn wrong(args: &[&str]) -> String {
        match read(args) {
            Err(Refused::Wrong(what)) => what,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    #[test]
    fn nothing_given_is_every_default() {
        let c = read(&[]).unwrap();
        assert_eq!((c.network, c.mine, c.threads, c.keep), (Network::Mainnet, true, 0, 1008));
        // The pool's policy: the default, or what is set of it.
        assert_eq!(c.net.policy, crate::mempool::Policy::MAINNET);
        let set = read(&["--min-fee", "50", "--fee-half-life", "6", "--mempool-expiry", "3", "--reserve", "25"]);
        assert_eq!(set.unwrap().net.policy, crate::mempool::Policy::set(50, 6, 3, 25));
        let some = read(&["--reserve", "0"]).unwrap().net.policy;
        assert_eq!(some, crate::mempool::Policy::set(crate::mempool::MIN_FEE_PER_UNIT, 12, 14, 0));
        assert!(read(&["--fee-half-life", "0"]).is_err() && read(&["--mempool-expiry", "0"]).is_err());
        // What a transaction's parts weigh, and the largest one taken.
        let weighed =
            read(&["--weight-output", "5", "--weight-reveal", "9", "--max-tx-size", "300k"]).unwrap().net.policy;
        let weights = crate::mempool::Weights { output: 5, reveal: 9, ..crate::mempool::Weights::DEFAULT };
        assert_eq!((weighed.weights, weighed.max_tx_size), (weights, 300 << 10));
        assert!(read(&["--weight-input", "0"]).is_err());
        assert!(!c.prebuild_table && read(&["--prebuild-table"]).unwrap().prebuild_table);
        assert_eq!(c.max_block_signatures, 256);
        assert_eq!(c.pow_table, c.data_dir.join("pow.table"));
        let elsewhere = read(&["--pow-table", "/keep/pow.table"]).unwrap();
        assert_eq!(elsewhere.pow_table, Path::new("/keep/pow.table"));
        assert!(elsewhere.lines().contains(&("PoW Table".to_string(), "/keep/pow.table".to_string())));
        assert_eq!(read(&["--max-block-signatures", "1024"]).unwrap().max_block_signatures, 1024);
        assert_eq!(c.listen.to_string(), "0.0.0.0:3737");
        assert_eq!(c.data_dir, Path::new("/home/chris/.tabernacle/tabminer"));
        assert_eq!(c.main_log, Path::new("/home/chris/.tabernacle/tabminer/tabernacle.log"));
        assert_eq!(c.request_log, Path::new("/home/chris/.tabernacle/tabminer/request.log"));
        assert_eq!(c.stat_log, Path::new("/home/chris/.tabernacle/tabminer/stat.log"));
        assert_eq!((c.net.clone(), c.rotation, c.stats), (Net::default(), Rotation::default(), Every::default()));
        assert_eq!((c.request_log_queue, c.built_in_seeds, c.peers.len(), c.seeds.len()), (10_000, true, 0, 0));
        // Each network has a directory of its own.
        assert_eq!(read(&["--network", "dev"]).unwrap().data_dir, Path::new("/home/chris/.tabernacle/tabminer-dev"));
        let recursive = read(&["--network", "dev-recursive"]).unwrap();
        assert_eq!(recursive.data_dir, Path::new("/home/chris/.tabernacle/tabminer-dev-recursive"));
    }

    #[test]
    fn what_is_given_is_what_is_had() {
        let c = read(&[
            "--no-mine",
            "--network",
            "dev",
            "--data-dir",
            "/srv/tab",
            "--threads",
            "4",
            "--listen",
            "10.0.0.5:4000",
            "--peer",
            "203.0.113.7:3737",
            "--peer",
            "198.51.100.20:3738",
            "--seed",
            "seed.example.org:3737",
            "--no-seeds",
            "--max-peers",
            "2000",
            "--target-peers",
            "50",
            "--max-peers-per-host",
            "2",
            "--max-peers-per-network",
            "16",
            "--ping-seconds",
            "20",
            "--peer-live-seconds",
            "45",
            "--peer-drop-seconds",
            "120",
            "--ban-strikes",
            "3",
            "--ban-seconds",
            "60",
            "--sync-point",
            "100",
            "--max-undo-blocks",
            "500",
            "--header-fetches",
            "4",
            "--block-fetches",
            "10",
            "--block-fetches-per-peer",
            "5",
            "--part-fetches",
            "64",
            "--header-wait-seconds",
            "30",
            "--pass-over-seconds",
            "90",
            "--serve-chunks-per-second",
            "100000",
            "--serve-queue",
            "5000",
            "--serve-queue-per-peer",
            "16",
            "--log-rotate-seconds",
            "600",
            "--log-rotate-bytes",
            "5000000",
            "--request-log-queue",
            "250",
            "--stat-interval-seconds",
            "5",
            "--stat-summary-seconds",
            "30",
            "--request-queue-size",
            "99",
        ])
        .unwrap();
        assert_eq!((c.network, c.mine, c.threads, c.keep), (Network::Dev, false, 4, 500));
        assert_eq!((c.data_dir.as_path(), c.listen.to_string().as_str()), (Path::new("/srv/tab"), "10.0.0.5:4000"));
        assert_eq!(
            c.peers.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            ["203.0.113.7:3737", "198.51.100.20:3738"]
        );
        assert_eq!((c.seeds.clone(), c.built_in_seeds), (vec!["seed.example.org:3737".to_string()], false));
        let (p, s) = (&c.net.peers, &c.net.sync);
        assert_eq!((p.max, p.target, p.per_host, p.per_network, p.strikes), (2000, 50, 2, 16, 3));
        assert_eq!(
            (p.ping, p.live_silence, p.drop_silence, p.ban),
            (20 * SECOND, 45 * SECOND, 120 * SECOND, 60 * SECOND)
        );
        assert_eq!((s.sync_point, s.header_fetches, s.blocks, s.blocks_per_peer, s.parts), (100, 4, 10, 5, 64));
        assert_eq!((s.header_wait, s.pass_over), (30 * SECOND, 90 * SECOND));
        assert_eq!((c.net.serve.rate, c.net.serve.waiting, c.net.serve.waiting_each), (100_000, 5000, 16));
        assert_eq!(c.rotation, Rotation { max_age: 600, max_size: 5_000_000 });
        assert_eq!((c.request_log_queue, c.stats), (250, Every { interval: 5000, summary: 30_000 }));
        assert_eq!(c.net.request_queue, 99);
        // What was not given is still its default.
        assert_eq!(p.host_stale, Net::default().peers.host_stale);
    }

    /// A log is where its own option says; else in the directory for
    /// logs; else in the data directory. And every path kept is whole.
    #[test]
    fn a_log_goes_where_the_nearest_option_says() {
        let logs = |args: &[&str]| {
            let c = read(args).unwrap();
            // (With the line between a directory and what is in it
            // written one way, whichever way the system writes it.)
            [c.main_log, c.request_log, c.stat_log].map(|p| p.display().to_string().replace('\\', "/"))
        };
        assert_eq!(
            logs(&["--data-dir", "/srv/tab"]),
            ["/srv/tab/tabernacle.log", "/srv/tab/request.log", "/srv/tab/stat.log"]
        );
        assert_eq!(
            logs(&["--data-dir", "/srv/tab", "--log-dir", "/var/log/tab"]),
            ["/var/log/tab/tabernacle.log", "/var/log/tab/request.log", "/var/log/tab/stat.log"]
        );
        assert_eq!(
            logs(&["--log-dir", "/var/log/tab", "--stat-log", "/mnt/fast/s.log"]),
            ["/var/log/tab/tabernacle.log", "/var/log/tab/request.log", "/mnt/fast/s.log"]
        );
        assert_eq!(
            logs(&["--main-log", "/a/m.log", "--request-log", "/b/r.log", "--stat-log", "/c/s.log", "--log-dir", "/x"]),
            ["/a/m.log", "/b/r.log", "/c/s.log"]
        );
        // Not from the root: from where the node was started.
        assert_eq!(
            logs(&["--data-dir", "data", "--log-dir", "logs", "--main-log", "m.log"]),
            ["/work/here/m.log", "/work/here/logs/request.log", "/work/here/logs/stat.log"]
        );
        assert_eq!(read(&["--data-dir", "data"]).unwrap().data_dir, Path::new("/work/here/data"));
        // Two logs in one file would write over one another.
        assert!(
            wrong(&["--main-log", "/a/x.log", "--stat-log", "/a/x.log"]).starts_with("two logs cannot be one file")
        );
        // Nowhere to keep anything.
        let none = Configuration::read(&[], None, Path::new("/"), &load);
        assert!(matches!(none, Err(Refused::Wrong(w)) if w.contains("--data-dir")));
    }

    #[test]
    fn help_anywhere_is_help_and_an_unknown_option_is_named() {
        assert_eq!(read(&["--help"]), Err(Refused::Help));
        assert_eq!(read(&["--max-peers", "5", "--help", "--no-such"]), Err(Refused::Help));
        assert_eq!(read(&["--no-such", "--help"]), Err(Refused::Help));
        assert_eq!(wrong(&["--prot", "3737"]), "unknown configuration option: '--prot'");
        assert_eq!(wrong(&["--no-mine", "mine"]), "unknown configuration option: 'mine'");
        assert_eq!(wrong(&["-h"]), "unknown configuration option: '-h'");
        assert_eq!(wrong(&["--max-peers=5"]), "unknown configuration option: '--max-peers=5'");
    }

    #[test]
    fn what_is_wrong_is_said_by_the_options_name() {
        // No value, or the next option where one should be.
        assert_eq!(wrong(&["--max-peers"]), "--max-peers needs a value");
        assert_eq!(wrong(&["--data-dir", "--no-mine"]), "--data-dir needs a value");
        // Not a number; under the least.
        assert_eq!(wrong(&["--max-peers", "many"]), "--max-peers: 'many' is not a number");
        assert_eq!(wrong(&["--max-peers", "-5"]), "--max-peers: '-5' is not a number");
        assert_eq!(wrong(&["--max-peers", "0"]), "--max-peers: 0 is under the least it may be (1)");
        assert_eq!(wrong(&["--ping-seconds", "1.5"]), "--ping-seconds: '1.5' is not a time (as 90, 90s, 60m or 1h)");
        assert_eq!(
            wrong(&["--log-rotate-bytes", "1mb"]),
            "--log-rotate-bytes: '1mb' is not a size (as 1048576, 1024k or 1m)"
        );
        // A port out of range, no port, a name where an address is
        // wanted, port nothing.
        for bad in ["0.0.0.0:70000", "0.0.0.0", "localhost:3737", "0.0.0.0:0", "1.2.3:4", "[::1]:3737"] {
            assert_eq!(
                wrong(&["--listen", bad]),
                format!("--listen: '{bad}' is not an address and port (as 203.0.113.7:3737)")
            );
        }
        assert!(wrong(&["--peer", "1.2.3.4:99999"]).starts_with("--peer: '1.2.3.4:99999' is not an address"));
        assert!(
            wrong(&["--seed", "seed.example.org"]).starts_with("--seed: 'seed.example.org' is not a host and port")
        );
        assert!(wrong(&["--seed", ":3737"]).starts_with("--seed"));
        assert!(wrong(&["--seed", "a.example:70000"]).starts_with("--seed"));
        // Given twice, where once is all there may be.
        assert_eq!(wrong(&["--max-peers", "5", "--max-peers", "6"]), "--max-peers was given twice");
        assert!(read(&["--peer", "1.2.3.4:5", "--peer", "1.2.3.4:6"]).is_ok());
        assert_eq!(
            wrong(&["--network", "testnet"]),
            "--network: 'testnet' is not mainnet, dev, dev-recursive or dev-main-work"
        );
        // Limits that cannot both hold.
        assert_eq!(wrong(&["--target-peers", "100"]), "--target-peers (100) is over --max-peers (64)");
        assert_eq!(
            wrong(&["--max-peers-per-host", "9"]),
            "--max-peers-per-network (8) is under --max-peers-per-host (9)"
        );
        assert_eq!(wrong(&["--ping-seconds", "40"]), "--peer-live-seconds (65) is under two of --ping-seconds (40)");
        assert_eq!(wrong(&["--peer-drop-seconds", "30"]), "--peer-drop-seconds (30) is under --peer-live-seconds (65)");
        assert_eq!(wrong(&["--block-fetches", "4"]), "--block-fetches-per-peer (8) is over --block-fetches (4)");
        assert_eq!(wrong(&["--serve-queue", "4"]), "--serve-queue-per-peer (32) is over --serve-queue (4)");
        assert_eq!(
            wrong(&["--sync-point", "2000", "--sync-behind", "4000"]),
            "--sync-point (2000) is not under --max-undo-blocks (1008)"
        );
        let twice = "a setting cannot be run with: sync.sync_behind is under twice sync.sync_point";
        assert_eq!(wrong(&["--sync-behind", "200"]), twice);
        assert_eq!(wrong(&["--sync-point", "600"]), twice);
        assert_eq!(
            wrong(&["--stat-summary-seconds", "5"]),
            "--stat-summary-seconds (5) is under --stat-interval-seconds (10)"
        );
    }

    /// A node has a wallet unless told not to, and one that makes
    /// blocks must: their rewards are paid to it.
    #[test]
    fn a_node_that_makes_blocks_has_a_wallet() {
        let c = read(&[]).unwrap();
        assert!(c.wallet && c.prompt && c.password_file.is_none() && c.min_confirmations == 6);
        assert_eq!(read(&["--min-confirmations", "1"]).unwrap().min_confirmations, 1);
        assert_eq!(wrong(&["--min-confirmations", "0"]), "--min-confirmations: 0 is under the least it may be (1)");
        assert!(c.lines().contains(&("Wallet".to_string(), "yes".to_string())));
        let c = read(&["--no-mine", "--no-wallet", "--no-prompt", "--password-file", "secret"]).unwrap();
        assert!(!c.wallet && !c.prompt && c.password_file.as_deref() == Some(Path::new("/work/here/secret")));
        assert_eq!(
            wrong(&["--no-wallet"]),
            "--no-wallet needs --no-mine: the rewards of blocks made here are paid to the wallet"
        );
    }

    /// A time may be said in minutes, hours or days, and a size in
    /// kilobytes, megabytes or gigabytes of 1024.
    #[test]
    fn times_and_sizes_take_units() {
        let rotation = |seconds: &str, bytes: &str| {
            let c = read(&["--log-rotate-seconds", seconds, "--log-rotate-bytes", bytes]).unwrap();
            (c.rotation.max_age, c.rotation.max_size)
        };
        assert_eq!(rotation("3600", "1048576"), (3600, 1 << 20));
        assert_eq!(rotation("60m", "1024k"), (3600, 1 << 20));
        assert_eq!(rotation("1h", "1m"), (3600, 1 << 20));
        assert_eq!(rotation("90s", "2g"), (90, 2 << 30));
        assert_eq!(rotation("7d", "1K"), (7 * 86_400, 1024));
        assert_eq!(rotation("1H", "5M"), (3600, 5 << 20));
        // Nothing is no limit, said either way.
        assert_eq!(rotation("0", "0k"), (0, 0));
        // Every option that is a time takes them.
        let c = read(&[
            "--ping-seconds",
            "1m",
            "--peer-live-seconds",
            "3m",
            "--peer-drop-seconds",
            "1h",
            "--ban-seconds",
            "1d",
        ])
        .unwrap();
        let p = &c.net.peers;
        assert_eq!(
            (p.ping, p.live_silence, p.drop_silence, p.ban),
            (60 * SECOND, 180 * SECOND, 3600 * SECOND, 86_400 * SECOND)
        );
        let c = read(&["--stat-interval-seconds", "30s", "--stat-summary-seconds", "5m"]).unwrap();
        assert_eq!(c.stats, Every { interval: 30_000, summary: 300_000 });
        // What is neither: no number, a unit of the other kind, two
        // units, a fraction, more than can be counted.
        for bad in ["h", "1x", "1hh", "1.5h", "-1h", "1 h", "99999999999999999999", "9999999999999999999d", "1k"] {
            assert!(wrong(&["--log-rotate-seconds", bad]).contains("is not a time"), "{bad}");
        }
        assert!(wrong(&["--log-rotate-bytes", "1h"]).contains("is not a size"));
        assert!(wrong(&["--log-rotate-bytes", "99999999999g"]).contains("is not a size"));
        // A count is a count: no units.
        assert_eq!(wrong(&["--max-peers", "1k"]), "--max-peers: '1k' is not a number");
    }

    /// Asked for, the help is the help and nothing is wrong; something
    /// wrong is said first, then the help, and the node ends in failure.
    #[test]
    fn help_asked_for_is_no_failure_and_help_for_an_error_is() {
        let (said, code) = read(&["--help"]).unwrap_err().said();
        assert_eq!((said, code), (help(), 0));
        let (said, code) = read(&["--prot", "1"]).unwrap_err().said();
        assert_eq!(code, -1);
        assert_eq!(said, format!("Error: unknown configuration option: '--prot'\n\n{}", help()));
        let (said, code) = read(&["--max-peers", "0"]).unwrap_err().said();
        assert!(code == -1 && said.starts_with("Error: --max-peers: 0 is under the least it may be (1)\n\ntabminer: "));
    }

    /// Options kept in a file are the configuration, and what the
    /// command line says is taken before them.
    #[test]
    fn a_file_of_options_is_given_with_an_at() {
        let c = read(&["@my_config"]).unwrap();
        assert_eq!((c.net.peers.max, c.mine, c.rotation.max_age), (2000, false, 7200));
        // (The rest of a line is the value: a path may have spaces.)
        assert_eq!(c.data_dir, Path::new("/srv/my tab"));
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.files, [Path::new("/work/here/my_config")]);
        // The command line over the file, wherever on it the file is.
        for args in [["@my_config", "--max-peers", "70"], ["--max-peers", "70", "@my_config"]] {
            let c = read(&args).unwrap();
            assert_eq!((c.net.peers.max, c.mine, c.data_dir.as_path()), (70, false, Path::new("/srv/my tab")));
        }
        // An option that may be given many times has them all.
        let c = read(&["@my_config", "--peer", "10.9.8.7:1"]).unwrap();
        assert_eq!(c.peers.iter().map(|p| p.to_string()).collect::<Vec<_>>(), ["203.0.113.7:3737", "10.9.8.7:1"]);
        // Two files: the later over the earlier, and the command line
        // over both.
        let c = read(&["@my_config", "@/etc/tab/second"]).unwrap();
        assert_eq!((c.net.peers.max, c.net.peers.target, c.peers.len()), (300, 20, 2));
        assert_eq!(c.files.len(), 2);
        let c = read(&["@/etc/tab/second", "@my_config", "--target-peers", "9"]).unwrap();
        assert_eq!((c.net.peers.max, c.net.peers.target), (2000, 9));
        // What is wrong in a file is said with the file and the line.
        assert_eq!(wrong(&["@/bad/unknown"]), "/bad/unknown line 2: unknown configuration option: '--prot'");
        assert_eq!(wrong(&["@/bad/twice"]), "/bad/twice line 2: --max-peers was given twice");
        assert_eq!(wrong(&["@/bad/value"]), "/bad/value line 1: --max-peers needs a value");
        assert_eq!(wrong(&["@/bad/help"]), "/bad/help line 1: --help is for the command line");
        assert_eq!(wrong(&["@/bad/nested"]), "/bad/nested line 1: a file of options cannot name another");
        assert_eq!(wrong(&["@/no/such"]), "/no/such cannot be read: no such file");
        assert_eq!(wrong(&["@"]), "@ needs the name of a file after it");
        // And twice on the command line is still a mistake.
        assert_eq!(wrong(&["@my_config", "--max-peers", "5", "--max-peers", "6"]), "--max-peers was given twice");
        // The help, asked for, is the help whatever files are named.
        assert_eq!(read(&["@/no/such", "--help"]), Err(Refused::Help));
    }

    /// The help names every option there is, and every option the help
    /// names is one: with a value where it takes one, each is taken.
    #[test]
    fn the_help_and_the_options_are_one_list() {
        let help = help();
        assert!(help.starts_with("tabminer: a node of the Tabernacle network."));
        for section in ["General", "Mining", "Wallet", "Network", "Peers", "Sync", "Serving", "Debugging", "Logging"] {
            assert!(help.contains(&format!("\n{section}\n")), "{section}");
        }
        let mut named = 0;
        for line in help.lines().filter(|l| l.starts_with("  --")) {
            let mut words = line.split_whitespace();
            let (option, takes) = (words.next().unwrap(), words.next().unwrap());
            let value = match takes {
                "NAME" => Some("dev"),
                "DIR" | "FILE" => Some("/somewhere/of/its/own"),
                "N" | "TIME" | "SIZE" | "N[,S]" | "N[,K]" => Some("70"),
                "HEX" => Some("0000000000000000000000000000000000000000000000000000000000000000"),
                "ADDR:PORT" => Some("10.1.2.3:4000"),
                "HOST:PORT" => Some("seed.example.org:4000"),
                _ => None,
            };
            named += 1;
            if option == "--help" {
                continue;
            }
            let mut args = vec![option];
            args.extend(value);
            // (Alone it may clash with a default; what matters is that
            // it is known and its value read.)
            match read(&args) {
                Ok(_) => {}
                Err(Refused::Wrong(what)) => {
                    let clash = what.contains(" is over ") || what.contains(" under ") || what.contains(" needs --");
                    assert!(clash, "{option}: {what}")
                }
                Err(Refused::Help) => panic!("{option}"),
            }
        }
        assert_eq!(named, OPTIONS.iter().map(|(_, opts)| opts.len()).sum::<usize>());
        // In columns: what every option is begins at one place.
        let begins: Vec<usize> = help
            .lines()
            .filter(|l| l.starts_with("  --"))
            .map(|l| {
                let after = l.trim_start().find("  ").unwrap() + 2;
                after + l[after..].find(|c: char| c != ' ').unwrap()
            })
            .collect();
        assert!(begins.windows(2).all(|w| w[0] == w[1]), "{begins:?}");
        assert!(help.lines().all(|l| l.len() <= 100 && !l.ends_with(' ')), "{help}");
    }

    /// What a node says when it starts: when, and how it is configured,
    /// each thing by name with what it is in quotes, in columns.
    #[test]
    fn the_configuration_is_said_at_the_start() {
        let dir = std::env::temp_dir().join(format!("tabminer-configuration-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.display().to_string();
        let c = read(&["--data-dir", &data, "--peer", "203.0.113.7:3737", "--max-peers", "2000", "--no-mine"]).unwrap();
        let main = Logger::open(&c.main_log, c.rotation).unwrap();
        c.announce(&main);
        Configuration::ready(&main);
        let text = std::fs::read_to_string(&c.main_log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // The time it started, a rule, the configuration, a rule, ready.
        assert!(lines[0][26..].starts_with("Server started ") && lines[0].ends_with(" UTC"), "{}", lines[0]);
        assert_eq!((lines[1], lines[lines.len() - 2]), ("-".repeat(105).as_str(), "-".repeat(105).as_str()));
        assert!(lines[lines.len() - 1].ends_with("] Server is ready!"));
        let said: Vec<&str> = lines[2..lines.len() - 2].iter().map(|l| &l[26..]).collect();
        assert_eq!(said[0], "UDP Server Listening on: '0.0.0.0:3737'");
        let within = |file: &str| dir.join(file).display().to_string();
        assert!(
            said.contains(&format!("Main Log:                '{}'", within("tabernacle.log")).as_str()),
            "{said:#?}"
        );
        assert!(said.contains(&format!("Request Log:             '{}'", within("request.log")).as_str()));
        assert!(said.contains(&"Mining:                  'no'"));
        assert!(said.contains(&"Max Peers:               '2,000'"));
        assert!(said.contains(&"Peer:                    '203.0.113.7:3737'"));
        assert!(said.contains(&"Log Rotation Time:       '3,600 seconds'"));
        assert!(said.contains(&"Log Rotation Size:       '1,048,576 bytes'"));
        // Every one has the time before it, its name, and what it is in
        // quotes beginning at one place.
        for (line, said) in lines[2..lines.len() - 2].iter().zip(&said) {
            assert!(line.starts_with('[') && &line[24..26] == "] ", "{line}");
            assert_eq!(said.find('\''), Some(25), "{said}");
            assert!(said.ends_with('\'') && said[..25].trim_end().ends_with(':'), "{said}");
        }
        assert_eq!(said.len(), c.lines().len());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
