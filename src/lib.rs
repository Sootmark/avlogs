//! Antivirus logs, for forensics: what the endpoint protection saw, blocked
//! and cleaned, often the first trace of an intrusion and of the tools it
//! brought.
//!
//! - McAfee VirusScan's `AccessProtectionLog.txt`: tab-separated, local
//!   time: the rule that blocked (or would have blocked) a process, the
//!   process, the account and what it touched.
//! - Symantec Endpoint Protection's scan logs (`<MMDDYYYY>.Log`, CSV): a
//!   time in hexadecimal (`2A0A1E011B21`: years since 1970, month from 0,
//!   day, hour, minute, second; local), the event, the computer and user,
//!   the threat and file, the actions requested and taken.
//! - Sophos Anti-Virus's `SAV.txt` (UTF-16): `YYYYMMDD HHMMSS message`,
//!   local time; detections, cleanings and quarantines are in the message.
//! - Trend Micro OfficeScan's virus detection log (`pccnt35.log`) and web
//!   reputation log (`OfcUrlf.log`): fields between `<;>`, with a Unix time
//!   at the end when written, the local date and minute otherwise.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let data = std::fs::read("AccessProtectionLog.txt")?;
//! if let Some(kind) = avlogs::detect("AccessProtectionLog.txt", &data) {
//!     for entry in avlogs::read(kind, &data).entries {
//!         println!("{:?} {:?} {:?} {:?}", entry.time, entry.action, entry.path, entry.message);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Lines that can't be read go to `problems`, never a panic.

mod text;

use common::time::{days_from_civil, Precision, Ts};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const TICKS_PER_SECOND: i64 = 10_000_000;

/// A kind of antivirus log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// McAfee's `AccessProtectionLog.txt`.
    McAfeeAccessProtection,
    /// A Symantec scan log.
    SymantecScan,
    /// Sophos's `SAV.txt`.
    SophosSav,
    /// Trend Micro's virus detection log (`pccnt35.log`).
    TrendMicroVirus,
    /// Trend Micro's web reputation log (`OfcUrlf.log`).
    TrendMicroWeb,
}

impl Kind {
    /// The product's name.
    #[must_use]
    pub const fn product(self) -> &'static str {
        match self {
            Self::McAfeeAccessProtection => "McAfee",
            Self::SymantecScan => "Symantec",
            Self::SophosSav => "Sophos",
            Self::TrendMicroVirus | Self::TrendMicroWeb => "Trend Micro",
        }
    }
}

/// An entry of a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its line, from 1.
    pub line: usize,
    /// When: UTC for Trend Micro's Unix times, local (zone unknown)
    /// otherwise.
    pub time: Option<Ts>,
    /// The threat named (`W32.Changeup!gen33`, `EICAR-AV-Test`).
    pub threat: Option<String>,
    /// The file or process concerned.
    pub path: Option<String>,
    /// The account.
    pub user: Option<String>,
    /// What was done (`Action blocked : Terminate`, Symantec's action
    /// numbers, Trend Micro's action code).
    pub action: Option<String>,
    /// The entry's text (Symantec's description, Sophos's message,
    /// McAfee's status, the URL for Trend Micro's web reputation).
    pub message: Option<String>,
    /// Every other value, by name.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// A value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A log's entries and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The entries, in order.
    pub entries: Vec<Entry>,
    /// The lines that couldn't be read, with why.
    pub problems: Vec<String>,
}

/// Which log a file is, by its name and first line.
#[must_use]
pub fn detect(name: &str, head: &[u8]) -> Option<Kind> {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let text = text::decode(&head[..head.len().min(4096) & !1]);
    let first = text.lines().next().unwrap_or_default();
    if base == "accessprotectionlog.txt" || text::is_mcafee(first) {
        Some(Kind::McAfeeAccessProtection)
    } else if base == "sav.txt" || text::is_sophos(first) {
        Some(Kind::SophosSav)
    } else if base.starts_with("pccnt") || (first.contains("<;>") && text::is_trend_virus(first)) {
        Some(Kind::TrendMicroVirus)
    } else if base.starts_with("ofcurlf") || (first.contains("<;>") && text::is_trend_web(first)) {
        Some(Kind::TrendMicroWeb)
    } else if text::is_symantec(first) {
        Some(Kind::SymantecScan)
    } else {
        None
    }
}

/// Read a log of `kind`.
#[must_use]
pub fn read(kind: Kind, data: &[u8]) -> Log {
    let text = text::decode(data);
    let parse: fn(&str) -> Result<Entry, String> = match kind {
        Kind::McAfeeAccessProtection => text::mcafee,
        Kind::SymantecScan => text::symantec,
        Kind::SophosSav => text::sophos,
        Kind::TrendMicroVirus => text::trend_virus,
        Kind::TrendMicroWeb => text::trend_web,
    };
    let mut log = Log::default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        match parse(line) {
            Ok(mut entry) => {
                entry.line = index + 1;
                log.entries.push(entry);
            }
            Err(why) => log.problems.push(format!("line {}: {why}", index + 1)),
        }
    }
    log
}

/// A local wall-clock time, checked.
fn local(year: i64, month: u32, day: u32, hour: i64, minute: i64, second: i64) -> Option<Ts> {
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(Ts::from_local_ticks(
        seconds * TICKS_PER_SECOND,
        Precision::Second,
    ))
}

/// `-`, empty and whitespace mean none.
fn value(text: &str) -> Option<String> {
    Some(text.trim())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}
