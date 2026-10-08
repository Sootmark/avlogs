//! plaso's antivirus logs (Apache-2.0, `tests/fixtures/plaso/`): every
//! entry plaso's `mcafee_protection`, `symantec_scanlog`,
//! `text/sophos_av`, `trendmicro_vd` and `trendmicro_url` parsers read,
//! read the same (`tests/oracle/plaso.tsv`, written from plaso's output;
//! local times as plaso shows them, as if UTC). One line plaso misreads:
//! McAfee's port blocking entry, which has no account and ends with the
//! address; plaso shifts its fields and fills the last two with text from
//! elsewhere. It is checked here as written.

use avlogs::{Entry, Kind};

fn some(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}

fn get(entry: &Entry, name: &str) -> String {
    entry.get(name).unwrap_or_default().to_owned()
}

fn line(name: &str, kind: Kind, e: &Entry) -> String {
    let micros = (e.time.unwrap().ticks().unwrap() / 10).to_string();
    let values = match kind {
        Kind::McAfeeAccessProtection => vec![
            some(e.message.as_ref()),
            some(e.user.as_ref()),
            some(e.path.as_ref()),
            get(e, "Target"),
            get(e, "Rule"),
            some(e.action.as_ref()),
        ],
        Kind::SymantecScan => vec![
            get(e, "Event"),
            some(e.user.as_ref()),
            some(e.threat.as_ref()),
            some(e.path.as_ref()),
            get(e, "RequestedAction"),
            get(e, "SecondaryAction"),
            some(e.action.as_ref()),
            some(e.message.as_ref()),
            get(e, "Computer"),
        ],
        Kind::SophosSav => vec![some(e.message.as_ref())],
        Kind::TrendMicroVirus => vec![
            some(e.threat.as_ref()),
            some(e.action.as_ref()),
            get(e, "Folder"),
            get(e, "File"),
            get(e, "ScanType"),
        ],
        Kind::TrendMicroWeb => vec![
            some(e.message.as_ref()),
            some(e.path.as_ref()),
            get(e, "Group"),
            get(e, "CredibilityScore"),
        ],
    };
    [vec![name.to_owned(), micros], values].concat().join("\t")
}

#[test]
fn every_entry_as_plaso_reads_it() {
    let mut got = Vec::new();
    for (name, kind) in [
        ("AccessProtectionLog.txt", Kind::McAfeeAccessProtection),
        ("Symantec.Log", Kind::SymantecScan),
        ("sav.txt", Kind::SophosSav),
        ("pccnt35.log", Kind::TrendMicroVirus),
        ("OfcUrlf.log", Kind::TrendMicroWeb),
    ] {
        let data = std::fs::read(format!(
            "{}/tests/fixtures/plaso/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert_eq!(avlogs::detect(name, &data), Some(kind), "{name}");
        assert_eq!(
            avlogs::detect("copy.log", &data),
            Some(kind),
            "{name} by content"
        );
        let log = avlogs::read(kind, &data);
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
        got.extend(log.entries.iter().map(|e| line(name, kind, e)));
    }
    got.sort();
    let port = "AccessProtectionLog.txt\t1375179482000000\tWould be blocked by port blocking rule  (rule is currently not enforced)";
    let ours: Vec<&String> = got.iter().filter(|g| g.starts_with(port)).collect();
    assert_eq!(
        ours,
        [&format!("{port}\t\tC:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashPlayerUpdateService.exe\t\tCommon Maximum Protection:Prevent HTTP communication\t")]
    );
    got.retain(|g| !g.starts_with(port));
    let expected: Vec<&str> = include_str!("oracle/plaso.tsv")
        .lines()
        .filter(|e| !e.starts_with(port))
        .collect();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}
