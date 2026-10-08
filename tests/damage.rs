//! Any input gives entries, problems or nothing, never a panic.

use avlogs::Kind;
use proptest::prelude::*;

const KINDS: [Kind; 5] = [
    Kind::McAfeeAccessProtection,
    Kind::SymantecScan,
    Kind::SophosSav,
    Kind::TrendMicroVirus,
    Kind::TrendMicroWeb,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\t\n<;>,\"/:]{0,600}") {
        for kind in KINDS {
            let _ = avlogs::read(kind, text.as_bytes());
        }
        let _ = avlogs::detect("x.log", text.as_bytes());
    }

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1500)) {
        for kind in KINDS {
            let _ = avlogs::read(kind, &data);
        }
        let _ = avlogs::detect("sav.txt", &data);
    }
}

#[test]
fn port_blocking_destination() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/plaso/AccessProtectionLog.txt"
    ))
    .unwrap();
    let log = avlogs::read(Kind::McAfeeAccessProtection, &data);
    let port = log
        .entries
        .iter()
        .find(|e| e.get("Destination").is_some())
        .unwrap();
    assert_eq!(port.get("Destination"), Some("23.56.2.70:443"));
}

#[test]
fn other_csvs_are_not_symantec() {
    assert_eq!(avlogs::detect("ids.csv", b"2A0A1E011B21,host,user\n"), None);
}
