# avlogs

Antivirus logs, for forensics: what endpoint protection saw, blocked and cleaned, often the first trace of an intrusion and of the tools it brought. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-avlogs = "0.1"
```

```rust
let data = std::fs::read("AccessProtectionLog.txt")?;
if let Some(kind) = avlogs::detect("AccessProtectionLog.txt", &data) {
    for entry in avlogs::read(kind, &data).entries {
        println!("{:?} {:?} {:?} {:?}", entry.time, entry.action, entry.path, entry.message);
    }
}
```

## What you get

- McAfee VirusScan's `AccessProtectionLog.txt`: each block (or would-be block), the rule, the process, the account, what it touched, and port blocking rules' destinations.
- Symantec Endpoint Protection's scan logs (`<MMDDYYYY>.Log`): each event's hexadecimal time, event code, computer, user, threat, file, the actions requested and taken, its description, and the rest of Symantec's documented columns by name.
- Sophos Anti-Virus's `SAV.txt` (UTF-16): each message, the threat and file found in it.
- Trend Micro OfficeScan's virus detections (`pccnt35.log`: threat, action, folder, file, scan type) and web reputation blocks (`OfcUrlf.log`: URL, application, group, credibility).
- Each as an `Entry`: time (local, or UTC from Trend Micro's Unix times), threat, path, user, action, message, and the rest by name. Lines that can't be read go to `problems`, never a panic.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`): every one of the 38 entries plaso's parsers read, read the same, but one: McAfee's port blocking line, which plaso misreads (its fields shifted); here its process, rule and destination.
- Property tests: arbitrary text and bytes give entries, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
