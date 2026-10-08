//! Each format's lines.

use common::time::Ts;

use crate::{local, value, Entry};

/// Text in UTF-16 (byte order mark) or UTF-8, a UTF-8 mark dropped.
pub(crate) fn decode(data: &[u8]) -> String {
    let utf16 = |data: &[u8], big: bool| {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|p| {
                if big {
                    u16::from_be_bytes([p[0], p[1]])
                } else {
                    u16::from_le_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match data {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(data).into_owned(),
    }
}

/// `9/27/2013` and `2:42:26 PM` as a local time.
fn us_date_time(date: &str, time: &str) -> Option<Ts> {
    let mut date = date.trim().splitn(3, '/');
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    let year: i64 = date.next()?.parse().ok()?;
    let (clock, meridiem) = time.trim().split_once(' ').unwrap_or((time.trim(), ""));
    let mut clock = clock.splitn(3, ':');
    let mut hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next().unwrap_or("0").parse().ok()?;
    match meridiem.to_ascii_uppercase().as_str() {
        "PM" if hour < 12 => hour += 12,
        "AM" if hour == 12 => hour = 0,
        _ => {}
    }
    local(year, month, day, hour, minute, second)
}

/// `YYYYMMDD` and `HHMMSS` (or `HHMM`) as a local time.
fn compact_date_time(date: &str, time: &str) -> Option<Ts> {
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    if date.len() != 8 || !digits(date) || !(time.len() == 4 || time.len() == 6) || !digits(time) {
        return None;
    }
    let number = |t: &str| t.parse::<i64>().ok();
    local(
        number(&date[..4])?,
        u32::try_from(number(&date[4..6])?).ok()?,
        u32::try_from(number(&date[6..8])?).ok()?,
        number(&time[..2])?,
        number(&time[2..4])?,
        time.get(4..6).map_or(Some(0), number)?,
    )
}

pub(crate) fn is_mcafee(line: &str) -> bool {
    let mut fields = line.split('\t');
    fields
        .next()
        .zip(fields.next())
        .is_some_and(|(date, time)| us_date_time(date, time).is_some())
}

/// `date \t time \t status \t user \t process \t target \t rule \t action`;
/// a port blocking rule's line is `date \t time \t status \t process \t
/// rule \t address:port`.
pub(crate) fn mcafee(line: &str) -> Result<Entry, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() == 6 {
        let time = us_date_time(fields[0], fields[1]).ok_or("a date and time not read")?;
        let mut entry = Entry {
            time: Some(time),
            message: value(fields[2]),
            path: value(fields[3]),
            ..Entry::default()
        };
        for (name, at) in [("Rule", 4), ("Destination", 5)] {
            if let Some(text) = value(fields[at]) {
                entry.fields.push((name.to_owned(), text));
            }
        }
        return Ok(entry);
    }
    if fields.len() < 8 {
        return Err(format!("{} fields, 6 or 8 expected", fields.len()));
    }
    let time = us_date_time(fields[0], fields[1]).ok_or("a date and time not read")?;
    let mut entry = Entry {
        time: Some(time),
        message: value(fields[2]),
        user: value(fields[3]),
        path: value(fields[4]),
        action: value(fields[7]),
        ..Entry::default()
    };
    for (name, at) in [("Target", 5), ("Rule", 6)] {
        if let Some(text) = value(fields[at]) {
            entry.fields.push((name.to_owned(), text));
        }
    }
    Ok(entry)
}

pub(crate) fn is_sophos(line: &str) -> bool {
    let mut words = line.splitn(3, ' ');
    words
        .next()
        .zip(words.next())
        .is_some_and(|(date, time)| time.len() == 6 && compact_date_time(date, time).is_some())
}

/// `YYYYMMDD HHMMSS message`; the threat and file are found in the
/// message (`File "…" belongs to virus/spyware '…'`, `Virus/spyware '…'
/// detected in '…'`).
pub(crate) fn sophos(line: &str) -> Result<Entry, String> {
    let mut words = line.splitn(3, ' ');
    let (date, time) = words.next().zip(words.next()).ok_or("no date and time")?;
    let time = compact_date_time(date, time).ok_or("a date and time not read")?;
    let message = words.next().unwrap_or_default().trim().to_owned();
    Ok(Entry {
        time: Some(time),
        threat: quoted(&message, "virus/spyware '", '\'')
            .or_else(|| quoted(&message, "Virus/spyware '", '\'')),
        path: quoted(&message, "File \"", '"')
            .or_else(|| quoted(&message, "file \"", '"'))
            .or_else(|| quoted(&message, "detected in '", '\'')),
        message: Some(message),
        ..Entry::default()
    })
}

/// The text between `marker` and the next `close`.
fn quoted(text: &str, marker: &str, close: char) -> Option<String> {
    let rest = text.split_once(marker)?.1;
    let end = rest.find(close)?;
    value(&rest[..end])
}

/// A hexadecimal time first, and Symantec's forty or more columns.
pub(crate) fn is_symantec(line: &str) -> bool {
    csv(line).len() >= 40
        && line
            .split(',')
            .next()
            .is_some_and(|stamp| hex_time(stamp).is_some())
}

/// `2A0A1E011B21`: years since 1970, month from 0, day, hour, minute,
/// second, in hexadecimal; local time.
fn hex_time(text: &str) -> Option<Ts> {
    if text.len() != 12 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |at: usize| i64::from_str_radix(&text[at..at + 2], 16).ok();
    local(
        1970 + byte(0)?,
        u32::try_from(byte(2)? + 1).ok()?,
        u32::try_from(byte(4)?).ok()?,
        byte(6)?,
        byte(8)?,
        byte(10)?,
    )
}

/// Symantec's columns, in its documented order (the first sixty).
const SYMANTEC: [&str; 39] = [
    "Time",
    "Event",
    "Category",
    "Logger",
    "Computer",
    "User",
    "Virus",
    "File",
    "RequestedAction",
    "SecondaryAction",
    "ActualAction",
    "VirusType",
    "Flags",
    "Description",
    "ScanId",
    "NewExtension",
    "GroupId",
    "EventData",
    "VbinId",
    "VirusId",
    "QuarantineForwardStatus",
    "Access",
    "SdnStatus",
    "Compressed",
    "Depth",
    "StillInfected",
    "DefinitionInfo",
    "DefinitionSequence",
    "CleanInfo",
    "DeleteInfo",
    "BackupId",
    "Parent",
    "Guid",
    "ClientGroup",
    "Address",
    "DomainName",
    "NtDomain",
    "MacAddress",
    "Version",
];

/// A scan log line: CSV, its event data holding tabs.
pub(crate) fn symantec(line: &str) -> Result<Entry, String> {
    let fields = csv(line);
    let time = fields
        .first()
        .and_then(|t| hex_time(t))
        .ok_or("no hexadecimal time")?;
    let field = |at: usize| fields.get(at).and_then(|f| value(f));
    let mut entry = Entry {
        time: Some(time),
        threat: field(6),
        path: field(7),
        user: field(5),
        action: field(10),
        message: field(13),
        ..Entry::default()
    };
    for (at, name) in SYMANTEC.iter().enumerate().skip(1) {
        if [5, 6, 7, 10, 13].contains(&at) {
            continue;
        }
        if let Some(text) = field(at) {
            entry.fields.push(((*name).to_owned(), text));
        }
    }
    Ok(entry)
}

/// A CSV line's fields, quotes honoured.
fn csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => fields.push(std::mem::take(&mut field)),
            (c, _) => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// A Trend Micro line's fields.
fn trend_fields(line: &str) -> Vec<&str> {
    line.split("<;>").collect()
}

/// The time: the Unix seconds at `unix` when written, else the local date
/// and minute of the first two fields.
fn trend_time(fields: &[&str], unix: usize) -> Option<Ts> {
    fields
        .get(unix)
        .and_then(|t| t.trim().parse::<i64>().ok())
        .filter(|&t| t > 0)
        .map(Ts::from_unix_seconds)
        .or_else(|| compact_date_time(fields.first()?, fields.get(1)?))
}

pub(crate) fn is_trend_virus(line: &str) -> bool {
    let fields = trend_fields(line);
    fields.len() >= 8
        && compact_date_time(fields[0], fields[1]).is_some()
        && fields[3].parse::<u32>().is_ok()
}

/// `date<;>HHMM<;>threat<;>action<;>scan type<;>?<;>folder<;>file<;>?<;>unix<;>`.
pub(crate) fn trend_virus(line: &str) -> Result<Entry, String> {
    let fields = trend_fields(line);
    if fields.len() < 8 {
        return Err(format!("{} fields, 8 or more expected", fields.len()));
    }
    let time = trend_time(&fields, 9).ok_or("no time")?;
    let folder = fields[6].trim();
    let file = fields[7].trim();
    let mut entry = Entry {
        time: Some(time),
        threat: value(fields[2]),
        path: value(&format!("{folder}{file}")),
        action: value(fields[3]),
        ..Entry::default()
    };
    for (name, text) in [("ScanType", fields[4]), ("Folder", folder), ("File", file)] {
        if let Some(text) = value(text) {
            entry.fields.push((name.to_owned(), text));
        }
    }
    Ok(entry)
}

pub(crate) fn is_trend_web(line: &str) -> bool {
    let fields = trend_fields(line);
    fields.len() >= 10
        && compact_date_time(fields[0], fields[1]).is_some()
        && fields[3].contains("://")
}

/// `date<;>HHMM<;>policy<;>URL<;>group code<;>group<;>credibility
/// rating<;>block mode<;>application<;>credibility score<;>IP<;>threshold<;>unix<;>`.
pub(crate) fn trend_web(line: &str) -> Result<Entry, String> {
    let fields = trend_fields(line);
    if fields.len() < 10 {
        return Err(format!("{} fields, 10 or more expected", fields.len()));
    }
    let time = trend_time(&fields, 12).ok_or("no time")?;
    let mut entry = Entry {
        time: Some(time),
        path: value(fields[8]),
        message: value(fields[3]),
        ..Entry::default()
    };
    for (name, at) in [
        ("Policy", 2),
        ("GroupCode", 4),
        ("Group", 5),
        ("CredibilityRating", 6),
        ("BlockMode", 7),
        ("CredibilityScore", 9),
        ("Ip", 10),
        ("Threshold", 11),
    ] {
        if let Some(text) = fields.get(at).and_then(|f| value(f)) {
            entry.fields.push((name.to_owned(), text));
        }
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let iso = |t: Option<Ts>| t.and_then(|t| t.to_iso8601());
        assert_eq!(
            iso(us_date_time("9/27/2013", "2:42:26 PM")).as_deref(),
            Some("2013-09-27T14:42:26.0000000")
        );
        assert_eq!(
            iso(us_date_time("9/27/2013", "12:05:00 AM")).as_deref(),
            Some("2013-09-27T00:05:00.0000000")
        );
        assert_eq!(
            iso(hex_time("2A0A1E011B21")).as_deref(),
            Some("2012-11-30T01:27:33.0000000")
        );
        assert_eq!(hex_time("2A0C1E011B21"), None);
        assert_eq!(
            iso(compact_date_time("20180130", "1446")).as_deref(),
            Some("2018-01-30T14:46:00.0000000")
        );
    }
}
