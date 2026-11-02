//! A zip archive with deflated files, no extra fields, no comment and no ZIP64: the release
//! archives are a few small files.

use crate::Entry;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

/// Created on Unix, so that readers apply the Unix permissions of the external attributes.
const MADE_BY_UNIX: u16 = 3 << 8 | 20;
/// Version 2.0, the first with deflate and directories.
const NEEDED: u16 = 20;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
/// The MS-DOS directory attribute.
const DOS_DIRECTORY: u32 = 0x10;

/// The MS-DOS time and date of `mtime`, read as UTC: two-second steps, years 1980 to 2107.
fn dos_time(mtime: u64) -> Result<(u16, u16), String> {
    let days = mtime / 86_400;
    let seconds = mtime % 86_400;
    let (year, month, day) = civil(days);
    if !(1980..=2107).contains(&year) {
        return Err(format!(
            "{mtime} is outside the years a zip archive can hold"
        ));
    }
    let time = ((seconds / 3600) << 11) | ((seconds % 3600 / 60) << 5) | ((seconds % 60) / 2);
    let date = ((year - 1980) << 9) | (month << 5) | day;
    Ok((time as u16, date as u16))
}

/// Year, month and day of a day count since 1970-01-01 (Howard Hinnant's civil_from_days).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

fn u16_of(value: usize, what: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("{what} {value} needs ZIP64"))
}

fn u32_of(value: usize, what: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{what} {value} needs ZIP64"))
}

pub fn archive(entries: &[Entry], mtime: u64) -> Result<Vec<u8>, String> {
    let (time, date) = dos_time(mtime)?;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let name = entry.name.as_bytes();
        let (method, crc, size, compressed, external) = match &entry.data {
            Some(data) => {
                let mut deflate = DeflateEncoder::new(Vec::new(), Compression::best());
                deflate.write_all(data).map_err(|e| e.to_string())?;
                let compressed = deflate.finish().map_err(|e| e.to_string())?;
                let external = (S_IFREG | entry.mode) << 16;
                (
                    DEFLATED,
                    crc32fast::hash(data),
                    data.len(),
                    compressed,
                    external,
                )
            }
            None => (
                STORED,
                0,
                0,
                Vec::new(),
                (S_IFDIR | entry.mode) << 16 | DOS_DIRECTORY,
            ),
        };
        let offset = u32_of(out.len(), "offset")?;
        let fields = |out: &mut Vec<u8>| -> Result<(), String> {
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&time.to_le_bytes());
            out.extend_from_slice(&date.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&u32_of(compressed.len(), "size")?.to_le_bytes());
            out.extend_from_slice(&u32_of(size, "size")?.to_le_bytes());
            out.extend_from_slice(&u16_of(name.len(), "name length")?.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            Ok(())
        };

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&NEEDED.to_le_bytes());
        fields(&mut out)?;
        out.extend_from_slice(name);
        out.extend_from_slice(&compressed);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&MADE_BY_UNIX.to_le_bytes());
        central.extend_from_slice(&NEEDED.to_le_bytes());
        fields(&mut central)?;
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&external.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let count = u16_of(entries.len(), "entry count")?;
    let central_offset = u32_of(out.len(), "offset")?;
    let central_size = u32_of(central.len(), "size")?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk of the central directory
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    fn le16(b: &[u8], at: usize) -> usize {
        usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
    }

    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    #[test]
    fn dos_time_follows_the_calendar() {
        // 2026-11-02 08:47:11 UTC.
        let (time, date) = dos_time(1_793_609_231).unwrap();
        assert_eq!((date >> 9, date >> 5 & 15, date & 31), (46, 11, 2));
        assert_eq!((time >> 11, time >> 5 & 63, (time & 31) * 2), (8, 47, 10));
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert!(dos_time(0).is_err());
    }

    #[test]
    fn the_central_directory_lists_every_entry_and_the_files_inflate_back() {
        let files = [
            ("x".to_string(), vec![5u8; 3000], true),
            ("y".to_string(), b"hi".to_vec(), false),
        ];
        let members = crate::entries("d", &files).unwrap();
        let zip = archive(&members, 1_793_609_231).unwrap();
        assert_eq!(zip, archive(&members, 1_793_609_231).unwrap());

        let end = zip.len() - 22;
        assert_eq!(le32(&zip, end), 0x0605_4b50);
        assert_eq!(le16(&zip, end + 10), 3);
        let mut at = le32(&zip, end + 16) as usize;
        let mut seen = Vec::new();
        for _ in 0..3 {
            assert_eq!(le32(&zip, at), 0x0201_4b50);
            let compressed = le32(&zip, at + 20) as usize;
            let size = le32(&zip, at + 24) as usize;
            let name_len = le16(&zip, at + 28);
            let external = le32(&zip, at + 38);
            let local = le32(&zip, at + 42) as usize;
            let name = String::from_utf8(zip[at + 46..at + 46 + name_len].to_vec()).unwrap();
            assert_eq!(le32(&zip, local), 0x0403_4b50);
            assert_eq!(zip[local + 30..local + 30 + name_len], *name.as_bytes());
            let data = &zip[local + 30 + name_len..local + 30 + name_len + compressed];
            let mut inflated = Vec::new();
            if le16(&zip, at + 10) == 8 {
                DeflateDecoder::new(data)
                    .read_to_end(&mut inflated)
                    .unwrap();
            }
            assert_eq!(inflated.len(), size);
            assert_eq!(crc32fast::hash(&inflated), le32(&zip, at + 16));
            seen.push((name, external >> 16, inflated));
            at += 46 + name_len;
        }
        assert_eq!(seen[0], ("d/".to_string(), 0o040755, Vec::new()));
        assert_eq!(seen[1], ("d/x".to_string(), 0o100755, vec![5u8; 3000]));
        assert_eq!(seen[2], ("d/y".to_string(), 0o100644, b"hi".to_vec()));
    }
}
