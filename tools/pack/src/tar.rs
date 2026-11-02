//! A POSIX ustar archive, compressed with gzip.

use crate::Entry;
use flate2::{Compression, GzBuilder};
use std::io::Write;

const BLOCK: usize = 512;

/// The ustar header of one entry: owner and group 0 without names, the given time.
fn header(entry: &Entry, mtime: u64) -> Result<[u8; BLOCK], String> {
    let mut h = [0u8; BLOCK];
    let name = entry.name.as_bytes();
    // The name field holds 100 bytes; the release names are far shorter, so no prefix split.
    if name.len() > 100 {
        return Err(format!("{}: longer than 100 bytes", entry.name));
    }
    let size = entry.data.as_ref().map_or(0, Vec::len) as u64;
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(entry.mode))?;
    octal(&mut h[108..116], 0)?;
    octal(&mut h[116..124], 0)?;
    octal(&mut h[124..136], size)?;
    octal(&mut h[136..148], mtime)?;
    h[156] = if entry.data.is_some() { b'0' } else { b'5' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    octal(&mut h[329..337], 0)?;
    octal(&mut h[337..345], 0)?;
    // The checksum is the sum of the header bytes with its own field read as spaces.
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    octal(&mut h[148..155], sum)?;
    h[155] = b' ';
    Ok(h)
}

/// Writes `value` as zero-padded octal digits followed by a NUL, filling `field`.
fn octal(field: &mut [u8], value: u64) -> Result<(), String> {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() > digits {
        return Err(format!("{value} does not fit {digits} octal digits"));
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

/// The uncompressed archive: each header, its data padded to whole blocks, and two zero blocks.
pub fn archive(entries: &[Entry], mtime: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(&header(entry, mtime)?);
        if let Some(data) = &entry.data {
            out.extend_from_slice(data);
            out.resize(out.len().next_multiple_of(BLOCK), 0);
        }
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    Ok(out)
}

/// The archive in a gzip stream with no file name and time 0 in its header, so that only the
/// contents decide its bytes.
pub fn gzipped(entries: &[Entry], mtime: u64) -> Result<Vec<u8>, String> {
    let tar = archive(entries, mtime)?;
    let mut gz = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    gz.write_all(&tar).map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn sample() -> Vec<Entry> {
        crate::entries(
            "d",
            &[
                ("x".to_string(), vec![7u8; 700], true),
                ("y".to_string(), b"hi".to_vec(), false),
            ],
        )
        .unwrap()
    }

    #[test]
    fn headers_carry_a_valid_checksum_and_the_fixed_metadata() {
        let tar = archive(&sample(), 1_700_000_000).unwrap();
        // Directory, x (700 bytes, two blocks), y (one block), two end blocks.
        assert_eq!(tar.len(), BLOCK * (1 + 1 + 2 + 1 + 1 + 2));
        for offset in [0, BLOCK, 4 * BLOCK] {
            let h = &tar[offset..offset + BLOCK];
            let stored =
                u64::from_str_radix(std::str::from_utf8(&h[148..154]).unwrap(), 8).unwrap();
            let sum: u64 = h
                .iter()
                .enumerate()
                .map(|(i, &b)| {
                    if (148..156).contains(&i) {
                        32
                    } else {
                        u64::from(b)
                    }
                })
                .sum();
            assert_eq!(stored, sum);
            assert_eq!(&h[136..147], format!("{:011o}", 1_700_000_000).as_bytes());
            assert_eq!(&h[108..115], b"0000000");
            assert_eq!(&h[257..263], b"ustar\0");
        }
        assert_eq!(&tar[..2], b"d/");
        assert_eq!(tar[156], b'5');
        assert_eq!(&tar[BLOCK + 100..BLOCK + 107], b"0000755");
        assert_eq!(
            &tar[BLOCK + 124..BLOCK + 135],
            format!("{:011o}", 700).as_bytes()
        );
        assert_eq!(&tar[2 * BLOCK..2 * BLOCK + 700], &[7u8; 700][..]);
        assert_eq!(&tar[4 * BLOCK + 100..4 * BLOCK + 107], b"0000644");
    }

    #[test]
    fn the_same_input_gives_the_same_bytes_and_decompresses_to_the_tar() {
        let first = gzipped(&sample(), 1).unwrap();
        assert_eq!(first, gzipped(&sample(), 1).unwrap());
        // Time 0 and no name in the gzip header.
        assert_eq!(&first[4..8], &[0, 0, 0, 0]);
        assert_eq!(first[3] & 0x08, 0);
        let mut tar = Vec::new();
        GzDecoder::new(&first[..]).read_to_end(&mut tar).unwrap();
        assert_eq!(tar, archive(&sample(), 1).unwrap());
    }

    #[test]
    fn a_name_that_does_not_fit_is_refused() {
        let long =
            crate::entries(&"n".repeat(99), &[("f".to_string(), Vec::new(), false)]).unwrap();
        assert!(archive(&long, 0).is_err());
    }
}
