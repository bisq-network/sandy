//! Which code a program file holds. On Apple silicon, a program without arm64 code runs through
//! Rosetta, which cannot load its runtime inside the sandbox. Pure code, so it runs and is tested
//! on every platform.

/// How many bytes of the file `has_arm64_code` needs at most: the fat header and its entries.
pub const HEADER_SIZE: usize = 4096;

const MH_MAGIC: [u8; 4] = [0xce, 0xfa, 0xed, 0xfe];
const MH_MAGIC_64: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
const FAT_MAGIC_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf];
/// `CPU_TYPE_ARM | CPU_ARCH_ABI64`, also the CPU type of arm64e.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// Real fat files hold a few architectures. A Java class file starts with the same magic and
/// has its version there, which is larger.
const MAX_FAT_ARCHS: u32 = 32;

/// Whether the Mach-O file that starts with `header` contains arm64 code. `None` when `header`
/// is not the start of a Mach-O file, for example a script, which its interpreter runs.
pub fn has_arm64_code(header: &[u8]) -> Option<bool> {
    let magic: [u8; 4] = header.get(..4)?.try_into().ok()?;
    match magic {
        // A thin file: the CPU type follows the magic, in the byte order of the magic.
        MH_MAGIC | MH_MAGIC_64 => Some(u32_le(header, 4)? == CPU_TYPE_ARM64),
        FAT_MAGIC | FAT_MAGIC_64 => {
            let count = u32_be(header, 4)?;
            if count == 0 || count > MAX_FAT_ARCHS {
                return None;
            }
            let entry = if magic == FAT_MAGIC { 20 } else { 32 };
            let mut found = false;
            for index in 0..count as usize {
                found |= u32_be(header, 8 + index * entry)? == CPU_TYPE_ARM64;
            }
            Some(found)
        }
        _ => None,
    }
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: u32 = 0x0100_0007;

    fn thin(cpu: u32) -> Vec<u8> {
        let mut header = MH_MAGIC_64.to_vec();
        header.extend(cpu.to_le_bytes());
        header.extend([0; 24]);
        header
    }

    fn fat(magic: [u8; 4], cpus: &[u32]) -> Vec<u8> {
        let entry = if magic == FAT_MAGIC { 20 } else { 32 };
        let mut header = magic.to_vec();
        header.extend((cpus.len() as u32).to_be_bytes());
        for &cpu in cpus {
            header.extend(cpu.to_be_bytes());
            header.extend(vec![0; entry - 4]);
        }
        header
    }

    #[test]
    fn thin_files_report_their_cpu() {
        assert_eq!(has_arm64_code(&thin(CPU_TYPE_ARM64)), Some(true));
        assert_eq!(has_arm64_code(&thin(X86_64)), Some(false));
        let mut i386 = MH_MAGIC.to_vec();
        i386.extend(7u32.to_le_bytes());
        assert_eq!(has_arm64_code(&i386), Some(false));
    }

    #[test]
    fn fat_files_need_one_arm64_slice() {
        for magic in [FAT_MAGIC, FAT_MAGIC_64] {
            assert_eq!(
                has_arm64_code(&fat(magic, &[X86_64, CPU_TYPE_ARM64])),
                Some(true)
            );
            assert_eq!(has_arm64_code(&fat(magic, &[X86_64])), Some(false));
        }
    }

    #[test]
    fn other_files_are_not_judged() {
        assert_eq!(has_arm64_code(b"#!/bin/sh\necho hi\n"), None);
        assert_eq!(has_arm64_code(&[0xcf, 0xfa]), None);
        assert_eq!(has_arm64_code(&[]), None);
        // A Java class file: the magic of a fat file, then minor and major version 0 and 65.
        assert_eq!(has_arm64_code(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65]), None);
        // A fat header cut short is not judged either.
        let mut cut = fat(FAT_MAGIC, &[X86_64, CPU_TYPE_ARM64]);
        cut.truncate(30);
        assert_eq!(has_arm64_code(&cut), None);
    }
}
