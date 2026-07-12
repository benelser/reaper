//! Pure parsers for the kernel-written buffers the fast leaves read. No OS
//! calls — these compile and test on EVERY platform, and run under Miri in
//! CI. A repr(C)-padding name-shear was caught here once on a real kernel;
//! this module is where that bug class comes to die.

#![allow(unsafe_code)] // read_unaligned over kernel-shaped buffers; each use carries SAFETY

/// One `linux_dirent64` record: name starts at byte 19 — the header is
/// PACKED (plain repr(C) pads to 24 and shears 5 bytes off every name).
#[repr(C, packed)]
struct LinuxDirent64Head {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
}
const LINUX_HEAD: usize = std::mem::size_of::<LinuxDirent64Head>(); // 19

#[derive(Debug, PartialEq, Eq)]
pub struct RawLinuxEntry {
    pub ino: u64,
    pub d_type: u8,
    pub name: String,
}

/// Parse a getdents64 output buffer (`buf[..n]` as the kernel filled it).
/// Skips `.` and `..`. Malformed records terminate the parse rather than
/// read out of bounds — fail closed, never overread.
pub fn linux_dirents(buf: &[u8]) -> Vec<RawLinuxEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + LINUX_HEAD <= buf.len() {
        // SAFETY: bounds-checked above; packed struct has align 1, and
        // read_unaligned copies field-by-field from the checked region.
        let (ino, d_type, reclen) = unsafe {
            let h = buf.as_ptr().add(off) as *const LinuxDirent64Head;
            ((*h).d_ino, (*h).d_type, (*h).d_reclen as usize)
        };
        if reclen < LINUX_HEAD || off + reclen > buf.len() {
            break; // malformed record: stop, never overread
        }
        let name_bytes = &buf[off + LINUX_HEAD..off + reclen];
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        off += reclen;
        if name == "." || name == ".." {
            continue;
        }
        out.push(RawLinuxEntry { ino, d_type, name });
    }
    out
}

/// getattrlistbulk record fields, in the packing order validated empirically
/// plus ATTR_CMN_FLAGS (man-page canonical order: NAME · OBJTYPE · MODTIME ·
/// FLAGS · FILEID). The differential test screams if the order is wrong.
#[derive(Debug, PartialEq, Eq)]
pub struct RawMacEntry {
    pub name: String,
    pub objtype: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: u32,
    pub file_id: u64,
    /// ATTR_FILE_DATALENGTH — present for files only.
    pub data_length: Option<i64>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AttributeSet {
    commonattr: u32,
    volattr: u32,
    dirattr: u32,
    fileattr: u32,
    forkattr: u32,
}

pub const ATTR_CMN_NAME: u32 = 0x0000_0001;
pub const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
pub const ATTR_CMN_MODTIME: u32 = 0x0000_0400;
/// 0x0004_0000 — NOT 0x40 (that's OBJPERMANENTID; the differential test
/// caught exactly that misrequest shifting the whole record).
pub const ATTR_CMN_FLAGS: u32 = 0x0004_0000;
pub const ATTR_CMN_FILEID: u32 = 0x0200_0000;
pub const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
pub const ATTR_FILE_DATALENGTH: u32 = 0x0000_0200;

/// SAFETY: caller guarantees `buf[off..off+size_of::<T>()]` is in bounds
/// (checked by `take`'s callers via the record-length check).
unsafe fn take<T: Copy>(buf: &[u8], off: &mut usize) -> T {
    let v = (buf.as_ptr().add(*off) as *const T).read_unaligned();
    *off += std::mem::size_of::<T>();
    v
}

/// Parse `count` getattrlistbulk records from `buf`. Records whose declared
/// length overruns the buffer terminate the parse (fail closed).
pub fn mac_attrbulk(buf: &[u8], count: usize) -> Vec<RawMacEntry> {
    let mut out = Vec::new();
    let mut base = 0usize;
    for _ in 0..count {
        if base + 4 > buf.len() {
            break;
        }
        // SAFETY: 4 bytes bounds-checked above.
        let length = unsafe { (buf.as_ptr().add(base) as *const u32).read_unaligned() } as usize;
        if length < 4 || base + length > buf.len() {
            break;
        }
        let record = &buf[base..base + length];
        let mut off = 4usize;
        macro_rules! within {
            ($n:expr) => {
                if off + $n > record.len() {
                    break;
                }
            };
        }
        within!(std::mem::size_of::<AttributeSet>());
        // SAFETY: bounds-checked by `within!` immediately above each take.
        let returned: AttributeSet = unsafe { take(record, &mut off) };

        let mut name = String::new();
        if returned.commonattr & ATTR_CMN_NAME != 0 {
            within!(8);
            let name_field = off;
            // SAFETY: 8 bytes checked; attrreference is (i32 offset, u32 len).
            let (data_off, _len): (i32, u32) =
                unsafe { (take(record, &mut off), take(record, &mut off)) };
            let start = name_field.wrapping_add(data_off as usize);
            if start < record.len() {
                let tail = &record[start..];
                let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                name = String::from_utf8_lossy(&tail[..end]).into_owned();
            }
        }
        let mut objtype = 0u32;
        if returned.commonattr & ATTR_CMN_OBJTYPE != 0 {
            within!(4);
            // SAFETY: 4 bytes checked.
            objtype = unsafe { take(record, &mut off) };
        }
        let (mut mtime_sec, mut mtime_nsec) = (0i64, 0i64);
        if returned.commonattr & ATTR_CMN_MODTIME != 0 {
            within!(16);
            // SAFETY: 16 bytes checked (timespec = 2×i64 on 64-bit darwin).
            mtime_sec = unsafe { take(record, &mut off) };
            mtime_nsec = unsafe { take(record, &mut off) };
        }
        let mut flags = 0u32;
        if returned.commonattr & ATTR_CMN_FLAGS != 0 {
            within!(4);
            // SAFETY: 4 bytes checked.
            flags = unsafe { take(record, &mut off) };
        }
        let mut file_id = 0u64;
        if returned.commonattr & ATTR_CMN_FILEID != 0 {
            within!(8);
            // SAFETY: 8 bytes checked.
            file_id = unsafe { take(record, &mut off) };
        }
        let mut data_length = None;
        if returned.fileattr & ATTR_FILE_DATALENGTH != 0 {
            within!(8);
            // SAFETY: 8 bytes checked.
            data_length = Some(unsafe { take::<i64>(record, &mut off) });
        }
        out.push(RawMacEntry {
            name,
            objtype,
            mtime_sec,
            mtime_nsec,
            flags,
            file_id,
            data_length,
        });
        base += length;
    }
    out
}

/// FILE_ID_BOTH_DIR_INFORMATION header — repr(C) reproduces the MSVC layout
/// (FileName at offset 104, verified against real NTFS).
#[repr(C)]
struct FileIdBothHead {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: i64,
    allocation_size: i64,
    file_attributes: u32,
    file_name_length: u32, // bytes
    ea_size: u32,
    short_name_length: i8,
    short_name: [u16; 12],
    file_id: i64,
}
const WIN_HEAD: usize = std::mem::size_of::<FileIdBothHead>(); // 104

#[derive(Debug, PartialEq, Eq)]
pub struct RawWinEntry {
    pub name: String,
    pub attributes: u32,
    pub end_of_file: i64,
    pub last_write_time: i64, // FILETIME ticks
    pub file_id: i64,
}

/// Parse a FileIdBothDirectoryInformation chain. Skips `.`/`..`; malformed
/// offsets terminate the parse (fail closed).
pub fn win_id_both(buf: &[u8]) -> Vec<RawWinEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        if off + WIN_HEAD > buf.len() {
            break;
        }
        // SAFETY: bounds-checked above; unaligned copy of a POD header.
        let (next, attributes, end_of_file, last_write_time, file_id, name_len) = unsafe {
            let h = buf.as_ptr().add(off) as *const FileIdBothHead;
            let h = h.read_unaligned();
            (
                h.next_entry_offset as usize,
                h.file_attributes,
                h.end_of_file,
                h.last_write_time,
                h.file_id,
                h.file_name_length as usize,
            )
        };
        if off + WIN_HEAD + name_len > buf.len() {
            break;
        }
        let name_units = name_len / 2;
        let mut name_u16 = Vec::with_capacity(name_units);
        for i in 0..name_units {
            let p = off + WIN_HEAD + i * 2;
            name_u16.push(u16::from_le_bytes([buf[p], buf[p + 1]]));
        }
        let name = String::from_utf16_lossy(&name_u16);
        if name != "." && name != ".." {
            out.push(RawWinEntry {
                name,
                attributes,
                end_of_file,
                last_write_time,
                file_id,
            });
        }
        if next == 0 {
            break;
        }
        if next < WIN_HEAD {
            break; // malformed: refuse to loop
        }
        off += next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic getdents64 buffer: the exact byte layout the kernel
    /// writes, including the 19-byte packed header the padding bug was about.
    fn dirent_buf(entries: &[(u64, u8, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for &(ino, d_type, name) in entries {
            let name_bytes = name.as_bytes();
            let reclen = (LINUX_HEAD + name_bytes.len() + 1).div_ceil(8) * 8; // kernel 8-aligns
            buf.extend_from_slice(&ino.to_le_bytes());
            buf.extend_from_slice(&0i64.to_le_bytes());
            buf.extend_from_slice(&(reclen as u16).to_le_bytes());
            buf.push(d_type);
            buf.extend_from_slice(name_bytes);
            buf.resize(buf.len() + (reclen - LINUX_HEAD - name_bytes.len()), 0);
        }
        buf
    }

    #[test]
    fn linux_names_start_at_byte_19_not_24() {
        let buf = dirent_buf(&[
            (7, 8, "f00000.dat"),
            (8, 4, "sub"),
            (1, 4, "."),
            (2, 4, ".."),
        ]);
        let got = linux_dirents(&buf);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            RawLinuxEntry {
                ino: 7,
                d_type: 8,
                name: "f00000.dat".into()
            }
        );
        assert_eq!(got[1].name, "sub");
    }

    #[test]
    fn linux_malformed_reclen_terminates_without_overread() {
        let mut buf = dirent_buf(&[(7, 8, "ok")]);
        let good = linux_dirents(&buf).len();
        assert_eq!(good, 1);
        // Corrupt reclen to point past the buffer: parse must stop cleanly.
        let reclen_off = 16;
        buf[reclen_off] = 0xFF;
        buf[reclen_off + 1] = 0x7F;
        assert!(linux_dirents(&buf).is_empty());
    }

    /// Synthetic getattrlistbulk record in the canonical packing order.
    fn attrbulk_record(
        name: &str,
        objtype: u32,
        mtime: (i64, i64),
        flags: u32,
        id: u64,
        len: Option<i64>,
    ) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.as_bytes().iter().copied().chain([0]).collect();
        let fixed = 4 + 20 + 8 + 4 + 16 + 4 + 8 + if len.is_some() { 8 } else { 0 };
        let total = (fixed + name_bytes.len()).div_ceil(4) * 4;
        let mut r = Vec::with_capacity(total);
        r.extend_from_slice(&(total as u32).to_le_bytes());
        let common =
            ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_MODTIME | ATTR_CMN_FLAGS | ATTR_CMN_FILEID;
        let fileattr = if len.is_some() {
            ATTR_FILE_DATALENGTH
        } else {
            0
        };
        for v in [common, 0, 0, fileattr, 0] {
            r.extend_from_slice(&v.to_le_bytes());
        }
        // attrreference: name data goes after the fixed region
        let name_data_off = (fixed - 4/*length itself not counted from field*/) as i32
            - 20 /*returned set*/;
        // offset is from the attrreference FIELD (at 4+20=24) to the name data (at `fixed`).
        let _ = name_data_off;
        let ref_field_pos = 4 + 20;
        r.extend_from_slice(&((fixed - ref_field_pos) as i32).to_le_bytes());
        r.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        r.extend_from_slice(&objtype.to_le_bytes());
        r.extend_from_slice(&mtime.0.to_le_bytes());
        r.extend_from_slice(&mtime.1.to_le_bytes());
        r.extend_from_slice(&flags.to_le_bytes());
        r.extend_from_slice(&id.to_le_bytes());
        if let Some(l) = len {
            r.extend_from_slice(&l.to_le_bytes());
        }
        r.extend_from_slice(&name_bytes);
        r.resize(total, 0);
        r
    }

    #[test]
    fn mac_attrbulk_roundtrips_in_canonical_order() {
        let mut buf = attrbulk_record("hello.rs", 1, (1000, 500), 0, 42, Some(1234));
        buf.extend(attrbulk_record(
            "subdir",
            2,
            (2000, 0),
            0x4000_0000,
            43,
            None,
        ));
        let got = mac_attrbulk(&buf, 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "hello.rs");
        assert_eq!(got[0].objtype, 1);
        assert_eq!(got[0].mtime_sec, 1000);
        assert_eq!(got[0].file_id, 42);
        assert_eq!(got[0].data_length, Some(1234));
        assert_eq!(got[1].name, "subdir");
        assert_eq!(got[1].flags, 0x4000_0000);
        assert_eq!(got[1].data_length, None);
    }

    #[test]
    fn mac_attrbulk_overrun_length_terminates() {
        let mut buf = attrbulk_record("x", 1, (0, 0), 0, 1, None);
        let n = buf.len();
        buf[0..4].copy_from_slice(&((n as u32) * 10).to_le_bytes());
        assert!(mac_attrbulk(&buf, 1).is_empty());
    }

    /// Synthetic FILE_ID_BOTH_DIR_INFORMATION chain.
    fn win_record(name: &str, attrs: u32, eof: i64, lwt: i64, id: i64, last: bool) -> Vec<u8> {
        let name_u16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let unaligned = WIN_HEAD + name_u16.len();
        let total = unaligned.div_ceil(8) * 8;
        let mut r = vec![0u8; total];
        let next = if last { 0u32 } else { total as u32 };
        r[0..4].copy_from_slice(&next.to_le_bytes());
        r[24..32].copy_from_slice(&lwt.to_le_bytes());
        r[40..48].copy_from_slice(&eof.to_le_bytes());
        r[56..60].copy_from_slice(&attrs.to_le_bytes());
        r[60..64].copy_from_slice(&(name_u16.len() as u32).to_le_bytes());
        r[96..104].copy_from_slice(&id.to_le_bytes());
        r[WIN_HEAD..WIN_HEAD + name_u16.len()].copy_from_slice(&name_u16);
        r
    }

    #[test]
    fn win_id_both_parses_chain_and_skips_dot_entries() {
        let mut buf = win_record(".", 0x10, 0, 0, 0, false);
        buf.extend(win_record(
            "build.log",
            0x20,
            4096,
            132_000_000_000_000_000,
            9,
            false,
        ));
        buf.extend(win_record("junc", 0x410, 0, 0, 10, true));
        let got = win_id_both(&buf);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "build.log");
        assert_eq!(got[0].end_of_file, 4096);
        assert_eq!(got[1].name, "junc");
        assert_eq!(got[1].attributes & 0x400, 0x400);
    }

    #[test]
    fn win_header_is_104_bytes() {
        assert_eq!(WIN_HEAD, 104);
        assert_eq!(LINUX_HEAD, 19);
    }
}
