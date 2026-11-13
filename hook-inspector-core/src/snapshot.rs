//! Capture and offline replay of one scan.
//!
//! The plugin can wrap its `read` and `module_of` closures in a [`Recorder`]; everything the scan
//! and the trampoline search asked of the live process is then in a [`Snapshot`]: the executable's
//! size and SHA-256, the image base, the Address Library `(id, offset)` pairs, every memory read
//! with what it returned (or that it was unreadable), the answer to every `module_of` query, and
//! the loaded-module map. [`replay`] runs the same analysis on a host from that file and the
//! executable on disk, answering reads from the snapshot. A read the snapshot does not hold returns
//! `None` and is counted, so a replay that saw different memory than the plugin is visible.
//!
//! Binary layout (all integers LEB128 varints unless noted; read addresses are zigzag deltas from
//! the previous read): `SPMSNAP\0`, format, plugin version, exe name, exe size, exe SHA-256 (32 raw
//! bytes), image base, pairs, trampoline-search regions, reads, module queries, loaded modules,
//! names, conflict count, `SPMEND`. A read's bytes are stored raw or run-length coded (runs of 4 or
//! more, only for reads of 64 bytes or more, where it is smaller). A read returns at most the bytes
//! it asked for (a shorter answer is recorded as given); the parser refuses a longer one, a read over
//! 32 MiB, and a file whose reads decode to more than 512 MiB in all.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

use crate::{Report, analyse, format};

/// Version of the binary layout.
pub const FORMAT: u32 = 1;
/// File names next to the report.
pub const BIN_NAME: &str = "skse-hook-inspector-snapshot.bin";
pub const INDEX_NAME: &str = "skse-hook-inspector-snapshot.json";

const MAGIC: &[u8; 8] = b"SPMSNAP\0";
const END: &[u8; 6] = b"SPMEND";
/// Reads of at least this many bytes are run-length coded when that is smaller.
const RLE_MIN: usize = 64;
/// No read is longer than this (the plugin caps a region at 16 MiB; this leaves room).
const MAX_READ: usize = 1 << 25;
/// Everything a snapshot decodes to, over all reads, is at most this much (the plugin reads 256 MiB
/// of regions at most, plus a few MiB of entries).
const MAX_DECODED: usize = 512 << 20;
/// Recorded reads up to this long are found by start address when a new read is checked for overlap.
const SMALL_READ: usize = 4096;

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut block = |chunk: &[u8; 64]| {
        let mut w = [0u32; 64];
        for (i, b) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*b);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    };
    let full = data.len() / 64 * 64;
    for chunk in data[..full].as_chunks::<64>().0 {
        block(chunk);
    }
    let mut tail = data[full..].to_vec();
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in tail.as_chunks::<64>().0 {
        block(chunk);
    }
    let mut out = [0u8; 32];
    for (o, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *o = v.to_be_bytes();
    }
    out
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A loaded module: file name, base address, size in bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

/// One memory read the analysis made: `bytes` is what it returned, `None` when unreadable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub address: u64,
    pub len: usize,
    pub bytes: Option<Vec<u8>>,
}

/// Everything one scan saw.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub format: u32,
    pub plugin_version: String,
    pub exe: String,
    pub exe_size: u64,
    pub exe_sha256: [u8; 32],
    pub base: u64,
    /// The Address Library `(id, offset)` pairs the scan used.
    pub pairs: Vec<(u64, u64)>,
    /// The committed private executable regions the trampoline search read, `(start, len)`.
    pub regions: Vec<(u64, usize)>,
    pub reads: Vec<Read>,
    /// Every `module_of` query and its answer.
    pub asked: Vec<(u64, Option<String>)>,
    /// All modules loaded when the scan ran.
    pub modules: Vec<Module>,
    /// Function names applied to the report, by id.
    pub names: Vec<(u64, String)>,
    /// Reads of different length that overlap and disagree on the shared bytes (the process changed
    /// during the scan). The capture itself is a frozen view; a nonzero count is a warning.
    pub conflicts: u64,
}

impl Snapshot {
    /// A snapshot holding the metadata of a scan, ready for [`Recorder::finish`].
    #[must_use]
    pub fn new(plugin_version: &str, exe: &str, pe: &[u8], base: u64) -> Self {
        Self {
            format: FORMAT,
            plugin_version: plugin_version.to_owned(),
            exe: exe.to_owned(),
            exe_size: pe.len() as u64,
            exe_sha256: sha256(pe),
            base,
            ..Self::default()
        }
    }
}

/// Wraps the live `read` and `module_of` closures and keeps what they answered.
///
/// The capture is a frozen view: each `(address, len)` read and each `module_of` address is
/// answered from the live closure once, and every later identical query during the scan returns
/// that first answer (the live closure is not asked again). The analysis therefore sees exactly
/// what the snapshot holds, and a replay reproduces it even if the process changed meanwhile.
/// What the frozen view cannot hide is two reads of different length that overlap and disagree on
/// the shared bytes (the process changed between them); those are counted in `conflicts`. A live
/// closure must not call back into the recorder.
pub struct Recorder<'a> {
    read: &'a dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &'a dyn Fn(u64) -> Option<String>,
    reads: RefCell<Vec<Read>>,
    read_index: RefCell<HashMap<(u64, usize), usize>>,
    /// Readable reads of at most [`SMALL_READ`] bytes, by start address (indices into `reads`).
    small: RefCell<BTreeMap<u64, Vec<usize>>>,
    /// Longer readable reads (trampoline regions).
    large: RefCell<Vec<usize>>,
    asked: RefCell<Vec<(u64, Option<String>)>>,
    asked_index: RefCell<HashMap<u64, usize>>,
    conflicts: Cell<u64>,
}

impl<'a> Recorder<'a> {
    #[must_use]
    pub fn new(read: &'a dyn Fn(u64, usize) -> Option<Vec<u8>>, module_of: &'a dyn Fn(u64) -> Option<String>) -> Self {
        Self {
            read,
            module_of,
            reads: RefCell::default(),
            read_index: RefCell::default(),
            small: RefCell::default(),
            large: RefCell::default(),
            asked: RefCell::default(),
            asked_index: RefCell::default(),
            conflicts: Cell::new(0),
        }
    }

    /// Whether `bytes` at `address` disagrees with an earlier readable read on shared bytes.
    fn disagrees(&self, reads: &[Read], address: u64, bytes: &[u8]) -> bool {
        let end = address.saturating_add(bytes.len() as u64);
        let differs = |i: usize| {
            let Some(old) = reads[i].bytes.as_deref() else { return false };
            let old_end = reads[i].address.saturating_add(old.len() as u64);
            let (from, to) = (address.max(reads[i].address), end.min(old_end));
            from < to && bytes[(from - address) as usize..(to - address) as usize] != old[(from - reads[i].address) as usize..(to - reads[i].address) as usize]
        };
        let small = self.small.borrow();
        let near = small.range(address.saturating_sub(SMALL_READ as u64)..end).flat_map(|(_, v)| v.iter().copied());
        near.chain(self.large.borrow().iter().copied()).any(differs)
    }

    /// The wrapped read, recorded; the first answer to `(address, len)` is the only one.
    pub fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let seen = self.read_index.borrow().get(&(address, len)).copied();
        if let Some(i) = seen {
            return self.reads.borrow()[i].bytes.clone();
        }
        // a closure that returns more than asked is cut to what was asked, for the analysis and the file alike
        let got = (self.read)(address, len).map(|mut b| {
            b.truncate(len);
            b
        });
        let mut reads = self.reads.borrow_mut();
        if let Some(b) = &got {
            if self.disagrees(&reads, address, b) {
                self.conflicts.set(self.conflicts.get() + 1);
            }
            if b.len() <= SMALL_READ {
                self.small.borrow_mut().entry(address).or_default().push(reads.len());
            } else {
                self.large.borrow_mut().push(reads.len());
            }
        }
        self.read_index.borrow_mut().insert((address, len), reads.len());
        reads.push(Read { address, len, bytes: got.clone() });
        got
    }

    /// The wrapped module lookup, recorded; the first answer for `address` is the only one.
    pub fn module_of(&self, address: u64) -> Option<String> {
        let seen = self.asked_index.borrow().get(&address).copied();
        if let Some(i) = seen {
            return self.asked.borrow()[i].1.clone();
        }
        let got = (self.module_of)(address);
        let mut asked = self.asked.borrow_mut();
        self.asked_index.borrow_mut().insert(address, asked.len());
        asked.push((address, got.clone()));
        got
    }

    /// `template` with what was recorded.
    #[must_use]
    pub fn finish(self, mut template: Snapshot) -> Snapshot {
        template.reads = self.reads.into_inner();
        template.asked = self.asked.into_inner();
        template.conflicts = self.conflicts.get();
        template
    }
}

fn put(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn zigzag(d: i64) -> u64 {
    ((d << 1) ^ (d >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Run-length coding: a control varint, even = that many literal bytes follow, odd = a run of
/// `control >> 1` copies of the next byte.
fn rle_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut lit: Vec<u8> = Vec::new();
    let flush = |out: &mut Vec<u8>, lit: &mut Vec<u8>| {
        if !lit.is_empty() {
            put(out, (lit.len() as u64) << 1);
            out.append(lit);
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..].iter().take_while(|&&b| b == bytes[i]).count();
        if run >= 4 {
            flush(&mut out, &mut lit);
            put(&mut out, ((run as u64) << 1) | 1);
            out.push(bytes[i]);
            i += run;
        } else {
            lit.push(bytes[i]);
            i += 1;
        }
    }
    flush(&mut out, &mut lit);
    out
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.data.len()).ok_or("snapshot truncated")?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn var(&mut self) -> Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.u8()?;
            if shift == 63 && b > 1 {
                return Err("varint overflows u64".into());
            }
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("varint too long".into())
    }
    fn len(&mut self) -> Result<usize, String> {
        usize::try_from(self.var()?).map_err(|_| "length too large".to_owned())
    }
    fn string(&mut self) -> Result<String, String> {
        let n = self.len()?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "string is not UTF-8".to_owned())
    }
    /// A count of records that each take at least `min` bytes: refuses one larger than the rest of the data.
    fn count(&mut self, min: usize) -> Result<usize, String> {
        let n = self.len()?;
        if n.checked_mul(min).is_none_or(|b| b > self.data.len() - self.pos) {
            return Err("count larger than the data".into());
        }
        Ok(n)
    }
}

fn rle_decode(data: &[u8], total: usize) -> Result<Vec<u8>, String> {
    let mut r = Reader { data, pos: 0 };
    // the declared size is untrusted: never reserve more than the encoded bytes in hand
    let mut out = Vec::with_capacity(total.min(data.len()));
    while r.pos < data.len() {
        let c = r.var()?;
        let n = usize::try_from(c >> 1).map_err(|_| "run too long".to_owned())?;
        if out.len().checked_add(n).is_none_or(|t| t > total) {
            return Err("run-length data longer than its read".into());
        }
        if c & 1 == 1 {
            let b = r.u8()?;
            out.resize(out.len() + n, b);
        } else {
            out.extend_from_slice(r.take(n)?);
        }
    }
    (out.len() == total).then_some(out).ok_or_else(|| "run-length data shorter than its read".to_owned())
}

impl Snapshot {
    /// The binary file.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(MAGIC);
        put(&mut o, u64::from(self.format));
        put_str(&mut o, &self.plugin_version);
        put_str(&mut o, &self.exe);
        put(&mut o, self.exe_size);
        o.extend_from_slice(&self.exe_sha256);
        put(&mut o, self.base);
        put(&mut o, self.pairs.len() as u64);
        for &(id, off) in &self.pairs {
            put(&mut o, id);
            put(&mut o, off);
        }
        put(&mut o, self.regions.len() as u64);
        for &(start, len) in &self.regions {
            put(&mut o, start);
            put(&mut o, len as u64);
        }
        put(&mut o, self.reads.len() as u64);
        let mut prev = 0u64;
        for r in &self.reads {
            put(&mut o, zigzag(r.address.wrapping_sub(prev) as i64));
            prev = r.address;
            put(&mut o, r.len as u64);
            match &r.bytes {
                None => o.push(0),
                Some(b) => {
                    let rle = (b.len() >= RLE_MIN).then(|| rle_encode(b)).filter(|e| e.len() < b.len());
                    if let Some(e) = rle {
                        o.push(2);
                        put(&mut o, b.len() as u64);
                        put(&mut o, e.len() as u64);
                        o.extend_from_slice(&e);
                    } else {
                        o.push(1);
                        put(&mut o, b.len() as u64);
                        o.extend_from_slice(b);
                    }
                }
            }
        }
        put(&mut o, self.asked.len() as u64);
        for (a, name) in &self.asked {
            put(&mut o, *a);
            match name {
                None => o.push(0),
                Some(n) => {
                    o.push(1);
                    put_str(&mut o, n);
                }
            }
        }
        put(&mut o, self.modules.len() as u64);
        for m in &self.modules {
            put_str(&mut o, &m.name);
            put(&mut o, m.base);
            put(&mut o, m.size);
        }
        put(&mut o, self.names.len() as u64);
        for (id, n) in &self.names {
            put(&mut o, *id);
            put_str(&mut o, n);
        }
        put(&mut o, self.conflicts);
        o.extend_from_slice(END);
        o
    }

    /// Parses the binary file; every malformed or truncated input is an `Err`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::from_bytes_within(data, MAX_DECODED)
    }

    /// [`Self::from_bytes`] with `budget` as the most read bytes all records may decode to. A read
    /// longer than [`MAX_READ`], one returning more bytes than it asked for, or one that would pass
    /// the budget is refused before anything is allocated for it.
    pub fn from_bytes_within(data: &[u8], budget: usize) -> Result<Self, String> {
        let mut left = budget;
        let mut r = Reader { data, pos: 0 };
        if r.take(MAGIC.len())? != MAGIC {
            return Err("not a hook-inspector snapshot (bad magic)".into());
        }
        let format = u32::try_from(r.var()?).map_err(|_| "bad format number".to_owned())?;
        if format != FORMAT {
            return Err(format!("snapshot format {format}, this build reads {FORMAT}"));
        }
        let mut s = Self { format, ..Self::default() };
        s.plugin_version = r.string()?;
        s.exe = r.string()?;
        s.exe_size = r.var()?;
        s.exe_sha256.copy_from_slice(r.take(32)?);
        s.base = r.var()?;
        for _ in 0..r.count(2)? {
            s.pairs.push((r.var()?, r.var()?));
        }
        for _ in 0..r.count(2)? {
            s.regions.push((r.var()?, r.len()?));
        }
        let mut prev = 0u64;
        for _ in 0..r.count(3)? {
            let address = prev.wrapping_add(unzigzag(r.var()?) as u64);
            prev = address;
            let len = r.len()?;
            if len > MAX_READ {
                return Err("read larger than the limit".into());
            }
            // A readable read holds at most what was asked (the recorder cuts longer answers; the
            // plugin's own read is all or nothing). Checked, and charged to the budget, before any
            // allocation.
            let mut charge = |n: usize| -> Result<(), String> {
                if n > len {
                    return Err("read returned more bytes than it asked for".to_owned());
                }
                left = left.checked_sub(n).ok_or("snapshot decodes to more than the size budget")?;
                Ok(())
            };
            let bytes = match r.u8()? {
                0 => None,
                1 => {
                    let n = r.len()?;
                    charge(n)?;
                    Some(r.take(n)?.to_vec())
                }
                2 => {
                    let n = r.len()?;
                    let enc = r.len()?;
                    charge(n)?;
                    Some(rle_decode(r.take(enc)?, n)?)
                }
                t => return Err(format!("unknown read tag {t}")),
            };
            s.reads.push(Read { address, len, bytes });
        }
        for _ in 0..r.count(2)? {
            let a = r.var()?;
            let name = match r.u8()? {
                0 => None,
                1 => Some(r.string()?),
                t => return Err(format!("unknown module tag {t}")),
            };
            s.asked.push((a, name));
        }
        for _ in 0..r.count(3)? {
            s.modules.push(Module { name: r.string()?, base: r.var()?, size: r.var()? });
        }
        for _ in 0..r.count(2)? {
            s.names.push((r.var()?, r.string()?));
        }
        s.conflicts = r.var()?;
        if r.take(END.len())? != END {
            return Err("snapshot end marker missing".into());
        }
        if r.pos != data.len() {
            return Err("data after the end marker".into());
        }
        Ok(s)
    }

    /// A small JSON index of the binary file, for people and other tools.
    #[must_use]
    pub fn index_json(&self, binary_bytes: usize) -> String {
        use std::fmt::Write as _;
        fn esc(s: &str) -> String {
            let mut o = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => o.push_str("\\\""),
                    '\\' => o.push_str("\\\\"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(o, "\\u{:04x}", c as u32);
                    }
                    c => o.push(c),
                }
            }
            o.push('"');
            o
        }
        let unreadable = self.reads.iter().filter(|r| r.bytes.is_none()).count();
        let read_bytes: usize = self.reads.iter().filter_map(|r| r.bytes.as_ref()).map(Vec::len).sum();
        let mut o = String::new();
        let _ = writeln!(o, "{{");
        let _ = writeln!(o, "  \"format\": {},", self.format);
        let _ = writeln!(o, "  \"plugin_version\": {},", esc(&self.plugin_version));
        let _ = writeln!(o, "  \"exe\": {},", esc(&self.exe));
        let _ = writeln!(o, "  \"exe_size\": {},", self.exe_size);
        let _ = writeln!(o, "  \"exe_sha256\": \"{}\",", hex(&self.exe_sha256));
        let _ = writeln!(o, "  \"image_base\": \"{:#x}\",", self.base);
        let _ = writeln!(o, "  \"binary\": {},", esc(BIN_NAME));
        let _ = writeln!(o, "  \"binary_bytes\": {binary_bytes},");
        let _ = writeln!(o, "  \"address_library_pairs\": {},", self.pairs.len());
        let _ = writeln!(o, "  \"trampoline_regions\": {},", self.regions.len());
        let _ = writeln!(o, "  \"reads\": {},", self.reads.len());
        let _ = writeln!(o, "  \"reads_unreadable\": {unreadable},");
        let _ = writeln!(o, "  \"read_bytes\": {read_bytes},");
        let _ = writeln!(o, "  \"read_conflicts\": {},", self.conflicts);
        let _ = writeln!(o, "  \"module_queries\": {},", self.asked.len());
        let _ = writeln!(o, "  \"names\": {},", self.names.len());
        let _ = writeln!(o, "  \"modules\": [");
        for (i, m) in self.modules.iter().enumerate() {
            let comma = if i + 1 < self.modules.len() { "," } else { "" };
            let _ = writeln!(o, "    {{\"name\": {}, \"base\": \"{:#x}\", \"size\": {}}}{comma}", esc(&m.name), m.base, m.size);
        }
        let _ = writeln!(o, "  ]");
        let _ = writeln!(o, "}}");
        o
    }
}

/// Answers the analysis from a snapshot. Anything the snapshot does not hold is counted.
pub struct Replay<'a> {
    reads: HashMap<(u64, usize), &'a Option<Vec<u8>>>,
    asked: HashMap<u64, &'a Option<String>>,
    modules: &'a [Module],
    missed_reads: Cell<u64>,
    missed_modules: Cell<u64>,
    examples: RefCell<Vec<String>>,
}

impl<'a> Replay<'a> {
    #[must_use]
    pub fn new(snap: &'a Snapshot) -> Self {
        let mut reads = HashMap::new();
        for r in &snap.reads {
            reads.entry((r.address, r.len)).or_insert(&r.bytes);
        }
        let mut asked = HashMap::new();
        for (a, n) in &snap.asked {
            asked.entry(*a).or_insert(n);
        }
        Self {
            reads,
            asked,
            modules: &snap.modules,
            missed_reads: Cell::new(0),
            missed_modules: Cell::new(0),
            examples: RefCell::default(),
        }
    }

    fn miss(&self, what: String) {
        let mut e = self.examples.borrow_mut();
        if e.len() < 10 {
            e.push(what);
        }
    }

    /// The recorded answer for `(address, len)`; `None` and a count when it was never read.
    pub fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        if let Some(r) = self.reads.get(&(address, len)) {
            return (*r).clone();
        }
        self.missed_reads.set(self.missed_reads.get() + 1);
        self.miss(format!("read {len} bytes at {address:#x}"));
        None
    }

    /// The recorded answer for `address`. An address the scan never asked about is counted and
    /// answered from the module map (`None` outside every module).
    pub fn module_of(&self, address: u64) -> Option<String> {
        if let Some(n) = self.asked.get(&address) {
            return (*n).clone();
        }
        self.missed_modules.set(self.missed_modules.get() + 1);
        self.miss(format!("module of {address:#x}"));
        self.modules.iter().find(|m| address >= m.base && address - m.base < m.size).map(|m| m.name.clone())
    }

    #[must_use]
    pub fn missed_reads(&self) -> u64 {
        self.missed_reads.get()
    }

    #[must_use]
    pub fn missed_modules(&self) -> u64 {
        self.missed_modules.get()
    }

    /// The first few misses, described.
    #[must_use]
    pub fn examples(&self) -> Vec<String> {
        self.examples.borrow().clone()
    }
}

/// The outcome of [`replay`].
#[derive(Debug)]
pub struct Replayed {
    pub report: Report,
    /// The report text, as the plugin wrote it.
    pub text: String,
    /// Reads the snapshot did not hold (answered `None`).
    pub missed_reads: u64,
    /// `module_of` queries the snapshot did not hold.
    pub missed_modules: u64,
    pub examples: Vec<String>,
    /// The snapshot's overlapping-read conflicts: the process changed while it was captured.
    pub conflicts: u64,
}

/// Applies the snapshot's names to a report.
pub fn apply_names(report: &mut Report, names: &[(u64, String)]) {
    let by_id: HashMap<u64, &String> = names.iter().map(|(i, n)| (*i, n)).collect();
    for f in &mut report.findings {
        if let Some(n) = by_id.get(&f.id) {
            f.name = Some((*n).clone());
        }
    }
}

/// The names of a report's findings, to store in a snapshot.
#[must_use]
pub fn names_of(report: &Report) -> Vec<(u64, String)> {
    report.findings.iter().filter_map(|f| f.name.clone().map(|n| (f.id, n))).collect()
}

/// Runs the analysis again from `snap` and the executable file `pe`. Refuses a file whose size or
/// SHA-256 differs from the one the snapshot was taken against.
pub fn replay(snap: &Snapshot, pe: &[u8]) -> Result<Replayed, String> {
    if pe.len() as u64 != snap.exe_size {
        return Err(format!("{} is {} bytes, the snapshot was taken against {}", snap.exe, pe.len(), snap.exe_size));
    }
    let got = sha256(pe);
    if got != snap.exe_sha256 {
        return Err(format!("{} SHA-256 {} differs from the snapshot's {}", snap.exe, hex(&got), hex(&snap.exe_sha256)));
    }
    let rp = Replay::new(snap);
    let mut report = analyse(&snap.pairs, snap.base, pe, &snap.exe, &snap.regions, &|a, n| rp.read(a, n), &|a| rp.module_of(a));
    apply_names(&mut report, &snap.names);
    let text = format(&report, &snap.exe);
    Ok(Replayed { report, text, missed_reads: rp.missed_reads(), missed_modules: rp.missed_modules(), examples: rp.examples(), conflicts: snap.conflicts })
}
