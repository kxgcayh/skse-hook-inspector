//! Finds code another module patched into the game's functions, and who owns each patch.
//!
//! The scan compares the first bytes of every function the Address Library lists, as they are in
//! memory, with the same bytes in the game's executable on disk. A difference is classified (a
//! jump at the entry, a retargeted branch inside it, a stub that returns at once, a filled region,
//! other bytes) and any branch is followed through trampolines and generated thunks to the module
//! that owns it. Hooks stacked on one function are found from the trampolines each hook keeps to
//! call the code it replaced. Nothing here touches the game; memory and module lookups are passed in.

use std::collections::{BTreeMap, HashMap};

pub mod fonts;
pub mod snapshot;

/// Bytes compared at each function entry.
pub const ENTRY_LEN: usize = 16;
/// Jumps followed from one branch.
pub const MAX_HOPS: usize = 5;
/// Bytes of a generated thunk searched for a branch into a module. A CommonLib context hook loads
/// its detour's address about 60 bytes in.
pub const THUNK_LEN: usize = 128;

/// Windows and C runtime modules: a generated thunk calls into them (`RtlCaptureContext`, a lock),
/// but they never own a hook.
const SYSTEM: &[&str] = &[
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    "msvcp140.dll", "user32.dll", "win32u.dll",
];

fn is_system(module: &str) -> bool {
    SYSTEM.iter().any(|s| s.eq_ignore_ascii_case(module))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub exec: bool,
}

/// The section table of a PE file; `None` when it is not a 64-bit PE.
#[must_use]
pub fn sections(pe: &[u8]) -> Option<Vec<Section>> {
    let u16_at = |o: usize| pe.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| pe.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if pe.get(0..2)? != b"MZ" {
        return None;
    }
    let nt = u32_at(0x3c)? as usize;
    if pe.get(nt..nt + 4)? != b"PE\0\0" || u16_at(nt + 4)? != 0x8664 {
        return None;
    }
    let count = usize::from(u16_at(nt + 6)?);
    let optional = usize::from(u16_at(nt + 20)?);
    let table = nt + 24 + optional;
    (0..count)
        .map(|i| {
            let s = table + i * 40;
            Some(Section {
                virtual_size: u32_at(s + 8)?,
                rva: u32_at(s + 12)?,
                raw_size: u32_at(s + 16)?,
                raw_ptr: u32_at(s + 20)?,
                exec: u32_at(s + 36)? & 0x2000_0000 != 0,
            })
        })
        .collect()
}

/// The file bytes of `len` bytes at `rva` when they lie in an executable section's raw data.
#[must_use]
pub fn disk_code<'a>(pe: &'a [u8], secs: &[Section], rva: u32, len: usize) -> Option<&'a [u8]> {
    let s = secs.iter().find(|s| s.exec && rva >= s.rva && rva < s.rva + s.raw_size.min(s.virtual_size))?;
    let start = (s.raw_ptr + (rva - s.rva)) as usize;
    let avail = (s.raw_size.min(s.virtual_size) - (rva - s.rva)) as usize;
    pe.get(start..start + len.min(avail))
}

fn i32_at(code: &[u8], o: usize) -> Option<i32> {
    code.get(o..o + 4).map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(code: &[u8], o: usize) -> Option<u64> {
    code.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// A memory read of exactly 8 bytes as a little-endian value; any other length is `None`.
fn le_u64(bytes: Vec<u8>) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Where a jump at the start of `code` (located at `at`) leads. `read_u64` reads memory for the
/// indirect form. Recognised: `jmp rel8`, `jmp rel32`, `jmp [rip+disp32]`, `mov rax, imm64; jmp rax`
/// and `mov r11, imm64; jmp r11`.
#[must_use]
pub fn decode_jump(code: &[u8], at: u64, read_u64: &dyn Fn(u64) -> Option<u64>) -> Option<u64> {
    match code {
        [0xEB, rel, ..] => Some(at.wrapping_add(2).wrapping_add_signed(i64::from(*rel as i8))),
        [0xE9, ..] => Some(at.wrapping_add(5).wrapping_add_signed(i64::from(i32_at(code, 1)?))),
        [0xFF, 0x25, ..] => read_u64(at.wrapping_add(6).wrapping_add_signed(i64::from(i32_at(code, 2)?))),
        [0x48, 0xB8, ..] if code.get(10..12) == Some(&[0xFF, 0xE0]) => u64_at(code, 2),
        [0x49, 0xBB, ..] if code.get(10..13) == Some(&[0x41, 0xFF, 0xE3]) => u64_at(code, 2),
        _ => None,
    }
}

/// A branch or call that starts at `code[0]`: `call`/`jmp rel32` or `call`/`jmp [rip+disp32]`.
/// Returns the target and the instruction's length.
#[must_use]
pub fn decode_branch(code: &[u8], at: u64, read_u64: &dyn Fn(u64) -> Option<u64>) -> Option<(u64, usize)> {
    match code {
        [0xE8 | 0xE9, ..] => Some((at.wrapping_add(5).wrapping_add_signed(i64::from(i32_at(code, 1)?)), 5)),
        [0xFF, 0x15 | 0x25, ..] => Some((read_u64(at.wrapping_add(6).wrapping_add_signed(i64::from(i32_at(code, 2)?)))?, 6)),
        _ => None,
    }
}

/// What a stub at the start of `code` does, when the code returns at once: `ret`,
/// `xor eax/rax, eax/rax; ret`, `xor al, al; ret`, `mov al, imm8; ret`, `mov eax, imm32; ret`.
#[must_use]
pub fn stub(code: &[u8]) -> Option<String> {
    Some(match code {
        [0xC3, ..] => "returns at once".to_owned(),
        [0x31 | 0x33, 0xC0, 0xC3, ..] | [0x48, 0x31 | 0x33, 0xC0, 0xC3, ..] => "returns 0".to_owned(),
        [0x32, 0xC0, 0xC3, ..] => "returns false".to_owned(),
        [0xB0, v, 0xC3, ..] => format!("returns {v:#x}"),
        [0xB8, a, b, c, d, 0xC3, ..] => format!("returns {:#x}", u32::from_le_bytes([*a, *b, *c, *d])),
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub address: u64,
    /// The module file name holding `address`; `None` for anonymous memory (a trampoline page).
    pub module: Option<String>,
    /// Reached by searching generated code for a branch, not by a jump at the hop before.
    pub via_thunk: bool,
}

fn is_other(module: Option<&str>, exe: &str) -> bool {
    module.is_some_and(|m| !m.eq_ignore_ascii_case(exe))
}

/// The first branch or 64-bit constant in `code` (at `at`) that points into a module other than
/// the executable or a system module: how generated thunks reach the hook they serve.
fn thunk_target(
    code: &[u8],
    at: u64,
    exe: &str,
    read_u64: &dyn Fn(u64) -> Option<u64>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Option<u64> {
    for i in 0..code.len() {
        let mut candidates = Vec::new();
        if let Some((t, _)) = decode_branch(&code[i..], at + i as u64, read_u64) {
            candidates.push(t);
        }
        // mov r64, imm64 (REX.W 48/49, B8+r)
        if matches!(code[i], 0x48 | 0x49) && code.get(i + 1).is_some_and(|b| (0xB8..=0xBF).contains(b)) {
            if let Some(v) = u64_at(code, i + 2) {
                candidates.push(v);
            }
        }
        if let Some(t) = candidates.into_iter().find(|&t| {
            let m = module_of(t);
            is_other(m.as_deref(), exe) && !m.as_deref().is_some_and(is_system)
        }) {
            return Some(t);
        }
    }
    None
}

/// Follows a branch chain from `target`. Each hop is recorded; while one lands in the executable
/// or in anonymous memory, the jump there is followed, or failing that the first branch into
/// another module inside the generated code there.
pub fn follow(
    target: u64,
    exe: &str,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Vec<Hop> {
    let read_u64 = |a: u64| read(a, 8).and_then(le_u64);
    let mut hops: Vec<Hop> = Vec::new();
    let mut at = target;
    let mut via_thunk = false;
    for _ in 0..MAX_HOPS {
        let module = module_of(at);
        let stop = is_other(module.as_deref(), exe);
        hops.push(Hop { address: at, module: module.clone(), via_thunk });
        if stop {
            break;
        }
        // a thunk near the end of its region: the long read fails as a whole
        let Some(code) = read(at, THUNK_LEN).or_else(|| read(at, ENTRY_LEN)) else { break };
        if let Some(next) = decode_jump(&code, at, &read_u64) {
            at = next;
            via_thunk = false;
        } else if module.is_none() && let Some(next) = thunk_target(&code, at, exe, &read_u64, module_of) {
            at = next;
            via_thunk = true;
        } else {
            break;
        }
        if hops.iter().any(|h| h.address == at) {
            break;
        }
    }
    hops
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The entry now starts with a jump.
    Jump,
    /// A call or jump inside the compared bytes now leads elsewhere, or was written there.
    Inner { offset: usize },
    /// Like `Inner`, but the walker stopped at an unrecognised byte before `offset`, so it cannot
    /// say that an instruction starts there.
    InnerUnverified { offset: usize },
    /// The entry now returns at once.
    Stub(String),
    /// The entry was already a stub and now returns another value.
    Retval { was: String, now: String },
    /// The compared bytes are one byte repeated: the region was reused or wiped.
    Filled(u8),
    /// The bytes differ in a way this tool does not decode, first at `offset`.
    Bytes { offset: usize },
}

/// A hook below the one at the entry, found from a trampoline that calls the replaced code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// The trampoline's copy of the entry bytes.
    pub trampoline: u64,
    /// The copied bytes are the game's own: this is the bottom of the stack.
    pub original: bool,
    pub hops: Vec<Hop>,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: u64,
    pub rva: u64,
    pub kind: Kind,
    pub disk: Vec<u8>,
    pub memory: Vec<u8>,
    pub hops: Vec<Hop>,
    pub layers: Vec<Layer>,
    pub name: Option<String>,
}

fn owner_of<'a>(hops: &'a [Hop], exe: &str) -> Option<&'a str> {
    hops.iter().rev().find_map(|h| h.module.as_deref().filter(|m| !m.eq_ignore_ascii_case(exe)))
}

/// How much attention a row deserves. Nothing is hidden at either level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Hooked by more than one module, or changed with no known owner.
    Look,
    /// One named owner (or several hops, one module).
    Info,
}

impl Severity {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Look => "[look]",
            Self::Info => "[info]",
        }
    }
}

/// Counts for the report header and the log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub changed: usize,
    /// Distinct modules named by any row (a module in a stack counts once).
    pub modules: usize,
    /// Functions hooked by more than one module.
    pub multi: usize,
    /// Changes with no known owner.
    pub unowned: usize,
    /// Rows tagged info.
    pub info: usize,
}

#[must_use]
pub fn summarize(report: &Report, exe: &str) -> Summary {
    let mut names: Vec<String> = Vec::new();
    let (mut multi, mut unowned) = (0, 0);
    for f in &report.findings {
        let stack = f.stack(exe);
        match stack.len() {
            0 => unowned += 1,
            1 => {}
            _ => multi += 1,
        }
        for n in stack {
            if !names.iter().any(|o| o.eq_ignore_ascii_case(&n)) {
                names.push(n);
            }
        }
    }
    let changed = report.findings.len();
    Summary { changed, modules: names.len(), multi, unowned, info: changed - multi - unowned }
}

/// The one line the plugin logs: counts with real numbers and where the report went.
#[must_use]
pub fn summary_line(report: &Report, exe: &str, report_path: &str) -> String {
    let s = summarize(report, exe);
    format!(
        "{} functions changed by {} modules; {} hooked by more than one; {} with no known owner; report: {report_path}",
        s.changed, s.modules, s.multi, s.unowned
    )
}

impl Finding {
    /// `Look` for a function hooked by several modules or changed with no known owner.
    #[must_use]
    pub fn severity(&self, exe: &str) -> Severity {
        if self.stack(exe).len() == 1 { Severity::Info } else { Severity::Look }
    }

    /// The module that owns the patch: the last hop inside a module other than the executable.
    #[must_use]
    pub fn owner(&self, exe: &str) -> Option<&str> {
        owner_of(&self.hops, exe)
    }

    /// Every module hooked on this function, top first, without repeats.
    #[must_use]
    pub fn stack(&self, exe: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let names = self.owner(exe).into_iter().chain(self.layers.iter().filter_map(|l| owner_of(&l.hops, exe)));
        for name in names {
            if !out.iter().any(|o| o.eq_ignore_ascii_case(name)) {
                out.push(name.to_owned());
            }
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub entries: usize,
    pub in_code: usize,
    pub differing: usize,
    pub findings: Vec<Finding>,
    /// Over a fifth of the entries differ: the file on disk is probably not what the game runs
    /// (packed or encrypted), so the list means nothing.
    pub baseline_suspect: bool,
    /// Executable memory searched for trampolines, in bytes, and the trampolines found.
    pub searched: u64,
    pub trampolines: usize,
}

/// Longest branch `decode_branch` reads (`call [rip+disp32]`).
const BRANCH_MAX: usize = 6;

/// Length of the instruction at the start of `code`, for the fixed set of encodings commonly
/// written in front of a tail jump: `mov r64, [rip+disp32]` / `lea r64, [rip+disp32]` (REX.W 8B/8D,
/// mod 00 rm 101), `mov r64, imm64`, `mov r32, imm32` (optional REX.B), `mov r64, r64`, `sub`/`add
/// r64, imm8` (REX.W 83 /5, /0, mod 11), `push`/`pop r64` (optional REX or REX.B), `mov r64, [reg+disp8]`
/// and `mov [reg+disp8], r64` (REX.W 89/8B, mod 01, with or without a SIB byte), `movss xmm,
/// [reg+disp8]` and the store form (`f3 0f 10/11`, mod 01, no SIB), and `nop`, `66 90`, `0f 1f 40
/// 00`, `0f 1f 44 00 00`. `None` for anything else, or an instruction cut off by `code`.
fn known_len(code: &[u8]) -> Option<usize> {
    let rex_w = |b: u8| (0x48..=0x4F).contains(&b);
    let len = match code {
        [r, 0x8B | 0x8D, m, ..] if rex_w(*r) && m & 0xC7 == 0x05 => 7,
        [r, 0x89 | 0x8B, m, ..] if rex_w(*r) && m & 0xC0 == 0xC0 => 3,
        // mod 01: [reg+disp8], or [base+index*scale+disp8] when rm is 100 (one SIB byte more)
        [r, 0x89 | 0x8B, m, ..] if rex_w(*r) && m & 0xC7 == 0x44 => 5,
        [r, 0x89 | 0x8B, m, ..] if rex_w(*r) && m & 0xC0 == 0x40 => 4,
        [0xF3, 0x0F, 0x10 | 0x11, m, ..] if m & 0xC0 == 0x40 && m & 7 != 4 => 5,
        [r, 0xB8..=0xBF, ..] if rex_w(*r) => 10,
        [0x41, 0xB8..=0xBF, ..] => 6,
        [0xB8..=0xBF, ..] => 5,
        [r, 0x83, m, ..] if rex_w(*r) && m & 0xC0 == 0xC0 && matches!((m >> 3) & 7, 0 | 5) => 4,
        [0x40 | 0x41, 0x50..=0x5F, ..] => 2,
        [0x50..=0x5F, ..] | [0x90, ..] => 1,
        [0x66, 0x90, ..] => 2,
        [0x0F, 0x1F, 0x40, 0x00, ..] => 4,
        [0x0F, 0x1F, 0x44, 0x00, 0x00, ..] => 5,
        _ => return None,
    };
    (len <= code.len()).then_some(len)
}

/// Offsets in `memory` that start an instruction, walking from +0 over `known_len` encodings. The
/// walk stops at the first byte it does not recognise; that offset is the last boundary.
fn live_boundaries(memory: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < memory.len() {
        out.push(at);
        match known_len(&memory[at..]) {
            Some(n) => at += n,
            None => break,
        }
    }
    out
}

/// How an `Inner` start relates to the instruction boundaries the walker knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// The walk from +0 over recognised encodings lands on the start (or stops exactly there).
    Validated,
    /// The walk stopped at an unrecognised byte before the start and could not say more.
    Unverified,
    /// The start lies inside a recognised instruction: not an instruction start.
    Inside,
}

/// Whether offset `start` begins an instruction, by the walker over `memory` and, past its stop
/// point, over `disk`.
fn boundary_of(start: usize, memory: &[u8], disk: &[u8]) -> Boundary {
    let live = live_boundaries(memory);
    if live.contains(&start) {
        return Boundary::Validated;
    }
    // The walk may have stopped before `start` (the byte it stopped at is not in the recogniser's
    // set); past that point nothing is known. Otherwise it stepped over `start`.
    let stopped_before = live.last().is_some_and(|&b| b < start && known_len(&memory[b..]).is_none());
    if !stopped_before {
        return Boundary::Inside;
    }
    // the same recogniser over the file bytes reaches `start` with every byte before it unchanged
    if start <= disk.len() && disk[..start] == memory[..start] && live_boundaries(disk).contains(&start) {
        Boundary::Validated
    } else {
        Boundary::Unverified
    }
}

/// A branch inside `memory` leading to a module other than the executable, and whether its start
/// is a validated instruction boundary. Two kinds of start are tried, earliest first: a start within
/// five bytes before the first difference from `disk`, or at it, whose branch overlaps that
/// difference (a retargeted or replaced branch); then a start after the first difference that is a
/// boundary reached by `live_boundaries` (the walk's stop point included) and whose own bytes
/// inside the window differ from disk. A start after the first difference that is not such a
/// boundary (inside the immediate or displacement of a rewritten instruction) is never tried.
/// A start from the first group must also be a boundary: one inside a recognised instruction is
/// skipped; one past the point where the walker stopped is accepted but returned as unverified
/// (`false`), unless the file bytes validate it (`boundary_of`). The upper bytes of the target are
/// read through `read`; the owner of the target is the acceptance condition.
fn inner_branch(
    memory: &[u8],
    disk: &[u8],
    at: u64,
    exe: &str,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Option<(usize, Vec<Hop>, bool)> {
    let read_u64 = |a: u64| read(a, 8).and_then(le_u64);
    let first = memory.iter().zip(disk).position(|(m, d)| m != d)?;
    // Starts that overlap the first difference come first. Then validated boundaries after it: a
    // branch written behind rewritten leading bytes (`mov r8, [rip+disp]; jmp [rip+0]` at +7).
    // Those count only when the branch's own bytes inside the window differ from disk, so a
    // decodable `ff 25` that is the game's own code, lying after the difference, is never taken.
    let later = live_boundaries(memory).into_iter().filter(|&s| s > first);
    for start in (first.saturating_sub(5)..=first).chain(later) {
        // a branch that starts inside the window can have its operand past the window's end
        // (a `call rel32` at +13 of 16): take the rest of it from memory, if it still agrees
        let tail;
        let code = if memory.len() - start < BRANCH_MAX {
            tail = read(at + start as u64, BRANCH_MAX).filter(|t| t.starts_with(&memory[start..]));
            tail.as_deref().unwrap_or(&memory[start..])
        } else {
            &memory[start..]
        };
        let Some((target, len)) = decode_branch(code, at + start as u64, &read_u64) else { continue };
        let mut verified = true;
        if start <= first {
            if first >= start + len {
                continue;
            }
            if start > 0 {
                match boundary_of(start, memory, disk) {
                    Boundary::Validated => {}
                    Boundary::Unverified => verified = false,
                    Boundary::Inside => continue,
                }
            }
        } else {
            let end = (start + len).min(memory.len()).min(disk.len());
            if end <= start || memory[start..end] == disk[start..end] {
                continue;
            }
        }
        let hops = follow(target, exe, read, module_of);
        if owner_of(&hops, exe).is_some() {
            return Some((start, hops, verified));
        }
    }
    None
}

/// Classifies one changed entry and follows its branch.
fn classify(
    memory: &[u8],
    disk: &[u8],
    at: u64,
    exe: &str,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> (Kind, Vec<Hop>) {
    let read_u64 = |a: u64| read(a, 8).and_then(le_u64);
    if let Some(target) = decode_jump(memory, at, &read_u64)
        && decode_jump(disk, at, &read_u64) != Some(target)
    {
        return (Kind::Jump, follow(target, exe, read, module_of));
    }
    if let Some(now) = stub(memory) {
        match stub(disk) {
            None => return (Kind::Stub(now), Vec::new()),
            Some(was) if was != now => return (Kind::Retval { was, now }, Vec::new()),
            // the same stub on disk: the change lies past its `ret`
            Some(_) => {}
        }
    }
    if memory.len() >= 8 && memory.iter().all(|&b| b == memory[0]) {
        return (Kind::Filled(memory[0]), Vec::new());
    }
    if let Some((offset, hops, verified)) = inner_branch(memory, disk, at, exe, read, module_of) {
        let kind = if verified { Kind::Inner { offset } } else { Kind::InnerUnverified { offset } };
        return (kind, hops);
    }
    let offset = memory.iter().zip(disk).position(|(m, d)| m != d).unwrap_or(0);
    (Kind::Bytes { offset }, Vec::new())
}

/// Scans `(id, offset)` pairs (offsets from `base`) against the executable file `pe`.
pub fn scan(
    pairs: impl Iterator<Item = (u64, u64)>,
    base: u64,
    pe: &[u8],
    exe: &str,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Report {
    let secs = sections(pe).unwrap_or_default();
    let mut report = Report::default();
    let by_offset: BTreeMap<u64, u64> = pairs.map(|(id, off)| (off, id)).collect();
    report.entries = by_offset.len();
    let mut next = by_offset.keys().skip(1);
    for (&offset, &id) in &by_offset {
        // Entries closer than ENTRY_LEN: the bytes past the next listed function belong to it, so
        // they only decide whether this entry changed (`room`). A changed entry is still decoded
        // and stored with the full window, because a hook written here (5 to 14 bytes) can cover
        // the next entry's start.
        let room = next.next().map_or(ENTRY_LEN, |&n| usize::try_from(n - offset).map_or(ENTRY_LEN, |d| d.min(ENTRY_LEN)));
        let Ok(rva) = u32::try_from(offset) else { continue };
        let Some(disk) = disk_code(pe, &secs, rva, ENTRY_LEN) else { continue };
        let Some(memory) = read(base + offset, disk.len()) else { continue };
        report.in_code += 1;
        let r = room.min(disk.len());
        if memory.len() >= r && memory[..r] == disk[..r] {
            continue;
        }
        report.differing += 1;
        let (kind, hops) = classify(&memory, disk, base + offset, exe, read, module_of);
        report.findings.push(Finding { id, rva: offset, kind, disk: disk.to_vec(), memory, hops, layers: Vec::new(), name: None });
    }
    report.baseline_suspect = report.in_code > 0 && report.differing * 5 > report.in_code;
    report
}

/// The whole analysis, as the plugin and the offline replay both run it: `scan`, then a trampoline
/// search over each `(start, len)` region of committed private executable memory. Names are applied
/// by the caller.
pub fn analyse(
    pairs: &[(u64, u64)],
    base: u64,
    pe: &[u8],
    exe: &str,
    regions: &[(u64, usize)],
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Report {
    analyse_until(pairs, base, pe, exe, regions, read, module_of, &|| false).0
}

/// [`analyse`] that asks `cancel` before the entry scan, after it, and before each region's
/// trampoline search. Once it answers true the rest is skipped and the flag returned is true; the
/// report is then partial and must be discarded.
#[allow(clippy::too_many_arguments)]
pub fn analyse_until(
    pairs: &[(u64, u64)],
    base: u64,
    pe: &[u8],
    exe: &str,
    regions: &[(u64, usize)],
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
    cancel: &dyn Fn() -> bool,
) -> (Report, bool) {
    let none: &[(u64, u64)] = &[];
    let mut report = scan(if cancel() { none } else { pairs }.iter().copied(), base, pe, exe, read, module_of);
    if cancel() {
        return (report, true);
    }
    let returns = Returns::new(&report, base);
    for &(start, len) in regions {
        if cancel() {
            return (report, true);
        }
        if let Some(bytes) = read(start, len) {
            returns.search(&mut report, start, &bytes, exe, read, module_of);
        }
    }
    (report, false)
}

/// Return addresses a trampoline of each hooked entry would jump back to: the entry plus the
/// number of bytes the hook moved out of it (5 to 16, within the stored disk bytes).
pub struct Returns {
    by_target: HashMap<u64, Vec<(usize, usize)>>,
}

impl Returns {
    #[must_use]
    pub fn new(report: &Report, base: u64) -> Self {
        let mut by_target: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
        for (i, f) in report.findings.iter().enumerate() {
            if f.kind == Kind::Jump {
                for k in 5..=f.disk.len().min(ENTRY_LEN) {
                    by_target.entry(base + f.rva + k as u64).or_default().push((i, k));
                }
            }
        }
        Self { by_target }
    }

    /// Searches executable memory at `region` for trampolines ending in a jump back into a hooked
    /// entry (`jmp rel32`, or `jmp [rip+0]` with the address after it), and records the hook their
    /// copied bytes lead to as a lower layer of that entry.
    pub fn search(
        &self,
        report: &mut Report,
        region: u64,
        bytes: &[u8],
        exe: &str,
        read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
        module_of: &dyn Fn(u64) -> Option<String>,
    ) {
        let read_u64 = |a: u64| read(a, 8).and_then(le_u64);
        report.searched += bytes.len() as u64;
        for i in 0..bytes.len() {
            // `end` is where the copied entry bytes end: at the jump back, or at the start of a
            // context-hook stub that resumes through RtlRestoreContext
            let (target, end) = match bytes[i] {
                0xE9 => (i32_at(bytes, i + 1).map(|r| (region + i as u64 + 5).wrapping_add_signed(i64::from(r))), i),
                0xFF if bytes.get(i + 1..i + 6) == Some(&[0x25, 0, 0, 0, 0]) => (u64_at(bytes, i + 6), i),
                0x48 => context_stub(bytes, i).map_or((None, i), |(resume, start)| (Some(resume), start)),
                _ => (None, i),
            };
            let Some(hits) = target.and_then(|t| self.by_target.get(&t)) else { continue };
            for &(index, k) in hits {
                if end < k {
                    continue;
                }
                let i = end;
                let copy = &bytes[i - k..i];
                let at = region + (i - k) as u64;
                let finding = &report.findings[index];
                let layer = if copy == &finding.disk[..k] {
                    Layer { trampoline: at, original: true, hops: Vec::new() }
                } else if let Some(t) = decode_jump(copy, at, &read_u64) {
                    Layer { trampoline: at, original: false, hops: follow(t, exe, read, module_of) }
                } else if let Some((start, hops)) = relocated_copy(bytes, region, i, exe, read, module_of) {
                    // the copied jump was rewritten to a longer form, so it starts earlier
                    Layer { trampoline: region + start as u64, original: false, hops }
                } else {
                    continue;
                };
                report.trampolines += 1;
                let finding = &mut report.findings[index];
                if !finding.layers.contains(&layer) {
                    finding.layers.push(layer);
                }
            }
        }
    }
}

/// Length of the `mov rdx, f; mov r8, a; mov r9, b; mov rax, g; call rax` tail of a context hook.
const CONTEXT_TAIL: usize = 42;

/// A CommonLibSSE-NG `install_context_hook` stub (`SKSE/ContextHook.h`) whose tail starts at
/// `bytes[i]`, as laid out with a positive include size: `[copied entry bytes | stub]`. The stub
/// ends in `mov rcx, rsp; sub rsp, 0x20; mov rdx, imm64; mov r8, imm64; mov r9, imm64; mov rax,
/// imm64; call rax` and never jumps back: it resumes through `RtlRestoreContext`, with the
/// resume address in `r8` (internal) and `r9` (public). Both equal entry + patch size when the
/// include size is positive. Returns that address and the offset where the stub starts (`push
/// rsp; push rax; push rcx; pushfq`, 40 to 80 bytes before the tail), which is where the copied
/// bytes end.
fn context_stub(bytes: &[u8], i: usize) -> Option<(u64, usize)> {
    let tail = bytes.get(i..i + CONTEXT_TAIL)?;
    let marks = [(0, [0x48, 0xBA]), (10, [0x49, 0xB8]), (20, [0x49, 0xB9]), (30, [0x48, 0xB8]), (40, [0xFF, 0xD0])];
    if marks.iter().any(|&(o, m)| tail[o..o + 2] != m) {
        return None;
    }
    // mov rcx, rsp; sub rsp, 0x20
    if i < 7 || bytes[i - 7..i] != [0x48, 0x89, 0xE1, 0x48, 0x83, 0xEC, 0x20] {
        return None;
    }
    let internal = u64_at(tail, 12)?;
    let public = u64_at(tail, 22)?;
    if internal != public {
        return None;
    }
    let start = (i.saturating_sub(80)..=i.saturating_sub(40)).rev().find(|&s| bytes.get(s..s + 4) == Some(&[0x54, 0x50, 0x51, 0x9C]))?;
    Some((public, start))
}

/// A jump that ends before `end` in `bytes` (at `region`) and leads into a module other than the
/// executable: a copied entry jump the hook rewrote to a longer form (`jmp [rip+0]` with its
/// address, or `mov rax, imm64; jmp rax`).
fn relocated_copy(
    bytes: &[u8],
    region: u64,
    end: usize,
    exe: &str,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
    module_of: &dyn Fn(u64) -> Option<String>,
) -> Option<(usize, Vec<Hop>)> {
    let read_u64 = |a: u64| read(a, 8).and_then(le_u64);
    for start in (end.saturating_sub(24)..end.saturating_sub(4)).rev() {
        let Some(t) = decode_jump(&bytes[start..end], region + start as u64, &read_u64) else { continue };
        let hops = follow(t, exe, read, module_of);
        if owner_of(&hops, exe).is_some() {
            return Some((start, hops));
        }
    }
    None
}

/// The branch opcode bytes at `offset` in `code`: `e8`, `e9`, `ff 15` or `ff 25`.
fn branch_opcode(code: &[u8], offset: usize) -> Option<&[u8]> {
    let rest = code.get(offset..)?;
    match rest {
        [0xE8 | 0xE9, ..] => Some(&rest[..1]),
        [0xFF, 0x15 | 0x25, ..] => Some(&rest[..2]),
        _ => None,
    }
}

/// True when `disk[..offset] == memory[..offset]` (an offset past either length is false) and the
/// same branch opcode bytes sit at `offset` on both sides.
fn same_branch_site(disk: &[u8], memory: &[u8], offset: usize) -> bool {
    match (disk.get(..offset), memory.get(..offset)) {
        (Some(d), Some(m)) if d == m => matches!((branch_opcode(disk, offset), branch_opcode(memory, offset)), (Some(a), Some(b)) if a == b),
        _ => false,
    }
}

fn describe(kind: &Kind, disk: &[u8], memory: &[u8]) -> String {
    match kind {
        Kind::Jump => "jump at entry".to_owned(),
        // `Inner` means +N is an instruction start the walker reached from +0 through recognised
        // encodings. "retargeted" then needs every byte before +N unchanged and the same branch
        // opcode at +N on both sides: the recognised instructions before +N are identical, so an
        // instruction starts at +N in the game's bytes as well, and it begins with that opcode
        // (its operand may differ). It does not prove the game's instruction there is a whole
        // branch of that length. Otherwise the branch was written.
        Kind::Inner { offset } if same_branch_site(disk, memory, *offset) => {
            format!("branch at +{offset} retargeted")
        }
        Kind::Inner { offset } => format!("branch written at +{offset}"),
        Kind::InnerUnverified { offset } => format!("branch at +{offset} (boundary unverified)"),
        Kind::Stub(what) => format!("disabled: {what}"),
        Kind::Retval { was, now } => format!("{was} -> {now}"),
        Kind::Filled(b) => format!("filled with {b:#04x}"),
        Kind::Bytes { offset } => format!("bytes changed at +{offset}"),
    }
}

/// The report as text: functions with several hooks, a per-owner summary, then every finding.
#[must_use]
pub fn format(report: &Report, exe: &str) -> String {
    use std::fmt::Write as _;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
    let label = |f: &Finding| f.name.clone().unwrap_or_else(|| "-".to_owned());
    let mut out = String::new();
    let _ = writeln!(
        out,
        "functions checked {}, changed {}, trampolines found {} in {} KiB of executable memory",
        report.in_code,
        report.differing,
        report.trampolines,
        report.searched >> 10
    );
    let s = summarize(report, exe);
    let _ = writeln!(
        out,
        "Changed functions are normal: SKSE plugins work by patching the game. Worth a look: functions hooked by more than one module ({}) and changes with no known owner ({}).",
        s.multi, s.unowned
    );
    let _ = writeln!(
        out,
        "Rows are tagged: look {} (hooked by more than one module {}, no known owner {}), info {} (one named owner). Nothing is filtered out.",
        s.multi + s.unowned,
        s.multi,
        s.unowned,
        s.info
    );
    if report.baseline_suspect {
        let _ = writeln!(out, "WARNING: more than a fifth of functions differ from the file on disk; the executable is probably packed, so this list is unreliable.");
    }

    let stacked: Vec<&Finding> = report.findings.iter().filter(|f| f.stack(exe).len() > 1).collect();
    let _ = writeln!(out, "\nfunctions hooked by more than one module ({})", stacked.len());
    for f in &stacked {
        let _ = writeln!(out, "  {:<48} {}", label(f), f.stack(exe).join(" > "));
    }

    let mut owners: BTreeMap<String, usize> = BTreeMap::new();
    for f in &report.findings {
        let stack = f.stack(exe);
        if stack.is_empty() {
            let key = match &f.kind {
                Kind::Stub(_) => "(disabled, owner unknown)",
                Kind::Retval { .. } => "(return value changed, owner unknown)",
                Kind::Filled(_) => "(filled region, owner unknown)",
                Kind::Bytes { .. } => "(changed bytes, owner unknown)",
                Kind::Jump | Kind::Inner { .. } | Kind::InnerUnverified { .. } => "(branch into unowned memory)",
            };
            *owners.entry(key.to_owned()).or_default() += 1;
        }
        for name in stack {
            *owners.entry(name).or_default() += 1;
        }
    }
    let mut owners: Vec<_> = owners.into_iter().collect();
    owners.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let _ = writeln!(out, "\nfunctions per module");
    for (name, n) in &owners {
        let _ = writeln!(out, "{n:6}  {name}");
    }

    let _ = writeln!(out, "\nevery change: look|info / function / id / offset / what / modules (top first) / chain / bytes on disk -> in memory");
    for f in &report.findings {
        let stack = f.stack(exe);
        let chain = f
            .hops
            .iter()
            .map(|h| format!("{}{:#x}@{}", if h.via_thunk { "~" } else { "" }, h.address, h.module.as_deref().unwrap_or("?")))
            .collect::<Vec<_>>()
            .join(" > ");
        let bottom = if f.layers.iter().any(|l| l.original) { " > game" } else { "" };
        // a difference past the 8 shown bytes: show the bytes where it is (from the branch start
        // for a retargeted branch), and say where
        let first = f.memory.iter().zip(&f.disk).position(|(m, d)| m != d).unwrap_or(0);
        let at = if first < 8 {
            0
        } else {
            match f.kind {
                Kind::Inner { offset } | Kind::InnerUnverified { offset } => offset.min(first),
                _ => first,
            }
        };
        let tag = if at > 0 { format!("@+{at}: ") } else { String::new() };
        let window = |b: &[u8]| hex(b.get(at..).map_or(&[][..], |t| &t[..t.len().min(8)]));
        let _ = writeln!(
            out,
            "{:<6} {:<48} {:>7} +{:#09x}  {:<28} {}{}  {}  [{tag}{} -> {}]",
            f.severity(exe).tag(),
            label(f),
            f.id,
            f.rva,
            describe(&f.kind, &f.disk, &f.memory),
            if stack.is_empty() { "?".to_owned() } else { stack.join(" > ") },
            bottom,
            chain,
            window(&f.disk),
            window(&f.memory)
        );
        // no owner found: show the whole window, so the rewrite can be read from the report
        if stack.is_empty() {
            let _ = writeln!(out, "    full window: {} -> {}", hex(&f.disk), hex(&f.memory));
        }
    }
    out
}

#[cfg(test)]
mod tests;
