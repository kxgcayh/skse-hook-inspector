use super::*;
use std::collections::HashMap;

const BASE: u64 = 0x1_4000_0000;
const TEXT_RVA: u32 = 0x1000;
const TEXT_RAW: u32 = 0x400;
const TEXT_LEN: u32 = 0x1000;

/// A minimal PE32+ with one executable section `.text` (rva 0x1000, raw 0x400, 0x1000 bytes) and
/// one data section.
fn fake_pe(text: &[u8]) -> Vec<u8> {
    let mut pe = vec![0u8; (TEXT_RAW + TEXT_LEN) as usize];
    pe[0..2].copy_from_slice(b"MZ");
    let nt = 0x80usize;
    pe[0x3c..0x40].copy_from_slice(&(nt as u32).to_le_bytes());
    pe[nt..nt + 4].copy_from_slice(b"PE\0\0");
    pe[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[nt + 6..nt + 8].copy_from_slice(&2u16.to_le_bytes());
    pe[nt + 20..nt + 22].copy_from_slice(&0xF0u16.to_le_bytes());
    let table = nt + 24 + 0xF0;
    let mut sec = |i: usize, rva: u32, raw: u32, size: u32, chars: u32| {
        let s = table + i * 40;
        pe[s + 8..s + 12].copy_from_slice(&size.to_le_bytes());
        pe[s + 12..s + 16].copy_from_slice(&rva.to_le_bytes());
        pe[s + 16..s + 20].copy_from_slice(&size.to_le_bytes());
        pe[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
        pe[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
    };
    sec(0, TEXT_RVA, TEXT_RAW, TEXT_LEN, 0x6000_0020);
    sec(1, 0x3000, 0, 0x100, 0xC000_0040);
    pe[TEXT_RAW as usize..TEXT_RAW as usize + text.len()].copy_from_slice(text);
    pe
}

/// Memory: regions by start address, and modules by address range.
struct Mem {
    regions: HashMap<u64, Vec<u8>>,
    modules: Vec<(u64, u64, &'static str)>,
}

impl Mem {
    fn read(&self, a: u64, n: usize) -> Option<Vec<u8>> {
        self.regions.iter().find_map(|(&start, bytes)| {
            let off = a.checked_sub(start)? as usize;
            (off < bytes.len()).then(|| bytes[off..(off + n).min(bytes.len())].to_vec())
        })
    }
    fn module(&self, a: u64) -> Option<String> {
        self.modules.iter().find(|m| a >= m.0 && a < m.1).map(|m| m.2.to_owned())
    }
}

fn rel32(from: u64, to: u64) -> [u8; 4] {
    (i32::try_from(to as i64 - (from as i64 + 5)).unwrap()).to_le_bytes()
}

#[test]
fn parses_sections() {
    let secs = sections(&fake_pe(&[0x90; 32])).unwrap();
    assert_eq!(secs.len(), 2);
    assert!(secs[0].exec && !secs[1].exec);
    assert_eq!(secs[0].rva, TEXT_RVA);
    assert!(sections(b"not a pe").is_none());
}

#[test]
fn disk_code_only_in_executable_sections() {
    let pe = fake_pe(&[0xAA; 32]);
    let secs = sections(&pe).unwrap();
    assert_eq!(disk_code(&pe, &secs, TEXT_RVA, 4), Some(&[0xAA; 4][..]));
    assert_eq!(disk_code(&pe, &secs, 0x3000, 4), None);
    // clipped at the section end
    assert_eq!(disk_code(&pe, &secs, TEXT_RVA + TEXT_LEN - 2, 16).map(<[u8]>::len), Some(2));
}

#[test]
fn decodes_each_jump_form() {
    let none = |_| None;
    let at = 0x1000;
    let mut e9 = vec![0xE9];
    e9.extend_from_slice(&rel32(at, 0x5000));
    assert_eq!(decode_jump(&e9, at, &none), Some(0x5000));
    assert_eq!(decode_jump(&[0xEB, 0xFE], at, &none), Some(at)); // jmp $
    let ind = [0xFF, 0x25, 0, 0, 0, 0];
    assert_eq!(decode_jump(&ind, at, &|a| (a == at + 6).then_some(0xDEAD_BEEF)), Some(0xDEAD_BEEF));
    let mut rax = vec![0x48, 0xB8];
    rax.extend_from_slice(&0x6FFF_D5B6_12E5u64.to_le_bytes());
    rax.extend_from_slice(&[0xFF, 0xE0]);
    assert_eq!(decode_jump(&rax, at, &none), Some(0x6FFF_D5B6_12E5));
    let mut r11 = vec![0x49, 0xBB];
    r11.extend_from_slice(&0x1234u64.to_le_bytes());
    r11.extend_from_slice(&[0x41, 0xFF, 0xE3]);
    assert_eq!(decode_jump(&r11, at, &none), Some(0x1234));
    // a prologue is not a jump
    assert_eq!(decode_jump(&[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20], at, &none), None);
    // mov rax, imm64 without the jmp rax is not a jump
    assert_eq!(decode_jump(&rax[..10], at, &none), None);
}

#[test]
fn scan_reports_owner_through_a_trampoline() {
    let original = [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
    let mut text = Vec::new();
    for _ in 0..4 {
        text.extend_from_slice(&original);
    }
    let pe = fake_pe(&text);

    let tramp: u64 = BASE + 0x10_0000; // anonymous page, within rel32 reach
    let dll: u64 = 0x7FF0_0000_0000;
    let mut live = text.clone();
    // fn 0: jmp rel32 -> trampoline, which jmp [rip] -> dll
    let f0 = BASE + u64::from(TEXT_RVA);
    live[0] = 0xE9;
    live[1..5].copy_from_slice(&rel32(f0, tramp));
    // fn 1: mov rax, dll+0x40; jmp rax
    live[16..18].copy_from_slice(&[0x48, 0xB8]);
    live[18..26].copy_from_slice(&(dll + 0x40).to_le_bytes());
    live[26..28].copy_from_slice(&[0xFF, 0xE0]);
    // fn 2: bytes changed, not a jump
    live[32] = 0xCC;
    // fn 3: untouched
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(dll + 0x10).to_le_bytes());

    let mem = Mem {
        regions: HashMap::from([(BASE + u64::from(TEXT_RVA), live), (tramp, t), (dll, vec![0xC3; 0x100])]),
        modules: vec![(BASE, BASE + 0x10000, "SkyrimSE.exe"), (dll, dll + 0x100, "SomePlugin.dll")],
    };
    let r = |a, n| mem.read(a, n);
    let m = |a| mem.module(a);
    let base_off = u64::from(TEXT_RVA);
    // id 5 duplicates fn 0's offset; a data-section id is skipped
    let pairs = vec![(1, base_off), (5, base_off), (2, base_off + 16), (3, base_off + 32), (4, base_off + 48), (9, 0x3000)];
    let report = scan(pairs.into_iter(), BASE, &pe, "SkyrimSE.exe", &r, &m);

    assert_eq!(report.entries, 5);
    assert_eq!(report.in_code, 4);
    assert_eq!(report.differing, 3);
    assert!(report.baseline_suspect, "3 of 4 differ");
    let f0 = &report.findings[0];
    assert_eq!(f0.kind, Kind::Jump);
    assert_eq!(f0.hops.len(), 2);
    assert_eq!(f0.hops[0].module, None);
    assert_eq!(f0.owner("SkyrimSE.exe"), Some("SomePlugin.dll"));
    assert_eq!(report.findings[1].owner("skyrimse.exe"), Some("SomePlugin.dll"));
    assert!(matches!(report.findings[2].kind, Kind::Bytes { .. }));
    assert_eq!(report.findings[2].owner("SkyrimSE.exe"), None);
    let text = format(&report, "SkyrimSE.exe");
    assert!(text.contains("2  SomePlugin.dll"), "{text}");
    assert!(text.contains("WARNING"));
}

#[test]
fn follow_stops_on_a_loop() {
    let at: u64 = 0x5000;
    let mem = Mem { regions: HashMap::from([(at, vec![0xEB, 0xFE])]), modules: vec![] };
    let hops = follow(at, "SkyrimSE.exe", &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(hops.len(), 1, "a jump to itself is not followed again");
}

const EXE: &str = "SkyrimSE.exe";
const DLL: u64 = 0x7FF0_0000_0000;
const DLL2: u64 = 0x7FF1_0000_0000;

fn mem_with(regions: Vec<(u64, Vec<u8>)>) -> Mem {
    Mem {
        regions: regions.into_iter().collect(),
        modules: vec![(BASE, BASE + 0x10000, "SkyrimSE.exe"), (DLL, DLL + 0x1000, "Top.dll"), (DLL2, DLL2 + 0x1000, "Bottom.dll")],
    }
}

#[test]
fn stubs_are_named() {
    assert_eq!(stub(&[0xC3, 0xCC]).as_deref(), Some("returns at once"));
    assert_eq!(stub(&[0x48, 0x31, 0xC0, 0xC3]).as_deref(), Some("returns 0"));
    assert_eq!(stub(&[0x32, 0xC0, 0xC3]).as_deref(), Some("returns false"));
    assert_eq!(stub(&[0xB0, 0x01, 0xC3]).as_deref(), Some("returns 0x1"));
    assert_eq!(stub(&[0xB8, 0, 0, 0, 8, 0xC3]).as_deref(), Some("returns 0x8000000"));
    assert_eq!(stub(&[0x40, 0x53, 0xC3]), None);
}

fn classify_one(disk: &[u8], memory: &[u8], mem: &Mem) -> (Kind, Vec<Hop>) {
    let at = BASE + u64::from(TEXT_RVA);
    classify(memory, disk, at, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a))
}

#[test]
fn classifies_changes() {
    let mem = mem_with(vec![(DLL, vec![0xC3; 0x100])]);
    let disk = [0x48, 0x83, 0xEC, 0x28, 0xC6, 0x44, 0x24, 0x38, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
    let mut m = disk;
    m[..4].copy_from_slice(&[0x48, 0x31, 0xC0, 0xC3]);
    assert_eq!(classify_one(&disk, &m, &mem).0, Kind::Stub("returns 0".into()));
    assert_eq!(classify_one(&disk, &[0x10; 16], &mem).0, Kind::Filled(0x10));
    let mut m = disk;
    m[5] = 0x00;
    assert_eq!(classify_one(&disk, &m, &mem).0, Kind::Bytes { offset: 5 });
    // a constant changed in a stub: the return value, with what it was
    let (k, _) = classify_one(&[0xB8, 0, 0, 0, 4, 0xC3], &[0xB8, 0, 0, 0, 8, 0xC3], &mem);
    assert_eq!(k, Kind::Retval { was: "returns 0x4000000".into(), now: "returns 0x8000000".into() });
    // the same stub on disk and in memory: the change is past its ret, not a disabled function
    let disk = [0x33, 0xC0, 0xC3, 0xCC, 0xCC, 0x40, 0x53, 0x48];
    let mut m = disk;
    m[5] = 0xE9;
    assert_eq!(classify_one(&disk, &m, &mem).0, Kind::Bytes { offset: 5 });
}

#[test]
fn inner_branch_is_followed() {
    let at = BASE + u64::from(TEXT_RVA);
    // movss [rcx+4c], xmm1 ; jmp somewhere  -> the jmp is retargeted to Top.dll
    let mut disk = vec![0xF3, 0x0F, 0x11, 0x49, 0x4C, 0xE9];
    disk.extend_from_slice(&rel32(at + 5, BASE + 0x2000));
    disk.extend_from_slice(&[0xCC; 5]);
    let mut memory = disk.clone();
    // a rel32 cannot reach DLL in the test, so the hop goes through an anonymous trampoline
    let tramp = BASE + 0x10_0000;
    memory[6..10].copy_from_slice(&rel32(at + 5, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x20).to_le_bytes());
    let mem = mem_with(vec![(tramp, t), (DLL, vec![0xC3; 0x100])]);
    let (kind, hops) = classify_one(&disk, &memory, &mem);
    assert_eq!(kind, Kind::Inner { offset: 5 });
    assert_eq!(owner_of(&hops, EXE), Some("Top.dll"));
}

#[test]
fn generated_thunk_is_searched() {
    // anonymous code that saves registers, loads the hook's address and calls it
    let thunk_at = BASE + 0x20_0000;
    let mut thunk = vec![0x50, 0x51, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8];
    thunk.extend_from_slice(&(DLL + 0x40).to_le_bytes());
    thunk.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0x59, 0x58, 0xC3]);
    let mem = mem_with(vec![(thunk_at, thunk), (DLL, vec![0xC3; 0x100])]);
    let hops = follow(thunk_at, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(hops.len(), 2);
    assert!(hops[1].via_thunk);
    assert_eq!(hops[1].module.as_deref(), Some("Top.dll"));
}

#[test]
fn stacked_hooks_are_found_from_trampolines() {
    let prologue = [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x45, 0x8B, 0xC8, 0x48, 0x63, 0xDA, 0x41, 0x83, 0xE9, 0x18];
    let pe = fake_pe(&prologue);
    let entry = BASE + u64::from(TEXT_RVA);
    // Top.dll jumped in last: entry -> anon jump -> Top.dll
    let top_tramp = BASE + 0x10_0000;
    let mut live = prologue.to_vec();
    live[0] = 0xE9;
    live[1..5].copy_from_slice(&rel32(entry, top_tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x10).to_le_bytes());

    // Bottom.dll hooked first: its own jump stub
    let bottom_tramp = BASE + 0x11_0000;
    let mut b = vec![0xFF, 0x25, 0, 0, 0, 0];
    b.extend_from_slice(&(DLL2 + 0x10).to_le_bytes());

    // A private region holding three trampolines:
    //  1. Top's call-original: the 5 bytes it copied (Bottom's jump, re-encoded here) + jmp back to entry+5
    //  2. Bottom's call-original: the game's 6 bytes + jmp [rip+0] entry+6
    //  3. the same Bottom jump copied as a 14-byte absolute jump (relocated form) + jmp back to entry+5
    let region = BASE + 0x30_0000;
    let mut r = vec![0x90; 8];
    let t1 = region + r.len() as u64;
    r.push(0xE9);
    r.extend_from_slice(&rel32(t1, bottom_tramp));
    let back1 = region + r.len() as u64;
    r.push(0xE9);
    r.extend_from_slice(&rel32(back1, entry + 5));
    r.extend_from_slice(&[0xCC; 4]);
    r.extend_from_slice(&prologue[..6]);
    r.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    r.extend_from_slice(&(entry + 6).to_le_bytes());
    r.extend_from_slice(&[0xCC; 4]);
    r.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    r.extend_from_slice(&(DLL2 + 0x30).to_le_bytes());
    let back3 = region + r.len() as u64;
    r.push(0xE9);
    r.extend_from_slice(&rel32(back3, entry + 5));

    let mem = mem_with(vec![(entry, live), (top_tramp, t), (bottom_tramp, b), (region, r.clone()), (DLL, vec![0xC3; 0x100]), (DLL2, vec![0xC3; 0x100])]);
    let read = |a, n| mem.read(a, n);
    let module = |a| mem.module(a);
    let mut report = scan(vec![(7, u64::from(TEXT_RVA))].into_iter(), BASE, &pe, EXE, &read, &module);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].owner(EXE), Some("Top.dll"));

    let returns = Returns::new(&report, BASE);
    returns.search(&mut report, region, &r, EXE, &read, &module);
    let f = &report.findings[0];
    assert_eq!(f.stack(EXE), vec!["Top.dll".to_owned(), "Bottom.dll".to_owned()]);
    assert!(f.layers.iter().any(|l| l.original), "the game's own bytes were found");
    assert!(report.trampolines >= 3, "{}", report.trampolines);
    let text = format(&report, EXE);
    assert!(text.contains("functions hooked by more than one module (1)"), "{text}");
    assert!(text.contains("Top.dll > Bottom.dll > game"), "{text}");
}

#[test]
fn thunk_search_skips_system_modules() {
    // a CommonLib context hook: loads RtlCaptureContext (ntdll), calls it, then loads the detour
    const NTDLL: u64 = 0x7FFF_0000_0000;
    let thunk_at = BASE + 0x20_0000;
    let mut thunk = vec![0x54, 0x50, 0x51, 0x9C, 0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00, 0x48, 0x89, 0xE1, 0x48, 0xB8];
    thunk.extend_from_slice(&(NTDLL + 0x9E4).to_le_bytes());
    thunk.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x89, 0xE1, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xBA]);
    thunk.extend_from_slice(&(DLL + 0x40).to_le_bytes());
    let mut mem = mem_with(vec![(thunk_at, thunk), (DLL, vec![0xC3; 0x100]), (NTDLL, vec![0xC3; 0x1000])]);
    mem.modules.push((NTDLL, NTDLL + 0x1000, "ntdll.dll"));
    let hops = follow(thunk_at, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(hops.last().and_then(|h| h.module.as_deref()), Some("Top.dll"));
}

#[test]
fn window_stops_at_the_next_listed_function() {
    // ids 27194 / 27195 of the game: entries 0x0f apart. The first is a 3-byte stub (`xor eax,eax;
    // ret`) plus padding, a jump is written at the second; the second's first byte lies at index 15
    // of the first entry's 16-byte window, so a full-window compare also blamed the first entry.
    let mut text = vec![0x90u8; 0x40];
    text[..3].copy_from_slice(&[0x33, 0xC0, 0xC3]);
    text[0x0f..0x1e].copy_from_slice(&[0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90]);
    let pe = fake_pe(&text);
    let dll: u64 = 0x7FF0_0000_0000;
    let mut live = text.clone();
    let second = BASE + u64::from(TEXT_RVA) + 0x0f;
    live[0x0f] = 0xE9;
    let tramp: u64 = BASE + 0x10_0000;
    live[0x10..0x14].copy_from_slice(&rel32(second, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(dll + 0x10).to_le_bytes());
    let mem = Mem {
        regions: HashMap::from([(BASE + u64::from(TEXT_RVA), live), (tramp, t), (dll, vec![0xC3; 0x100])]),
        modules: vec![(BASE, BASE + 0x10000, EXE), (dll, dll + 0x100, "Hook.dll")],
    };
    let off = u64::from(TEXT_RVA);
    let pairs = vec![(1, off), (2, off + 0x0f), (3, off + 0x30)];
    let report = scan(pairs.into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert_eq!(report.findings[0].id, 2);
    assert_eq!(report.findings[0].kind, Kind::Jump);
    assert_eq!(report.findings[0].owner(EXE), Some("Hook.dll"));
}

#[test]
fn hook_over_the_next_entry_keeps_its_attribution() {
    // entries A and A+3; the game's A is `xor eax,eax; ret; <padding>`, and a 5-byte jump is written
    // at A, over A+3 and A+4. A is still a jump with its owner followed (not `bytes changed`).
    // A+3 changed too, since the hook overwrote its first two bytes: it is reported on its own as
    // changed bytes at +0, because its own bytes did change.
    let mut text = vec![0x90u8; 0x40];
    text[..3].copy_from_slice(&[0x33, 0xC0, 0xC3]);
    let pe = fake_pe(&text);
    let dll: u64 = 0x7FF0_0000_0000;
    let entry = BASE + u64::from(TEXT_RVA);
    let mut live = text.clone();
    live[0] = 0xE9;
    let tramp: u64 = BASE + 0x10_0000;
    live[1..5].copy_from_slice(&rel32(entry, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(dll + 0x10).to_le_bytes());
    let mem = Mem {
        regions: HashMap::from([(entry, live), (tramp, t), (dll, vec![0xC3; 0x100])]),
        modules: vec![(BASE, BASE + 0x10000, EXE), (dll, dll + 0x100, "Hook.dll")],
    };
    let off = u64::from(TEXT_RVA);
    let report = scan([(1, off), (2, off + 3)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
    let a = &report.findings[0];
    assert_eq!(a.id, 1);
    assert_eq!(a.kind, Kind::Jump);
    assert_eq!(a.owner(EXE), Some("Hook.dll"));
    assert_eq!(a.disk.len(), ENTRY_LEN, "the full window is kept");
    let b = &report.findings[1];
    assert_eq!(b.id, 2);
    assert_eq!(b.kind, Kind::Bytes { offset: 0 });
}

#[test]
fn stolen_bytes_past_the_window_still_find_the_lower_layer() {
    // entries A and A+8; Top.dll writes `jmp [rip+0]; <addr>` (14 bytes) at A, over A+8. Bottom.dll's
    // jump (the same 14 bytes, to Bottom.dll) was copied into a trampoline that returns to A+14,
    // beyond the 8-byte window. The lower layer must still be found.
    let prologue: Vec<u8> = (0x40u8..0x50).collect();
    let mut text = vec![0x90u8; 0x40];
    text[..16].copy_from_slice(&prologue);
    let pe = fake_pe(&text);
    let entry = BASE + u64::from(TEXT_RVA);
    let mut live = text.clone();
    live[..6].copy_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    live[6..14].copy_from_slice(&(DLL + 0x10).to_le_bytes());
    let mut r = vec![0xFF, 0x25, 0, 0, 0, 0];
    r.extend_from_slice(&(DLL2 + 0x30).to_le_bytes());
    r.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    r.extend_from_slice(&(entry + 14).to_le_bytes());
    let region = BASE + 0x30_0000;
    let mem = mem_with(vec![(entry, live), (region, r.clone()), (DLL, vec![0xC3; 0x100]), (DLL2, vec![0xC3; 0x100])]);
    let read = |a, n| mem.read(a, n);
    let module = |a| mem.module(a);
    let off = u64::from(TEXT_RVA);
    let mut report = scan([(1, off), (2, off + 8)].into_iter(), BASE, &pe, EXE, &read, &module);
    assert_eq!(report.findings[0].kind, Kind::Jump);
    assert_eq!(report.findings[0].owner(EXE), Some("Top.dll"));
    Returns::new(&report, BASE).search(&mut report, region, &r, EXE, &read, &module);
    assert_eq!(report.findings[0].stack(EXE), vec!["Top.dll".to_owned(), "Bottom.dll".to_owned()]);
}

#[test]
fn bytes_changed_far_in_shows_those_bytes() {
    let disk: Vec<u8> = (0u8..16).collect();
    let mut memory = disk.clone();
    memory[14] = 0xAA;
    memory[15] = 0xBB;
    let finding = Finding {
        id: 7,
        rva: 0x1000,
        kind: Kind::Bytes { offset: 14 },
        disk,
        memory,
        hops: Vec::new(),
        layers: Vec::new(),
        name: None,
    };
    let mut report = Report { in_code: 1, differing: 1, findings: vec![finding], ..Report::default() };
    let text = format(&report, EXE);
    assert!(text.contains("[@+14: 0e 0f -> aa bb]"), "{text}");
    // a change inside the first 8 bytes keeps the plain layout
    report.findings[0].kind = Kind::Bytes { offset: 3 };
    report.findings[0].memory[3] = 0xCC;
    report.findings[0].memory[14] = 0x0E;
    report.findings[0].memory[15] = 0x0F;
    assert!(format(&report, EXE).contains("[00 01 02 03 04 05 06 07 -> 00 01 02 cc 04 05 06 07]"));
}

#[test]
fn late_differences_show_their_bytes_for_every_kind() {
    let disk: Vec<u8> = (0u8..16).collect();
    let mut memory = disk.clone();
    memory[14] = 0xAA;
    memory[15] = 0xBB;
    let mk = |kind| Finding { id: 7, rva: 0x1000, kind, disk: disk.clone(), memory: memory.clone(), hops: Vec::new(), layers: Vec::new(), name: None };
    let show = |f: Finding| format(&Report { in_code: 1, differing: 1, findings: vec![f], ..Report::default() }, EXE);
    // a retargeted branch at +13: the bytes from the branch start, where the difference is
    let text = show(mk(Kind::Inner { offset: 13 }));
    assert!(text.contains("[@+13: 0d 0e 0f -> 0d aa bb]"), "{text}");
    // any other kind whose first difference is at +8 or later
    let text = show(mk(Kind::Jump));
    assert!(text.contains("[@+14: 0e 0f -> aa bb]"), "{text}");
    // a branch that starts early but whose difference is late keeps the difference in view
    let text = show(mk(Kind::Inner { offset: 11 }));
    assert!(text.contains("[@+11: 0b 0c 0d 0e 0f -> 0b 0c 0d aa bb]"), "{text}");
}

#[test]
fn findings_without_an_owner_show_the_full_window() {
    let disk: Vec<u8> = (0u8..16).collect();
    let mut memory = disk.clone();
    memory[0] = 0x4C;
    memory[15] = 0xFF;
    let finding = Finding { id: 9, rva: 0x1000, kind: Kind::Bytes { offset: 0 }, disk, memory, hops: Vec::new(), layers: Vec::new(), name: None };
    let report = Report { in_code: 1, differing: 1, findings: vec![finding], ..Report::default() };
    let text = format(&report, EXE);
    assert!(text.contains("\n    full window: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f -> 4c 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e ff\n"), "{text}");
    // an owned finding gets no second line
    let mut owned = report;
    owned.findings[0].hops = vec![Hop { address: DLL, module: Some("Top.dll".to_owned()), via_thunk: false }];
    assert!(!format(&owned, EXE).contains("full window"));
}

#[test]
fn windows_shorter_than_a_jump_do_not_panic() {
    let mem = mem_with(vec![(DLL, vec![0xC3; 0x100])]);
    for len in 0..=5usize {
        for first in [0xE9u8, 0xEB, 0xFF, 0x48, 0xC3, 0xB8, 0x00] {
            let disk = vec![0x90u8; len];
            let mut m = disk.clone();
            if let Some(b) = m.first_mut() {
                *b = first;
            }
            let _ = classify_one(&disk, &m, &mem);
        }
    }
    // through scan: entries 3 and 1 bytes apart, a change in the first one
    let mut text = vec![0x90u8; 0x20];
    let pe = fake_pe(&text);
    text[0] = 0xE9;
    let mem = Mem { regions: HashMap::from([(BASE + u64::from(TEXT_RVA), text)]), modules: vec![(BASE, BASE + 0x10000, EXE)] };
    let off = u64::from(TEXT_RVA);
    let report = scan([(1, off), (2, off + 3), (3, off + 4)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1);
    // the change is decided on the 3-byte room, the jump decoded from the full window
    assert_eq!(report.findings[0].kind, Kind::Jump);
    let _ = Returns::new(&report, BASE);
}

/// The bytes `SKSE::stl::install_context_hook` emits for its stub (`ContextHook.h`, `buildStub`),
/// encoded by hand from Xbyak's rules: save rsp/rax/rcx/flags, the alignment sentinel, CONTEXT
/// allocation, `RtlCaptureContext`, then `mov rcx, rsp; sub rsp, 0x20; mov rdx, func; mov r8,
/// internal; mov r9, public; mov rax, execute; call rax`.
fn context_stub_bytes(func: u64, internal: u64, public: u64) -> Vec<u8> {
    let mut s = vec![0x54, 0x50, 0x51, 0x9C]; // push rsp; push rax; push rcx; pushfq
    s.extend_from_slice(&[0x48, 0x31, 0xC0, 0x50]); // xor rax, rax; push rax
    s.extend_from_slice(&[0x48, 0x89, 0xE0, 0x48, 0x83, 0xE0, 0xF0, 0x48, 0x39, 0xE0]); // mov rax, rsp; and rax, -16; cmp rax, rsp
    // Xbyak encodes `mov rax, 1` as the 5-byte `mov eax, imm32` (zero-extending): je +6; mov eax, 1; push rax
    s.extend_from_slice(&[0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x50]);
    s.extend_from_slice(&[0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00, 0x48, 0x89, 0xE1]); // sub rsp, 0x4D0; mov rcx, rsp
    s.extend_from_slice(&[0x48, 0xB8]);
    s.extend_from_slice(&0x7FFF_0000_09E4u64.to_le_bytes()); // mov rax, RtlCaptureContext
    s.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x89, 0xE1, 0x48, 0x83, 0xEC, 0x20]); // call rax; mov rcx, rsp; sub rsp, 0x20
    for (op, v) in [([0x48, 0xBA], func), ([0x49, 0xB8], internal), ([0x49, 0xB9], public), ([0x48, 0xB8], 0x6FFF_E346_C870)] {
        s.extend_from_slice(&op);
        s.extend_from_slice(&v.to_le_bytes());
    }
    s.extend_from_slice(&[0xFF, 0xD0]);
    assert_eq!(s.len(), 97, "the stub is 97 bytes with Xbyak's encodings");
    s
}

/// An entry hooked by Top.dll (jump -> anonymous page -> `jmp [rip+0]`), and a context-hook cave
/// `[copy | stub]` at `region` whose stub resumes at `entry + resume_k` through `r8`/`r9`.
fn context_hook_world(copy: &[u8], internal_k: u64, public_k: u64) -> (Report, Vec<u8>, u64, Mem) {
    let prologue = [0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x49];
    let pe = fake_pe(&prologue);
    let entry = BASE + u64::from(TEXT_RVA);
    let top_tramp = BASE + 0x10_0000;
    let mut live = prologue.to_vec();
    live[0] = 0xE9;
    live[1..5].copy_from_slice(&rel32(entry, top_tramp));
    live[5..10].fill(0x90);
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x10).to_le_bytes());
    let region = BASE + 0x30_0000;
    let mut cave = copy.to_vec();
    cave.extend_from_slice(&context_stub_bytes(DLL + 0x40, entry + internal_k, entry + public_k));
    let mem = mem_with(vec![(entry, live), (top_tramp, t), (region, cave.clone()), (DLL, vec![0xC3; 0x100]), (DLL2, vec![0xC3; 0x100])]);
    let report = scan(vec![(68617, u64::from(TEXT_RVA))].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, Kind::Jump);
    (report, cave, region, mem)
}

#[test]
fn context_hook_stub_over_the_game_bytes_is_the_bottom_layer() {
    // DevBench's `install_context_hook(addr, 10, fn, +10)`: `[10 copied bytes | stub]`, no jump back
    let prologue = [0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18];
    let (mut report, cave, region, mem) = context_hook_world(&prologue, 10, 10);
    Returns::new(&report, BASE).search(&mut report, region, &cave, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    let f = &report.findings[0];
    assert!(f.layers.iter().any(|l| l.original && l.trampoline == region), "{:?}", f.layers);
    assert!(format(&report, EXE).contains("Top.dll > game"));
}

#[test]
fn context_hook_stub_copying_another_hook_finds_that_hook() {
    // the copied 10 bytes are Bottom.dll's jump (5) plus the game's next 5
    let bottom_tramp = BASE + 0x11_0000;
    let region = BASE + 0x30_0000;
    let mut copy = vec![0xE9];
    copy.extend_from_slice(&rel32(region, bottom_tramp));
    copy.extend_from_slice(&[0x48, 0x89, 0x74, 0x24, 0x18]);
    let (mut report, cave, region, mut mem) = context_hook_world(&copy, 10, 10);
    let mut b = vec![0xFF, 0x25, 0, 0, 0, 0];
    b.extend_from_slice(&(DLL2 + 0x10).to_le_bytes());
    mem.regions.insert(bottom_tramp, b);
    Returns::new(&report, BASE).search(&mut report, region, &cave, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    let f = &report.findings[0];
    assert_eq!(f.stack(EXE), vec!["Top.dll".to_owned(), "Bottom.dll".to_owned()]);
    assert!(!f.layers.iter().any(|l| l.original));
}

#[test]
fn a_resume_constant_alone_is_not_a_context_hook() {
    let prologue = [0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18];
    // r8 (internal) differs from r9 (public): the include < 0 shape, which jumps back by `jmp [rip+0]`
    let (mut report, cave, region, mem) = context_hook_world(&prologue, 12, 10);
    Returns::new(&report, BASE).search(&mut report, region, &cave, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert!(report.findings[0].layers.is_empty(), "{:?}", report.findings[0].layers);
    // the same imm64 loads with none of the stub around them
    let entry = BASE + u64::from(TEXT_RVA);
    let mut loose = prologue.to_vec();
    for op in [[0x49u8, 0xB8], [0x49, 0xB9]] {
        loose.extend_from_slice(&op);
        loose.extend_from_slice(&(entry + 10).to_le_bytes());
    }
    let (mut report, _, region, mem) = context_hook_world(&prologue, 10, 10);
    Returns::new(&report, BASE).search(&mut report, region, &loose, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert!(report.findings[0].layers.is_empty(), "{:?}", report.findings[0].layers);
    // the full stub but a copy that is neither the game's bytes nor a jump: no layer either
    let (mut report, cave, region, mem) = context_hook_world(&[0x11; 10], 10, 10);
    Returns::new(&report, BASE).search(&mut report, region, &cave, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert!(report.findings[0].layers.is_empty());
}

#[test]
fn call_whose_operand_crosses_the_window_is_followed() {
    // id 37177 (Actor::vfunc_106, +0x06713e0) in the 0.2.2 report: bytes changed at +14. The game's
    // bytes are `.. 48 8b d9 | e8 ee 8a c7 ff | 48 8b f8`: a `call rel32` at +13, its operand at
    // +14..+17, so the 16-byte window ends inside it and only two operand bytes differ.
    let mut text = vec![0x90u8; 0x40];
    let game = [
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xD9, 0xE8, 0xEE, 0x8A, 0xC7, 0xFF, 0x48, 0x8B, 0xF8,
    ];
    text[..game.len()].copy_from_slice(&game);
    let pe = fake_pe(&text);
    let entry = BASE + u64::from(TEXT_RVA);
    let tramp = BASE + 0x10_0030; // its rel32 differs from the game's in the first operand byte
    let mut live = text.clone();
    live[14..18].copy_from_slice(&rel32(entry + 13, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x20).to_le_bytes());
    let mem = mem_with(vec![(entry, live.clone()), (tramp, t), (DLL, vec![0xC3; 0x100])]);
    assert_eq!(live[..16].iter().zip(&text[..16]).position(|(a, b)| a != b), Some(14));
    let off = u64::from(TEXT_RVA);
    let report = scan([(37177, off), (37178, off + 0x30)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    let f = &report.findings[0];
    assert_eq!(f.kind, Kind::Inner { offset: 13 }, "{f:?}");
    assert_eq!(f.owner(EXE), Some("Top.dll"));
    // disk `e8 ee 8a c7 ff` and memory `e8 c8 0f ..`: the same opcode, only the displacement differs
    let text = format(&Report { in_code: 1, differing: 1, findings: vec![f.clone()], ..Report::default() }, EXE);
    assert!(text.contains("branch at +13 retargeted"), "{text}");
    // a window whose operand is unreadable stays a plain byte change
    let cut = Mem { regions: HashMap::from([(entry, live[..16].to_vec()), (DLL, vec![0xC3; 0x100])]), modules: mem.modules.clone() };
    let report = scan([(37177, off), (37178, off + 0x30)].into_iter(), BASE, &pe, EXE, &|a, n| cut.read(a, n), &|a| cut.module(a));
    assert_eq!(report.findings[0].kind, Kind::Bytes { offset: 14 });
}

const RACE: u64 = 0x6FFF_D853_0000;

/// Row 21431 (`Cmd::SameRaceAsPC_Eval`, +0x0331450) of the 0.2.4 in-game report, the exact bytes:
/// the game's window, and the live window `mov r8, [rip+disp]; jmp [rip+0]` whose 8-byte operand
/// (`e0 09 53 d8 ff 6f 00 00`) starts at +13 and ends 5 bytes past the 16-byte window.
const R21431_DISK: [u8; 16] = [0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x15, 0x1D, 0xF3, 0xEF, 0x02, 0x33, 0xD2, 0x49, 0x89, 0x11];
const R21431_MEM: [u8; 16] = [0x4C, 0x8B, 0x05, 0x21, 0xF3, 0xEF, 0x02, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x09, 0x53];
const R21431_TAIL: [u8; 5] = [0xD8, 0xFF, 0x6F, 0x00, 0x00];

/// Memory for a rewritten entry (window plus `tail`) and a module `race.dll` at `RACE`.
fn written_branch_world(window: &[u8; 16], tail: &[u8]) -> Mem {
    let mut live = window.to_vec();
    live.extend_from_slice(tail);
    live.extend_from_slice(&[0x90; 8]);
    let entry = BASE + u64::from(TEXT_RVA);
    Mem {
        regions: HashMap::from([(entry, live), (RACE + 0x9E0, vec![0xC3; 0x20])]),
        modules: vec![(BASE, BASE + 0x10000, "SkyrimSE.exe"), (RACE, RACE + 0x10000, "race.dll")],
    }
}

fn scan_written(disk: &[u8; 16], mem: &Mem) -> Finding {
    let mut text = vec![0x90u8; 0x40];
    text[..16].copy_from_slice(disk);
    let pe = fake_pe(&text);
    let off = u64::from(TEXT_RVA);
    let report = scan([(21431, off), (21432, off + 0x30)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    report.findings.into_iter().next().unwrap()
}

#[test]
fn branch_written_behind_rewritten_bytes_is_followed() {
    // first difference at +0, the `jmp [rip+0]` at +7, its operand crossing the window end
    let mem = written_branch_world(&R21431_MEM, &R21431_TAIL);
    let f = scan_written(&R21431_DISK, &mem);
    assert_eq!(f.kind, Kind::Inner { offset: 7 }, "{f:?}");
    assert_eq!(f.owner(EXE), Some("race.dll"));
    assert_eq!(f.hops[0].address, RACE + 0x9E0);
    // the report names it as written, not retargeted, and gives no unowned full-window line
    let text = format(&Report { in_code: 1, differing: 1, findings: vec![f], ..Report::default() }, EXE);
    assert!(text.contains("branch written at +7"), "{text}");
    assert!(text.contains("race.dll"), "{text}");
    assert!(!text.contains("full window"), "{text}");
}

#[test]
fn unchanged_branch_bytes_after_the_first_difference_are_not_used() {
    // the game's own `ff 25 <disp 0> <abs64>` at +7 sits in both windows; only +0..+2 differ
    let mut disk = R21431_MEM;
    disk[..3].copy_from_slice(&[0x48, 0x8B, 0x05]);
    let mem = written_branch_world(&R21431_MEM, &R21431_TAIL);
    let f = scan_written(&disk, &mem);
    assert_eq!(f.kind, Kind::Bytes { offset: 0 }, "{f:?}");
    assert_eq!(f.owner(EXE), None);
}

#[test]
fn written_branch_without_an_owner_stays_bytes() {
    // the same rewrite, but the jump leads into the executable, which has no code there to follow
    // abs64 = 0x1_4000_2000 (BASE + 0x2000): bytes +13..+15 in the window, five more past it
    let mut window = R21431_MEM;
    window[13..].copy_from_slice(&[0x00, 0x20, 0x00]);
    let mem = written_branch_world(&window, &[0x40, 0x01, 0x00, 0x00, 0x00]);
    let f = scan_written(&R21431_DISK, &mem);
    assert_eq!(f.kind, Kind::Bytes { offset: 0 }, "{f:?}");
    assert_eq!(f.owner(EXE), None);
    // a target in unmapped memory leaves it alone as well
    let mem = written_branch_world(&R21431_MEM, &[0xFF; 5]);
    assert_eq!(scan_written(&R21431_DISK, &mem).kind, Kind::Bytes { offset: 0 });
}

#[test]
fn inner_label_tells_written_from_retargeted() {
    let disk: Vec<u8> = (0u8..16).collect();
    let mut mem = disk.clone();
    mem[7] = 0xE9;
    // no branch opcode on disk
    assert_eq!(describe(&Kind::Inner { offset: 7 }, &disk, &mem), "branch written at +7");
    // the same opcode on both sides: retargeted
    let mut with_call = disk.clone();
    with_call[13] = 0xE8;
    let mut now = with_call.clone();
    now[14] = 0x99;
    assert_eq!(describe(&Kind::Inner { offset: 13 }, &with_call, &now), "branch at +13 retargeted");
    // `ff 25` in the last two bytes compares as two bytes; a lone `ff` in the last byte is no opcode
    assert_eq!(describe(&Kind::Inner { offset: 14 }, &[0xFF, 0x25].repeat(8), &[0xFF, 0x25].repeat(8)), "branch at +14 retargeted");
    assert_eq!(describe(&Kind::Inner { offset: 15 }, &[0xFF; 16], &[0xFF; 16]), "branch written at +15");
    // different opcodes (`e8` on disk, `e9` in memory; `ff 15` to `ff 25`): written
    let mut jmp = with_call.clone();
    jmp[13] = 0xE9;
    assert_eq!(describe(&Kind::Inner { offset: 13 }, &with_call, &jmp), "branch written at +13");
    let (mut a, mut b) = (disk.clone(), disk);
    a[2..4].copy_from_slice(&[0xFF, 0x15]);
    b[2..4].copy_from_slice(&[0xFF, 0x25]);
    assert_eq!(describe(&Kind::Inner { offset: 2 }, &a, &b), "branch written at +2");
}

// --- walker tests begin

const WRONG: u64 = BASE + TEXT_RVA as u64 + 0x1_0000;
const REAL: u64 = 0x6FFF_D860_0000;

/// A world for a 16-byte live window at the entry with an 8-byte absolute pointer to `real.dll+0x20`
/// right after it (the operand of a `jmp [rip+0]` at +10), and a `wrong.dll` holding the target a
/// misdecoded `e9` at +2 would have (`entry + 2 + 5 + 0xfffb`).
fn immediate_world(window: &[u8; 16]) -> Mem {
    let entry = BASE + u64::from(TEXT_RVA);
    let mut live = window.to_vec();
    live.extend_from_slice(&(REAL + 0x20).to_le_bytes());
    live.extend_from_slice(&[0x90; 8]);
    Mem {
        regions: HashMap::from([(entry, live), (WRONG + 2, vec![0xC3; 0x20]), (REAL + 0x20, vec![0xC3; 0x20])]),
        modules: vec![(BASE, BASE + 0x10000, "SkyrimSE.exe"), (WRONG, WRONG + 0x100, "wrong.dll"), (REAL, REAL + 0x100, "real.dll")],
    }
}

/// `mov rax, 0x9090900000fffbe9` (+0, 10 bytes) hiding `e9 fb ff 00 00` at +2, then `jmp [rip+0]` at +10.
const HIDING: [u8; 16] = [0x48, 0xB8, 0xE9, 0xFB, 0xFF, 0x00, 0x00, 0x90, 0x90, 0x90, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];

#[test]
fn branch_hidden_in_an_immediate_is_not_taken() {
    // counterexample 1: the game's window is NOPs; the real jump is at +10, past the mov
    let mem = immediate_world(&HIDING);
    let f = scan_written(&[0x90; 16], &mem);
    assert_eq!(f.kind, Kind::Inner { offset: 10 }, "{f:?}");
    assert_eq!(f.owner(EXE), Some("real.dll"));
    assert!(f.hops.iter().all(|h| h.module.as_deref() != Some("wrong.dll")), "{f:?}");
}

#[test]
fn partial_overlap_with_an_immediate_is_not_taken() {
    // counterexample 2: the game has `49 b8 e9 fa ..` (a mov of its own, its jump at +10
    // unchanged); memory differs at +0 and +3, so the `e9` at +2 has one changed byte of its own
    let mut disk = HIDING;
    disk[0] = 0x49;
    disk[3] = 0xFA;
    let mem = immediate_world(&HIDING);
    let f = scan_written(&disk, &mem);
    assert_eq!(f.kind, Kind::Bytes { offset: 0 }, "{f:?}");
    assert_eq!(f.owner(EXE), None);
    assert!(f.hops.iter().all(|h| h.module.as_deref() != Some("wrong.dll")), "{f:?}");
}

#[test]
fn label_is_written_when_the_game_had_no_branch_there() {
    // counterexample 3: the game's `mov rax, imm64` has an `e8` inside its immediate at +2;
    // memory has a two-byte nop and a new `jmp rel32` at +2 into wrong.dll
    let mut disk = [0x00u8; 16];
    disk[..3].copy_from_slice(&[0x48, 0xB8, 0xE8]);
    disk[10..].fill(0x90);
    let mut window = [0x90u8; 16];
    window[..7].copy_from_slice(&[0x66, 0x90, 0xE9, 0xFB, 0xFF, 0x00, 0x00]);
    let mem = immediate_world(&window);
    let f = scan_written(&disk, &mem);
    assert_eq!(f.kind, Kind::Inner { offset: 2 }, "{f:?}");
    assert_eq!(f.owner(EXE), Some("wrong.dll"));
    let text = format(&Report { in_code: 1, differing: 1, findings: vec![f], ..Report::default() }, EXE);
    assert!(text.contains("branch written at +2"), "{text}");
    assert!(!text.contains("retargeted"), "{text}");
}

#[test]
fn label_is_written_when_the_same_opcode_sits_inside_a_disk_immediate() {
    // counterexample: disk `48 b8 e9 ..` (mov rax, imm64, `e9` in the immediate) vs live
    // `66 90 e9 ..` (nop; new jmp at +2): same opcode at +2, but the bytes before it changed
    let mut disk = [0x00u8; 16];
    disk[..3].copy_from_slice(&[0x48, 0xB8, 0xE9]);
    disk[10..].fill(0x90);
    let mut window = [0x90u8; 16];
    window[..7].copy_from_slice(&[0x66, 0x90, 0xE9, 0xFB, 0xFF, 0x00, 0x00]);
    let mem = immediate_world(&window);
    let f = scan_written(&disk, &mem);
    assert_eq!(f.kind, Kind::Inner { offset: 2 }, "{f:?}");
    let text = format(&Report { in_code: 1, differing: 1, findings: vec![f], ..Report::default() }, EXE);
    assert!(text.contains("branch written at +2"), "{text}");
    assert!(!text.contains("retargeted"), "{text}");
}

#[test]
fn label_is_retargeted_with_an_identical_prefix_and_the_same_opcode() {
    // `push rbx; sub rsp, 20h; call rel32` kept, only the call operand changed
    let mut disk = [0x90u8; 16];
    disk[..6].copy_from_slice(&[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20]);
    disk[6] = 0xE8;
    let mut mem = disk;
    mem[7..11].copy_from_slice(&[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(describe(&Kind::Inner { offset: 6 }, &disk, &mem), "branch at +6 retargeted");
    // one changed byte before the branch makes it written, even with the same opcode
    mem[3] = 0x89;
    assert_eq!(describe(&Kind::Inner { offset: 6 }, &disk, &mem), "branch written at +6");
    // an offset past either length never panics and is written
    assert_eq!(describe(&Kind::Inner { offset: 20 }, &disk, &mem), "branch written at +20");
    assert_eq!(describe(&Kind::Inner { offset: 6 }, &disk[..4], &mem), "branch written at +6");
}

#[test]
fn live_boundaries_walk_the_known_encodings_and_stop() {
    // 21431: `mov r8, [rip+disp32]` then a `ff 25` the walker does not know: boundaries +0 and +7
    assert_eq!(live_boundaries(&R21431_MEM), vec![0, 7]);
    // push rbp; sub rsp, 0x20; 5-byte nop; nop; then an unknown `e9`
    let code = [0x55, 0x48, 0x83, 0xEC, 0x20, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(live_boundaries(&code), vec![0, 1, 5, 10, 11]);
    // 41 57 push r15; 49 b8 imm64 (10); 4c 8b c0 mov r8, rax; 41 b8 imm32 (6); b8 imm32 would not fit
    let code = [0x41, 0x57, 0x49, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0x4C, 0x8B, 0xC0, 0x41, 0xB8, 1, 2, 3, 4, 0xB8, 1, 2];
    assert_eq!(live_boundaries(&code), vec![0, 2, 12, 15, 21]);
    assert!(live_boundaries(&[]).is_empty());
}

// --- walker tests end

#[test]
fn short_reads_never_panic() {
    // `jmp [rip+0]` in memory where the game has a prologue; a read of 8 bytes comes back short
    let mut text = vec![0x90u8; 0x40];
    text[..6].copy_from_slice(&[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20]);
    let pe = fake_pe(&text);
    let mut live = text.clone();
    live[..6].copy_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    live[6..14].copy_from_slice(&(DLL + 0x10).to_le_bytes());
    let mem = mem_with(vec![(BASE + u64::from(TEXT_RVA), live.clone()), (DLL, vec![0xC3; 0x100])]);
    let off = u64::from(TEXT_RVA);
    for cap in [0usize, 3, 7] {
        let short = |a: u64, n: usize| mem.read(a, n).map(|mut b| {
            if n == 8 || cap == 0 {
                b.truncate(cap);
            }
            b
        });
        let mut report = scan([(1, off), (2, off + 0x30)].into_iter(), BASE, &pe, EXE, &short, &|a| mem.module(a));
        assert!(!report.findings.is_empty());
        let _ = follow(BASE + u64::from(TEXT_RVA), EXE, &short, &|a| mem.module(a));
        let _ = classify(&live[..16], &text[..16], BASE + u64::from(TEXT_RVA), EXE, &short, &|a| mem.module(a));
        Returns::new(&report, BASE).search(&mut report, BASE + u64::from(TEXT_RVA), &live, EXE, &short, &|a| mem.module(a));
        let _ = format(&report, EXE);
    }
}

#[test]
fn report_header_counts_kib() {
    let report = Report { searched: 42 << 10, ..Report::default() };
    assert!(format(&report, EXE).contains("in 42 KiB"));
}

// --- 0.2.6: boundary check for the old candidate path

fn text_of(f: Finding) -> String {
    format(&Report { in_code: 1, differing: 1, findings: vec![f], ..Report::default() }, EXE)
}

#[test]
fn constant_change_inside_a_mov_is_not_a_retargeted_branch() {
    // counterexample: the game has `mov rax, 0x9090900000fffae9` (+0, 10 bytes) and `jmp [rip+0]` at +10;
    // memory differs only in the constant (+3). The first difference is +3, so +2 is an old-path
    // candidate whose `e9 fb ff 00 00` decodes into wrong.dll, but +2 is inside the mov.
    let mut disk = HIDING;
    disk[3] = 0xFA;
    let mem = immediate_world(&HIDING);
    let f = scan_written(&disk, &mem);
    assert_ne!(f.kind, Kind::Inner { offset: 2 }, "{f:?}");
    assert!(f.hops.iter().all(|h| h.module.as_deref() != Some("wrong.dll")), "{f:?}");
    assert_eq!(f.owner(EXE), None, "{f:?}");
    let text = text_of(f);
    assert!(!text.contains("retargeted"), "{text}");
    assert!(!text.contains("wrong.dll"), "{text}");
    assert!(text.contains("bytes changed at +3"), "{text}");
}

#[test]
fn candidate_past_an_unrecognised_byte_is_labelled_unverified() {
    // `int3 x4` is not in the recogniser's set, so the walk stops at +0 and cannot say that +4
    // starts an instruction; the call there is still followed, but not called retargeted
    let at = BASE + u64::from(TEXT_RVA);
    let tramp = BASE + 0x10_0030;
    let mut text = vec![0x90u8; 0x40];
    text[..4].fill(0xCC);
    text[4] = 0xE8;
    text[5..9].copy_from_slice(&rel32(at + 4, BASE + 0x2000));
    let pe = fake_pe(&text);
    let mut live = text.clone();
    live[5..9].copy_from_slice(&rel32(at + 4, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x20).to_le_bytes());
    let mem = mem_with(vec![(at, live), (tramp, t), (DLL, vec![0xC3; 0x100])]);
    let off = u64::from(TEXT_RVA);
    let report = scan([(1, off), (2, off + 0x30)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    let f = &report.findings[0];
    assert_eq!(f.owner(EXE), Some("Top.dll"), "{f:?}");
    let out = text_of(f.clone());
    assert!(out.contains("branch at +4 (boundary unverified)"), "{out}");
    assert!(!out.contains("retargeted"), "{out}");
}

/// Disk bytes of three rows of the 0.2.5 in-game report, read from SkyrimSE.exe (1.6.1170).
const R19718: [u8; 16] = [0x40, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xF9, 0xE8, 0xB2, 0x78, 0xFA, 0xFF, 0x84, 0xC0]; // +0x2e9590, call at +9
const R53016: [u8; 16] = [0xF3, 0x0F, 0x11, 0x49, 0x4C, 0xE9, 0x76, 0x24, 0xBC, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]; // +0x9969f0, jmp at +5
const R77246: [u8; 16] = [0x48, 0x83, 0xEC, 0x48, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x22, 0xA9, 0x58, 0x00, 0x80, 0x3D]; // +0x1009f70, call at +9
const R37177: [u8; 16] = [0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xD9, 0xE8, 0xEE, 0x8A]; // +0x6713e0, call at +13

/// Scans a function whose game bytes are `game` and whose branch at `at_n` was retargeted to Top.dll.
fn retargeted_row(game: &[u8; 16], at_n: usize) -> (Finding, String) {
    let entry = BASE + u64::from(TEXT_RVA);
    let mut text = vec![0x90u8; 0x40];
    text[..16].copy_from_slice(game);
    let pe = fake_pe(&text);
    let tramp = BASE + 0x10_0030;
    let mut live = text.clone();
    live[at_n + 1..at_n + 5].copy_from_slice(&rel32(entry + at_n as u64, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x20).to_le_bytes());
    let mem = mem_with(vec![(entry, live), (tramp, t), (DLL, vec![0xC3; 0x100])]);
    let off = u64::from(TEXT_RVA);
    let report = scan([(1, off), (2, off + 0x30)].into_iter(), BASE, &pe, EXE, &|a, n| mem.read(a, n), &|a| mem.module(a));
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    let f = report.findings[0].clone();
    let out = text_of(f.clone());
    (f, out)
}

#[test]
fn the_four_retargeted_rows_stay_retargeted() {
    for (name, game, n) in [("37177", R37177, 13), ("19718", R19718, 9), ("53016", R53016, 5), ("77246", R77246, 9)] {
        let (f, out) = retargeted_row(&game, n);
        assert_eq!(f.kind, Kind::Inner { offset: n }, "{name}: {f:?}");
        assert_eq!(f.owner(EXE), Some("Top.dll"), "{name}");
        assert!(out.contains(&format!("branch at +{n} retargeted")), "{name}: {out}");
        assert!(!out.contains("unverified"), "{name}: {out}");
    }
}

#[test]
fn walker_knows_the_prologues_of_the_four_rows() {
    // 37177: mov [rsp+8], rbx; push rdi; sub rsp, 0x40; mov rbx, rcx; then the call
    assert_eq!(live_boundaries(&R37177), vec![0, 5, 6, 10, 13]);
    // 19718: push rdi (with REX); sub rsp, 0x60; mov rdi, rcx; call
    assert_eq!(live_boundaries(&R19718), vec![0, 2, 6, 9]);
    // 53016: movss [rcx+4c], xmm1; jmp
    assert_eq!(live_boundaries(&R53016), vec![0, 5]);
    // 77246: sub rsp, 0x48; mov ecx, 1; call
    assert_eq!(live_boundaries(&R77246), vec![0, 4, 9]);
}

#[test]
fn boundary_of_tells_inside_from_unknown() {
    // inside the 10-byte mov: not a start
    assert_eq!(boundary_of(2, &HIDING, &HIDING), Boundary::Inside);
    assert_eq!(boundary_of(10, &HIDING, &HIDING), Boundary::Validated);
    // past an unrecognised first byte: unknown
    let code = [0xCC, 0x90, 0x90, 0x90];
    assert_eq!(boundary_of(2, &code, &code), Boundary::Unverified);
    assert_eq!(boundary_of(0, &code, &code), Boundary::Validated);
}

// --- 0.2.6: severity and the header

fn hop(module: &str) -> Hop {
    Hop { address: 0x7FF0_0000_1000, module: Some(module.to_owned()), via_thunk: false }
}

fn finding(id: u64, kind: Kind, hops: Vec<Hop>, layers: Vec<Layer>) -> Finding {
    Finding { id, rva: id * 0x10, kind, disk: vec![0x90; 16], memory: vec![0xCC; 16], hops, layers, name: None }
}

fn severity_report() -> Report {
    let layer = Layer { trampoline: 0x1000, original: false, hops: vec![hop("B.dll")] };
    Report {
        in_code: 10,
        differing: 4,
        findings: vec![
            finding(1, Kind::Jump, vec![hop("A.dll")], vec![]),
            finding(2, Kind::Jump, vec![hop("A.dll")], vec![layer]),
            finding(3, Kind::Bytes { offset: 0 }, vec![], vec![]),
            finding(4, Kind::Stub("returns 0".into()), vec![], vec![]),
        ],
        ..Report::default()
    }
}

#[test]
fn header_explains_and_rows_carry_a_severity_tag() {
    let text = format(&severity_report(), EXE);
    let mut lines = text.lines();
    assert!(lines.next().unwrap().starts_with("functions checked 10, changed 4"), "{text}");
    let explain = lines.next().unwrap();
    assert_eq!(
        explain,
        "Changed functions are normal: SKSE plugins work by patching the game. Worth a look: functions hooked by more than one module (1) and changes with no known owner (2).",
        "{text}"
    );
    let counts = lines.next().unwrap();
    assert!(counts.contains("look 3 (hooked by more than one module 1, no known owner 2), info 1"), "{counts}");
    let rows: Vec<&str> = text.lines().filter(|l| l.starts_with("[look]") || l.starts_with("[info]")).collect();
    assert_eq!(rows.len(), 4, "{text}");
    assert_eq!(rows.iter().filter(|l| l.starts_with("[look]")).count(), 3, "{text}");
    // multi-module and unowned rows are look, the single-owner row is info; nothing is dropped
    assert!(rows.iter().any(|l| l.starts_with("[info]") && l.contains("A.dll")), "{text}");
    assert!(rows.iter().any(|l| l.starts_with("[look]") && l.contains("A.dll > B.dll")), "{text}");
    assert!(rows.iter().filter(|l| l.starts_with("[look]") && l.contains(" ? ")).count() == 2, "{text}");
}

#[test]
fn summary_line_has_the_real_numbers_and_the_path() {
    let line = summary_line(&severity_report(), EXE, "C:/logs/skse-hook-inspector-report.txt");
    assert_eq!(
        line,
        "4 functions changed by 2 modules; 1 hooked by more than one; 2 with no known owner; report: C:/logs/skse-hook-inspector-report.txt"
    );
    let s = summarize(&severity_report(), EXE);
    assert_eq!((s.changed, s.modules, s.multi, s.unowned, s.info), (4, 2, 1, 2, 1));
    assert_eq!(summary_line(&Report::default(), EXE, "p"), "0 functions changed by 0 modules; 0 hooked by more than one; 0 with no known owner; report: p");
}

// --- 0.2.6: snapshot capture and replay

use crate::snapshot::{Module, Recorder, Snapshot, apply_names, hex, names_of, replay, sha256};

#[test]
fn sha256_known_vectors() {
    assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // 64 bytes (a whole block, padding in a block of its own) and 1000 bytes
    let a64 = [b'a'; 64];
    assert_eq!(hex(&sha256(&a64)), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    let pat: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(hex(&sha256(&pat)), "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371");
}

/// A stacked-hook world (Top.dll over Bottom.dll, a trampoline region) as in the 0.2.2 test.
struct World {
    pe: Vec<u8>,
    mem: Mem,
    region: u64,
    region_len: usize,
}

fn capture_world() -> World {
    let prologue = [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x45, 0x8B, 0xC8, 0x48, 0x63, 0xDA, 0x41, 0x83, 0xE9, 0x18];
    let pe = fake_pe(&prologue);
    let entry = BASE + u64::from(TEXT_RVA);
    let top_tramp = BASE + 0x10_0000;
    let mut live = prologue.to_vec();
    live[0] = 0xE9;
    live[1..5].copy_from_slice(&rel32(entry, top_tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x10).to_le_bytes());
    let bottom_tramp = BASE + 0x11_0000;
    let mut b = vec![0xFF, 0x25, 0, 0, 0, 0];
    b.extend_from_slice(&(DLL2 + 0x10).to_le_bytes());
    let region = BASE + 0x30_0000;
    let mut r = vec![0x90; 8];
    let t1 = region + r.len() as u64;
    r.push(0xE9);
    r.extend_from_slice(&rel32(t1, bottom_tramp));
    let back1 = region + r.len() as u64;
    r.push(0xE9);
    r.extend_from_slice(&rel32(back1, entry + 5));
    r.extend_from_slice(&[0xCC; 4]);
    r.extend_from_slice(&prologue[..6]);
    r.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);
    r.extend_from_slice(&(entry + 6).to_le_bytes());
    r.extend_from_slice(&[0x00; 300]);
    let region_len = r.len();
    let mem = mem_with(vec![(entry, live), (top_tramp, t), (bottom_tramp, b), (region, r), (DLL, vec![0xC3; 0x100]), (DLL2, vec![0xC3; 0x100])]);
    World { pe, mem, region, region_len }
}

/// Runs the analysis through a recorder and returns the report text and the snapshot.
fn capture(w: &World) -> (String, Snapshot) {
    let read = |a, n| w.mem.read(a, n);
    let module = |a| w.mem.module(a);
    let rec = Recorder::new(&read, &module);
    let pairs = vec![(7u64, u64::from(TEXT_RVA))];
    let regions = vec![(w.region, w.region_len)];
    let mut report = analyse(&pairs, BASE, &w.pe, EXE, &regions, &|a, n| rec.read(a, n), &|a| rec.module_of(a));
    report.findings[0].name = Some("Some::Function".to_owned());
    let text = format(&report, EXE);
    let mut snap = Snapshot::new("0.2.6", EXE, &w.pe, BASE);
    snap.pairs = pairs;
    snap.regions = regions;
    snap.modules = w.mem.modules.iter().map(|m| Module { name: m.2.to_owned(), base: m.0, size: m.1 - m.0 }).collect();
    snap.names = names_of(&report);
    (text, rec.finish(snap))
}

#[test]
fn snapshot_round_trip_replays_the_same_report_with_no_missed_reads() {
    let w = capture_world();
    let (text, snap) = capture(&w);
    assert!(text.contains("Top.dll > Bottom.dll > game"), "{text}");
    assert!(text.contains("Some::Function"), "{text}");
    assert!(snap.reads.len() >= 4 && snap.asked.len() >= 2, "{} reads, {} queries", snap.reads.len(), snap.asked.len());
    assert_eq!(snap.conflicts, 0);
    let bytes = snap.to_bytes();
    let back = Snapshot::from_bytes(&bytes).unwrap();
    assert_eq!(back, snap);
    let r = replay(&back, &w.pe).unwrap();
    assert_eq!((r.missed_reads, r.missed_modules), (0, 0), "{:?}", r.examples);
    assert_eq!(r.text, text);
    let json = snap.index_json(bytes.len());
    assert!(json.contains(&hex(&sha256(&w.pe))) && json.contains("\"plugin_version\": \"0.2.6\""), "{json}");
}

#[test]
fn replay_counts_what_the_snapshot_does_not_hold() {
    let w = capture_world();
    let (text, snap) = capture(&w);
    // the trampoline region was never read: the search finds nothing, and the miss is counted
    let mut gap = snap.clone();
    gap.reads.retain(|r| r.address != w.region);
    let r = replay(&gap, &w.pe).unwrap();
    assert_eq!(r.missed_reads, 1, "{:?}", r.examples);
    assert_ne!(r.text, text);
    assert!(r.examples[0].contains(&format!("{:#x}", w.region)), "{:?}", r.examples);
    // a module query the snapshot never recorded
    let mut nomods = snap.clone();
    nomods.asked.clear();
    assert!(replay(&nomods, &w.pe).unwrap().missed_modules > 0);
    // another executable is refused: same size but another SHA-256, then another size
    let mut other = w.pe.clone();
    *other.last_mut().unwrap() ^= 1;
    assert!(replay(&snap, &other).unwrap_err().contains("SHA-256"));
    assert!(replay(&snap, &other[..other.len() - 1]).unwrap_err().contains("bytes"));
}

#[test]
fn snapshot_parser_never_panics_on_bad_input() {
    let w = capture_world();
    let bytes = capture(&w).1.to_bytes();
    for cut in 0..bytes.len() {
        assert!(Snapshot::from_bytes(&bytes[..cut]).is_err(), "cut {cut}");
    }
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0xFF;
        let _ = Snapshot::from_bytes(&b);
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Snapshot::from_bytes(&extra).is_err());
    assert!(Snapshot::from_bytes(b"").is_err());
}

#[test]
fn large_reads_are_run_length_coded_and_round_trip() {
    let mut big = vec![0u8; 4096];
    big[100] = 0xE9;
    big[2000..2005].copy_from_slice(&[1, 2, 3, 4, 5]);
    let mut snap = Snapshot::new("t", EXE, b"x", BASE);
    snap.reads = vec![
        crate::snapshot::Read { address: 0x1000, len: 4096, bytes: Some(big) },
        crate::snapshot::Read { address: 0x10, len: 16, bytes: None },
        crate::snapshot::Read { address: u64::MAX - 3, len: 4, bytes: Some(vec![1, 2, 3, 4]) },
    ];
    let bytes = snap.to_bytes();
    assert!(bytes.len() < 300, "{}", bytes.len());
    assert_eq!(Snapshot::from_bytes(&bytes).unwrap(), snap);
}

#[test]
fn snapshot_size_for_a_full_scan_is_well_under_the_target() {
    // 0.2.5 in game: 185,681 functions checked, one 16-byte read each, plus 170 changed entries with
    // a few reads, 44 trampolines, 183 loaded DLLs; the private-code search is simulated as 1 MiB of
    // regions, 95% zero bytes. Entry bytes are pseudo-random (they do not compress).
    let mut snap = Snapshot::new("0.2.6", EXE, b"x", BASE);
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut off = 0x1000u64;
    for id in 0..185_681u64 {
        off += 16 + next() % 180;
        snap.pairs.push((id * 3 + 1, off));
        let bytes = next().to_le_bytes().iter().chain(next().to_le_bytes().iter()).copied().collect();
        snap.reads.push(crate::snapshot::Read { address: BASE + off, len: 16, bytes: Some(bytes) });
    }
    for i in 0..500u64 {
        snap.reads.push(crate::snapshot::Read { address: 0x6FFF_D853_0000 + i * 64, len: 8, bytes: Some(next().to_le_bytes().to_vec()) });
        snap.asked.push((0x6FFF_D853_0000 + i * 64, Some("SomeModule.dll".into())));
    }
    for r in 0..16u64 {
        let region: Vec<u8> = (0..65_536).map(|_| if next() % 20 == 0 { (next() & 0xFF) as u8 } else { 0 }).collect();
        snap.regions.push((0x1_4100_0000 + r * 0x1_0000, region.len()));
        snap.reads.push(crate::snapshot::Read { address: 0x1_4100_0000 + r * 0x1_0000, len: region.len(), bytes: Some(region) });
    }
    for m in 0..400u64 {
        snap.modules.push(Module { name: format!("SomePlugin{m}.dll"), base: 0x7FF0_0000_0000 + m * 0x10_0000, size: 0xF_0000 });
    }
    let bin = snap.to_bytes().len();
    let json = snap.index_json(bin).len();
    println!("snapshot size estimate: bin {bin} bytes ({:.1} MiB), json index {json} bytes", bin as f64 / 1_048_576.0);
    assert!(bin < 12 << 20, "{bin}");
    assert_eq!(Snapshot::from_bytes(&snap.to_bytes()).unwrap().reads.len(), snap.reads.len());
}

#[test]
fn names_round_trip_through_a_report() {
    let mut report = severity_report();
    apply_names(&mut report, &[(2, "Two".into()), (9, "Nine".into())]);
    assert_eq!(names_of(&report), vec![(2, "Two".to_owned())]);
}

/// With `HOOK_INSPECTOR_EXE` set to SkyrimSE.exe (read-only), the four rows of the 0.2.5 report are
/// scanned with their real disk bytes, found by the real section table, each with its branch
/// retargeted in a synthetic memory; each must still read retargeted. Skipped when unset.
#[test]
fn four_retargeted_rows_on_the_real_exe() {
    let Ok(path) = std::env::var("HOOK_INSPECTOR_EXE") else { return };
    let pe = std::fs::read(&path).unwrap();
    let rows = [(37177u64, 0x6713e0u64, 13usize), (19718, 0x2e9590, 9), (53016, 0x9969f0, 5), (77246, 0x1009f70, 9)];
    let secs = sections(&pe).unwrap();
    let tramp = 0x1_5000_0000u64;
    let mut regions = vec![(DLL, vec![0xC3; 0x100]), (tramp, {
        let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
        t.extend_from_slice(&(DLL + 0x20).to_le_bytes());
        t
    })];
    for &(_, rva, n) in &rows {
        let game = disk_code(&pe, &secs, rva as u32, 24).unwrap().to_vec();
        let mut live = game.clone();
        live[n + 1..n + 5].copy_from_slice(&rel32(BASE + rva + n as u64, tramp));
        regions.push((BASE + rva, live));
    }
    let mut mem = mem_with(regions);
    mem.modules[0].1 = BASE + 0x4000_0000;
    let pairs: Vec<(u64, u64)> = rows.iter().map(|&(id, rva, _)| (id, rva)).collect();
    let read = |a, n| mem.read(a, n);
    let module = |a| mem.module(a);
    let rec = Recorder::new(&read, &module);
    let report = analyse(&pairs, BASE, &pe, EXE, &[], &|a, n| rec.read(a, n), &|a| rec.module_of(a));
    // HOOK_INSPECTOR_SNAPSHOT_OUT: also write this synthetic capture, to try the replay example on the real file
    if let Ok(out) = std::env::var("HOOK_INSPECTOR_SNAPSHOT_OUT") {
        let mut snap = Snapshot::new("0.2.6-test", EXE, &pe, BASE);
        snap.pairs = pairs.clone();
        let snap = rec.finish(snap);
        std::fs::write(&out, snap.to_bytes()).unwrap();
        std::fs::write(format!("{out}.expected.txt"), format(&report, EXE)).unwrap();
    }
    assert_eq!(report.findings.len(), 4, "{:?}", report.findings);
    for &(id, rva, n) in &rows {
        let f = report.findings.iter().find(|f| f.id == id).unwrap();
        assert_eq!(f.kind, Kind::Inner { offset: n }, "{id} @{rva:#x}: {f:?}");
        let out = text_of(f.clone());
        assert!(out.contains(&format!("branch at +{n} retargeted")), "{id}: {out}");
    }
}

/// With `HOOK_INSPECTOR_SNAPSHOT` (a captured `.bin`) and `HOOK_INSPECTOR_EXE` set, the replay must hold every
/// read. Skipped when either is unset, so `cargo test` passes without a snapshot.
#[test]
fn replay_of_a_captured_snapshot() {
    let (Ok(snap), Ok(exe)) = (std::env::var("HOOK_INSPECTOR_SNAPSHOT"), std::env::var("HOOK_INSPECTOR_EXE")) else { return };
    let snap = Snapshot::from_bytes(&std::fs::read(snap).unwrap()).unwrap();
    let r = replay(&snap, &std::fs::read(exe).unwrap()).unwrap();
    assert_eq!((r.missed_reads, r.missed_modules), (0, 0), "{:?}", r.examples);
}

// --- 0.2.6 fix round: frozen capture, parser limits

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};

thread_local! {
    /// The largest single allocation this thread asked for since the last reset.
    static BIGGEST: Cell<usize> = const { Cell::new(0) };
}

struct Track;

fn note(size: usize) {
    let _ = BIGGEST.try_with(|b| b.set(b.get().max(size)));
}

unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        note(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        note(new);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static TRACK: Track = Track;

/// Runs `f` and returns its result with the largest single allocation it made on this thread.
fn biggest_alloc<T>(f: impl FnOnce() -> T) -> (T, usize) {
    BIGGEST.with(|b| b.set(0));
    let out = f();
    (out, BIGGEST.with(Cell::get))
}

/// Two functions whose entries jump to one shared trampoline (`jmp [rip+0]` into Top.dll), so the
/// second finding asks the same memory and module questions as the first.
fn shared_thunk_world() -> World {
    let original = [0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
    let text: Vec<u8> = original.iter().chain(original.iter()).copied().collect();
    let pe = fake_pe(&text);
    let f0 = BASE + u64::from(TEXT_RVA);
    let tramp = BASE + 0x10_0000;
    let mut live = text.clone();
    live[0] = 0xE9;
    live[1..5].copy_from_slice(&rel32(f0, tramp));
    live[16] = 0xE9;
    live[17..21].copy_from_slice(&rel32(f0 + 16, tramp));
    let mut t = vec![0xFF, 0x25, 0, 0, 0, 0];
    t.extend_from_slice(&(DLL + 0x10).to_le_bytes());
    let mem = mem_with(vec![(f0, live), (tramp, t), (DLL, vec![0xC3; 0x100]), (DLL2, vec![0xC3; 0x100])]);
    World { pe, mem, region: 0, region_len: 0 }
}

#[test]
fn capture_is_a_frozen_view_so_the_replay_matches_what_the_analysis_saw() {
    let w = shared_thunk_world();
    let pairs = vec![(1u64, u64::from(TEXT_RVA)), (2, u64::from(TEXT_RVA) + 16)];
    // the live process changes its answer to every repeated question: the trampoline now leads to
    // Bottom.dll, and the module lookup of an address already asked names another module
    let read_calls: RefCell<HashMap<(u64, usize), u32>> = RefCell::default();
    let module_calls: RefCell<HashMap<u64, u32>> = RefCell::default();
    let read = |a: u64, n: usize| {
        let mut calls = read_calls.borrow_mut();
        let c = calls.entry((a, n)).or_default();
        *c += 1;
        let mut b = w.mem.read(a, n)?;
        if *c > 1 && b.starts_with(&[0xFF, 0x25]) && b.len() >= 14 {
            b[6..14].copy_from_slice(&(DLL2 + 0x10).to_le_bytes());
        }
        Some(b)
    };
    let module = |a: u64| {
        let mut calls = module_calls.borrow_mut();
        let c = calls.entry(a).or_default();
        *c += 1;
        if *c > 1 { Some("Drift.dll".to_owned()) } else { w.mem.module(a) }
    };
    let rec = Recorder::new(&read, &module);
    let report = analyse(&pairs, BASE, &w.pe, EXE, &[], &|a, n| rec.read(a, n), &|a| rec.module_of(a));
    let text = format(&report, EXE);
    let owners: Vec<_> = report.findings.iter().map(|f| f.owner(EXE).map(str::to_owned)).collect();
    assert_eq!(owners, [Some("Top.dll".to_owned()), Some("Top.dll".to_owned())], "{text}");
    assert!(!text.contains("Drift.dll") && !text.contains("Bottom.dll"), "{text}");
    // the live closures were asked each question once
    assert!(read_calls.borrow().values().all(|&c| c == 1), "{:?}", read_calls.borrow());
    assert!(module_calls.borrow().values().all(|&c| c == 1), "{:?}", module_calls.borrow());
    let mut snap = Snapshot::new("0.2.6", EXE, &w.pe, BASE);
    snap.pairs = pairs;
    snap.modules = w.mem.modules.iter().map(|m| Module { name: m.2.to_owned(), base: m.0, size: m.1 - m.0 }).collect();
    let snap = Snapshot::from_bytes(&rec.finish(snap).to_bytes()).unwrap();
    assert_eq!(snap.conflicts, 0);
    let r = replay(&snap, &w.pe).unwrap();
    assert_eq!((r.missed_reads, r.missed_modules), (0, 0), "{:?}", r.examples);
    assert_eq!(r.text, text, "capture and replay disagree");
}

#[test]
fn recorder_answers_a_repeated_query_from_its_first_answer() {
    let memory = RefCell::new(vec![0u8; 0x100]);
    let live_reads = Cell::new(0u32);
    let read = |a: u64, n: usize| {
        live_reads.set(live_reads.get() + 1);
        let m = memory.borrow();
        let off = usize::try_from(a.checked_sub(0x1000)?).ok()?;
        m.get(off..off + n).map(<[u8]>::to_vec)
    };
    let owner = RefCell::new("A.dll");
    let module = |_| Some((*owner.borrow()).to_owned());
    let rec = Recorder::new(&read, &module);
    let first = rec.read(0x1000, 16).unwrap();
    memory.borrow_mut()[3] = 0x77;
    owner.replace("B.dll");
    assert_eq!(rec.read(0x1000, 16).unwrap(), first, "the second answer is the first");
    assert_eq!(live_reads.get(), 1, "the live read ran once");
    assert_eq!(rec.module_of(0x1000).as_deref(), Some("B.dll"));
    owner.replace("C.dll");
    assert_eq!(rec.module_of(0x1000).as_deref(), Some("B.dll"));
    let snap = rec.finish(Snapshot::default());
    assert_eq!((snap.reads.len(), snap.asked.len(), snap.conflicts), (1, 1, 0));
}

#[test]
fn overlapping_reads_that_disagree_are_counted_and_survive_the_file() {
    let memory = RefCell::new(vec![0u8; 0x4000]);
    let read = |a: u64, n: usize| {
        let off = usize::try_from(a.checked_sub(0x1000)?).ok()?;
        memory.borrow().get(off..off + n).map(<[u8]>::to_vec)
    };
    let module = |_| None;
    let rec = Recorder::new(&read, &module);
    rec.read(0x1000, 16).unwrap();
    rec.read(0x1008, 8).unwrap(); // overlaps, still equal: no conflict
    memory.borrow_mut()[5] = 0x99;
    rec.read(0x1010, 16).unwrap(); // starts after the changed byte
    rec.read(0x1004, 8).unwrap(); // covers it and the first read held the old value
    // a region larger than the small-read index, then a change inside it and a read across the change
    rec.read(0x2000, 0x2000).unwrap();
    memory.borrow_mut()[0x1100] = 0x42;
    rec.read(0x20F8, 16).unwrap();
    let snap = rec.finish(Snapshot::new("0.2.6", EXE, b"x", BASE));
    assert_eq!(snap.conflicts, 2);
    let back = Snapshot::from_bytes(&snap.to_bytes()).unwrap();
    assert_eq!(back.conflicts, 2);
    let w = shared_thunk_world();
    let mut snap = Snapshot::new("0.2.6", EXE, &w.pe, BASE);
    snap.conflicts = 2;
    let r = replay(&snap, &w.pe).unwrap();
    assert_eq!(r.conflicts, 2, "replay reports the conflicts");
    assert!(snap.index_json(0).contains("\"read_conflicts\": 2"));
}

// hand-built snapshot files

fn var(out: &mut Vec<u8>, mut v: u64) {
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

fn header(reads: u64) -> Vec<u8> {
    let mut o = b"SPMSNAP\0".to_vec();
    var(&mut o, 1); // format
    for s in ["0.2.6", "SkyrimSE.exe"] {
        var(&mut o, s.len() as u64);
        o.extend_from_slice(s.as_bytes());
    }
    var(&mut o, 100); // exe size
    o.extend_from_slice(&[0; 32]);
    var(&mut o, BASE);
    var(&mut o, 0); // pairs
    var(&mut o, 0); // regions
    var(&mut o, reads);
    o
}

fn trailer(o: &mut Vec<u8>) {
    for _ in 0..4 {
        var(o, 0); // asked, modules, names, conflicts
    }
    o.extend_from_slice(b"SPMEND");
}

/// A read record: address delta 0, requested `len`, tag 2 (run-length): `n` decoded bytes in
/// one run of zeros.
fn rle_record(o: &mut Vec<u8>, len: u64, n: u64) {
    var(o, 0);
    var(o, len);
    o.push(2);
    var(o, n);
    let mut enc = Vec::new();
    var(&mut enc, (n << 1) | 1);
    enc.push(0);
    var(o, enc.len() as u64);
    o.extend_from_slice(&enc);
}

fn raw_record(o: &mut Vec<u8>, len: u64, bytes: &[u8]) {
    var(o, 0);
    var(o, len);
    o.push(1);
    var(o, bytes.len() as u64);
    o.extend_from_slice(bytes);
}

const MIB: u64 = 1 << 20;

#[test]
fn many_huge_run_length_records_are_refused_without_a_large_allocation() {
    let mut o = header(4);
    for _ in 0..4 {
        rle_record(&mut o, 256 * MIB, 256 * MIB);
    }
    trailer(&mut o);
    assert!(o.len() < 200, "a tiny file: {} bytes", o.len());
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.is_err(), "{res:?}");
    assert!(biggest < 1 << 20, "allocated {biggest} bytes in one piece");
}

#[test]
fn aggregate_decoded_size_is_budgeted_before_decoding() {
    let mut o = header(5);
    for _ in 0..5 {
        rle_record(&mut o, 8 * MIB, 8 * MIB);
    }
    trailer(&mut o);
    // within a budget that fits two records, the third is refused before it is decoded
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes_within(&o, 20 * MIB as usize));
    let err = res.unwrap_err();
    assert!(err.contains("budget"), "{err}");
    assert!(biggest <= 8 * MIB as usize + 1024, "{biggest}");
    // and the same file passes with room for all five
    assert_eq!(Snapshot::from_bytes_within(&o, 40 * MIB as usize).unwrap().reads.len(), 5);
}

#[test]
fn a_read_may_not_return_more_than_it_asked_for() {
    let mut o = header(1);
    raw_record(&mut o, 16, &[7; 17]);
    trailer(&mut o);
    assert!(Snapshot::from_bytes(&o).unwrap_err().contains("more bytes"));
    let mut o = header(1);
    rle_record(&mut o, 16, 1000);
    trailer(&mut o);
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.unwrap_err().contains("more bytes"));
    assert!(biggest < 1 << 20, "{biggest}");
    // a short answer is a recorded fact (a closure may return less), so it parses
    let mut o = header(1);
    raw_record(&mut o, 16, &[7; 8]);
    trailer(&mut o);
    assert_eq!(Snapshot::from_bytes(&o).unwrap().reads[0].bytes.as_deref(), Some(&[7u8; 8][..]));
}

#[test]
fn raw_reads_obey_the_per_read_limit_too() {
    let mut o = header(1);
    raw_record(&mut o, 64 * MIB, &[1; 32]);
    trailer(&mut o);
    assert!(Snapshot::from_bytes(&o).unwrap_err().contains("limit"));
    // an unreadable read with an absurd length is refused as well
    let mut o = header(1);
    var(&mut o, 0);
    var(&mut o, u64::MAX >> 2);
    o.push(0);
    trailer(&mut o);
    assert!(Snapshot::from_bytes(&o).is_err());
}

#[test]
fn counts_and_lengths_larger_than_the_file_are_refused_without_reserving() {
    let mut o = header(1 << 40);
    trailer(&mut o);
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.unwrap_err().contains("count"));
    assert!(biggest < 1 << 20, "{biggest}");
    // a raw length and an encoded length far beyond the data
    let mut o = header(1);
    var(&mut o, 0);
    var(&mut o, 16);
    o.push(1);
    var(&mut o, u64::MAX >> 4);
    trailer(&mut o);
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.is_err() && biggest < 1 << 20, "{res:?} {biggest}");
    let mut o = header(1);
    var(&mut o, 0);
    var(&mut o, 16 * MIB);
    o.push(2);
    var(&mut o, 16 * MIB);
    var(&mut o, 1 << 40);
    trailer(&mut o);
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.is_err() && biggest < 1 << 20, "{res:?} {biggest}");
    // a declared 16 MiB read whose encoding is empty: refused, nothing reserved for the declared size
    let mut o = header(1);
    var(&mut o, 0);
    var(&mut o, 16 * MIB);
    o.push(2);
    var(&mut o, 16 * MIB);
    var(&mut o, 0);
    trailer(&mut o);
    let (res, biggest) = biggest_alloc(|| Snapshot::from_bytes(&o));
    assert!(res.unwrap_err().contains("shorter"));
    assert!(biggest < 1 << 20, "{biggest}");
}
