//! SKSE Hook Inspector: a skyrim-rs plugin that lists which modules hook or rewrite the game's functions.
//! Read-only: it hooks nothing and writes nothing but its report.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;

use framework::{Host, egui, theme};

use hook_inspector_core::fonts::{Kind as FontKind, MONO_CANDIDATES, plan_monospace};
use hook_inspector_core::snapshot::{self, Module, Recorder, Snapshot};
use hook_inspector_core::{Report, analyse_until, format, summarize, summary_line};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Plugin setting (`skse-hook-inspector.settings.json`, a `true`/`false` value): write a snapshot of
/// everything the scan read, next to the report, for offline replay. Off by default.
const CAPTURE_KEY: &str = "capture_snapshot";
static CAPTURE: AtomicBool = AtomicBool::new(false);

framework::plugin! {
    name: "skse-hook-inspector",
    load: load,
    unload: unload,
}

static HOST: OnceLock<&'static Host> = OnceLock::new();
static RESULT: Mutex<Option<(Report, String)>> = Mutex::new(None);
static STATUS: Mutex<String> = Mutex::new(String::new());
static RUNNING: AtomicBool = AtomicBool::new(false);
/// Set by [`unload`] and never cleared: the scan thread stops at its next phase boundary and no scan
/// starts again. A reloaded plugin is a new DLL copy with its own statics.
static CANCEL: AtomicBool = AtomicBool::new(false);
/// The scan thread, kept so [`unload`] can join it before the host frees the DLL. Locked only to
/// start a scan or to take the handle; never while the scan thread runs or while joining.
static SCAN_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// A lock that a panic elsewhere poisoned still holds valid data here (a string, a report), so the
/// callback paths take it over instead of panicking.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn cancelled() -> bool {
    CANCEL.load(Ordering::Acquire)
}

fn set_status(s: impl Into<String>) {
    *lock(&STATUS) = s.into();
}

fn log(line: &str) {
    use std::io::Write as _;
    if let Some(host) = HOST.get()
        && let Ok(mut f) = skse::log::append(host.skse().runtime_version, "skse-hook-inspector")
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Reads `len` bytes of this process's memory; `None` where the pages are not readable or fewer
/// than `len` bytes could be read.
fn read(address: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(GetCurrentProcess(), address as *const _, buf.as_mut_ptr().cast(), len, &raw mut got)
    };
    (ok != 0 && got == len).then_some(buf)
}

/// The file name of the module holding `address`; `None` for memory no module owns.
fn module_of(address: u64) -> Option<String> {
    let path = versionlib::module_file(address as *const _).ok()?;
    Some(path.file_name()?.to_string_lossy().into_owned())
}

/// Every module loaded in this process: file name, base and size.
fn loaded_modules() -> Vec<Module> {
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows_sys::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetModuleInformation, MODULEINFO};
    let process = unsafe { GetCurrentProcess() };
    let mut handles: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    let bytes = (handles.len() * size_of::<HMODULE>()) as u32;
    if unsafe { K32EnumProcessModules(process, handles.as_mut_ptr(), bytes, &raw mut needed) } == 0 {
        return Vec::new();
    }
    handles.truncate((needed as usize / size_of::<HMODULE>()).min(handles.len()));
    let mut out = Vec::new();
    for h in handles {
        let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
        if unsafe { K32GetModuleInformation(process, h, &raw mut info, size_of::<MODULEINFO>() as u32) } == 0 {
            continue;
        }
        let mut path = [0u16; 1024];
        let n = unsafe { GetModuleFileNameW(h, path.as_mut_ptr(), path.len() as u32) } as usize;
        let full = String::from_utf16_lossy(&path[..n.min(path.len())]);
        let name = full.rsplit(['\\', '/']).next().unwrap_or_default().to_owned();
        out.push(Module { name, base: info.lpBaseOfDll as u64, size: u64::from(info.SizeOfImage) });
    }
    out
}

/// Committed private executable regions (where hook libraries put trampolines), each capped at
/// 16 MiB, 256 MiB in all.
fn private_code() -> Vec<(u64, usize)> {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, VirtualQuery,
    };
    let exec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    let mut out = Vec::new();
    let (mut at, mut total) = (0u64, 0usize);
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let got = unsafe { VirtualQuery(at as *const _, &raw mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
        if got == 0 || mbi.RegionSize == 0 {
            break;
        }
        let start = mbi.BaseAddress as u64;
        if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect & exec != 0 && mbi.Protect & PAGE_GUARD == 0 {
            let len = mbi.RegionSize.min(16 << 20);
            if total + len > 256 << 20 {
                break;
            }
            total += len;
            out.push((start, len));
        }
        at = start + mbi.RegionSize as u64;
    }
    out
}

/// Why a scan ended without a report.
enum Stop {
    /// The plugin is unloading.
    Cancelled,
    Failed(String),
}

impl From<String> for Stop {
    fn from(e: String) -> Self {
        Self::Failed(e)
    }
}

/// Between phases of a scan: stop if the plugin is unloading.
fn checkpoint() -> Result<(), Stop> {
    if cancelled() { Err(Stop::Cancelled) } else { Ok(()) }
}

fn run_scan() {
    // SCAN_THREAD is held while the thread starts, so `unload` either sees the new handle or this call
    // sees CANCEL; nothing the scan thread needs is locked meanwhile
    let mut handle_slot = lock(&SCAN_THREAD);
    if cancelled() || RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    // the previous scan thread cleared RUNNING as its last act, so this join is immediate
    if let Some(done) = handle_slot.take() {
        let _ = done.join();
    }
    set_status("scanning...");
    let capture = CAPTURE.load(Ordering::Acquire);
    let spawned = std::thread::Builder::new().name("hook-inspector-scan".to_owned()).spawn(move || {
        scan_worker(capture);
        RUNNING.store(false, Ordering::Release);
    });
    match spawned {
        Ok(handle) => *handle_slot = Some(handle),
        Err(e) => {
            RUNNING.store(false, Ordering::Release);
            let msg = format!("scan failed: could not start the scan thread: {e}");
            log(&msg);
            set_status(msg);
        }
    }
}

fn scan_worker(capture: bool) {
    {
        let started = std::time::Instant::now();
        // once the plugin is unloading, the analysis's reads answer at once and nothing touches memory
        let live_read = |a: u64, n: usize| if cancelled() { None } else { read(a, n) };
        let live_module = |a: u64| if cancelled() { None } else { module_of(a) };
        let outcome = (|| -> Result<(Report, String, Option<Snapshot>), Stop> {
            let running = versionlib::running().map_err(|e| format!("Address Library: {e}"))?;
            let exe_path = std::env::current_exe().map_err(|e| format!("exe path: {e}"))?;
            let exe = exe_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            checkpoint()?;
            let pe = std::fs::read(&exe_path).map_err(|e| format!("reading {}: {e}", exe_path.display()))?;
            checkpoint()?;
            let base = running.base() as u64;
            let pairs: Vec<(u64, u64)> = running.db().iter().collect();
            let regions = private_code();
            checkpoint()?;
            // with capture on, the closures the analysis calls are wrapped, so the snapshot holds
            // exactly what the scan saw
            let (mut report, mut snap) = if capture {
                let rec = Recorder::new(&live_read, &live_module);
                let (report, stopped) =
                    analyse_until(&pairs, base, &pe, &exe, &regions, &|a, n| rec.read(a, n), &|a| rec.module_of(a), &cancelled);
                if stopped {
                    return Err(Stop::Cancelled);
                }
                checkpoint()?;
                let mut snap = Snapshot::new(env!("CARGO_PKG_VERSION"), &exe, &pe, base);
                snap.pairs = pairs;
                snap.regions = regions;
                snap.modules = loaded_modules();
                (report, Some(rec.finish(snap)))
            } else {
                let (report, stopped) = analyse_until(&pairs, base, &pe, &exe, &regions, &live_read, &live_module, &cancelled);
                if stopped {
                    return Err(Stop::Cancelled);
                }
                (report, None)
            };
            checkpoint()?;
            // names from skyrim-rs's function table; a medium-confidence name ends in '?'
            let names: std::collections::HashMap<u32, &sre::raw::Function> =
                sre::raw::symbols::FUNCTIONS.iter().map(|row| (row.id, row)).collect();
            for f in &mut report.findings {
                if let Some(row) = u32::try_from(f.id).ok().and_then(|id| names.get(&id)) {
                    let sure = row.confidence == sre::raw::Confidence::High;
                    f.name = Some(format!("{}{}", row.name, if sure { "" } else { "?" }));
                }
            }
            if let Some(s) = snap.as_mut() {
                s.names = snapshot::names_of(&report);
            }
            Ok((report, exe, snap))
        })();
        match outcome {
            Ok((report, exe, snap)) => {
                let text = format(&report, &exe);
                let s = summarize(&report, &exe);
                let summary = format!(
                    "{} functions changed by {} modules; {} hooked by more than one; {} with no known owner ({} of {} checked, {} ms)",
                    s.changed,
                    s.modules,
                    s.multi,
                    s.unowned,
                    s.changed,
                    report.in_code,
                    started.elapsed().as_millis()
                );
                let conflicts = snap.as_ref().map_or(0, |s| s.conflicts);
                let summary = if conflicts > 0 {
                    format!("{summary}; WARNING: {conflicts} snapshot read conflicts (game memory changed during the scan)")
                } else {
                    summary
                };
                let mut shown = "report not written".to_owned();
                // the unload check between the writes: a report and a snapshot are each written whole
                if !cancelled()
                    && let Some(host) = HOST.get()
                    && let Ok(dir) = skse::log::dir(host.skse().runtime_version)
                {
                    let path = dir.join("skse-hook-inspector-report.txt");
                    shown = match std::fs::write(&path, &text) {
                        Ok(()) => path.display().to_string(),
                        Err(e) => format!("not written: {e}"),
                    };
                    if let Some(snap) = snap
                        && !cancelled()
                    {
                        let bin = snap.to_bytes();
                        let bin_path = dir.join(snapshot::BIN_NAME);
                        let json_path = dir.join(snapshot::INDEX_NAME);
                        let written = if cancelled() {
                            Err(std::io::Error::other("plugin unloading"))
                        } else {
                            std::fs::write(&bin_path, &bin).and_then(|()| std::fs::write(&json_path, snap.index_json(bin.len())))
                        };
                        match written {
                            Ok(()) => {
                                log(&format!(
                                    "snapshot written: {} ({} bytes, {} reads), index {}",
                                    bin_path.display(),
                                    bin.len(),
                                    snap.reads.len(),
                                    json_path.display()
                                ));
                                if snap.conflicts > 0 {
                                    log(&format!(
                                        "WARNING: the snapshot holds {} overlapping reads that disagreed: the game's memory changed during the scan; the capture is a frozen view of the first answers and the replay tool exits 3",
                                        snap.conflicts
                                    ));
                                }
                            }
                            Err(e) => log(&format!("snapshot not written: {e}")),
                        }
                    }
                }
                if cancelled() {
                    log("scan cancelled: the plugin is unloading");
                    set_status("scan cancelled: the plugin is unloading");
                    return;
                }
                log(&summary_line(&report, &exe, &shown));
                set_status(summary);
                *lock(&RESULT) = Some((report, text));
            }
            Err(Stop::Cancelled) => {
                log("scan cancelled: the plugin is unloading");
                set_status("scan cancelled: the plugin is unloading");
            }
            Err(Stop::Failed(e)) => {
                log(&format!("scan failed: {e}"));
                set_status(format!("scan failed: {e}"));
            }
        }
    }
}

/// Runs on the host's reload thread before it detaches the plugin's callbacks and frees the DLL
/// (`Descriptor::unload`): stops the scan thread and waits until it has returned, so no code or
/// static of this DLL runs after the host unmaps it.
///
/// No lock is held across the join. `SCAN_THREAD` is released before it, and the scan thread takes only the
/// short `STATUS` and `RESULT` locks, which a draw callback holds for a bounded time and never
/// while waiting on anything this function holds. The host's own draining of draw callbacks comes
/// after this returns.
fn unload() {
    CANCEL.store(true, Ordering::Release);
    let handle_slot = lock(&SCAN_THREAD).take();
    if let Some(handle) = handle_slot {
        let _ = handle.join();
    }
}

fn load(host: &'static Host) -> bool {
    let _ = HOST.set(host);
    CAPTURE.store(host.settings().get_or(CAPTURE_KEY, false), Ordering::Release);
    log(&format!("loaded; snapshot capture {}", if CAPTURE.load(Ordering::Acquire) { "on" } else { "off" }));
    host.on_message(|msg| {
        if msg.kind == skse::MessagingInterface::DATA_LOADED {
            run_scan();
        }
    });
    host.add_tab("SKSE Hook Inspector").section("Hooks", draw);
    true
}

/// Set on the first draw, once the monospace family has been checked.
static FONTS_CHECKED: AtomicBool = AtomicBool::new(false);

/// The overlay builds Monospace only from `consola.ttf` and `segoeui.ttf` in the Windows font
/// folder; a CrossOver bottle with neither leaves it empty and every monospace glyph is a box.
/// On the first draw, if the family is empty in this plugin's context, give it a font from the
/// folder (or the proportional fonts) through `set_fonts`, which touches this plugin's context only.
fn ensure_monospace(ctx: &egui::Context) {
    if FONTS_CHECKED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut defs = ctx.fonts(|f| f.definitions().clone());
    let families: BTreeMap<FontKind, Vec<String>> = BTreeMap::from([
        (FontKind::Proportional, defs.families.get(&egui::FontFamily::Proportional).cloned().unwrap_or_default()),
        (FontKind::Monospace, defs.families.get(&egui::FontFamily::Monospace).cloned().unwrap_or_default()),
    ]);
    let dir = std::env::var_os("WINDIR").map(|w| std::path::PathBuf::from(w).join("Fonts"));
    // epaint 0.37.0 parses with `skrifa::FontRef::from_index(bytes, index)`; `FontData::from_owned`
    // uses index 0, so a collection is fine at 0. A font it rejects is an error there, and a bad
    // font must never reach `set_fonts` (panic=abort).
    let parses = |bytes: &[u8]| skrifa::FontRef::from_index(bytes, 0).is_ok();
    let Some(fix) = plan_monospace(&families, &MONO_CANDIDATES, |file| std::fs::read(dir.as_ref()?.join(file)).ok(), parses) else { return };
    let chosen = match fix.file {
        Some((name, bytes)) => {
            defs.font_data.insert(name.clone(), egui::FontData::from_owned(bytes).into());
            name
        }
        None => "the proportional fonts".to_owned(),
    };
    defs.families.insert(egui::FontFamily::Monospace, fix.monospace);
    ctx.set_fonts(defs);
    log(&format!("monospace font family was empty; now {chosen}"));
}

fn draw(ui: &mut egui::Ui) {
    ensure_monospace(ui.ctx());
    ui.label(lock(&STATUS).as_str());
    let mut capture = CAPTURE.load(Ordering::Acquire);
    if ui
        .checkbox(&mut capture, "Capture a snapshot on the next scan (skse-hook-inspector-snapshot.bin, for offline replay)")
        .changed()
    {
        CAPTURE.store(capture, Ordering::Release);
        if let Some(host) = HOST.get() {
            host.settings().set(CAPTURE_KEY, capture);
        }
    }
    if ui.add_enabled(!RUNNING.load(Ordering::Acquire), egui::Button::new("Scan again")).clicked() {
        run_scan();
    }
    let result = lock(&RESULT);
    let Some((report, text)) = result.as_ref() else { return };
    if report.baseline_suspect {
        ui.label(egui::RichText::new("The game file on disk differs from memory in over a fifth of functions; results are unreliable.").color(theme::DIM));
    }
    ui.label(egui::RichText::new("The full list is in skse-hook-inspector-report.txt in the SKSE log folder.").color(theme::DIM));
    egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
        for line in text.lines().take(400) {
            ui.monospace(line);
        }
    });
}
