//! Offline replay of a SKSE Hook Inspector snapshot (host, read-only).
//!
//! `cargo run -p hook-inspector-core --example replay -- <skse-hook-inspector-snapshot.bin> <SkyrimSE.exe> [report-out]`
//!
//! Checks the executable's size and SHA-256 against the snapshot, runs the scan and the trampoline
//! search with reads answered from the snapshot, and writes the report text the plugin wrote (to
//! `report-out`, or stdout). Reads the snapshot did not hold are counted on stderr and make the exit
//! code 2. A snapshot that recorded read conflicts (the game's memory changed while it was captured)
//! is reported and makes the exit code 3, which takes precedence over 2.

use hook_inspector_core::snapshot::{Replayed, Snapshot, replay};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [snap_path, exe_path, rest @ ..] = args.as_slice() else {
        eprintln!("usage: replay <snapshot.bin> <SkyrimSE.exe> [report-out]");
        std::process::exit(64);
    };
    let run = || -> Result<Replayed, String> {
        let snap = Snapshot::from_bytes(&std::fs::read(snap_path).map_err(|e| format!("{snap_path}: {e}"))?)?;
        let pe = std::fs::read(exe_path).map_err(|e| format!("{exe_path}: {e}"))?;
        let r = replay(&snap, &pe)?;
        eprintln!(
            "snapshot from plugin {}: {} pairs, {} reads, {} module queries; {} findings",
            snap.plugin_version,
            snap.pairs.len(),
            snap.reads.len(),
            snap.asked.len(),
            r.report.findings.len()
        );
        Ok(r)
    };
    match run() {
        Ok(r) => {
            match rest.first() {
                Some(out) => {
                    if let Err(e) = std::fs::write(out, &r.text) {
                        eprintln!("{out}: {e}");
                        std::process::exit(1);
                    }
                    eprintln!("report written to {out}");
                }
                None => print!("{}", r.text),
            }
            eprintln!("missed reads: {}; missed module queries: {}; read conflicts: {}", r.missed_reads, r.missed_modules, r.conflicts);
            if r.missed_reads + r.missed_modules > 0 {
                for e in &r.examples {
                    eprintln!("  missed: {e}");
                }
                eprintln!("REPLAY DIFFERS FROM THE CAPTURE: the snapshot lacks memory the analysis asked for");
            }
            if r.conflicts > 0 {
                eprintln!(
                    "WARNING: {} overlapping reads disagreed while the snapshot was captured: the game's memory changed during the scan; the capture is a frozen view of the first answers",
                    r.conflicts
                );
                std::process::exit(3);
            }
            if r.missed_reads + r.missed_modules > 0 {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("replay failed: {e}");
            std::process::exit(1);
        }
    }
}
