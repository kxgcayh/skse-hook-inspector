//! The replay example's exit codes: 0 for a clean replay, 3 when the snapshot recorded read conflicts.

use std::path::PathBuf;
use std::process::Command;

use hook_inspector_core::snapshot::Snapshot;

/// `target/<profile>/examples/replay`: the nearest ancestor of this test binary that has an
/// `examples/replay` (`deps/` on older Cargo, `build/<pkg>/<hash>/out/` on Cargo 1.100).
fn example() -> PathBuf {
    let name = format!("replay{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe().unwrap();
    exe.ancestors().map(|a| a.join("examples").join(&name)).find(|p| p.exists()).unwrap_or_else(|| exe.join("examples").join(name))
}

fn run(conflicts: u64) -> (Option<i32>, String) {
    let exe = example();
    assert!(exe.exists(), "build the example first: {}", exe.display());
    let dir = std::env::temp_dir().join(format!("hook-inspector-replay-cli-{}-{conflicts}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pe = vec![0x4Du8; 64];
    let mut snap = Snapshot::new("0.2.6", "SkyrimSE.exe", &pe, 0x1_4000_0000);
    snap.conflicts = conflicts;
    std::fs::write(dir.join("s.bin"), snap.to_bytes()).unwrap();
    std::fs::write(dir.join("exe"), &pe).unwrap();
    let out = Command::new(exe).arg(dir.join("s.bin")).arg(dir.join("exe")).arg(dir.join("report.txt")).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_clean_replay_exits_zero() {
    let (code, err) = run(0);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("read conflicts: 0"), "{err}");
}

#[test]
fn a_snapshot_with_read_conflicts_prints_a_warning_and_exits_three() {
    let (code, err) = run(2);
    assert_eq!(code, Some(3), "{err}");
    assert!(err.contains("WARNING: 2 overlapping reads"), "{err}");
}
