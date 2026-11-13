# SKSE Hook Inspector

A Skyrim SE/AE plugin that shows which SKSE plugin DLLs hook or rewrite which game functions. It reads the start of every Address Library function from the running game, compares it with `SkyrimSE.exe` on disk, follows any jump it finds through trampolines, and names the DLL that owns the target. It is read-only: it hooks nothing and changes nothing in the game.

It is built for modlist authors and plugin developers who want to know why two SKSE plugins fight over a function, or which DLL is behind a change nobody remembers installing.

## What it reports

- Which module hooks or rewrites which game function, by Address Library id, offset and (where known) name.
- Functions hooked by more than one module. These are listed first.
- Changes with no known owner, shown with the original and the current bytes so you can read the rewrite yourself.

A changed function is normal: SKSE plugins work by patching the game. The report does not say a change is a problem. It marks the rows that are worth a second look.

## Requirements

- Skyrim Runtime Extender (the plugin loader this plugin is built for) and the Address Library for SKSE Plugins.
- Tested on Skyrim Special Edition / Anniversary Edition 1.7.104 only. Other runtimes are untested.
- Windows, or Wine/CrossOver. The game executable must be the unpacked one that matches the Address Library.

## Install

With Mod Organizer 2: install the release zip as a mod. If you have an older "Skyrim Patch Map" mod (the previous name of this plugin), remove it first, or both will load and scan twice.

By hand: copy `SKSE/Plugins/skyrim-runtime-extender/skse_hook_inspector.dll` into the same folder under the game's `Data`.

## Where the output goes

All files are written to the SKSE log folder, `Documents\My Games\Skyrim Special Edition\SKSE\`:

| File | Content |
|---|---|
| `skse-hook-inspector-report.txt` | the full report |
| `skse-hook-inspector.log` | one summary line per scan and any warnings |
| `skse-hook-inspector-snapshot.bin`, `.json` | only when snapshot capture is on |

The scan runs once when the game data has loaded (about 150 ms on a large load order). The overlay tab "SKSE Hook Inspector" shows the same report and has a "Scan again" button.

## How to read the report

The header gives the counts. Every row starts with a tag:

- `[look]`: the function is hooked by more than one module, or the change has no known owner.
- `[info]`: one named owner. Nothing is hidden; this tag only sorts the rows.

After the tag come the function name (when known; a trailing `?` means a medium-confidence name), the Address Library id, the offset in the executable, the kind of change, the owner, the jump chain, and the first bytes before and after.

Kinds of change:

| Kind | Meaning |
|---|---|
| `jump at entry` | the function now starts with a jump into another module |
| `branch at +N retargeted` | a call or jump inside the first 16 bytes that the game already had now leads elsewhere |
| `branch written at +N` | a branch that was not there before, after rewritten instructions |
| `stub` | the function now returns at once, or returns 0, false or a constant |
| `returns A -> returns B` | the function already returned a constant and now returns another |
| `filled` | one byte repeated: the region was wiped or reused |
| `bytes changed` | the bytes differ but no branch with a known owner explains them |
| `> game` | after the owner's code, the game's own original instructions run (the hook calls the original) |

When several hooks are stacked on one function, the owners are listed top to bottom with `>`, and `> game` ends the chain if the original code is still reached.

## Example

```
functions checked 185681, changed 169, trampolines found 44 in 952 KiB of executable memory
Changed functions are normal: SKSE plugins work by patching the game. Worth a look: functions hooked by more than one module (0) and changes with no known owner (22).
Rows are tagged: look 22 (hooked by more than one module 0, no known owner 22), info 147 (one named owner). Nothing is filtered out.

functions per module
    26  EngineFixes.dll
     8  po3_Tweaks.dll
     4  race-compatibility-skse.dll

[info] -                                  13754 +0x01bf060  jump at entry             EngineFixes.dll > game  [40 55 53 56 57 41 54 41 -> e9 bd 0f e2 ff 41 54 41]
[info] FindFormByID                       14617 +0x01e5860  jump at entry             EngineFixes.dll         [40 57 48 83 ec 30 48 c7 -> ff 25 00 00 00 00 60 f4]
[info] Actor::vfunc_106                   37177 +0x06713e0  branch at +13 retargeted  po3_Tweaks.dll
[info] Cmd::SameRaceAsPC_Eval             21431 +0x0331450  branch written at +7      race-compatibility-skse.dll
```

## Snapshot capture and offline replay

Setting `capture_snapshot` to `true` in `Data/SKSE/Plugins/skyrim-runtime-extender/skse-hook-inspector.settings.json` (`{"capture_snapshot": true}`), or ticking "Capture a snapshot on the next scan" in the tab and pressing "Scan again", records everything the scan read from the game. The snapshot is a few MB. It lets you rebuild the exact report later, on another machine, without the game:

```
cargo run -p hook-inspector-core --example replay -- <snapshot.bin> <SkyrimSE.exe>
```

The replay refuses an executable whose size or SHA-256 differs from the one captured, and reports any read the snapshot does not hold (exit code 2). It is useful for bug reports and for testing changes to the analysis.

## Building

macOS (cross-compile to Windows): install rustup, LLVM and an `xwin`-style Windows SDK/CRT splat, then

```
git clone --recurse-submodules <this repo>
WINSYSROOT=<splat dir> scripts/build-macos.sh --release -p hook-inspector
```

The script remaps source paths so the DLL carries no build-machine paths.

Windows: with the MSVC toolchain installed,

```
cargo build --release -p hook-inspector
```

The DLL is `target/x86_64-pc-windows-msvc/release/skse_hook_inspector.dll` (or `target/release/` on Windows). Tests run on the host: `cargo build -p hook-inspector-core --examples && cargo test -p hook-inspector-core`.

## Known limits

- Function names are Address Library ids for the Anniversary Edition runtime; ids with no known name show `-`.
- On a large load order about 22 rows have no known owner. They are usually functions that a plugin disabled or wiped, not unknown hooks.
- Only the first 16 bytes of each function are compared. Patches deeper in a function, and call sites patched inside functions, are not seen.
- The recogniser for rewritten instructions covers a short list of common encodings. A rewrite it does not know is shown as `bytes changed` with the full bytes, not guessed.
- A runtime other than 1.7.104 is untested.

## License

MPL-2.0, see `LICENSE`. Third-party code is listed in `THIRD-PARTY-NOTICES.md`. Built on [skyrim-rs](https://github.com/TwistedModding/skyrim-rs).

## Credits

Author: kautsaralbaa on Nexus Mods, kxgcayh on GitHub.
