# Changelog

## 0.3.0

- Renamed from "Skyrim Patch Map" to "SKSE Hook Inspector". No change in behaviour.
- New file names: `skse_hook_inspector.dll`, `skse-hook-inspector-report.txt`, `skse-hook-inspector.log`, `skse-hook-inspector-snapshot.bin` and `.json`, `skse-hook-inspector.settings.json`. The tab is now called "SKSE Hook Inspector".
- The old and new DLLs are different files. Remove the old "Skyrim Patch Map" mod before installing this one, or both will load and scan twice. The old settings file is not migrated; snapshot capture starts off.
- Snapshot format is unchanged, so snapshots from 0.2.6 and 0.2.7 still replay.

## 0.2.7

- The report tab drew every character as a box when the Wine/CrossOver font folder had no Consolas. The plugin now falls back to Courier New, Andale Mono or Lucida Console, and only uses a font file that parses.

## 0.2.6

- Every row now starts with `[look]` (hooked by more than one module, or no known owner) or `[info]` (one named owner). Nothing is filtered out.
- The report starts with a short explanation and counts per tag. The log gets a one-line summary.
- Optional snapshot capture (setting `capture_snapshot`, or the checkbox in the tab) saves everything a scan read, plus the loaded module list, so the same report can be rebuilt offline with the `replay` example. The replay refuses a different executable and reports reads the snapshot does not hold.
- A branch is labelled `retargeted` only when the bytes before it are unchanged and it starts a recognised instruction boundary. Otherwise it reads `branch written` or `(boundary unverified)`.
- Unloading the plugin now stops a running scan first. A failure to start the scan thread is reported instead of ignored.

## 0.2.5

- A branch written after the first changed byte is now found (a rewritten start followed by a tail jump), so rows such as race-compatibility-skse hooks are attributed to their module. Shown as `branch written at +N`.
- Instruction boundaries are checked with a small recogniser so that an `e9` or `ff 25` inside an immediate is never read as a jump.

## 0.2.4

- A change at +8 or later shows the bytes from that offset, marked `@+N`.
- A row with no known owner prints the full 16-byte window before and after.

## 0.2.3

- Recognises the stub that CommonLibSSE-NG `install_context_hook` generates, so such hooks show `> game`.
- Recognises a `call` that starts inside the 16-byte window and ends outside it (`branch at +13 retargeted`).
- Short or failed memory reads can no longer panic.

## 0.2.2

- A function is reported as changed only when its bytes up to the next listed function differ. Two entries closer than 16 bytes no longer produce a false `bytes changed` on the first.
- A hook that covers the next entry keeps its owner and its lower layer.

## 0.2.1

- Function names for the ids that the skyrim-rs symbol table lists. A name ending in `?` has medium confidence.
- Hooks that load a system function before jumping (context hooks) are no longer attributed to `ntdll.dll`; system modules are skipped when following a generated thunk.
- A change after a `ret` is `bytes changed at +N`, not a disabled function. A changed return value reads `returns A -> returns B`.
- The header showed memory in MiB (0); it now shows KiB.

## 0.2.0

- Each changed function is classified: `jump at entry`, a branch inside the first 16 bytes, `stub` (returns at once, 0, false or a constant), `filled` (one repeated byte: wiped or reused), `return value changed`, or `bytes changed`.
- Chains follow up to five hops, and generated thunks are searched for a branch into another module.
- Stacked hooks: private executable memory is searched for trampolines that jump back into a function, so a hook under another hook is listed as a lower layer. Functions with several hooks are listed first.

## 0.1

- First version. At game load, and on "Scan again", compares the first 16 bytes of every Address Library function in memory with `SkyrimSE.exe` on disk. Where memory starts with a jump, follows it through trampolines and names the module that owns the target. Memory is read through `ReadProcessMemory` on the game itself, so an invalid address cannot fault. Nothing is hooked or changed.
