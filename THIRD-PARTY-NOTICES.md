# Third-party notices

SKSE Hook Inspector is licensed under MPL-2.0 (see `LICENSE`). The DLL it builds contains the following third-party code.

## skyrim-rs

The plugin framework, overlay, SKSE bindings and Address Library reader come from [skyrim-rs](https://github.com/TwistedModding/skyrim-rs) by TwistedModding (crates `skse`, `crash`, `skyrim`, `hook`, `versionlib`, `framework`, `skyrim-sre`, `overlay`), licensed under MPL-2.0 (no copyleft exception). It is included as a git submodule in `extern/skyrim-rs`. Its table of game function names (`sre` symbol names) is compiled into the DLL and is most of its size.

## Address Library

The plugin reads the Address Library for SKSE Plugins database files at runtime (through skyrim-rs `versionlib`) to learn which game functions exist. No Address Library data is shipped here.

## MinHook

skyrim-rs builds the `minhook` crate, which compiles in MinHook by Tsuda Kageyu and the Hacker Disassembler Engine by Vyacheslav Patkov (BSD-2-Clause):

```
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Rust crates

Crates from crates.io in the dependency tree of the DLL, grouped by their declared license (generated from `cargo metadata` for the `x86_64-pc-windows-msvc` target, normal dependencies, procedural-macro crates excluded). For "OR" expressions the plugin is used under the first-listed option that is permissive (MIT or Apache-2.0, or the Zlib/BSD choice); the full license texts are in each crate's source package and in the skyrim-rs `THIRD-PARTY-NOTICES.txt`.

### MIT OR Apache-2.0

accesskit 0.25.2, ahash 0.8.12, arrayvec 0.7.8, bitflags 2.13.2, cfg-if 1.0.5, ecolor 0.37.0, egui 0.37.0, either 1.19.0, emath 0.37.0, epaint 0.37.0, euclid 0.22.14, font-types 0.12.7, hashbrown 0.17.1, itertools 0.15.0, lock_api 0.4.14, log 0.4.35, memmap2 0.9.12, num-traits 0.2.19, once_cell 1.21.4, parking_lot 0.12.5, parking_lot_core 0.9.12, polycool 0.4.0, profiling 1.0.18, read-fonts 0.41.0, scopeguard 1.2.0, skrifa 0.44.0, smallvec 1.16.5, thiserror 2.0.21, unicode-segmentation 1.13.3, windows 0.62.2, windows-collections 0.3.2, windows-core 0.62.2, windows-future 0.3.2, windows-link 0.2.1, windows-numerics 0.3.1, windows-result 0.4.1, windows-strings 0.5.1, windows-sys 0.61.2, windows-threading 0.2.1

### Apache-2.0 OR MIT

color 0.3.3, fearless_simd 0.4.1, glifo 0.3.0, kurbo 0.13.1, linebender_resource_handle 0.1.1, nohash-hasher 0.2.0, peniko 0.6.1, pin-project-lite 0.2.17, uuid 1.29.2, vello_common 0.2.0, vello_cpu 0.2.0

### MIT

harfrust 0.12.0, tracing 0.1.44, tracing-core 0.1.36

### (MIT OR Apache-2.0) AND Unicode-3.0

unicode-properties 0.1.5

### Apache-2.0

unicode-general-category 1.1.0

### Apache-2.0 OR GPL-2.0-only

self_cell 1.3.0

### BSD-2-Clause OR Apache-2.0 OR MIT

zerocopy 0.8.63

### MIT AND BSD-2-Clause

minhook 0.9.0

### MIT/Apache-2.0

guillotiere 0.7.0

### Zlib

foldhash 0.2.0

### Zlib OR Apache-2.0 OR MIT

bytemuck 1.25.2
