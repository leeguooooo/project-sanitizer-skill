# Analysis Quick-Reference Checklist

A condensed cheat sheet for the techniques explained in
`analysis-methodology.md`. Print this; keep open during an audit.

## Before opening Ghidra

- [ ] Reproduced the symptom with a minimal trigger
- [ ] Captured logs / network calls / file writes at the point of symptom
- [ ] Checked process env vars, command-line args, working directory
- [ ] Read every preference / config file the binary touches
- [ ] Identified what `/etc/hosts` / DNS / proxy / VPN setup is active
- [ ] Run `codesign -dv --verbose=4 <binary>` to know signing posture

If any of these is "skipped, I'll come back to it" — come back to it
*now*. Binary work without this baseline doubles your time-to-answer.

## Initial reconnaissance commands

```bash
# What flavour of binary
file <bin>
otool -hv <bin>                  # macOS load commands
lipo -detailed_info <bin>        # if universal, list slices + offsets

# Strings, exports, imports
rabin2 -zz <bin> > strings.txt   # cstring + reflstr + objc_methname all annotated
nm <bin> | xcrun swift-demangle > symbols.txt
otool -L <bin>                   # linked libraries

# Signature posture
codesign -dv --verbose=4 <bin>
codesign -d --entitlements - <bin>
```

## Finding the right function (in order of effort)

1. **String anchor** — `rabin2 -zz | grep` a visible UI string, find
   adrp+add pairs that load it.
2. **Swift inline string** — for ≤15-char strings not in `__cstring`,
   scan movz/movk immediates for the 2-byte chunks (e.g. "Issue" →
   `0x7349, 0x7573`).
3. **XREF rank** — list functions sorted by inbound call count,
   filter out runtime helpers (>500 callers, system frameworks).
   The chokepoint is usually in the 30–200 range with bitmask body
   shape.
4. **Backtrace at the symptom** — set breakpoint at a visible boundary
   API, trigger symptom, read frames outward past framework plumbing.
5. **Binary diff against baseline** — only useful if you have two
   versions to compare.

## Patching mindset

- Find the chokepoint first; patch one place, not 30.
- Verify the assumed write pattern: direct `strb` for non-observed
  state, `_withMutation`-wrapped write for observed state. SwiftUI
  requires the observation path.
- Save patches as a `(offset, expected_old_hex, new_hex, why)` table,
  not as a hex blob. Make it idempotent — every patch sanity-checks
  the byte before writing.
- Always write a reapply script before the second patch you make.

## Verification (do all five)

| Layer | Tool | What it proves |
|---|---|---|
| Static | `xxd`/`hexdump` | Disk bytes changed |
| Signature | `codesign -dv` | Loader still accepts |
| Loaded | `lldb memory read` after `vmmap` for slide | CPU sees new bytes |
| Behavioural | Trigger the path | Patch affects flow |
| Stability | Leave running, retest in 5 min | No reconciliation undo |

## Universal binary cheat sheet (arm64 Mach-O)

```
static_base   = 0x100000000               # arm64 Mach-O default vaddr base
slice_base    = (from fat header)         # e.g., 0xa78000 for some binaries
file_offset   = slice_base + (vaddr - static_base)
runtime_addr  = vaddr + (load_addr - static_base)
                  ^^^^^^^^^^^^^^^^^^^^^^^^
                  this is the ASLR slide
```

A "slide" of, say, `0x2670000` means every static `0x1XXXXXXX` becomes
`0x1XXXXXXX + 0x2670000` at runtime. Forget this and every lldb
memory read returns garbage.

## Common Mach-O sections worth peeking

| Section | Holds |
|---|---|
| `__TEXT.__text` | Code |
| `__TEXT.__stubs` | Lazy-bound import trampolines (12 bytes each on arm64) |
| `__TEXT.__cstring` | C string literals |
| `__TEXT.__objc_methname` | ObjC selector names |
| `__TEXT.__swift5_reflstr` | Swift property / field names |
| `__TEXT.__swift5_types` | Swift nominal type descriptors |
| `__DATA.__la_symbol_ptr` | Lazy import pointer table (paired with stubs) |
| `__DATA.__got` | Global offset table |
| `__DATA.__data` | Initialised data |
| `__DATA.__objc_classlist` | ObjC class metadata pointer table |
| `__LINKEDIT` | Symbol/string tables, code signature, dyld info |

## When to stop, write up, and share

You're done with the analysis pass when:

- You have a written description of how the binary makes the
  decision you cared about, at the level of "function X reads field Y
  and branches on condition Z".
- You can predict what the binary will do under a new input without
  running it.
- You have a verification trace showing your model matches reality.

Then run the `sanitize_project.sh` redaction pass before any sharing.
