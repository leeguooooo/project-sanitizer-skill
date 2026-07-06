# Binary Analysis Methodology

A practical methodology for reviewing native binaries — useful for security
audits, legacy-code archaeology, third-party SDK due diligence, and crash
investigation. Distilled from real engagements; every technique here has
saved measurable hours on real targets.

Scope: this document is about **understanding** a binary you are
authorised to audit. The companion `cleanup-rules.md` covers what to
**redact** before sharing artefacts.

---

## When to start (and when to stop)

Before reaching for a disassembler, exhaust cheap configuration-layer
investigations first. Most "this binary behaves weirdly" tickets resolve
without ever opening Ghidra:

| Layer | What to check | Cost |
|---|---|---|
| Process | Environment variables, working directory, command-line args | Minutes |
| User defaults | Preferences plists, app-specific settings | Minutes |
| Filesystem | Persisted state, caches, lock files | Minutes |
| Network | DNS resolution path, captive proxies, VPN/Private-Relay interception | Tens of minutes |
| Code signing | Notarization, ad-hoc vs developer, Gatekeeper quarantine bits | Tens of minutes |

Move to binary inspection only when the cheap layers cannot explain the
behaviour. Useful **stop signals** that mean "you're past diminishing
returns at this layer, escalate":

- You have understood the state machine but every state transition is
  protected by signature/server/cache cross-checks.
- The cheap-layer change you made *appears* to land but the symptom
  doesn't move (typical for cryptographic validation paths — the change
  is silently rejected and never logged at the level you can see).
- Tooling at this layer is being routed around by something else (e.g.
  `/etc/hosts` ignored by a userspace DNS resolver — see Subtlety #4
  below).

The most common failure mode for new analysts is sinking a full working
day into the configuration layer when the answer required binary work
from minute 30.

---

## The eight techniques

### 1. Function fingerprinting (hex pattern, not address)

**Use when**: you need a patch / hook to survive across binary versions.

Record the first ~32 bytes of the function body as a `(bytes, mask)`
pair. Mask out everything that's address-relative:

| Instruction class | Stable across rebuilds? | Mask? |
|---|---|---|
| `mov`, `ret`, `nop`, `cmp imm` | Yes | No |
| `ldrb/strb` with same `Rt`, `Rn`, `imm` | Yes | No |
| Direct `bl <relative>` | No | Yes — mask all 4 bytes |
| `adrp` + `add` pair (page-relative) | No | Yes — mask both |
| `cbz`/`cbnz`/`tbz` displacement bits | Often shifts | Mask `imm19`/`imm14` |

The fingerprint becomes "the algorithmic shape of the function body,
minus its layout in the binary". For most non-trivial functions in
release builds, this pattern is stable across minor version bumps.

**Tools**: Ghidra Memory Search (`?` wildcards), IDA `.sig` files,
BinaryNinja `bv.find_next_data_with_mask`, Frida's
`Memory.scan(addr, size, pattern)`.

**Pitfall**: don't fingerprint Swift runtime helpers (`swift_retain`,
`swift_release`) — they're called millions of times and your "unique"
pattern won't be unique.

### 2. XREF count heuristic (find the chokepoint)

**Use when**: a target binary exposes many UI/behavior callsites that
all consult a shared policy.

Sort functions by inbound call count, then filter aggressively:

- Drop anything in `libswiftCore.dylib`, system frameworks, or other
  shared libraries.
- Drop functions with >500 callers (runtime helpers, allocators).
- Keep functions with 30–200 callers in your target module.
- Add a content signal: prefer functions whose body contains heavy
  `and` / `orr` / `cbnz` against masks, and especially those whose
  callers do `mvn wN, w0; and xN, xN, MASK; cbnz xN, deny_path` on
  the return value. That's the textbook shape of a permission /
  policy bitmask gate.

When XREF rank + bitmask body shape both hit, the resulting function is
almost always the centralised decision point. From a defensive
perspective, the same heuristic identifies the function that most needs
multi-source verification and tamper resistance.

### 3. Swift / ObjC metadata exploitation

**Use when**: the binary is heavily stripped but built with Swift or
Objective-C.

Even fully stripped Mach-O binaries written in modern Swift retain
significant metadata in dedicated sections:

| Section | Contents |
|---|---|
| `__swift5_types` | Nominal type descriptors (class/struct/enum names + parents) |
| `__swift5_reflstr` | Property and field names |
| `__swift5_fieldmd` | Struct/class field types and layout |
| `__swift5_proto` | Protocol conformances |
| `__objc_classname`, `__objc_methname` | ObjC class & selector names |

Practical extraction:

- `rabin2 -zz <bin>` dumps every cstring with section + vaddr; pipe
  through `grep` filters by section name.
- `xcrun swift-demangle` resolves mangled symbol names.
- `nm <bin> | xcrun swift-demangle` enumerates all exported Swift names.
- `class-dump -E <bin>` covers ObjC.

**Realistic ceiling**: in heavily Swift-internal binaries you may find
that only a small fraction of methods have exported symbols. Public
APIs of submodules are usually exported; `private`/`fileprivate`
methods in the main executable are almost never. Plan to combine
metadata extraction with technique #6 (string xrefs) when symbol
coverage is partial.

**C++ portions leak type info too.** If the binary mixes in C++ (common
in cross-platform apps and native Electron/RN modules), RTTI is the
compiler-emitted analog of Swift metadata and survives stripping:

- `c++filt _ZTI7MyClass` demangles a typeinfo symbol to
  `typeinfo for MyClass`; the typeinfo struct is
  `{vtable_for_typeinfo, name_string, base_class_ptr}`, so one match
  hands you the class name *and* its parent.
- A vtable is `[typeinfo_ptr, destructor, method0, method1, …]`; the
  polymorphic-dispatch shape is `mov rax,[rdi]; call [rax+N]` (arm64:
  `ldr x8,[x0]; ldr x9,[x8,#N]; blr x9`). Reconstruct the vtable to
  name the virtual methods.
- `std::string` uses its own SSO (≤15 chars inline), layout
  `{char* ptr, size_t size, union{size_t cap, char buf[16]}}` — the C++
  cousin of the Swift SSO in technique #6, and it hides short strings
  from `__cstring` xrefs the same way.

### 4. Dynamic hooking (runtime over rewrite)

**Use when**: you need fast iteration, or you want symbol-based
hooks that survive binary updates.

Tools, ranked by friction:

- **Frida** — fastest for prototyping. `Interceptor.attach(addr, {...})`
  works regardless of the function's symbol status; combine with
  technique #1 (fingerprinting) to find the address at injection time.
- **`fishhook`** — for lazy-bound C function imports (PLT-equivalent
  slots).
- **`DYLD_INSERT_LIBRARIES`** — classic but blocked by Hardened Runtime,
  Library Validation entitlement, and SIP. To make it work you must
  resign the host with relaxed entitlements, which is itself a binary
  modification.
- **`mach_inject`** — older, more invasive, requires root.

**Caveats specific to modern Swift**:

- ObjC selectors are stable; Swift mangled symbols often are not
  (compiler version changes, generic specialisations, inlining).
- `private`/`internal` Swift functions frequently have no exported
  symbol at all; runtime symbol lookup will fail and you'll fall back
  to address-based hooks anyway. Plan for both.

### 5. Backtrace at the moment of behaviour

**Use when**: you can reproduce the symptom but can't statically find
which code path triggers it.

Attach a debugger at runtime, set a breakpoint at the visible boundary
(a known UI presentation API, a network call, a file write), trigger
the behaviour, and read the call stack outward toward the policy code:

- For UI presentation on macOS: `breakpoint set -F
  '-[NSWindow makeKeyAndOrderFront:]'` or
  `'-[NSWindowController showWindow:]'`.
- For network: `breakpoint set -F '-[NSURLSession dataTaskWithRequest:...]'`
  or set a syscall-level breakpoint on `connect`.
- For state observation systems: the relevant frames usually have
  names like `partial apply for closure #N in ...` — that's where the
  business logic decision lives, wrapped in framework plumbing.

**Modern Swift caveat**: SwiftUI / Combine / Observation will add 5–15
framework frames between the policy decision and the visible side
effect. Read past `_ViewBodyEvaluator`, `ObservationRegistrar._access`,
`partial apply`, and similar generic plumbing to reach the decision
code. `thread backtrace --extended` reveals closure capture context.

### 6. String xrefs (anchor through visible strings)

**Use when**: you know what text the binary displays and want to find
the code that decides to display it.

Standard playbook (works for `__cstring`):

1. Find the cstring address: `rabin2 -zz | grep "<text>"`.
2. Find adrp+add instruction pairs that load that address.
3. Each match is a callsite that consumes the string. From there, walk
   the surrounding control flow to find the decision.

**Modern Swift caveat** — Small String Optimization:
- Swift strings ≤15 bytes are encoded **inline** in instruction
  immediates (mov/movk imm16), not as memory references.
- They do not appear in standard `__cstring` xref tools.
- To find them, scan for the relevant 2-byte chunks in mov/movk
  immediates. A short string like "Issue" appears as
  `movz w?, #0x7349` (the bytes 'I','s' little-endian) followed by
  `movk w?, #0x7573, lsl #16` (the bytes 'u','e').

This split between dereference-style and inline-imm strings is one of
the more reliable signs that the binary is Swift-heavy.

### 7. Differential analysis (diff against a known baseline)

**Use when**: you have two adjacent versions of the same binary, or a
known-clean reference build alongside the audit target.

Run a function-level diff: BinDiff (Zynamics, Ghidra plugin) or
Ghidra's own VTMatch will produce a similarity ranking. The functions
with similarity in the 70–95% band — high enough to be the "same
function" but low enough to mean something changed — are the ones that
were touched between builds.

For security review this surfaces "what did the vendor harden in this
release"; for debugging it surfaces "what changed that might have
caused the regression".

### 8. Observation-system awareness (modern Swift / SwiftUI)

**Use when**: the target uses `Observation` (macOS 14+) or
`@Published`/`ObservableObject`. The symptom looks like "I modified
state but the UI didn't refresh".

Writes to observable state must flow through the observation registrar
to notify subscribers:

- Direct memory writes (`strb` of a new value into the storage byte)
  modify the data but **do not trigger UI re-render**.
- Reads in views must be inside an `_access(...)` wrapper to register
  the dependency.

Practical consequences:

- Patches that only rewrite direct memory writes will be invisible to
  SwiftUI even when the underlying value is verifiably changed
  (confirmed via `lldb memory read`).
- Patches that rewrite the observation-wrapped write path do propagate.
- Mixed approaches (direct write for fast-path, observation for
  notification) are common and both must be handled.

This is a Swift-era-specific gotcha. Analysts whose intuition was
built on KVO / `NSNotificationCenter` will lose hours here if not
warned. Test re-render explicitly after any state mutation; don't
assume.

---

## AI-assisted analysis (use it, but verify)

An LLM is now a legitimate accelerant for the tedious parts of this
work — provided you never trust its output unchecked. Two uses pay off:

- **Signature / semantic recovery where symbols are missing.** This
  directly relieves the technique-#3 ceiling: on undocumented macOS
  private frameworks and stripped ObjC, feeding call-site *usage
  patterns* to an LLM to infer method signatures and parameter types
  has been reported to lift ObjC signature recovery from ~15% (pure
  static) to ~86% (the MOTIF approach). The same works for renaming
  decompiled functions, guessing struct layouts, and identifying a
  crypto primitive from its round structure and constants.
- **Neural decompilation with a verification loop.** LLM-to-source
  tools are only trustworthy when closed against ground truth:
  decompile → recompile → diff/behaviour-compare against the original,
  and feed failures back. The feedback loop, not model size, is what
  makes the output usable; treat any un-recompiled LLM decompilation as
  a hypothesis, not a result.

**Hard limits — do not paper over these:** virtualized/VM-obfuscated
code, indirect calls (vtables, function pointers), aggressive inlining,
and functions past the context window all defeat current tools. And the
sanitization rule still applies: **do not paste a confidential target's
bytes or decompilation into a third-party model** any more than you'd
upload it to a cloud deobfuscator — use a local model for sensitive
work.

---

## When the target resists analysis

A hardened binary doesn't just sit there — it looks for you. If your
dynamic techniques (#4, #5) silently die, the target is probably
detecting the tooling rather than crashing on its own. Recognise the
three families before assuming your setup is broken:

### Anti-debug (macOS)

The macOS-native move is `PT_DENY_ATTACH` — the process calls
`ptrace(PT_DENY_ATTACH, …)` early, and any subsequent debugger attach
kills it. It shows up as an early `ptrace` / `syscall` call with a
first argument of `0x1f` (31). Neutralise it by breakpointing `ptrace`
before it runs and returning early, or by patching the call site. The
`sysctl(KERN_PROC, …)` + `P_TRACED` flag check is the passive cousin:
it reads its own process flags rather than blocking attach, so it needs
a `sysctl` hook, not a `ptrace` one.

### Anti-DBI (Frida / instrumentation detection)

Directly relevant to technique #4, because Frida is the first tool that
section reaches for. A target that expects Frida checks for it:

- Scans its own memory map (`/proc/self/maps` on Linux; `dyld`
  image list / `vm_region` on macOS) for `frida`, `gadget`, `substrate`.
- Probes Frida's default TCP port (27042) on loopback.
- Reads the prologue bytes of common libc functions and bails if it
  sees an inline-hook trampoline (`0xE9`/`0xFF` on x86, a `b`/`br` where
  a stack-frame setup should be).
- Enumerates its own threads for Frida's helper names (`gmain`,
  `gdbus`, `frida-*`).

The bypass is itself a Frida hook — intercept the detection primitive
(`strstr`/`open`/`fopen`/the map-reader) and lie about the result — or
switch to a no-instrumentation path entirely (emulation under Qiling,
or a hardware-breakpoint debugger that never modifies code). If a hook
that worked yesterday silently stops firing, suspect detection before
you suspect a stale address.

### Code-integrity / self-hashing watchdogs

This is the mechanism behind verification **layer 5** below — the
reason a patch that lands cleanly gets reverted 30 seconds later. A
background thread recomputes a CRC32/SHA-256 over `__text` on a timer
and, on mismatch, either restores the original bytes, zeroes a secret,
or exits:

```c
while (1) {
    if (crc32(text_start, text_size) != saved_crc) { /* undo / kill */ }
    usleep(100000);
}
```

Any static patch trips it. Options, cheapest first: use hardware
breakpoints (DR0–DR3 / arm64 watchpoints — they don't modify code so
the hash stays valid), hook the hash function to return the expected
value, kill the watchdog thread, or emulate instead of patch. Whichever
you pick, layer-5 stability testing is what *reveals* the watchdog in
the first place — so never skip it.

---

## Mutating a C++ container field at runtime (without crashing the target)

Reading a field is safe; *writing* one is where you crash the process.
The trap is any field whose in-memory form is runtime-dependent — a
`std::string` (or any small-buffer-optimised container) is the classic
one, and it will corrupt the heap the moment you blind-write it.

Recall the libc++ `std::string` dual form (technique #3): a short string
keeps its characters **inline**; a long string stores a **heap pointer**
at offset +0, size at +8, capacity at +0x10, with the long/short flag in
the object's last byte. Which form is live is decided at runtime by the
string's length.

**Why blind-writing crashes.** If you assume "short" and write inline
ASCII bytes over a field that currently holds a *long* string, you
overwrite the heap data pointer (and the size word after it) with your
characters. Nothing faults immediately. Then the next allocator
operation treats your ASCII as a freelist pointer and the process dies
with a heap-corruption abort — libc++/libmalloc reports
`BUG IN CLIENT OF LIBMALLOC: memory corruption of free block`, and the
fault address is the field's pointer/size region (base+0x8), not your
write site. The crash is displaced from the cause, which is what makes
it confusing.

Two safe ways to change such a field:

1. **Rebuild the whole object self-consistently — but read the old flag
   first.** Write all bytes of the object into one valid form
   (inline+size for short, ptr+size+cap for long), never leaving a state
   where the flag disagrees with the contents. Crucially, before
   overwriting, read the old flag byte: if the old form was *long*, free
   its heap buffer first, or you leak the block the allocator still
   thinks is live. Picking the *new* form needs no old-flag read; safely
   reclaiming the *old* storage does.
2. **Better — don't overwrite the destination at all; swap the source of
   the assignment.** Find the upstream call that populates the field
   (`basic_string::assign` / `operator=` / the constructor) and replace
   the *source argument* passed into it, letting the library allocate and
   manage storage. Zero manual heap manipulation means the heap cannot be
   corrupted. This is almost always the right hijack primitive for a
   container-typed field: change *what gets assigned*, not the bytes of
   the destination.

The same reasoning applies to any type that owns a heap resource behind a
value-typed field (`std::vector`, `shared_ptr` control blocks, Swift
class-backed properties): patch through the type's own mutation path, not
by poking its representation.

`scripts/lldb_std_string_field.py` is a reusable LLDB skeleton for this:
`sstr_dump` reads and types the object (run it across fires to detect
register aliasing), `sstr_set` does the crash-safe rebuild (reads the old
flag, frees the old heap buffer), and the module documents the
swap-the-assignment-source pattern.

---

## Verification: the five layers

After any non-trivial change — a patch, a hook, a configuration tweak —
verify all five layers before declaring success:

1. **Static**: bytes on disk reflect the intended change
   (`xxd` / `hexdump`).
2. **Signature**: the binary still satisfies its loader's signature
   requirements (`codesign -dv --verbose=4` on macOS).
3. **Loaded**: bytes in the running process's memory match the disk
   bytes, after accounting for ASLR slide
   (`vmmap <pid>` → load address; `lldb` memory read at
   `static_vaddr + (load_addr - static_base)`).
4. **Behavioural**: triggering the relevant code path produces the
   expected observable change.
5. **Stability**: leave the process running long enough to confirm
   the change isn't getting overwritten by a periodic check or
   reconciliation timer.

The most common failure mode is shipping after layer 1 only. Layer 3
catches "I edited the wrong copy of the binary" and "ASLR slide off by
the static base"; layer 5 catches "the patched path runs at init but
some other path rewrites the value 30 seconds later".

---

## Subtleties that bite first-timers

- **Universal binaries have nested offsets.** A Mach-O universal
  binary's `arm64` slice starts at a file offset that's not zero. If
  you compute a patch location as `static_vaddr - 0x100000000`, you
  get the *slice* offset, not the *file* offset. Add the slice base
  (from the fat header) to get the byte offset to seek in the
  universal file.
- **ASLR slide is not the load address.** `slide = load_addr -
  static_base`, where `static_base` is `0x100000000` for arm64
  Mach-O. Forgetting this offsets every runtime address by 4 GiB.
- **`codesign --deep` reads sealed resources.** Some apps include
  vendor-specific sentinel files under `Contents/` that get sealed
  into the signature. Standard `codesign --force --sign -` may fail
  with `bundle format unrecognized` until you move the sentinel out,
  sign, and put it back.
- **`/etc/hosts` is not the network ground truth.** Cloudflare WARP,
  iCloud Private Relay, corporate DNS-over-HTTPS clients, and most
  custom userspace resolvers route DNS queries around the system
  resolver. `nslookup` reading real-internet IPs while `/etc/hosts`
  says otherwise is the diagnostic signature.
- **Hardened Runtime ≠ App Sandbox.** Some hooking tools fail
  because of Hardened Runtime (which blocks
  `DYLD_INSERT_LIBRARIES`), not because of App Sandbox (which
  restricts filesystem and IPC). Check `codesign -d --entitlements
  -` to know which constraint you're hitting.
- **An App Store iOS binary is encrypted — static analysis returns
  garbage until you decrypt.** FairPlay DRM leaves the on-disk
  `__TEXT` encrypted; `strings`/`class-dump`/Ghidra all see noise.
  Check first: `otool -l <bin> | grep -A4 LC_ENCRYPTION_INFO` — a
  `cryptid` of `1` means encrypted. You must dump the decrypted image
  from a running process on a jailbroken device (`frida-ios-dump`,
  Clutch, bfdecrypt) before any of the technique catalogue applies.
  macOS apps and Simulator builds are not FairPlay-encrypted, so this
  bites only on real-device iOS work.
- **Jailbreak detection blocks the device you were going to analyse
  on.** Before a target even reaches its policy code it may check for
  `/Applications/Cydia.app`, `/bin/sh`, `/private/var/lib/apt`, a
  successful `fork()`, or substrate/substitute images, and refuse to
  run. It's the same obstacle class as anti-DBI: hook the probe
  (`access`/`stat`/`fopen`) and return "not found", or run on a device
  whose jailbreak is already hidden.
- **A field reached through a register (`xN+off`) is only that field on
  the path where `xN` holds the expected base.** Register allocation
  reuses the same register for different objects across call paths, so
  `[xN, #off]` at a shared breakpoint can be your struct on one entry
  and an unrelated object on another. The tell-tale is the *same*
  `(breakpoint, register, offset)` reading as empty on one fire and
  populated with something else on another — that is register aliasing,
  not a field that moved or fills late. Before trusting (let alone
  writing) such a field, confirm the register's provenance: disassemble
  back to where `xN` was last loaded and verify it is the object you
  think it is on *this* path.

---

## Building a runbook for your target

Every binary you audit deserves a small text file capturing:

1. **Versions audited**: SHA-256 of the binary file, OS version where
   tests ran, hardware architecture.
2. **Static map**: load address (slice base for universal), key
   function addresses (with their fingerprints from technique #1),
   relevant string section addresses.
3. **Field offsets**: any structure layouts you reverse-engineered
   (LicenseManager has `state` at +0x10, etc. — for your case,
   substitute your own findings).
4. **Hooks/patches table** if you applied any: `(location, expected
   old bytes, new bytes, rationale)` with one line per change.
5. **Verification log**: which of the five layers you confirmed and
   how.

The discipline pays off the second time you have to audit a similar
binary. The runbook accelerates from "weeks" to "hours".

---

## Further reading

- *The Mac Hacker's Handbook* (Miller & Zovi) — older but the chapter
  on Mach-O internals is still the clearest treatment.
- *Practical Binary Analysis* (Andriesse) — ELF-flavoured but the
  static/dynamic methodology generalises directly.
- Apple's `dyld` source — read `dyld3/MachOFile.h` to understand the
  metadata layout your tools surface.
- Frida documentation — `frida-trace` is the single best teaching
  tool for "what does this binary actually call at runtime".

---

*The anti-analysis, iOS FairPlay, and C++ RTTI/SSO notes adapt
platform-specific techniques from
[`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill)
(MIT), narrowed to the macOS/iOS + Swift scope of this document.*
