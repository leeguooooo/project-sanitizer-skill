# Deobfuscating OLLVM-Family Protected Binaries

Commercial macOS/iOS apps — and the third-party SDKs they embed —
frequently ship ARM64 dylibs hardened with an Obfuscator-LLVM
descendant. If a function's decompilation is a giant `switch` with no
logical flow between cases, or its body has ballooned with unreachable
branches and grotesque arithmetic, you are looking at OLLVM, not clever
engineering. This document is the recovery playbook.

Scope note: this narrows the broader RE community's OLLVM material to
what an ARM64 macOS/iOS auditor actually hits. Android `.so`/APK and
CTF-only specifics are omitted.

---

## Step 1 — identify the *variant* before picking a tool

"OLLVM" in 2026 is a family, not one tool. The counter-move differs per
variant, so classify first from the disassembly:

| Variant | Tell-tale signs | Counter-move |
|---|---|---|
| **Original OLLVM** | plain `sub` + `bcf` + `fla` | any standard tool |
| **Hikari** | string encryption, indirect branching, function wrapper | decrypt strings first, then fix indirect jumps |
| **Hikari-LLVM15** | + anti-debug, anti-hook, constant encryption (closed source) | constants decrypt at runtime — emulate the stub |
| **goron / Arkari** | indirect branch/call via `BR x8` (not `switch`) | set the data segment read-only, then the jump target often becomes statically solvable |
| **Pluto / Polaris** | MBA + a deliberate **"Trap Angr"** pass | angr will path-explode — switch to d810-ng or Unicorn |
| **O-MVLL** | Python-driven passes; anti-hooking, MBA, opaque constants | common on modern iOS hardening; layer normally |
| **amice / VMP-family** | control flow is a **VM dispatch loop** | *not* plain flattening — recover the VM handler table, don't run a deflattener |

Fastest disambiguator: if angr blows up, suspect Trap Angr (Pluto/
Polaris). If the dispatcher uses `BR x8` instead of a switch, suspect
goron/Arkari. If it's a `while(1)` state machine with no switch at all,
it's Hodur-style.

## Step 2 — recognise the three core passes

- **Control-flow flattening (`fla`)** — entry jumps to one dispatcher
  block; real blocks each end by writing a *state variable* and jumping
  back. CFG looks star-shaped.
- **Bogus control flow (`bcf`)** — unreachable fake branches guarded by
  *opaque predicates* (e.g. `x*(x+1) % 2 == 0`, always true, unprovable
  to a disassembler). Inflates the body with dead code.
- **Instruction substitution (`sub`) → MBA** — simple ops rewritten as
  equivalent Mixed Boolean-Arithmetic, e.g. `a + b → (a ^ b) + 2*(a & b)`.

## Step 3 — deobfuscate in layers (order matters)

Peel outermost first; doing it out of order leaves residue:

1. **bcf** — remove opaque predicates (d810-ng opaque-predicate removal,
   or symbolic execution).
2. **fla** — unflatten (see tool table).
3. **sub/MBA** — simplify expressions last.

Then re-check: did the function shrink, did the CFG go from star to
chain/tree, and does a Frida hook on the recovered function confirm the
logic? Nested flattening needs **iteration** — re-mark each new
dispatcher that appears after the first pass.

## Step 4 — tool selection

| Situation | First choice | Notes |
|---|---|---|
| IDA + Hex-Rays, local | **d810-ng** | open source, Z3-backed, widest variant coverage — the default |
| IDA + Hex-Rays, strongest result | obpo-plugin | microcode + concolic; **⚠ uploads the target function to a cloud server** |
| Binary Ninja | ollvm-breaker | ships Android `.so` samples; API-driven |
| No GUI, ARM64 dylib | **deollvm** (Unicorn) or angr | ARM64 is the iOS/macOS case |
| No GUI, scriptable, x86/x64 | ollvm-unflattener (Miasm) | BFS multi-layer |
| MBA-heavy | d810-ng MBA simplifier / SiMBA | Z3-validated |

**Sanitization tie-in:** obpo-plugin gives the best deflattening but
sends the function's bytes to a third-party server. For any binary under
audit that is confidential — an unreleased build, a customer's app, a
sample tied to a non-public finding — treat that upload the same way
Phase 2 treats leaking analysis artifacts: **use local tools only**
(d810-ng, angr, Unicorn). Never upload a sensitive target to a cloud
deobfuscator.

## MBA simplification identities

Static reference for the common `sub`-pass rewrites:

```
(a | b) + (a & b)   → a + b
(a | b) - (a & b)   → a ^ b
(a ^ b) + 2*(a & b) → a + b
(a | b) & ~(a & b)  → a ^ b
~(~a & ~b)          → a | b        # De Morgan
a + (~b) + 1        → a - b
```

Tools: d810-ng MBA simplifier (in-decompiler, Z3-validated), SiMBA
(`pip install simba-simplifier`) for batch expression work, or Z3
directly when template matching fails.

## Common traps

| Symptom | Cause | Fix |
|---|---|---|
| angr path-explodes / crashes | Pluto/Polaris Trap-Angr pass | switch to d810-ng or Unicorn |
| deflatten leaves function still messy | opaque predicates not removed first | do bcf before fla |
| indirect-jump deflatten fails | goron/Arkari `BR x8` dispatcher | set data segment read-only first |
| strings invisible in the decompiler | Hikari string-encryption pass | emulate the decrypt stub in Unicorn, dump plaintext |
| "flattening" won't come apart at all | amice VM-flatten / instruction virtualization | it's a VM, not fla — recover the handler table |
| nested flattening half-cleaned | single pass clears one layer | iterate: re-mark each new dispatcher |

---

*Distilled from the OLLVM material in
[`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill)
(MIT), narrowed to the ARM64 macOS/iOS scope of this skill. Tool
landscape reflects 2026 community activity — verify each project is
still maintained before relying on it.*
