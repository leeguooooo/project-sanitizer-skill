---
name: project-sanitizer
description: Binary analysis methodology + project sanitization workflow. Phase 1 covers the analysis playbook (function fingerprinting, XREF chokepoint heuristic, Swift/ObjC metadata + C++ RTTI exploitation, dynamic hooking trade-offs, backtrace at symptom, string xrefs incl. Swift small-string-optimization, differential analysis, observation-system awareness, anti-analysis awareness for Frida/self-hashing/PT_DENY_ATTACH, iOS FairPlay decryption) and the five-layer verification protocol. Phase 2 removes sensitive analysis artifacts and replaces internal RE terminology with neutral project language before sharing. Use for binary analysis, RE workflows, security audits, '反汇编', '逆向', '脱敏'.
---

# Project Sanitizer & Analysis Assistant

## Overview

This skill provides a workflow for reviewing projects that contain reverse-engineering artifacts. It assists in the initial analysis of binaries and automates the subsequent redaction pass before internal review or public sharing.

## Workflow

### Phase 1: Analysis & Recovery (Optional)
Use this phase to extract core information needed for "narrative reconstruction".
```bash
# Analyze a binary to extract strings/symbols
./local-skills/project-sanitizer/scripts/analyze_target.sh ./binaries/my-app
```

Methodology guidance lives in `references/`:

- **`references/analysis-methodology.md`** — eight transferable
  techniques (function fingerprinting, XREF chokepoint heuristic,
  Swift/ObjC metadata + C++ RTTI exploitation, dynamic hooking choices,
  backtrace-at-symptom, string xrefs incl. Swift SSO inline imm,
  differential analysis, observation-system awareness), a
  "when the target resists analysis" section (macOS anti-debug,
  Frida/anti-DBI detection, self-hashing watchdogs), plus the
  five-layer verification protocol and the subtleties that bite
  first-timers (universal binary offsets, ASLR slide arithmetic,
  `/etc/hosts` bypass by userspace DNS, `codesign --deep` sealed
  resources, Hardened Runtime vs App Sandbox, iOS FairPlay encryption,
  jailbreak-detection obstacles).
- **`references/analysis-checklist.md`** — condensed cheat sheet of
  the same material; keep open during an audit.

Read the methodology before reaching for a disassembler. Most
"this binary behaves weirdly" tickets resolve at the configuration
layer; binary inspection is for when cheap layers cannot explain
the behaviour.

### Phase 2: Sanitization (Essential)
Run this phase before sharing with Claude Code or uploading to GitHub.
```bash
# Scrub RE traces and rebrand
./local-skills/project-sanitizer/scripts/sanitize_project.sh .

# Preview changes without modifying files
./local-skills/project-sanitizer/scripts/sanitize_project.sh --dry-run .
```

### Phase 3: Provenance Review & Upload
1. Update `README.md` to accurately describe the project provenance and remaining third-party material.
2. Initialize a fresh Git repository.
3. Push to GitHub using `gh`.

## Resources

### scripts/sanitize_project.sh
- Deletes `analysis/`, `binaries/`, `pseudocode/`, etc.
- Recursively deletes lines containing cracking指纹 (e.g., `CRACKED`, `fake_`, `破解`).
- Globally replaces RE-related terms with neutral identifiers (e.g., `反汇编` -> `源码分析`).

### scripts/analyze_target.sh
- Extracts strings, exported symbols, and library dependencies from a target binary.
- Outputs results to an `analysis/` folder (which is later scrubbed by the sanitizer).

### references/analysis-methodology.md
- Long-form methodology for binary analysis (security audit, legacy
  archaeology, third-party SDK due diligence, crash investigation).
- Covers when to start binary work vs. exhaust configuration-layer
  investigation, the eight technique catalogue, five-layer
  verification protocol, and common subtleties.

### references/analysis-checklist.md
- Operational cheat sheet for an analyst doing an audit: initial
  recon commands, function-finding decision tree, patch verification
  matrix, Mach-O section reference, universal-binary offset arithmetic.
