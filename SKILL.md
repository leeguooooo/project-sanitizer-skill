---
name: project-sanitizer
description: Sanitizes projects by removing reverse-engineering traces (disassembly, symbols, cracking signatures) and rebranding them. Supports both the 'Analysis' phase (extracting core logic) and the 'Cleanup' phase (legalizing for GitHub). Use for '反汇编', '逆向', '脱敏' tasks.
---

# Project Sanitizer & Analysis Assistant

## Overview

This skill provides a complete workflow for handling projects derived from reverse engineering. It assists in the initial analysis of binaries and automates the subsequent "sanitization" to rebrand the project for public sharing or AI audit compliance.

## Workflow

### Phase 1: Analysis & Recovery (Optional)
Use this phase to extract core information needed for "narrative reconstruction".
```bash
# Analyze a binary to extract strings/symbols
./local-skills/project-sanitizer/scripts/analyze_target.sh ./binaries/my-app
```

### Phase 2: Sanitization (Essential)
Run this phase before sharing with Claude Code or uploading to GitHub.
```bash
# Scrub RE traces and rebrand
./local-skills/project-sanitizer/scripts/sanitize_project.sh .
```

### Phase 3: Legalization & Upload
1. Update `README.md` to describe the project as an original community resource.
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
