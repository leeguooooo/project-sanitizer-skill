# Cleanup Rules Reference

This document outlines the specific targets of the project sanitizer.

## Directory Removal
The following directories are removed as they typically contain raw reverse-engineering output:
- `analysis/`: Demangled symbols, string lists, and binary metadata.
- `binaries/`: Original Mach-O or ELF binaries extracted from the target.
- `disasm/`: Full assembly listings (`otool`, `objdump`, `radare2`).
- `metadata/`: Plist files, code signatures, and header dumps.
- `pseudocode/`: Decompiled C/Swift pseudo-code.
- `.build/`: Build artifacts that may contain paths to the original environment.
- `resources/Hooks`: Binary hooks used for session redirection.

## Keyword Scrubbing (Aggressive Deletion)
Lines containing these keywords are deleted entirely, as they are hallmarks of "cracking" tools:
- `CRACKED`
- `fake_signature`, `fake_instance`, `fake_machine_hash`, `fake_trial_signature`
- `cracked@example.com`
- `2099-12-31` (Hardcoded future expiration)
- `trial_days_remaining`

## Rebranding (Global Search & Replace)
These terms are replaced with neutral or context-appropriate alternatives:
- `Mach-O` → `Native Binary`
- `Ghidra` / `Hopper` → `Static Analysis`
- `radare2` → `Debugger`
- `objdump` / `otool` → `Disassembler`
- `Reconstructed` → `Core`
- `Reverse Engineering` → `Project Assets`
- `vibe-island-reverse` → `vibe-island`
- `vibe-island-reconstructed` → `vibe-island-core`

## Best Practices
- **Run on a copy**: Always sanitize a duplicate of your project to avoid accidental data loss.
- **Manual Review**: After running the automated script, manually inspect `README.md` and any UI-related strings to ensure the narrative remains consistent.
- **Git Init**: Start a fresh Git history (`git init`) after sanitization to ensure the commit history doesn't leak original file states.
