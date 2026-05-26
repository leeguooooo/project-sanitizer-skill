#!/usr/bin/env bash
set -euo pipefail

# Project Sanitization Script v2
# Removes reverse engineering traces and rebranding logic (Global/Chinese support)

usage() {
    echo "Usage: $0 [--dry-run] <target-directory>"
}

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    shift
fi

TARGET_DIR=${1:-}

if [[ -z "$TARGET_DIR" ]]; then
    usage
    exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: Directory $TARGET_DIR does not exist." >&2
    exit 1
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd -P)"

if [[ "$TARGET_DIR" == "/" || "$TARGET_DIR" == "$HOME" ]]; then
    echo "Error: Refusing to sanitize unsafe target: $TARGET_DIR" >&2
    exit 1
fi

echo "--- Sanitizing: $TARGET_DIR ---"
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run enabled; no files will be changed."
fi

run_rm_dir() {
    local relative_path=$1
    local path="${TARGET_DIR:?}/$relative_path"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "Would remove directory: $relative_path"
        return
    fi

    if [[ -d "$path" ]]; then
        rm -rf -- "$path"
        echo "Removed directory: $relative_path"
    fi
}

run_rm_file() {
    local relative_path=$1
    local path="${TARGET_DIR:?}/$relative_path"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "Would remove file: $relative_path"
        return
    fi

    if [[ -f "$path" ]]; then
        rm -f -- "$path"
        echo "Removed file: $relative_path"
    fi
}

escape_sed_pattern() {
    # shellcheck disable=SC2016
    printf '%s' "$1" | sed 's/[.[\*^$()+?{}|/]/\\&/g'
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[\/&|]/\\&/g'
}

sed_in_place() {
    local expression=$1
    local file=$2

    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$expression" "$file"
    else
        sed -i "$expression" "$file"
    fi
}

for_matching_text_files() {
    local keyword=$1
    local callback=$2
    local file

    while IFS= read -r -d '' file; do
        if grep -Iq . "$file" && grep -Fq -- "$keyword" "$file"; then
            "$callback" "$keyword" "$file"
        fi
    done < <(find "$TARGET_DIR" -type f ! -path '*/.git/*' -print0)
}

delete_matching_line() {
    local keyword=$1
    local file=$2
    local pattern
    pattern="$(escape_sed_pattern "$keyword")"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "Would clean keyword '$keyword' from: $file"
        return
    fi

    sed_in_place "/$pattern/d" "$file"
    echo "Cleaned keyword '$keyword' from: $file"
}

replace_keyword() {
    local key=$1
    local file=$2
    local value=$3
    local pattern replacement
    pattern="$(escape_sed_pattern "$key")"
    replacement="$(escape_sed_replacement "$value")"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "Would replace '$key' with '$value' in: $file"
        return
    fi

    sed_in_place "s|$pattern|$replacement|g" "$file"
    echo "Replaced '$key' with '$value' in: $file"
}

# 1. Remove sensitive directories (expanded)
folders_to_remove=("analysis" "binaries" "disasm" "metadata" "pseudocode" ".build" "resources/Hooks" "recovered_src" "re-output")
for folder in "${folders_to_remove[@]}"; do
    run_rm_dir "$folder"
done

# 2. Remove sensitive files
files_to_remove=("DISASSEMBLY-SUMMARY.txt" "MANIFEST.txt" "RE-GUIDE.md" "cracking_log.txt")
for file in "${files_to_remove[@]}"; do
    run_rm_file "$file"
done

# 3. Aggressive keyword deletion (CRACKED, fake_, and Chinese terms)
# These lines are deleted entirely
keywords=(
    "CRACKED" "fake_signature" "fake_instance" "fake_machine_hash" 
    "fake_trial_signature" "cracked@example.com" "2099-12-31" 
    "trial_days_remaining" "licenseKey" "LSLicenseKey"
    "破解" "授权过期" "试用期" "过期时间" "伪造签名"
)

for kw in "${keywords[@]}"; do
    for_matching_text_files "$kw" delete_matching_line
done

# 4. Keyword replacement (Mach-O, RE terms, Chinese terms)
replacements=(
    "Mach-O|Native Binary"
    "Ghidra|Static Analysis"
    "Hopper|Static Analysis"
    "radare2|Debugger"
    "objdump|Disassembler"
    "otool|Disassembler"
    "Reconstructed|Core"
    "reconstructed|core"
    "Reverse Engineering|Project Assets"
    "disassembly|source analysis"
    "pseudocode|core logic"
    "vibe-island-reverse|vibe-island"
    "vibe-island-reconstructed|vibe-island-core"
    "反汇编|源码分析"
    "逆向工程|系统重构"
    "逆向|重构"
    "反编译|代码生成"
)

for pair in "${replacements[@]}"; do
    key=${pair%%|*}
    val=${pair#*|}
    replace_current_keyword() {
        replace_keyword "$1" "$2" "$val"
    }
    for_matching_text_files "$key" replace_current_keyword
done

echo "--- Sanitization Complete ---"
