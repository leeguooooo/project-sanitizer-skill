#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file_contains() {
    local file=$1
    local expected=$2
    grep -Fq -- "$expected" "$file" || fail "Expected $file to contain: $expected"
}

assert_file_not_contains() {
    local file=$1
    local unexpected=$2
    if grep -Fq -- "$unexpected" "$file"; then
        fail "Expected $file not to contain: $unexpected"
    fi
}

test_sanitizer_rewrites_and_deletes() {
    local tmp_dir project
    tmp_dir="$(mktemp -d)"
    project="$tmp_dir/project"
    mkdir -p "$project/analysis" "$project/resources/Hooks" "$project/src" "$project/.git"
    printf 'keep\nCRACKED line\nMach-O and Reverse Engineering and 反汇编\n' > "$project/src/app.txt"
    printf 'Reverse Engineering should stay in git metadata\n' > "$project/.git/config"

    "$ROOT_DIR/scripts/sanitize_project.sh" "$project" >/dev/null

    [[ ! -d "$project/analysis" ]] || fail "analysis directory was not removed"
    [[ ! -d "$project/resources/Hooks" ]] || fail "resources/Hooks directory was not removed"
    assert_file_not_contains "$project/src/app.txt" "CRACKED"
    assert_file_contains "$project/src/app.txt" "Native Binary and Project Assets and 源码分析"
    assert_file_contains "$project/.git/config" "Reverse Engineering should stay in git metadata"
    rm -rf "$tmp_dir"
}

test_sanitizer_dry_run_preserves_files() {
    local tmp_dir project
    tmp_dir="$(mktemp -d)"
    project="$tmp_dir/project"
    mkdir -p "$project/analysis" "$project/src"
    printf 'CRACKED\nMach-O\n' > "$project/src/app.txt"

    "$ROOT_DIR/scripts/sanitize_project.sh" --dry-run "$project" >/dev/null

    [[ -d "$project/analysis" ]] || fail "dry-run removed analysis directory"
    assert_file_contains "$project/src/app.txt" "CRACKED"
    assert_file_contains "$project/src/app.txt" "Mach-O"
    rm -rf "$tmp_dir"
}

test_sanitizer_rejects_root() {
    if "$ROOT_DIR/scripts/sanitize_project.sh" / >/dev/null 2>&1; then
        fail "sanitizer accepted root directory"
    fi
}

test_analyzer_rejects_missing_target() {
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    if (cd "$tmp_dir" && "$ROOT_DIR/scripts/analyze_target.sh" "$tmp_dir/missing" >/dev/null 2>&1); then
        fail "analyzer accepted missing target"
    fi
    rm -rf "$tmp_dir"
}

test_analyzer_extracts_strings() {
    local tmp_dir output_dir target
    tmp_dir="$(mktemp -d)"
    output_dir="$tmp_dir/out"
    target="$tmp_dir/sample.bin"
    printf 'hello-from-target\n' > "$target"

    ANALYSIS_OUTPUT_DIR="$output_dir" "$ROOT_DIR/scripts/analyze_target.sh" "$target" >/dev/null

    assert_file_contains "$output_dir/strings.txt" "hello-from-target"
    rm -rf "$tmp_dir"
}

test_sanitizer_rewrites_and_deletes
test_sanitizer_dry_run_preserves_files
test_sanitizer_rejects_root
test_analyzer_rejects_missing_target
test_analyzer_extracts_strings

echo "All tests passed."
