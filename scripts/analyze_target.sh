#!/usr/bin/env bash
set -euo pipefail

# Project Analysis Helper
# Extracts basic info to aid in the initial 'Narrative Reconstruction' phase

TARGET_BINARY=${1:-}
OUTPUT_DIR=${ANALYSIS_OUTPUT_DIR:-analysis}

if [[ -z "$TARGET_BINARY" ]]; then
    echo "Usage: $0 <binary-path>"
    exit 1
fi

if [[ ! -f "$TARGET_BINARY" || ! -r "$TARGET_BINARY" ]]; then
    echo "Error: Target binary does not exist or is not readable: $TARGET_BINARY" >&2
    exit 1
fi

if ! command -v strings >/dev/null 2>&1; then
    echo "Error: strings is required but was not found." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "--- Analyzing: $TARGET_BINARY ---"

# 1. Extract Strings
strings "$TARGET_BINARY" > "$OUTPUT_DIR/strings.txt"
echo "Extracted strings to $OUTPUT_DIR/strings.txt"

# 2. Extract Symbols (if nm is available)
if command -v nm >/dev/null 2>&1; then
    if nm -gU "$TARGET_BINARY" > "$OUTPUT_DIR/symbols.txt" 2>"$OUTPUT_DIR/symbols.err"; then
        rm -f "$OUTPUT_DIR/symbols.err"
        echo "Extracted symbols to $OUTPUT_DIR/symbols.txt"
    else
        rm -f "$OUTPUT_DIR/symbols.txt"
        echo "Warning: nm could not extract exported symbols; see $OUTPUT_DIR/symbols.err" >&2
    fi
fi

# 3. Mach-O Header info (MacOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v otool >/dev/null 2>&1; then
        if otool -hv "$TARGET_BINARY" > "$OUTPUT_DIR/header.txt" 2>"$OUTPUT_DIR/header.err"; then
            rm -f "$OUTPUT_DIR/header.err"
            echo "Extracted Mach-O header to $OUTPUT_DIR/header.txt"
        else
            rm -f "$OUTPUT_DIR/header.txt"
            echo "Warning: otool could not extract header info; see $OUTPUT_DIR/header.err" >&2
        fi

        if otool -L "$TARGET_BINARY" > "$OUTPUT_DIR/libs.txt" 2>"$OUTPUT_DIR/libs.err"; then
            rm -f "$OUTPUT_DIR/libs.err"
            echo "Extracted Mach-O library info to $OUTPUT_DIR/libs.txt"
        else
            rm -f "$OUTPUT_DIR/libs.txt"
            echo "Warning: otool could not extract library info; see $OUTPUT_DIR/libs.err" >&2
        fi
    fi
fi

echo "Analysis complete. Use these artifacts to rebuild core logic."
echo "Remember: Run 'sanitize_project.sh' before sharing/uploading!"
