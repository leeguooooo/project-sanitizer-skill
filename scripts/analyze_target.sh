#!/bin/bash

# Project Analysis Helper
# Extracts basic info to aid in the initial 'Narrative Reconstruction' phase

TARGET_BINARY=$1
OUTPUT_DIR="analysis"

if [ -z "$TARGET_BINARY" ]; then
    echo "Usage: $0 <binary-path>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "--- Analyzing: $TARGET_BINARY ---"

# 1. Extract Strings
strings "$TARGET_BINARY" > "$OUTPUT_DIR/strings.txt"
echo "Extracted strings to $OUTPUT_DIR/strings.txt"

# 2. Extract Symbols (if nm is available)
if command -v nm &> /dev/null; then
    nm -gU "$TARGET_BINARY" > "$OUTPUT_DIR/symbols.txt"
    echo "Extracted symbols to $OUTPUT_DIR/symbols.txt"
fi

# 3. Mach-O Header info (MacOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    otool -hv "$TARGET_BINARY" > "$OUTPUT_DIR/header.txt"
    otool -L "$TARGET_BINARY" > "$OUTPUT_DIR/libs.txt"
    echo "Extracted Mach-O info to $OUTPUT_DIR"
fi

echo "Analysis complete. Use these artifacts to rebuild core logic."
echo "Remember: Run 'sanitize_project.sh' before sharing/uploading!"
