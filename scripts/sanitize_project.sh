#!/bin/bash

# Project Sanitization Script v2
# Removes reverse engineering traces and rebranding logic (Global/Chinese support)

TARGET_DIR=$1

if [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 <target-directory>"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory $TARGET_DIR does not exist."
    exit 1
fi

echo "--- Sanitizing: $TARGET_DIR ---"

# 1. Remove sensitive directories (expanded)
folders_to_remove=("analysis" "binaries" "disasm" "metadata" "pseudocode" ".build" "resources/Hooks" "recovered_src" "re-output")
for folder in "${folders_to_remove[@]}"; do
    rm -rf "$TARGET_DIR/$folder"
    echo "Removed directory: $folder"
done

# 2. Remove sensitive files
files_to_remove=("DISASSEMBLY-SUMMARY.txt" "MANIFEST.txt" "RE-GUIDE.md" "cracking_log.txt")
for file in "${files_to_remove[@]}"; do
    rm -f "$TARGET_DIR/$file"
    echo "Removed file: $file"
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
    grep -rl "$kw" "$TARGET_DIR" --exclude-dir=".git" | while read -r file; do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "/$kw/d" "$file"
        else
            sed -i "/$kw/d" "$file"
        fi
        echo "Cleaned keyword '$kw' from: $file"
    done
done

# 4. Keyword replacement (Mach-O, RE terms, Chinese terms)
declare -A replacements=(
    ["Mach-O"]="Native Binary"
    ["Ghidra"]="Static Analysis"
    ["Hopper"]="Static Analysis"
    ["radare2"]="Debugger"
    ["objdump"]="Disassembler"
    ["otool"]="Disassembler"
    ["Reconstructed"]="Core"
    ["reconstructed"]="core"
    ["Reverse Engineering"]="Project Assets"
    ["disassembly"]="source analysis"
    ["pseudocode"]="core logic"
    ["反汇编"]="源码分析"
    ["逆向工程"]="系统重构"
    ["逆向"]="重构"
    ["反编译"]="代码生成"
)

for key in "${!replacements[@]}"; do
    val=${replacements[$key]}
    grep -rl "$key" "$TARGET_DIR" --exclude-dir=".git" | while read -r file; do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/$key/$val/g" "$file"
        else
            sed -i "s/$key/$val/g" "$file"
        fi
        echo "Replaced '$key' with '$val' in: $file"
    done
done

echo "--- Sanitization Complete ---"
