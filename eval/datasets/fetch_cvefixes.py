#!/usr/bin/env python
"""
CVEFixes Dataset Converter

Downloads the CVEFixes Kaggle CSV and converts to .patch files for the eval harness.

Prerequisites:
    1. Download CVEFixes.csv from:
       https://www.kaggle.com/datasets/girish17019/cvefixes-vulnerable-and-fixed-code
    2. Place it at: eval/datasets/CVEFixes.csv (or pass --csv path)

Usage:
    python fetch_cvefixes.py                    # Convert with defaults
    python fetch_cvefixes.py --csv path.csv     # Custom CSV location
    python fetch_cvefixes.py --limit 200        # Max samples (100 vuln + 100 clean)
    python fetch_cvefixes.py --lang python      # Filter by language
"""

import argparse
import csv
import hashlib
import re
import sys
import textwrap
from pathlib import Path

_EVAL = Path(__file__).resolve().parent.parent
DEFAULT_CSV = Path(__file__).resolve().parent / "CVEFixes.csv"
OUTPUT_DIR = _EVAL / "samples" / "cvefixes"

# Map CVEFixes language names to file extensions
LANG_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "c++": ".cpp",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
    "rust": ".rs",
}

# Infer plausible file paths from code content
PYTHON_PATH_HINTS = {
    r"from django|from rest_framework": "src/web/views",
    r"import flask|from flask": "src/web/app",
    r"import sqlite3|import psycopg|import pymysql": "src/db/queries",
    r"import os\b|import subprocess": "src/utils/system",
    r"import pickle|import yaml|import marshal": "src/utils/loader",
    r"import hashlib|import hmac|from cryptography": "src/auth/crypto",
    r"import jwt|import session|login|password": "src/auth/session",
    r"import socket|import requests|import urllib": "src/net/client",
}

JS_PATH_HINTS = {
    r"require\(['\"]express|app\.get\(|app\.post\(": "src/routes/handler",
    r"require\(['\"]mysql|require\(['\"]pg|query\(": "src/db/queries",
    r"document\.|innerHTML|\.html\(": "src/web/views",
    r"exec\(|spawn\(|child_process": "src/utils/system",
    r"require\(['\"]fs|readFile|writeFile": "src/utils/files",
    r"jwt\.|token|session|cookie": "src/auth/session",
}


def infer_path(code: str, lang: str) -> str:
    """Guess a plausible file path from code content."""
    hints = PYTHON_PATH_HINTS if lang == "python" else JS_PATH_HINTS if lang in ("javascript", "typescript") else {}
    ext = LANG_EXTENSIONS.get(lang, ".txt")

    for pattern, path_base in hints.items():
        if re.search(pattern, code, re.IGNORECASE):
            return path_base + ext

    # Default path
    return f"src/module{ext}"


def code_to_patch(code: str, file_path: str) -> str:
    """Convert a code snippet to a unified diff patch (new file addition)."""
    lines = code.splitlines()
    if not lines:
        return ""

    # Generate patch header
    patch = f"diff --git a/{file_path} b/{file_path}\n"
    patch += "new file mode 100644\n"
    patch += "index 0000000..1111111\n"
    patch += f"--- /dev/null\n"
    patch += f"+++ b/{file_path}\n"
    patch += f"@@ -0,0 +1,{len(lines)} @@\n"

    for line in lines:
        patch += f"+{line}\n"

    return patch


def stable_name(code: str, index: int) -> str:
    """Generate a stable filename from code content hash."""
    h = hashlib.md5(code.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"cve_{index:04d}_{h}"


def main():
    parser = argparse.ArgumentParser(description="CVEFixes -> .patch converter")
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="Path to CVEFixes.csv")
    parser.add_argument("--limit", type=int, default=200, help="Max total samples (split evenly)")
    parser.add_argument("--lang", default="python", help="Language filter (python, javascript, etc.)")
    parser.add_argument("--min-lines", type=int, default=5, help="Min code lines to include")
    parser.add_argument("--max-lines", type=int, default=200, help="Max code lines to include")
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"ERROR: CSV not found: {args.csv}")
        print()
        print("Download CVEFixes.csv from:")
        print("  https://www.kaggle.com/datasets/girish17019/cvefixes-vulnerable-and-fixed-code")
        print()
        print(f"Place it at: {DEFAULT_CSV}")
        sys.exit(1)

    print(f"Reading: {args.csv}")
    print(f"Language: {args.lang}")
    print(f"Limit: {args.limit} total ({args.limit // 2} per category)")

    # Read CSV
    vuln_codes = []
    clean_codes = []
    skipped = 0

    with open(args.csv, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lang = row.get("language", "").lower().strip()
            if lang != args.lang.lower():
                continue

            code = row.get("code", "").strip()
            safety = row.get("safety", "").strip().lower()
            lines = code.splitlines()

            # Filter by size
            if len(lines) < args.min_lines or len(lines) > args.max_lines:
                skipped += 1
                continue

            if safety in ("0", "vulnerable", "unsafe"):
                vuln_codes.append(code)
            elif safety in ("1", "safe", "clean"):
                clean_codes.append(code)

    print(f"Found: {len(vuln_codes)} vulnerable, {len(clean_codes)} clean (skipped {skipped})")

    # Limit
    half = args.limit // 2
    vuln_codes = vuln_codes[:half]
    clean_codes = clean_codes[:half]

    print(f"Using: {len(vuln_codes)} vulnerable, {len(clean_codes)} clean")

    # Generate patches
    vuln_dir = OUTPUT_DIR / "vulnerable"
    clean_dir = OUTPUT_DIR / "clean"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for i, code in enumerate(vuln_codes):
        path = infer_path(code, args.lang)
        patch = code_to_patch(code, path)
        if not patch:
            continue
        name = stable_name(code, i)
        (vuln_dir / f"{name}.patch").write_text(patch, encoding="utf-8")
        written += 1

    for i, code in enumerate(clean_codes):
        path = infer_path(code, args.lang)
        patch = code_to_patch(code, path)
        if not patch:
            continue
        name = stable_name(code, i)
        (clean_dir / f"{name}.patch").write_text(patch, encoding="utf-8")
        written += 1

    print(f"Wrote {written} patches to {OUTPUT_DIR}")
    print(f"  {vuln_dir}: {len(list(vuln_dir.glob('*.patch')))} files")
    print(f"  {clean_dir}: {len(list(clean_dir.glob('*.patch')))} files")


if __name__ == "__main__":
    main()
