#!/usr/bin/env python3
"""Check that no new C++ exception sites are added to src/.

The project keeps a documented waiver for the exceptions inherited from the
Delphi port.  This script freezes the current counts in
tools/exception_baseline.json and fails when a file gains a new `throw`,
`try`, or `catch` site.  Removing exception sites is always allowed; run
`--update` afterwards to refresh the baseline.

Usage:
    tools/check_exceptions.py [--update]
"""

import json
import re
import sys
from pathlib import Path

BASELINE = Path(__file__).with_name("exception_baseline.json")
ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "src"
KEYWORDS = ("throw", "try", "catch")
KEYWORD_RE = re.compile(r"\b(" + "|".join(KEYWORDS) + r")\b")


def strip_comments_and_strings(text: str) -> str:
    """Remove comments and literals so keyword counting sees code only."""
    out = []
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char == "/" and i + 1 < length and text[i + 1] == "/":
            i += 2
            while i < length and text[i] != "\n":
                i += 1
        elif char == "/" and i + 1 < length and text[i + 1] == "*":
            i += 2
            while i + 1 < length and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            out.append(" ")
        elif char in ('"', "'"):
            quote = char
            i += 1
            while i < length:
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                elif text[i] == "\n":
                    break
                else:
                    i += 1
            out.append(" ")
        else:
            out.append(char)
            i += 1
    return "".join(out)


def count_exceptions(path: Path) -> dict[str, int]:
    code = strip_comments_and_strings(path.read_text(encoding="utf-8"))
    counts = {keyword: 0 for keyword in KEYWORDS}
    for match in KEYWORD_RE.finditer(code):
        counts[match.group(1)] += 1
    return counts


def collect_counts() -> dict[str, dict[str, int]]:
    result = {}
    for path in sorted(SOURCE_DIR.glob("*.cpp")) + sorted(SOURCE_DIR.glob("*.h")):
        counts = count_exceptions(path)
        if any(counts.values()):
            result[path.relative_to(ROOT).as_posix()] = counts
    return result


def load_baseline() -> dict[str, dict[str, int]]:
    if not BASELINE.exists():
        print(f"error: {BASELINE} is missing; run with --update", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def update() -> int:
    counts = collect_counts()
    BASELINE.write_text(
        json.dumps(counts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    total = sum(sum(values.values()) for values in counts.values())
    print(f"wrote {BASELINE} ({len(counts)} files, {total} sites)")
    return 0


def check() -> int:
    baseline = load_baseline()
    current = collect_counts()
    failures = []
    for path, counts in current.items():
        allowed = baseline.get(path, {})
        for keyword in KEYWORDS:
            if counts[keyword] > allowed.get(keyword, 0):
                failures.append(
                    f"{path}: {keyword} {counts[keyword]} "
                    f"(baseline {allowed.get(keyword, 0)})"
                )
    for path, counts in baseline.items():
        if path not in current:
            print(f"warning: {path} no longer has exception sites", file=sys.stderr)

    if failures:
        print("error: new C++ exception sites found:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "Use error codes or update the documented waiver in docs/style.md.",
            file=sys.stderr,
        )
        return 1
    print("exception baseline check passed")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--update":
        return update()
    if len(sys.argv) != 1:
        print(f"usage: {sys.argv[0]} [--update]", file=sys.stderr)
        return 2
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
