#!/usr/bin/env python3
"""Refuse to publish anything that looks like a secret.

Runs over every tracked file before a push or a release. It is deliberately noisy about
shapes rather than clever about context: a false positive costs a moment, and a private
key in a public repository cannot be taken back.

Usage:  python3 scripts/secret_scan.py [path]
Exit:   0 clean, 1 findings.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

#: (name, pattern, whether a match inside this scanner's own source counts)
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openssh private key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("pgp private key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    ("github token", re.compile(r"\b(gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}")),
    ("slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("aws access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe key", re.compile(r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}")),
    ("bearer token", re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}")),
    ("postgres url", re.compile(r"\bpostgres(ql)?://[^\s\"']*:[^\s\"'@]+@")),
    ("generic db url with password", re.compile(r"\b\w+://[^\s\"'/]+:[^\s\"'@]{6,}@")),
    (
        "assigned credential",
        re.compile(
            r"(?i)\b(pass(word|phrase)|secret|api[_-]?key|access[_-]?token|"
            r"client[_-]?secret)\b\s*[=:]\s*[\"']?(?P<value>[A-Za-z0-9/+=_-]{12,})"
        ),
    ),
]

#: An explicit, greppable opt-out for a line that is *supposed* to look like a secret —
#: a redaction test, a documented example. Deliberate, auditable, and never wildcarded.
PRAGMA = "secret-scan: allow"


def _is_code_reference(value: str) -> bool:
    """True when the "credential" is really an identifier — `passphrase = load_pass()`.

    Without this the scanner cries wolf on ordinary code, and a scanner people learn to
    ignore protects nothing.
    """
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)) and (
        "_" in value or value.islower() or value.isupper()
    )


#: Values that are supposed to appear: documented placeholders and test fixtures.
ALLOWED = re.compile(
    r"(?i)(test-secret-do-not-use|your[_-]?(secret|token|key)|<[^>]{1,40}>|"
    r"xxx+|example\.com|changeme|\.\.\.|\$\{[^}]+\}|hunter2)"
)

#: Paths never scanned: binary fixtures and anything git already ignores.
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2", ".ico"}
SKIP_NAMES = {"uv.lock", "es6_numbers.json"}

#: Filenames that must never be tracked at all, whatever their contents.
FORBIDDEN_NAMES = re.compile(
    r"(^|/)(\.env(\.[a-z]+)?|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa|id_ed25519|"
    r".*\.pass|state\.db.*)$"
)
FORBIDDEN_EXCEPTIONS = re.compile(r"(^|/)\.env\.example$|(^|/).*\.env\.example$")


def tracked_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
        return [root / name for name in out.split("\0") if name]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    self_path = Path(__file__).resolve()

    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()

        if FORBIDDEN_NAMES.search(relative) and not FORBIDDEN_EXCEPTIONS.search(relative):
            findings.append(f"{relative}: a file with this name must never be tracked")
            continue

        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES:
            continue
        if path.resolve() == self_path:
            continue  # this file is a list of secret shapes by definition
        if not path.exists():
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        lines = text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            if ALLOWED.search(line):
                continue
            # The pragma applies to its own line and to the next one, so it can sit in a
            # comment above the thing it exempts rather than trailing an already-long line.
            previous = lines[line_number - 2] if line_number >= 2 else ""
            if PRAGMA in line or PRAGMA in previous:
                continue
            for name, pattern in PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                captured = match.groupdict().get("value")
                if captured and _is_code_reference(captured):
                    continue
                findings.append(f"{relative}:{line_number}: possible {name}")
                break

    return findings


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    findings = scan(root)
    if findings:
        print(f"secret scan: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
