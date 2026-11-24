#!/usr/bin/env python3
"""Privacy gate: stops personal details reaching this public repository.

Checks tracked files, commit messages and commit author/committer emails for:
  * private terms (names, places, IDs) - kept OUT of the repo: read from the
    PRIVACY_TERMS environment variable (a GitHub secret in CI) or from the
    file named by PRIVACY_TERMS_FILE (local, never committed);
  * any email address other than the allowed no-reply/example ones;
  * any real-looking MAC address;
  * any public IPv4 address outside documentation/private ranges and the
    short list of public services the app talks to (tool/privacy_allow.txt).

Usage:
  privacy_check.py files                 # every tracked file (working tree)
  privacy_check.py staged                # staged changes (pre-commit hook)
  privacy_check.py msg FILE              # a commit message (commit-msg hook)
  privacy_check.py commits A..B          # messages + emails of a commit range
  privacy_check.py identity              # the configured git user.email

Exit code 1 (and a list of findings, with the private term masked) if anything
is found. Without any private-terms source the term check is skipped with a
warning locally, but is an error in CI (CI=true).
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
ALLOW_FILE = ROOT / "tool" / "privacy_allow.txt"

# Files that legitimately contain hashes/binary-ish data.
SKIP_SUFFIXES = (".png", ".ico", ".jpg", ".jpeg", ".gif", ".webp", ".ttf", ".otf",
                 ".jar", ".zip", ".dll", ".exe", ".keystore", ".jks")
SKIP_FILES = {"go.sum", "pubspec.lock"}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

ALLOWED_EMAIL_DOMAINS = ("users.noreply.github.com", "example.com", "example.org",
                         "example.net", "test.invalid", "invalid", "test", "localhost")
ALLOWED_EMAILS = {"noreply@anthropic.com", "noreply@github.com",
                  "41898282+github-actions[bot]@users.noreply.github.com"}
ALLOWED_MACS = {"00:11:22:33:44:55", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
                "aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01", "02:00:00:00:00:02"}

DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737 documentation
    "198.18.0.0/15",                                      # benchmarking (app's DNS lock)
    "100.64.0.0/10",                                      # CGNAT/Tailscale - checked by terms
    "240.0.0.0/4",                                        # app's bypass deadline marker
)]


def load_terms() -> list[str]:
    raw = os.environ.get("PRIVACY_TERMS")
    if raw is None:
        f = os.environ.get("PRIVACY_TERMS_FILE")
        if f and Path(f).is_file():
            raw = Path(f).read_text(encoding="utf-8")
    if raw is None:
        if os.environ.get("CI") == "true":
            sys.exit("privacy_check: PRIVACY_TERMS secret is missing - refusing to pass.")
        print("privacy_check: WARNING no private terms configured; term check skipped.", file=sys.stderr)
        return []
    return [t.strip() for t in raw.splitlines() if t.strip() and not t.strip().startswith("#")]


def term_regex(term: str) -> re.Pattern[str]:
    # Whole-word match where "_", "-", "." and digits around do not glue words
    # together, so "Tim_Phone", "kate-app" and "TIM-PC" are caught but "Timer"
    # and "optimise" are not.
    esc = re.escape(term).replace(r"\ ", r"[\s_-]?")
    return re.compile(r"(?<![A-Za-z])" + esc + r"(?![A-Za-z])", re.IGNORECASE)


def load_allow() -> tuple[set[str], set[str], set[str]]:
    ips, emails, macs = set(), set(), set()
    if ALLOW_FILE.is_file():
        for line in ALLOW_FILE.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if "@" in line:
                emails.add(line.lower())
            elif MAC_RE.fullmatch(line):
                macs.add(line.lower().replace("-", ":"))
            else:
                ips.add(line.lower())
    return ips, emails, macs


ALLOW_IPS, ALLOW_EMAILS_EXTRA, ALLOW_MACS_EXTRA = load_allow()
TERMS = [(t, term_regex(t)) for t in load_terms()]


def mask(term: str) -> str:
    return term[0] + "*" * (len(term) - 1) if len(term) > 1 else "*"


def ip_ok(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return True  # version numbers like 1.2.3.400
    if s in ALLOW_IPS:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_unspecified or ip.is_reserved:
        return True
    if any(ip in n for n in DOC_NETS):
        return True
    # Version-like strings (1.2.3.4 style placeholders) are fine.
    return s in {"1.2.3.4", "5.6.7.8", "4.3.2.1"}


def email_ok(e: str) -> bool:
    e = e.lower()
    if e in ALLOWED_EMAILS or e in ALLOW_EMAILS_EXTRA:
        return True
    dom = e.rsplit("@", 1)[1]
    return any(dom == d or dom.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS)


def scan_text(text: str, where: str, out: list[str]) -> None:
    for n, line in enumerate(text.splitlines(), 1):
        loc = f"{where}:{n}"
        for term, rx in TERMS:
            if rx.search(line):
                out.append(f"{loc}: private term '{mask(term)}'")
        for m in EMAIL_RE.findall(line):
            if not email_ok(m):
                out.append(f"{loc}: email address")
        for m in MAC_RE.findall(line):
            if m.lower().replace("-", ":") not in ALLOWED_MACS | ALLOW_MACS_EXTRA:
                out.append(f"{loc}: MAC address {m[:8]}...")
        for m in IPV4_RE.findall(line):
            if not ip_ok(m):
                out.append(f"{loc}: public IP {m}")


def tracked_files() -> list[str]:
    return [f for f in subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=True).split("\0") if f]


def scan_file(path: str, out: list[str], content: str | None = None) -> None:
    if path.endswith(SKIP_SUFFIXES) or Path(path).name in SKIP_FILES:
        return
    if content is None:
        p = ROOT / path
        if not p.is_file():
            return
        data = p.read_bytes()
        if b"\0" in data[:4096]:
            return
        content = data.decode("utf-8", "replace")
    # This file and the allow list hold no private data, but would match patterns.
    if path in ("tool/privacy_check.py",):
        return
    scan_text(content, path, out)
    scan_text(path, f"(path) {path}", out)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    mode, out = argv[0], []
    if mode == "files":
        for f in tracked_files():
            scan_file(f, out)
    elif mode == "staged":
        names = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], cwd=ROOT, text=True).split("\0")
        for f in filter(None, names):
            blob = subprocess.run(["git", "show", f":{f}"], cwd=ROOT, capture_output=True)
            if blob.returncode == 0 and b"\0" not in blob.stdout[:4096]:
                scan_file(f, out, blob.stdout.decode("utf-8", "replace"))
    elif mode == "msg":
        scan_text(Path(argv[1]).read_text(encoding="utf-8"), "commit message", out)
    elif mode == "identity":
        for key in ("user.email",):
            v = subprocess.run(["git", "config", key], cwd=ROOT, capture_output=True, text=True).stdout.strip()
            if v and not email_ok(v):
                out.append(f"git config {key} is not a no-reply address")
    elif mode == "commits":
        rng = argv[1]
        log = subprocess.check_output(
            ["git", "log", "--format=%H%x00%ae%x00%ce%x00%B%x01", rng], cwd=ROOT, text=True)
        for rec in filter(None, (r.strip("\n") for r in log.split("\x01"))):
            sha, ae, ce, body = rec.split("\x00", 3)
            for e in (ae, ce):
                if not email_ok(e):
                    out.append(f"commit {sha[:8]}: author/committer email is not a no-reply address")
            scan_text(body, f"commit {sha[:8]} message", out)
    else:
        print(__doc__)
        return 2
    if out:
        print("PRIVACY CHECK FAILED - personal details found:", file=sys.stderr)
        for o in sorted(set(out)):
            print("  " + o, file=sys.stderr)
        return 1
    print(f"privacy_check: OK ({mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
