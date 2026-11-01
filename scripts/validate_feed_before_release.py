#!/usr/bin/env python3
"""Fail-closed public repo gate before any signed feed is approved.

Deliberately allows only the current inactive public feed scaffolding.
This is NOT a publisher, signature verifier, manual approval, or secret store.
"""
from pathlib import Path
import json
import re
import sys

ALLOWED = {
    "README.md",
    "v2/dlt/status.json",
    "v2/ssq/status.json",
    "scripts/validate_feed_before_release.py",
    "tests/test_feed_before_release.py",
    ".github/workflows/validate-feed-review.yml",
}
REASONS = {
    "official_source_verification_pending",
    "publisher_key_provisioning_pending",
    "android_secure_sync_not_enabled",
}
PRIVATE_MARKERS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
)

class UnsafeFeed(ValueError):
    pass

def require(predicate, message):
    if not predicate:
        raise UnsafeFeed(message)

def strict_json(value):
    def unique_pairs(pairs):
        result = {}
        for key, entry in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = entry
        return result
    try:
        return json.loads(value, object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    except UnsafeFeed:
        raise
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise UnsafeFeed("invalid status JSON") from exc

def validate(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "missing trusted checkout")
    discovered = {}
    for file in root.rglob("*"):
        relative = file.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        require(not file.is_symlink(), "symlink is not allowed: " + relative)
        if file.is_dir():
            continue
        require(file.is_file(), "unexpected non-file path: " + relative)
        require(relative in ALLOWED, "unexpected public file: " + relative)
        raw = file.read_bytes()
        require(len(raw) <= 100_000, "file too large: " + relative)
        require(not any(pattern.search(raw) for pattern in PRIVATE_MARKERS),
                "potential secret in public repository: " + relative)
        discovered[relative] = raw

    require(set(discovered) == ALLOWED,
            "required public scaffold missing or extra content present")
    for game in ("ssq", "dlt"):
        path = f"v2/{game}/status.json"
        raw = discovered[path]
        require(len(raw) <= 2048, "status file is oversized")
        content = strict_json(raw)
        require(type(content) is dict and set(content) == {
            "schema", "game", "status", "reason_codes", "advisory"},
            "unexpected status fields")
        require(content["schema"] == "yaoguang-v2-public-feed-status-v1"
                and content["game"] == game and content["status"] == "not_ready"
                and type(content["advisory"]) is str
                and content["advisory"] == "No data or phone updates are published yet."
                and type(content["reason_codes"]) is list
                and set(content["reason_codes"]) == REASONS
                and len(content["reason_codes"]) == len(REASONS)
                and all(type(reason) is str for reason in content["reason_codes"]),
                "only explicitly disabled unsigned feed status allowed")
    print("PASS: public scaffold locked, both lotteries NOT READY; no current.json and no private keys")
    return True

if __name__ == "__main__":
    try:
        validate(Path(__file__).resolve().parents[1])
    except UnsafeFeed as err:
        print("STOP:", err, file=sys.stderr)
        raise SystemExit(1)
