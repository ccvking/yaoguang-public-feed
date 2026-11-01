"""Local synthetic negative tests for locked public feed scaffold."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from validate_feed_before_release import ALLOWED, UnsafeFeed, validate

REASONS = [
    "official_source_verification_pending",
    "publisher_key_provisioning_pending",
    "android_secure_sync_not_enabled",
]

def status(game):
    return json.dumps({
        "schema": "yaoguang-v2-public-feed-status-v1",
        "game": game, "status": "not_ready",
        "reason_codes": REASONS,
        "advisory": "No data or phone updates are published yet.",
    }).encode()

class PublicFeedSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ALLOWED:
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(status(name.split("/")[1]) if name.startswith("v2/") else b"Safe public stub\n")

    def test_locked_scaffold_ok(self):
        self.assertTrue(validate(self.root))

    def test_unsigned_current_json_is_never_allowed(self):
        f = self.root / "v2/dlt/current.json"
        f.write_text('{"numbers":[1,2,3]}')
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_private_key_file_rejected(self):
        f = self.root / "publisher-private.pem"
        f.write_text("secret")
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_key_inside_readme_rejected(self):
        f = self.root / "README.md"
        f.write_text("-----BEGIN PRIVATE KEY-----\nfake")
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_bad_kind_rejected(self):
        f = self.root / "v2/ssq/status.json"
        f.write_bytes(status("dlt"))
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_signed_status_is_not_approved(self):
        f = self.root / "v2/dlt/status.json"
        data = json.loads(f.read_text())
        data["status"] = "ready"
        f.write_text(json.dumps(data))
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_missing_required_scaffold_rejected(self):
        (self.root / "v2/ssq/status.json").unlink()
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_duplicate_json_key_rejected(self):
        f = self.root / "v2/dlt/status.json"
        f.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_extra_json_fields_rejected(self):
        f = self.root / "v2/dlt/status.json"
        data = json.loads(f.read_text())
        data["unsigned_payload"] = {"history":[]}
        f.write_text(json.dumps(data))
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

    def test_symlink_rejected(self):
        f = self.root / "README.md"
        f.unlink()
        f.symlink_to(self.root / "v2/ssq/status.json")
        with self.assertRaises(UnsafeFeed):
            validate(self.root)

if __name__ == "__main__":
    unittest.main()
