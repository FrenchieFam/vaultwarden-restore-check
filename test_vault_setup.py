import argparse
from datetime import datetime, timedelta, timezone
import gzip
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import vault_setup as setup


class VaultSetupTest(unittest.TestCase):
    def test_address_rejects_yaml_injection_and_non_tailnet_host(self):
        for host in ('test.tail1.ts.net\n    ADMIN_TOKEN: secret', 'vault.example.com',
                     'https://test.tail1.ts.net'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                setup.address(argparse.Namespace(host=host, port=8447))

    def test_funnel_is_rejected_before_network_probe(self):
        domain = 'test.tail1.ts.net:8447'
        config = '{"Web":{"test.tail1.ts.net:8447":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8223"}}}},"AllowFunnel":{"test.tail1.ts.net:8447":true}}'
        with patch.object(setup, 'command', return_value=config), patch.object(
                setup, 'build_opener') as opener:
            with self.assertRaisesRegex(ValueError, 'Funnel'):
                setup.check(argparse.Namespace(host=domain.split(':')[0], port=8447))
            opener.assert_not_called()

    def test_sqlite_counts_and_wrong_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with sqlite3.connect(root/'db.sqlite3') as db:
                db.executescript("CREATE TABLE users (password_hash TEXT);"
                                 "CREATE TABLE ciphers (id INTEGER);"
                                 "INSERT INTO users VALUES ('fixture');"
                                 "INSERT INTO ciphers VALUES (1);")
            self.assertEqual(setup.database_counts(root/'db.sqlite3'),
                             {'accounts': 1, 'encrypted_items': 1})
            receipt = root/'receipt.json'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                setup.restore(argparse.Namespace(archive=root/'db.sqlite3', sha256='0'*64,
                                                 identity=root/'identity', receipt=receipt))
            self.assertFalse(receipt.exists())

    def test_stale_receipt_reports_a_new_drill_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text(json.dumps({"isolated_startup": "passed", "archive_sha256": "a"*64,
                                        "checked_at": (datetime.now(timezone.utc) -
                                                       timedelta(days=40)).isoformat()}))
            with self.assertRaisesRegex(ValueError, "fresh restore drill"):
                setup.status(argparse.Namespace(receipt=path, max_age_days=30))

    def test_backup_rejects_symlinked_asset_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "attachments").symlink_to(root)
            with self.assertRaisesRegex(ValueError, "symlink"):
                setup.snapshot_inputs(root)

    def test_duplicate_member_or_symlink_rejected(self):
        class Decrypt:
            def __init__(self, payload):
                self.stdout = io.BytesIO(payload)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def poll(self):
                return 0

        for link in (False, True):
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                first = tarfile.TarInfo('vault/db.sqlite3')
                first.size = 3
                archive.addfile(first, io.BytesIO(b'abc'))
                member = tarfile.TarInfo('vault/rsa_key.pem' if link else first.name)
                if link:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    archive.addfile(member)
                else:
                    member.size = 3
                    archive.addfile(member, io.BytesIO(b'xyz'))
            with tempfile.TemporaryDirectory() as tmp, patch.object(
                    setup.subprocess, 'Popen', return_value=Decrypt(gzip.compress(raw.getvalue()))):
                with self.assertRaises(ValueError):
                    setup.extract_snapshot(Path('archive'), Path('identity'), Path(tmp))


if __name__ == '__main__':
    unittest.main()
