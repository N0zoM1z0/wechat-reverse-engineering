"""Synthetic regression tests; no real account data, binaries or keys required."""
import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import wechat_export as exporter
import export_selected_groups as readable


class CipherRequirementTests(unittest.TestCase):
    def test_old_or_missing_cipher_version_cannot_mislabel_compatibility(self):
        for version in ("3.4.2", ""):
            result = subprocess.CompletedProcess([], 0, stdout=version, stderr="")
            with mock.patch.object(exporter, "run_sqlcipher", return_value=result), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    exporter.require_sqlcipher4()
            self.assertEqual(error.exception.code, 1)


@unittest.skipUnless(shutil.which("sqlcipher"), "sqlcipher 4 is required")
class CipherIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.snapshot = self.root / "arbitrary-input-name"
        self.keys = [hashlib.sha256(f"synthetic-key-{i}".encode()).hexdigest() for i in range(2)]

    def encrypted(self, name, key, compatibility=4, mode="raw64"):
        path = self.snapshot / "db_storage/message" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        script = exporter.sqlcipher_key_pragma(path, key, mode)
        script += f"\nPRAGMA cipher_compatibility={compatibility};\nPRAGMA cipher_page_size=4096;\n"
        script += "CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES('synthetic message');\n"
        result = exporter.run_sqlcipher(path, script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return path

    def run_export(self, keys, *args):
        candidates = self.root / "candidates.json"
        candidates.write_text(json.dumps({"candidates": [{"key_hex": key} for key in keys]}))
        return subprocess.run([sys.executable, str(SCRIPTS / "wechat_export.py"),
            "--snapshot-dir", str(self.snapshot), "--key-candidates-json", str(candidates),
            "--out-dir", str(self.root / "output"), *args], capture_output=True, text=True)

    def test_distinct_keys_per_database_and_offline_custom_snapshot_path(self):
        for i, key in enumerate(self.keys):
            self.encrypted(f"message_{i}.db", key)
        result = self.run_export(self.keys, "--key-mode", "raw64")
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(result.stdout)
        self.assertEqual(len(metadata["decrypted_databases"]), 2)
        self.assertEqual([item["key_candidate_index"] for item in metadata["probe_results"]], [1, 2])
        for i in range(2):
            path = self.root / "output/plain/db_storage/message" / f"message_{i}.db"
            with contextlib.closing(sqlite3.connect(path)) as con:
                self.assertEqual(con.execute("SELECT value FROM fixture").fetchone(), ("synthetic message",))
        for key in self.keys:
            self.assertNotIn(key, result.stdout + result.stderr)
            self.assertNotIn(key, (self.root / "output/metadata.json").read_text())

    def test_missing_key_is_failure_in_probe_and_full_export(self):
        for i, key in enumerate(self.keys):
            self.encrypted(f"message_{i}.db", key)
        for args in (("--probe-only",), ()):
            result = self.run_export(self.keys[:1], "--key-mode", "raw64", *args)
            self.assertEqual(result.returncode, 1, result.stderr)
            metadata = json.loads(result.stdout)
            self.assertEqual([item["ok"] for item in metadata["probe_results"]], [True, False])
            if not args:
                self.assertEqual(len(metadata["failed_databases"]), 1)
                self.assertFalse((self.root / "output/plain/db_storage/message/message_1.db").exists())

    def test_legacy_binary_password_and_actual_compatibility(self):
        path = self.encrypted("message_0.db", self.keys[0], compatibility=3, mode="hexkey")
        params = exporter.probe_cipher_params(path, self.keys[:1])
        self.assertEqual((params.compatibility, params.order, params.key_mode), (3, "key_first", "hexkey"))
        result = self.run_export(self.keys[:1])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["probe_results"][0]["cipher_compatibility"], 3)

    def test_page_hmac_rejects_wrong_key_and_tampered_ciphertext(self):
        path = self.encrypted("message_0.db", self.keys[0])
        page = path.read_bytes()[:4096]
        self.assertTrue(exporter.verify_sqlcipher4_raw_key(page, self.keys[0]))
        self.assertFalse(exporter.verify_sqlcipher4_raw_key(page, self.keys[1]))
        changed = bytearray(page)
        changed[100] ^= 1
        self.assertFalse(exporter.verify_sqlcipher4_raw_key(bytes(changed), self.keys[0]))

    def test_snapshot_removes_stale_wal(self):
        path = self.encrypted("message_0.db", self.keys[0])
        destination = self.root / "copy"
        target = destination / path.relative_to(self.snapshot)
        target.parent.mkdir(parents=True)
        Path(str(target) + "-wal").write_bytes(b"obsolete WAL")
        exporter.copy_database_family(self.snapshot, str(path.relative_to(self.snapshot)), destination)
        self.assertFalse(Path(str(target) + "-wal").exists())

    def test_empty_snapshot_reports_clear_error(self):
        self.snapshot.mkdir(parents=True)
        result = self.run_export(self.keys)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no databases found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class ReadableGroupTests(unittest.TestCase):
    def test_secret_masking_preserves_public_urls_and_normal_text(self):
        key = "sk-proj-" + "syntheticCredentials0123456789" * 2
        examples = [f'OPENAI_API_KEY="{key}"', f'Authorization: Bearer {key}',
                    'https://example.invalid/?api_key=synthetic%2Fcredential',
                    'api_key: "' + hashlib.sha256(b"synthetic api key").hexdigest() + '"']
        for text in examples:
            masked, count = readable.redact(text)
            self.assertGreater(count, 0)
            self.assertIn(readable.MASK, masked)
            self.assertEqual(readable.redact(masked), (masked, 0))
            self.assertNotIn(key, masked)
        for text in ("讨论 API key 的使用", "https://example.invalid/some/0123456789abcdef0123456789abcdef",
                     "huggingface.co/datasets/example/a_very_long_collection_of_100_synthetic_envs"):
            self.assertEqual(readable.redact(text), (text, 0))

    def test_system_template_omits_attachment_keys_and_substitutes_members(self):
        text = ('<sysmsg><sysmsgtemplate><content_template><plain/><template>$username$ shared $history$</template>'
                '<link_list><link name="username"><memberlist><member><nickname>Fixture</nickname></member></memberlist></link>'
                '<link name="history"><title>3 messages</title><aeskey>synthetic-hidden-key</aeskey></link>'
                '</link_list></content_template></sysmsgtemplate></sysmsg>')
        self.assertEqual(readable.render(text, 10000), "Fixture shared 3 messages")
        self.assertEqual(readable.render("not parsed", 11000), "[贴纸]")

    def test_sharded_sender_resolution_deduplication_zstd_and_media(self):
        import zstandard
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contact = root / "plain/db_storage/contact/contact.db"
            contact.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(contact)) as con, con:
                con.execute("CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT)")
                con.executemany("INSERT INTO contact VALUES(?,?,?)", [
                    ("fixture@chatroom", "Fixture’s room", ""), ("sender_a", "Alice", ""), ("sender_b", "Bob", "")])
            table = "Msg_" + hashlib.md5(b"fixture@chatroom").hexdigest()
            secret = "sk-proj-" + "syntheticCredential0123456789"
            for shard in range(2):
                path = root / "plain/db_storage/message" / f"message_{shard}.db"
                path.parent.mkdir(parents=True, exist_ok=True)
                with contextlib.closing(sqlite3.connect(path)) as con, con:
                    con.execute("CREATE TABLE Name2Id(user_name TEXT)")
                    con.execute("INSERT INTO Name2Id VALUES(?)", ("sender_a" if shard == 0 else "sender_b",))
                    con.execute(f'CREATE TABLE "{table}"(local_id INTEGER,server_id INTEGER,local_type INTEGER,sort_seq INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content BLOB)')
                    rows = [(1, 10, 1, 1, 1, 100, zstandard.ZstdCompressor().compress(("secret: " + secret).encode())),
                            (2, 11, 3, 2, 1, 101, b"image bytes")]
                    if shard == 1:
                        rows = [(1, 10, 1, 1, 1, 100, b"duplicate"), (2, 12, 47, 3, 1, 102, b"sticker bytes")]
                    con.executemany(f'INSERT INTO "{table}" VALUES(?,?,?,?,?,?,?)', rows)
            groups = readable.resolve_groups(root / "plain", ["Fixture's room"])
            summary = readable.export(root / "plain", groups, root / "readable", "Asia/Shanghai")
            group = summary["groups"][0]
            self.assertEqual((group["messages"], group["duplicates_skipped"]), (3, 1))
            rows = [json.loads(line) for line in (root / "readable" / group["files"][2]).read_text().splitlines()]
            self.assertEqual([row["sender"] for row in rows], ["Alice", "Alice", "Bob"])
            self.assertEqual([row["content"] for row in rows], ["secret: " + readable.MASK, "[图片]", "[贴纸]"])
            with (root / "readable" / group["files"][0]).open(encoding="utf-8-sig", newline="") as handle:
                self.assertEqual([row["content"] for row in csv.DictReader(handle)], [row["content"] for row in rows])
            self.assertEqual(exporter.decode_message_content(zstandard.ZstdCompressor().compress("中文".encode())), "中文")


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class WrapperValidationTests(unittest.TestCase):
    def test_invalid_capture_options_fail_before_process_control(self):
        cases = [
            (["--account-path", "synthetic", "--kill-wechat"], "only valid"),
            (["--account-path", "synthetic", "--key-method", "debug-api"], "--cipher-rva"),
            (["--account-path"], "missing value"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for args, expected in cases:
                result = subprocess.run(["bash", str(SCRIPTS / "wechat_auto_export.sh"), *args],
                                        cwd=directory, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
