#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MESSAGE_DB_RE = re.compile(r"^(?:biz_)?(?:message|media)_\d+\.db$")
DEFAULT_DB_RELATIVES = (
    "db_storage/contact/contact.db",
    "db_storage/session/session.db",
    "db_storage/message/message_resource.db",
    "db_storage/hardlink/hardlink.db",
)
KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
KEY_MODES = ("raw64", "raw96", "asciihex", "hexkey")


@dataclass(frozen=True)
class CipherParams:
    key_hex: str
    key_index: int
    compatibility: int
    order: str
    key_mode: str


def fail(message: str, code: int = 1) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def normalize_key(value: str) -> str:
    value = value.strip()
    if value.startswith("x'") and value.endswith("'"):
        value = value[2:-1]
    if not KEY_RE.fullmatch(value):
        fail("key must be a 64-character hex raw SQLCipher key")
    return value.lower()


def collect_key_candidates(value: Any) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()

    def add(candidate: Any) -> None:
        if not isinstance(candidate, str):
            return
        candidate = candidate.strip()
        if KEY_RE.fullmatch(candidate):
            normalized = candidate.lower()
            if normalized not in seen:
                seen.add(normalized)
                keys.append(normalized)

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for name in ("KeyHex", "key_hex", "keyHex", "key"):
                add(item.get(name))
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return keys


def load_key_candidates(path: Path) -> list[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"could not read key candidate JSON {path}: {exc}")
    keys = collect_key_candidates(payload)
    if not keys:
        fail(f"no 64-hex KeyHex/key_hex entries found in {path}")
    return keys


def discover_account_path() -> Path:
    roots = glob.glob("/mnt/c/Users/*/Documents/xwechat_files/wxid_*")
    candidates: list[Path] = []
    for item in roots:
        path = Path(item)
        if (path / "db_storage" / "message").is_dir():
            candidates.append(path)
    if not candidates:
        fail("could not auto-discover an xwechat_files account path; pass --account-path")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def selected_database_relatives(account_path: Path) -> list[str]:
    rels: list[str] = []
    message_dir = account_path / "db_storage" / "message"
    if message_dir.is_dir():
        for db_path in sorted(message_dir.glob("*.db")):
            if MESSAGE_DB_RE.match(db_path.name):
                rels.append(str(db_path.relative_to(account_path)))
    for rel in DEFAULT_DB_RELATIVES:
        if (account_path / rel).exists():
            rels.append(rel)
    return rels


def key_capture_relative(account_path: Path) -> str | None:
    message_dir = account_path / "db_storage" / "message"
    preferred = message_dir / "message_0.db"
    if preferred.exists():
        return str(preferred.relative_to(account_path))
    message_dbs = sorted(message_dir.glob("message_*.db")) if message_dir.is_dir() else []
    if message_dbs:
        return str(message_dbs[0].relative_to(account_path))
    for rel in selected_database_relatives(account_path):
        if MESSAGE_DB_RE.match(Path(rel).name):
            return rel
    return None


def copy_database_family(account_path: Path, rel: str, snapshot_root: Path) -> Path:
    source = account_path / rel
    target = snapshot_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        item = Path(str(source) + suffix)
        if item.exists():
            out = Path(str(target) + suffix)
            shutil.copy2(item, out)
    return target


def make_snapshot(account_path: Path, out_dir: Path) -> list[Path]:
    snapshot_root = out_dir / "snapshot"
    snapshot_root.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for rel in selected_database_relatives(account_path):
        copied.append(copy_database_family(account_path, rel, snapshot_root))
    if not copied:
        fail(f"no supported databases found under {account_path}")
    return copied


def run_sqlcipher(db_path: Path, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sqlcipher", str(db_path)],
        input=script,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def to_windows_path(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"wslpath failed for {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def capture_key_with_powershell(database_path: Path) -> str:
    script_path = Path(__file__).resolve().with_name("Get-WeChatDbKey.ps1")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            to_windows_path(script_path),
            "-DatabasePath",
            to_windows_path(database_path),
            "-ShowKey",
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("auto key capture failed. " + (result.stderr or result.stdout).strip())
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"auto key capture returned invalid JSON: {exc}")
    first = payload[0] if isinstance(payload, list) else payload
    key_hex = first.get("key_hex")
    if not key_hex:
        fail("auto key capture did not return key_hex")
    return normalize_key(key_hex)


def database_salt_hex(db_path: Path) -> str:
    with db_path.open("rb") as handle:
        salt = handle.read(16)
    if len(salt) != 16:
        fail(f"database is too small to contain a SQLCipher salt: {db_path}")
    return salt.hex()


def sqlcipher_key_pragma(db_path: Path, key_hex: str, key_mode: str) -> str:
    if key_mode == "raw64":
        return f"PRAGMA key = \"x'{key_hex}'\";"
    if key_mode == "raw96":
        return f"PRAGMA key = \"x'{key_hex}{database_salt_hex(db_path)}'\";"
    if key_mode == "asciihex":
        return f"PRAGMA key = '{key_hex}';"
    if key_mode == "hexkey":
        return f"PRAGMA hexkey = '{key_hex}';"
    fail(f"unsupported SQLCipher key mode: {key_mode}")


def sqlcipher_probe_script(db_path: Path, key_hex: str, compatibility: int, order: str, key_mode: str) -> str:
    key_pragma = sqlcipher_key_pragma(db_path, key_hex, key_mode)
    if order == "compat_first":
        pragmas = [
            f"PRAGMA cipher_compatibility = {compatibility};",
            key_pragma,
            "PRAGMA cipher_page_size = 4096;",
        ]
    else:
        pragmas = [
            key_pragma,
            f"PRAGMA cipher_compatibility = {compatibility};",
            "PRAGMA cipher_page_size = 4096;",
        ]
    return "\n".join(pragmas + ["SELECT count(*) FROM sqlite_master;", ".quit"]) + "\n"


def sqlcipher_probe_success(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode == 0 and re.search(r"\b[0-9]+\b", result.stdout) is not None


def probe_cipher_params(db_path: Path, key_candidates: list[str]) -> CipherParams:
    errors: list[str] = []
    for index, key_hex in enumerate(key_candidates, 1):
        for key_mode in KEY_MODES:
            for compatibility in (3, 4):
                for order in ("key_first", "compat_first"):
                    result = run_sqlcipher(db_path, sqlcipher_probe_script(db_path, key_hex, compatibility, order, key_mode))
                    if sqlcipher_probe_success(result):
                        return CipherParams(
                            key_hex=key_hex,
                            key_index=index,
                            compatibility=compatibility,
                            order=order,
                            key_mode=key_mode,
                        )
                    message = (result.stderr or result.stdout).strip().splitlines()
                    if message:
                        errors.append(
                            f"candidate={index} mode={key_mode} compat={compatibility} order={order}: {message[-1]}"
                        )
    fail(
        "SQLCipher could not open the first database with the provided key candidates. "
        + " | ".join(errors[-5:])
    )


def probe_database_with_params(db_path: Path, params: CipherParams) -> dict[str, Any]:
    result = run_sqlcipher(
        db_path,
        sqlcipher_probe_script(db_path, params.key_hex, params.compatibility, params.order, params.key_mode),
    )
    item: dict[str, Any] = {
        "database": str(db_path),
        "ok": sqlcipher_probe_success(result),
    }
    number = re.search(r"\b[0-9]+\b", result.stdout)
    if number:
        item["sqlite_master_count"] = int(number.group(0))
    if not item["ok"]:
        message = (result.stderr or result.stdout).strip().splitlines()
        item["error"] = message[-1] if message else f"sqlcipher exited with {result.returncode}"
    return item


def sqlcipher_export_script(db_path: Path, key_hex: str, compatibility: int, order: str, key_mode: str, plain_db: Path) -> str:
    plain = str(plain_db).replace("'", "''")
    key_pragma = sqlcipher_key_pragma(db_path, key_hex, key_mode)
    pragmas: list[str]
    if order == "compat_first":
        pragmas = [
            f"PRAGMA cipher_compatibility = {compatibility};",
            key_pragma,
            "PRAGMA cipher_page_size = 4096;",
        ]
    else:
        pragmas = [
            key_pragma,
            f"PRAGMA cipher_compatibility = {compatibility};",
            "PRAGMA cipher_page_size = 4096;",
        ]
    return "\n".join(
        pragmas
        + [
            "SELECT count(*) FROM sqlite_master;",
            f"ATTACH DATABASE '{plain}' AS plaintext KEY '';",
            "SELECT sqlcipher_export('plaintext');",
            "DETACH DATABASE plaintext;",
            ".quit",
        ]
    ) + "\n"


def validate_plain_db(path: Path) -> int:
    con = open_plain_sqlite(path)
    try:
        return int(con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0])
    finally:
        con.close()


def open_plain_sqlite(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.text_factory = lambda raw: raw.decode("utf-8", "replace")
    return con


def decrypt_database(db_path: Path, plain_root: Path, params: CipherParams) -> Path | None:
    if "snapshot" in db_path.parts:
        parts = list(db_path.parts)
        index = len(parts) - 1 - list(reversed(parts)).index("snapshot")
        rel = Path(*parts[index + 1 :])
    else:
        rel = Path(db_path.name)
    plain_db = plain_root / rel
    plain_db.parent.mkdir(parents=True, exist_ok=True)
    if plain_db.exists():
        plain_db.unlink()
    result = run_sqlcipher(
        db_path,
        sqlcipher_export_script(
            db_path,
            params.key_hex,
            params.compatibility,
            params.order,
            params.key_mode,
            plain_db,
        ),
    )
    if result.returncode != 0:
        return None
    try:
        validate_plain_db(plain_db)
    except sqlite3.DatabaseError:
        return None
    return plain_db


def table_columns(con: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in con.execute(f"PRAGMA table_info({quote_identifier(table)})")]


def table_count(con: sqlite3.Connection, table: str) -> int | None:
    try:
        return int(con.execute(f"SELECT count(*) FROM {quote_identifier(table)}").fetchone()[0])
    except sqlite3.DatabaseError:
        return None


def first_existing(columns: list[str], names: tuple[str, ...]) -> str | None:
    lower = {c.lower(): c for c in columns}
    for name in names:
        if name.lower() in lower:
            return lower[name.lower()]
    return None


def decode_time(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    if number > 10**17:
        number /= 1_000_000_000
    elif number > 10**12:
        number /= 1000
    if number < 946684800 or number > 4102444800:
        return None
    return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc).isoformat()


def iter_rows(con: sqlite3.Connection, table: str):
    con.row_factory = sqlite3.Row
    query = f"SELECT rowid AS __rowid__, * FROM {quote_identifier(table)}"
    yield from con.execute(query)


def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=json_default) + "\n")
            count += 1
    return count


def export_contacts(plain_db: Path, out_dir: Path) -> dict[str, dict[str, Any]]:
    contacts: dict[str, dict[str, Any]] = {}
    if not plain_db.exists():
        return contacts
    con = open_plain_sqlite(plain_db)
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        exported: list[dict[str, Any]] = []
        for table in tables:
            cols = table_columns(con, table)
            user_col = first_existing(cols, ("userName", "username", "wxid", "contactUsername", "m_nsUsrName"))
            nick_col = first_existing(cols, ("nickName", "nickname", "conRemark", "remark", "alias", "displayName"))
            if not user_col:
                continue
            for row in iter_rows(con, table):
                item = dict(row)
                username = item.get(user_col)
                if isinstance(username, bytes):
                    username = username.decode("utf-8", "replace")
                if username:
                    display = item.get(nick_col) if nick_col else None
                    contacts[str(username)] = {"display": display, "source_table": table}
                item["_source_table"] = table
                exported.append(item)
        if exported:
            write_jsonl(out_dir / "contacts.jsonl", exported)
    finally:
        con.close()
    return contacts


def export_sessions(plain_db: Path, out_dir: Path) -> int:
    if not plain_db.exists():
        return 0
    con = open_plain_sqlite(plain_db)
    try:
        rows: list[dict[str, Any]] = []
        for table in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
            cols = table_columns(con, table)
            if not first_existing(cols, ("strUsrName", "userName", "username", "sessionId", "talker")):
                continue
            for row in iter_rows(con, table):
                item = dict(row)
                item["_source_table"] = table
                rows.append(item)
        return write_jsonl(out_dir / "sessions.jsonl", rows) if rows else 0
    finally:
        con.close()


def message_name_maps(con: sqlite3.Connection) -> tuple[dict[str, str], dict[int, str]]:
    shard_talkers: dict[str, str] = {}
    id_names: dict[int, str] = {}
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "Name2Id" not in tables:
        return shard_talkers, id_names
    try:
        for rowid, username in con.execute("SELECT rowid, user_name FROM Name2Id"):
            if username is None:
                continue
            value = str(username)
            shard_talkers[hashlib.md5(value.encode("utf-8")).hexdigest()] = value
            id_names[int(rowid)] = value
    except sqlite3.DatabaseError:
        return shard_talkers, id_names
    return shard_talkers, id_names


def shard_talker_for_table(table: str, shard_talkers: dict[str, str]) -> str | None:
    if not table.startswith("Msg_"):
        return None
    return shard_talkers.get(table[4:])


def mapped_sender(value: Any, id_names: dict[int, str]) -> Any:
    try:
        return id_names.get(int(value), value)
    except (TypeError, ValueError):
        return value


def normalize_message_row(
    db_name: str,
    table: str,
    columns: list[str],
    row: sqlite3.Row,
    contacts: dict[str, dict[str, Any]],
    shard_talkers: dict[str, str],
    id_names: dict[int, str],
) -> dict[str, Any] | None:
    id_col = first_existing(columns, ("localId", "local_id", "msgId", "msgSvrId", "server_id", "MesLocalID", "messageId"))
    talker_col = first_existing(columns, ("talker", "strTalker", "username", "userName", "chatName", "conversationId"))
    sender_col = first_existing(columns, ("sender", "fromUser", "from_username", "contentSender", "real_sender_id"))
    content_col = first_existing(columns, ("content", "msgContent", "message_content", "message", "msg", "xmlContent", "compress_content"))
    type_col = first_existing(columns, ("type", "msgType", "local_type", "messageType"))
    subtype_col = first_existing(columns, ("subType", "msgSubType"))
    is_send_col = first_existing(columns, ("isSend", "is_sender", "is_sender_msg"))
    time_col = first_existing(columns, ("createTime", "create_time", "msgCreateTime", "timestamp", "time"))

    if not content_col and not (talker_col and time_col and type_col):
        return None

    raw = dict(row)
    talker = raw.get(talker_col) if talker_col else shard_talker_for_table(table, shard_talkers)
    sender_raw = raw.get(sender_col) if sender_col else None
    sender = mapped_sender(sender_raw, id_names)
    timestamp = raw.get(time_col) if time_col else None
    item = {
        "db": db_name,
        "table": table,
        "rowid": raw.get("__rowid__"),
        "id": raw.get(id_col) if id_col else raw.get("__rowid__"),
        "talker": talker,
        "talker_display": contacts.get(str(talker), {}).get("display") if talker is not None else None,
        "sender": sender,
        "sender_display": contacts.get(str(sender), {}).get("display") if sender is not None else None,
        "sender_id": sender_raw,
        "is_send": raw.get(is_send_col) if is_send_col else None,
        "type": raw.get(type_col) if type_col else None,
        "subtype": raw.get(subtype_col) if subtype_col else None,
        "create_time": timestamp,
        "create_time_iso": decode_time(timestamp),
        "content": raw.get(content_col) if content_col else None,
    }
    return item


def export_messages(plain_dbs: list[Path], out_dir: Path, contacts: dict[str, dict[str, Any]]) -> int:
    messages: list[dict[str, Any]] = []
    for db_path in plain_dbs:
        if not MESSAGE_DB_RE.match(db_path.name):
            continue
        con = open_plain_sqlite(db_path)
        try:
            shard_talkers, id_names = message_name_maps(con)
            for table in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
                if table.startswith("sqlite_"):
                    continue
                cols = table_columns(con, table)
                for row in iter_rows(con, table):
                    item = normalize_message_row(db_path.name, table, cols, row, contacts, shard_talkers, id_names)
                    if item:
                        messages.append(item)
        finally:
            con.close()

    messages.sort(key=lambda m: (m.get("create_time") is None, m.get("create_time") or 0, m.get("rowid") or 0))
    if not messages:
        return 0

    write_jsonl(out_dir / "messages.jsonl", messages)
    with (out_dir / "messages.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "create_time_iso",
            "talker_display",
            "talker",
            "sender_display",
            "sender",
            "is_send",
            "type",
            "subtype",
            "content",
            "db",
            "table",
            "id",
            "rowid",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(messages)
    return len(messages)


def export_schema(plain_dbs: list[Path], out_dir: Path) -> dict[str, Any]:
    schema: dict[str, Any] = {}
    for db_path in plain_dbs:
        con = open_plain_sqlite(db_path)
        try:
            db_entry: dict[str, Any] = {}
            for table in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
                if table.startswith("sqlite_"):
                    continue
                db_entry[table] = {
                    "columns": table_columns(con, table),
                    "row_count": table_count(con, table),
                }
            schema[db_path.name] = db_entry
        finally:
            con.close()
    (out_dir / "schema.json").write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
    return schema


def export_resource_tables(plain_dbs: list[Path], out_dir: Path) -> int:
    exported = 0
    resource_names = {"message_resource.db", "hardlink.db"}
    for db_path in plain_dbs:
        if db_path.name not in resource_names:
            continue
        con = open_plain_sqlite(db_path)
        try:
            rows: list[dict[str, Any]] = []
            for table in [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
                if table.startswith("sqlite_"):
                    continue
                for row in iter_rows(con, table):
                    item = dict(row)
                    item["_source_db"] = db_path.name
                    item["_source_table"] = table
                    rows.append(item)
            if rows:
                exported += write_jsonl(out_dir / f"{db_path.stem}.jsonl", rows)
        finally:
            con.close()
    return exported


def main() -> int:
    parser = argparse.ArgumentParser(description="Snapshot and export WeChat 4.x WCDB chat databases.")
    parser.add_argument("--account-path", type=Path, help="Path to wxid_* account directory. Auto-discovers under /mnt/c/Users if omitted.")
    parser.add_argument("--key-hex", help="64 hex SQLCipher raw key. Accepts either raw hex or x'<hex>'.")
    parser.add_argument("--key-candidates-json", type=Path, help="JSON file produced by Capture-WeChatKey-DebugApi.ps1; tries each KeyHex entry.")
    parser.add_argument("--auto-key", action="store_true", help="Call Get-WeChatDbKey.ps1 through powershell.exe when --key-hex is omitted.")
    parser.add_argument("--out-dir", type=Path, default=Path("exports") / dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--snapshot-only", action="store_true", help="Only copy encrypted DB/WAL/SHM files.")
    parser.add_argument("--snapshot-dir", type=Path, help="Use an existing snapshot directory instead of copying from the account path.")
    parser.add_argument("--probe-only", action="store_true", help="Only verify SQLCipher parameters against the snapshot; do not decrypt or export plaintext DBs.")
    args = parser.parse_args()

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass

    account_path = args.account_path.resolve() if args.account_path else discover_account_path()
    if args.snapshot_dir:
        snapshot_dbs = sorted(args.snapshot_dir.rglob("*.db"))
    else:
        snapshot_dbs = make_snapshot(account_path, out_dir)

    metadata: dict[str, Any] = {
        "account_path": str(account_path),
        "output_dir": str(out_dir),
        "snapshot_databases": [str(p) for p in snapshot_dbs],
    }

    if args.snapshot_only:
        (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        print(json.dumps(metadata, indent=2))
        return 0

    key_candidates: list[str] = []
    if args.key_hex:
        key_candidates.append(normalize_key(args.key_hex))
    if args.key_candidates_json:
        for candidate in load_key_candidates(args.key_candidates_json.resolve()):
            if candidate not in key_candidates:
                key_candidates.append(candidate)
    if not key_candidates and args.auto_key:
        source_rel = key_capture_relative(account_path)
        if not source_rel:
            fail("auto key capture needs a message_*.db source database")
        key_candidates.append(capture_key_with_powershell(account_path / source_rel))
    if not key_candidates:
        fail("missing key input. Pass --key-hex, --key-candidates-json, or --auto-key while WeChat is running.")

    first_db = next((p for p in snapshot_dbs if MESSAGE_DB_RE.match(p.name)), snapshot_dbs[0])
    cipher_params = probe_cipher_params(first_db, key_candidates)

    metadata.update(
        {
            "key_candidate_count": len(key_candidates),
            "key_candidate_index": cipher_params.key_index,
            "cipher_compatibility": cipher_params.compatibility,
            "cipher_order": cipher_params.order,
            "cipher_key_mode": cipher_params.key_mode,
        }
    )

    if args.probe_only:
        metadata["probe_results"] = [probe_database_with_params(db_path, cipher_params) for db_path in snapshot_dbs]
        (out_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(metadata, ensure_ascii=False, indent=2))
        return 0

    plain_root = out_dir / "plain"
    plain_dbs: list[Path] = []
    failed: list[str] = []
    for db_path in snapshot_dbs:
        plain = decrypt_database(db_path, plain_root, cipher_params)
        if plain:
            plain_dbs.append(plain)
        else:
            failed.append(str(db_path))

    schema = export_schema(plain_dbs, out_dir)
    contact_db = next((p for p in plain_dbs if p.name == "contact.db"), None)
    session_db = next((p for p in plain_dbs if p.name == "session.db"), None)
    contacts = export_contacts(contact_db, out_dir) if contact_db else {}
    sessions = export_sessions(session_db, out_dir) if session_db else 0
    messages = export_messages(plain_dbs, out_dir, contacts)
    resources = export_resource_tables(plain_dbs, out_dir)

    metadata.update(
        {
            "decrypted_databases": [str(p) for p in plain_dbs],
            "failed_databases": failed,
            "schema_database_count": len(schema),
            "contacts": len(contacts),
            "sessions": sessions,
            "messages": messages,
            "resource_rows": resources,
        }
    )
    (out_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
