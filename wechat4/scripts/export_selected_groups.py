#!/usr/bin/env python3
"""Export selected WeChat group tables from decrypted snapshots, with secret masking."""
from __future__ import annotations

import argparse
import collections
from contextlib import closing
import csv
import datetime as dt
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import unicodedata
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo

import zstandard

MASK = "[API_KEY_REDACTED]"
KNOWN_SECRET = re.compile(
    r"(?<![\w-])(?:sk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{12,}"
    r"|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}"
    r"|AIza[A-Za-z0-9_-]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{12,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
LABELED_SECRET = re.compile(
    r"(?i)((?:[\w.-]*(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|"
    r"secret[_ -]?key|access[_ -]?key|client[_ -]?secret|password|passwd)[\w.-]*|"
    r"secret|token|key|"
    r"x-api-key|authorization|密钥|秘钥|令牌|口令|密码)"
    r"[\"']?\s*(?:[=:：]|\bis\b|为|是)\s*[\"']?)"
    r"(?:Bearer\s+)?([A-Za-z0-9_./+~=-]{8,})"
)
BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9_./+~=-]{8,}")
QUERY_SECRET = re.compile(
    r"(?i)([?&](?:api_?key|key|token|access_token|secret|signature|sig|auth)=)[^\s&#<>\"']+"
)
LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9_-])")
URL = re.compile(r"(?:https?://|(?:[\w-]+\.)+[A-Za-z]{2,24}/)[^\s<>\"']+", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def redact(text: str) -> tuple[str, int]:
    count = 0

    def mask(match: re.Match) -> str:
        nonlocal count
        count += 1
        return MASK

    def keep_label(match: re.Match) -> str:
        nonlocal count
        if match[0][len(match[1]):] == MASK:
            return match[0]
        count += 1
        return match[1] + MASK

    text = PRIVATE_KEY.sub(mask, text)
    text = QUERY_SECRET.sub(keep_label, text)
    text = LABELED_SECRET.sub(keep_label, text)
    text = BEARER.sub(keep_label, text)
    text = KNOWN_SECRET.sub(mask, text)
    url_spans = [match.span() for match in URL.finditer(text)]

    def opaque(match: re.Match) -> str:
        if any(start <= match.start() < end for start, end in url_spans):
            return match[0]
        value = match[0]
        frequencies = collections.Counter(value)
        entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in frequencies.values())
        if entropy >= 3.3 and (any(c.isdigit() for c in value) or len(value) >= 48):
            return mask(match)
        if re.fullmatch(r"[0-9a-fA-F]{32,}", value):
            return mask(match)
        return value

    return LONG_TOKEN.sub(opaque, text), count


def decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        if value.startswith(b"\x28\xb5\x2f\xfd"):
            value = zstandard.ZstdDecompressor().decompress(value, max_output_size=32 * 1024 * 1024)
        return value.decode("utf-8", "replace")
    return str(value)


def render(content: str, message_type: int, depth: int = 0) -> str:
    if depth > 8:
        return "[嵌套引用]"
    kind = message_type & 0xFFFFFFFF
    placeholders = {3: "[图片]", 47: "[贴纸]", 11000: "[贴纸]", 34: "[语音]", 43: "[视频]", 62: "[视频]", 48: "[位置]", 50: "[通话]"}
    if kind in placeholders:
        return placeholders[kind]
    if kind == 1:
        return content
    if "<" not in content:
        return content or f"[消息类型 {kind}]"
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        if kind == 49:
            parts = []
            for tag in ("title", "des", "url"):
                match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", content, re.S)
                if match:
                    parts.append(html.unescape(re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", match[1], flags=re.S)))
            return "\n".join(parts) or "[分享消息：内容无法解析]"
        return html.unescape(re.sub(r"<[^>]+>", "", content)).strip() or f"[消息类型 {kind}]"
    if kind == 49:
        app = root if root.tag == "appmsg" else root.find(".//appmsg")
        if app is None:
            return "[分享消息]"
        subtype = app.findtext("type", "")
        title = app.findtext("title", "")
        if subtype == "6":
            return "[文件] " + title
        if subtype == "19":
            pieces = ["[聊天记录] " + title]
            record = app.findtext("recorditem", "")
            if record:
                try:
                    rec = ET.fromstring(record)
                    for item in rec.findall(".//dataitem"):
                        typ = item.attrib.get("datatype", "")
                        who = item.findtext("sourcename", "")
                        if typ == "2":
                            body = "[图片]"
                        elif typ in ("8", "47"):
                            body = "[贴纸]" if typ == "47" else "[文件] " + item.findtext("datatitle", "")
                        else:
                            body = item.findtext("datadesc", "") or item.findtext("datatitle", "") or "[附件]"
                        pieces.append((who + ": " if who else "") + body)
                except ET.ParseError:
                    pieces.append("[转发内容无法解析]")
            return "\n".join(pieces)
        parts = [title]
        description = app.findtext("des", "")
        if description and description != title:
            parts.append(description)
        url = app.findtext("url", "")
        if url:
            parts.append(url)
        reference = app.find("refermsg")
        if reference is not None:
            who = reference.findtext("displayname", "")
            try:
                ref_type = int(reference.findtext("type", "1"))
            except ValueError:
                ref_type = 1
            body = render(reference.findtext("content", ""), ref_type, depth + 1)
            parts.append("[引用] " + (who + ": " if who else "") + body)
        return "\n".join(p for p in parts if p) or "[分享消息]"
    if kind == 10000 or kind == 10002:
        content_template = root.find(".//content_template")
        if content_template is not None:
            text = content_template.findtext("plain") or content_template.findtext("template", "")
            for link in content_template.findall(".//link"):
                name = link.attrib.get("name", "")
                if not name:
                    continue
                label = link.findtext("plain") or link.findtext("title")
                if not label:
                    label = ", ".join(
                        member.findtext("nickname") or member.findtext("username", "")
                        for member in link.findall(".//member")
                    )
                text = text.replace("$" + name + "$", label or "[系统消息链接]")
            return text.strip() or "[系统消息]"
        text = root.findtext(".//plain") or root.findtext(".//replacemsg")
        if text:
            return html.unescape(re.sub(r"<[^>]+>", "", text))
        return (root.text or "").strip() or "[系统消息]"
    if kind == 42:
        return "[名片] " + root.attrib.get("nickname", "")
    return f"[消息类型 {kind}]"


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def resolve_groups(plain_root: Path, names: list[str]) -> list[dict]:
    def normalized(value: str) -> str:
        return unicodedata.normalize("NFKC", value).casefold().replace("’", "'").replace("‘", "'")
    with closing(connect(plain_root / "db_storage/contact/contact.db")) as con:
        contacts = list(con.execute("SELECT username,nick_name,remark FROM contact WHERE username LIKE '%@chatroom'"))
    groups, seen = [], set()
    for name in names:
        matches = [row for row in contacts if normalized(name) in {
            normalized(row[column] or "") for column in ("username", "nick_name", "remark")}]
        if len(matches) != 1:
            raise ValueError("Group must match exactly one contact; use its chatroom username to disambiguate: " + name)
        row = matches[0]
        if row["username"] in seen:
            continue
        seen.add(row["username"])
        display = row["remark"] or row["nick_name"] or row["username"]
        stem = re.sub(r"[^\w.-]+", "_", display).strip("._")[:80] or "group"
        stem += "_" + hashlib.md5(row["username"].encode()).hexdigest()[:8]
        groups.append({"name": display, "username": row["username"], "filename": stem})
    return groups


def export(plain_root: Path, groups: list[dict], out_dir: Path, timezone: str) -> dict:
    os.umask(0o077)
    out_dir.mkdir(parents=True, exist_ok=True)
    contact_path = plain_root / "db_storage/contact/contact.db"
    with closing(connect(contact_path)) as con:
        contacts = {r["username"]: r["remark"] or r["nick_name"] or r["username"] for r in con.execute("SELECT username,remark,nick_name FROM contact")}
    tz = ZoneInfo(timezone)
    summary = {"timezone": timezone, "source": str(plain_root.resolve()), "groups": [], "redaction": "Known API key formats, labeled credentials, bearer tokens, sensitive URL parameters, and opaque long tokens; image/sticker payloads omitted."}
    for group in groups:
        username = group["username"]
        name = group["name"]
        table = "Msg_" + hashlib.md5(username.encode()).hexdigest()
        messages = []
        counts = collections.Counter()
        seen = set()
        for db_path in sorted((plain_root / "db_storage/message").glob("message_[0-9]*.db")):
            with closing(connect(db_path)) as con:
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if table not in tables:
                    continue
                id_names = {r[0]: r[1] for r in con.execute("SELECT rowid,user_name FROM Name2Id")}
                for row in con.execute(f'SELECT * FROM "{table}" ORDER BY create_time,sort_seq,local_id'):
                    server_id = int(row["server_id"] or 0)
                    identity = ("server", server_id) if server_id else (db_path.name, row["local_id"])
                    if identity in seen:
                        counts["duplicates_skipped"] += 1
                        continue
                    seen.add(identity)
                    raw_type = int(row["local_type"] or 0)
                    kind = raw_type & 0xFFFFFFFF
                    sender = id_names.get(row["real_sender_id"], str(row["real_sender_id"]))
                    if kind in (3, 47, 11000, 34, 43, 62, 48, 50):
                        content = ""
                    else:
                        content = decode(row["message_content"])
                        if not content and "compress_content" in row.keys():
                            content = decode(row["compress_content"])
                    prefix = re.match(r"^([^\s<>:]{1,100}):\r?\n", content)
                    if prefix and (prefix[1] == sender or prefix[1].startswith("wxid_") or prefix[1] in contacts):
                        sender = prefix[1]
                        content = content[prefix.end():]
                    readable = render(content, raw_type)
                    readable, masked = redact(readable)
                    display, display_masked = redact(contacts.get(sender, sender))
                    counts["redacted_values"] += masked + display_masked
                    if masked or display_masked:
                        counts["redacted_messages"] += 1
                    if kind == 3:
                        counts["images"] += 1
                    if kind in (47, 11000):
                        counts["stickers"] += 1
                    timestamp = int(row["create_time"] or 0)
                    messages.append({"time": dt.datetime.fromtimestamp(timestamp, tz).isoformat(), "sender": display, "sender_id": sender, "type": kind, "content": readable, "timestamp": timestamp, "server_id": str(server_id), "_order": int(row["sort_seq"] or row["local_id"])})
        messages.sort(key=lambda m: (m["timestamp"], m["_order"]))
        for item in messages:
            item.pop("_order")
        stem = group["filename"]
        if not stem or Path(stem).name != stem or stem in (".", "..") or "\\" in stem:
            raise ValueError("Group filename must be a single filename stem")
        fields = ["time", "sender", "sender_id", "type", "content", "timestamp", "server_id"]
        with (out_dir / (stem + ".csv")).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(messages)
        with (out_dir / (stem + ".jsonl")).open("w", encoding="utf-8") as handle:
            for item in messages:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        with (out_dir / (stem + ".txt")).open("w", encoding="utf-8") as handle:
            handle.write(f"{name}\n时区：{timezone}\n图片：[图片]；贴纸：[贴纸]；密钥：{MASK}\n\n")
            for item in messages:
                handle.write(f"[{item['time']}] {item['sender']}\n{item['content']}\n\n")
        summary["groups"].append({"name": name, "username": username, "messages": len(messages), "first": messages[0]["time"] if messages else None, "last": messages[-1]["time"] if messages else None, **counts, "files": [stem + suffix for suffix in (".csv", ".txt", ".jsonl")]})
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plain-root", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--groups-json", type=Path, help="Legacy list of name/username/filename records")
    selection.add_argument("--group", action="append", help="Exact group name, remark, or chatroom username; repeat for multiple groups")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timezone", default="Asia/Shanghai")
    args = parser.parse_args()
    try:
        groups = json.loads(args.groups_json.read_text(encoding="utf-8")) if args.groups_json else resolve_groups(args.plain_root, args.group)
        print(json.dumps(export(args.plain_root, groups, args.out_dir, args.timezone), ensure_ascii=False, indent=2))
    except ValueError as exc:
        parser.error(str(exc))
