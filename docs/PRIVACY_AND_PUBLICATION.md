# Privacy and Publication Policy

This repository is designed for public release. Keep it that way.

## Never commit

- WeChat binaries or proprietary resources.
- IDA databases, debugger memory dumps, or complete decompiler output.
- `key-candidates*.json` or any captured key material.
- Encrypted or decrypted `.db`, `.db-wal`, `.db-shm`, SQLite exports, CSVs, JSONL chat exports, or media files.
- Real wxid values, aliases, usernames, phone numbers, contact names, chatroom IDs, process IDs, machine names, absolute local paths, or message text.
- Screenshots of private chats, contacts, sessions, or local filesystem state.

## Acceptable public artifacts

- Original source code.
- Compact pseudocode and notes needed to support a finding.
- Build hashes and module-relative offsets.
- Sanitized schema descriptions.
- Synthetic test data.
- Aggregate validation summaries with no identifiers or message content.

## Release checklist

Before publishing:

```bash
rg -n -i "keyhex|bufferhex|wxid_|key-candidates|\\.db-wal|\\.db-shm|message_content|contact\\.db|session\\.db" .
find . -type f \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.jsonl' -o -name '*.csv' \)
```

Then manually inspect:

- `README.md`
- `wechat4/README.md`
- `wechat4/BLOG.md`
- `wechat4/reverse/analysis/*.md`
- `wechat4/artifacts/**/*.json`

Counts alone are acceptable if they cannot identify a person or account. When in doubt, replace local evidence with synthetic or redacted evidence.
