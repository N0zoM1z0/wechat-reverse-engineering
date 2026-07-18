# WeChat 4.x Case Study

This directory contains a sanitized public version of the WeChat for Windows 4.x local chat-storage study.

The goal is not to distribute private data or a universal decryptor. The goal is to document a reproducible analysis path and provide original tooling for authorized local research:

- identify the WCDB key-setting path;
- capture local key candidates with a precise runtime breakpoint;
- verify SQLCipher parameters against copied databases;
- export a local snapshot into readable JSONL/CSV.

## Directory layout

```text
BLOG.md                 full narrative write-up
scripts/                PowerShell, Python, and WSL helper scripts
reverse/analysis/       compact address map and schema notes
artifacts/validation/   sanitized validation summary only
```

## Tooling

### `scripts/Capture-WeChatKey-DebugApi.ps1`

Preferred key-capture path. It launches `Weixin.exe` under the Windows Debug API, waits for `Weixin.dll`, sets a one-byte breakpoint at the pinned `WCDB_Database_setCipherKey` RVA, reads the key object from the x64 calling convention, collects candidates, restores the original byte, and detaches.

The script requires an explicit `-WeChatExe` path in the public version.

### `scripts/wechat_export.py`

Snapshot/decrypt/export tool. It can:

- discover WeChat account folders under WSL;
- copy `.db`, `.db-wal`, and `.db-shm` families;
- probe SQLCipher key modes (`raw64`, `raw96`, `asciihex`, `hexkey`);
- decrypt copied databases with `sqlcipher_export`;
- export schema, contacts, sessions, messages, and resource tables.

### `scripts/wechat_auto_export.sh`

WSL wrapper for the capture/probe/export workflow. The public version requires explicit `--account-path`, `--snapshot-dir`, and `--wechat-exe` arguments.

## Example workflow

Take a snapshot while WeChat is closed:

```bash
python3 scripts/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-only \
  --out-dir exports/full-snapshot
```

Capture key candidates:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "$(wslpath -w scripts/Capture-WeChatKey-DebugApi.ps1)" `
  -WeChatExe "C:\Path\To\WeChat\Weixin.exe" `
  -MaxCaptures 16 `
  -OutFile "$(wslpath -w exports/key-candidates.json)"
```

Verify without writing plaintext databases:

```bash
python3 scripts/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-dir exports/full-snapshot/snapshot \
  --key-candidates-json exports/key-candidates.json \
  --probe-only \
  --out-dir exports/probe
```

Export:

```bash
python3 scripts/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-dir exports/full-snapshot/snapshot \
  --key-candidates-json exports/key-candidates.json \
  --out-dir exports/decrypted-full
```

## Output policy

Everything under `exports/` is ignored. Treat it as sensitive: it may contain key candidates, encrypted snapshots, decrypted SQLite databases, contacts, sessions, and message records.

Do not commit generated outputs.
