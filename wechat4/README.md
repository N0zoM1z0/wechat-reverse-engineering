# WeChat 4.x local export

The current workflow was validated against Windows WeChat **4.2.0.12**. The
original 4.1.11.54 study remains in [BLOG.md](BLOG.md) and the address map.

## Requirements

- Windows with 64-bit PowerShell, logged-in WeChat, and read access to its main process.
- WSL with Python 3.10+, SQLCipher **4**, `wslpath` and `powershell.exe` interop.
- Compressed-message support (run from the repository root):

```bash
python3 -m pip install -r wechat4/scripts/requirements.txt
```

The capture script can also run directly under Windows PowerShell; the wrapper
and documented exporter workflow use WSL.

## One-command export

```bash
bash wechat4/scripts/wechat_auto_export.sh \
  --account-path '/mnt/c/Users/<user>/Documents/xwechat_files/<account>' \
  --out-dir exports/current
```

The default `config` method reads Config.Cipher objects, decodes masked buffers
and saves candidate keys only to an ignored local file. It does not restart
WeChat, attach a debugger, or write process memory. If process auto-selection
fails, add `--process-id <main-process-id>`.

Each database receives its own authenticated key selection. Modern raw keys
first pass a SQLCipher 4 page-HMAC check and schema read; decrypted databases
must pass SQLite `quick_check`. Probe/export returns nonzero if any selected
database fails. Metadata includes per-database parameters without key values.

The wrapper finds tools relative to itself and works from other directories.
Output paths remain relative to the caller. Add `--snapshot-dir PATH` to reuse
an encrypted snapshot, or `--key-file PATH` for an existing candidate file.
Existing key files are reused; choose a fresh path after login/account changes.

## Separate capture and offline verification

Capture from logged-in WeChat and verify an existing snapshot:

```bash
python3 wechat4/scripts/wechat_export.py \
  --snapshot-dir exports/saved-snapshot/snapshot \
  --auto-key --probe-only --out-dir exports/probe
```

Offline verification needs neither a running client nor an account directory:

```bash
python3 wechat4/scripts/wechat_export.py \
  --snapshot-dir exports/saved-snapshot/snapshot \
  --key-candidates-json exports/key-candidates.json \
  --key-mode raw64 --probe-only --out-dir exports/probe-offline
```

Remove `--probe-only` and choose a fresh output directory to decrypt/export.
Omit `--key-mode raw64` to probe legacy password captures.

For a closed-state snapshot, quit WeChat, then run:

```bash
python3 wechat4/scripts/wechat_export.py \
  --account-path '/mnt/c/Users/<user>/Documents/xwechat_files/<account>' \
  --snapshot-only --out-dir exports/saved-snapshot
```

Live copying includes DB/WAL/SHM families and retries if DB/WAL size or mtime
changes during copying. This stability check is not an atomic snapshot
guarantee. Closed-state snapshots provide a stronger boundary. Missing history
must first be imported through WeChat.

## Readable selected groups

```bash
python3 wechat4/scripts/export_selected_groups.py \
  --plain-root exports/current/plain \
  --group 'Example Group' --group 'Another Group' \
  --out-dir exports/readable
```

Exact names, remarks and chatroom usernames are accepted. Ambiguous names fail;
use the exact chatroom username. Rows are merged across shards, deduplicated by
server ID, sorted by time, and resolved against each shard's own `Name2Id`.
Use `--timezone` to change the default `Asia/Shanghai` timezone.

Outputs are UTF-8 TXT/JSONL and UTF-8-with-BOM CSV. Keys, labeled credentials,
Bearer tokens and sensitive URL parameters are masked, including references.
Images/stickers become `[图片]` / `[贴纸]`; supported cards retain readable
text. System templates omit internal attachment keys. Rule-based masking cannot
recognize every custom secret format; review intended public exports.

Full exports and `plain/` remain private unredacted source material. Readable
exports are separate derivatives; masking does not change source files.

## Legacy debugger capture

`0x5D79A0` is pinned to **4.1.11.54**, not 4.2.0.12. The wrapper requires an
explicit verified offset for this route:

```bash
bash wechat4/scripts/wechat_auto_export.sh \
  --account-path '/mnt/c/Users/<user>/Documents/xwechat_files/<account>' \
  --snapshot-dir exports/saved-snapshot/snapshot \
  --key-method debug-api --wechat-exe 'C:\Path\To\Weixin.exe' \
  --cipher-rva 0x5D79A0 --out-dir exports/legacy
```

Only add `--kill-wechat` when you intend to terminate the existing instance;
the default config method rejects it.

## Verification and provenance

```bash
python3 -m unittest discover -s wechat4/tests -v
bash -n wechat4/scripts/wechat_auto_export.sh
```

Windows synthetic capture test (no WeChat required):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\wechat4\tests\Test-ConfigKeyCapture.ps1
```

See [4.2 migration notes](reverse/analysis/WECHAT_4_2.md),
[key capture](reverse/analysis/KEY_CAPTURE.md) and
[third-party notices](../THIRD_PARTY_NOTICES.md).
Generated keys, databases and exports are sensitive and ignored by Git.
