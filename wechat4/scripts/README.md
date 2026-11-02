# Local tools

- `Get-WeChat4ConfigKeys.ps1`: default read-only capture for validated 4.2.0.12;
  requires a fresh `-OutFile`, with optional `-ProcessId`, `-TimeoutSeconds`
  and `-MaxCandidates`. Console output contains counts only.
- `wechat_export.py`: stable snapshot copying, per-database key selection,
  SQLCipher decryption/integrity checks, Zstandard text decoding and JSONL/CSV.
  `--auto-key` invokes Config.Cipher capture. Offline snapshots need no account path.
- `export_selected_groups.py`: readable groups across shards, sender resolution,
  credential masking, image/sticker placeholders, CSV/TXT/JSONL.
- `wechat_auto_export.sh`: WSL capture/snapshot/probe/export wrapper, independent
  of the working directory. Run with `--help` for options.
- `Capture-WeChatKey-DebugApi.ps1` / `Capture-WeChatKey-Cdb.ps1`: historical
  build-specific capture; the pinned offset belongs to 4.1.11.54 only.
- `Get-WeChatDbKey.ps1`: legacy plaintext-cache scanner with bounded region-tail
  handling; modern masked caches need the Config.Cipher adapter.

See [the operation guide](../README.md) for commands and the distinction between
private full exports and redacted derivatives. The config adapter contains
attributed Apache-2.0 portions; see [notices](../../THIRD_PARTY_NOTICES.md).
