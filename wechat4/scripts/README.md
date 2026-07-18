# Scripts

These scripts are original tooling for authorized local research.

## Safety defaults

- `Capture-WeChatKey-DebugApi.ps1` requires `-OutFile` and prints only a summary to stdout.
- `Capture-WeChatKey-Cdb.ps1` redacts key material in stdout; pass `-OutFile` only for local sensitive storage.
- `wechat_auto_export.sh` requires explicit account, snapshot, and WeChat executable paths.
- Generated `exports/`, key candidate files, decrypted databases, CSVs, and JSONL files are ignored by Git and must not be committed.

## Main scripts

```text
Capture-WeChatKey-DebugApi.ps1  preferred low-load key capture
Capture-WeChatKey-Cdb.ps1       backup cdb-based capture
Get-WeChatDbKey.ps1             throttled diagnostic memory scanner
wechat_export.py                snapshot/decrypt/export pipeline
wechat_auto_export.sh           WSL workflow wrapper
```

Use these only on accounts and machines you are authorized to inspect.
