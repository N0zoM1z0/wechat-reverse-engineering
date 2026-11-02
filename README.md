# WeChat Reverse Engineering

Evidence-first reverse-engineering notes and original tooling for studying WeChat for Windows 4.x local WCDB chat storage.

This repository contains source code (including attributed Apache-2.0 adapter portions; see [third-party notices](THIRD_PARTY_NOTICES.md)), compact technical notes, sanitized validation summaries, and a long-form research article. It does not contain WeChat binaries, decrypted databases, chat records, key material, IDA databases, complete decompiler output, local logs, screenshots of private data, account identifiers, or user-specific paths. Use the material only with accounts and devices you are authorized to inspect.

## Contents

```text
docs/
  PRIVACY_AND_PUBLICATION.md       public release policy and sanitization checklist

wechat4/
  README.md                        target summary and operation guide
  BLOG.md                          full research article
  scripts/                         original local-only capture/export tooling
  reverse/analysis/                address map, schema notes, and key-capture notes
  artifacts/validation/            sanitized validation summary only
```

## Case study: WeChat 4.x local chat storage

The WeChat 4.x study follows the local WCDB stack from static analysis to a practical export pipeline:

1. identify the WCDB cipher-key entry point in `Weixin.dll`;
2. read Config.Cipher candidates without restarting WeChat, with legacy debugger capture available;
3. authenticate and select SQLCipher parameters independently for every database;
4. snapshot encrypted `.db`, `.db-wal`, and `.db-shm` families;
5. decrypt the snapshot with SQLCipher;
6. reconstruct WeChat 4.x sharded message tables through `Name2Id` and `Msg_<md5(user_name)>`;
7. export contacts, sessions, messages, and resource metadata to JSONL/CSV.

Start with [the WeChat 4.x case README](wechat4/README.md), then read [the full research article](wechat4/BLOG.md).

## Validated builds

| Observed Windows build | Capture route | Validation |
|---|---|---|
| 4.2.0.12 | Read-only Config.Cipher traversal and XOR decoding | Independent raw SQLCipher 4 keys, full snapshot export, selected-group exports |
| 4.1.11.54 | Windows Debug API breakpoint | Historical study; synthetic legacy compatibility tests remain in the suite |

The modern layout and XOR mask remain version-dependent. This does not claim
universal support for future builds. Missing keys and failed verification are
errors; there is no automatic fallback to an unverified debugger offset.

Selected-group exports decode compressed messages, mask API keys, and use
image/sticker placeholders in CSV, TXT and JSONL.

## Historical static-analysis target

The original address map and article describe this module:

| Component | Value |
|---|---|
| Module | `Weixin.dll` |
| Version path observed | `4.1.11.54` |
| MD5 | `280757000905500d1d024a0c20b6b4ec` |
| SHA-256 | `260e7b50797fb52ce6d86af215865b54628904fce67cf629c86190f6878111d8` |
| Key function RVA | `0x5D79A0` |

The scripts expose offsets as parameters. Treat the pinned RVA as build-specific. A different WeChat build should be analyzed and verified before use.

## Repository policy

- No WeChat executable, DLL, proprietary resource, account database, key file, or chat export is distributed.
- No IDA database or full decompiler listing is committed.
- No usernames, wxid values, machine paths, process IDs, private logs, contacts, or message text are part of the public tree.
- Runtime tooling is for local authorized research and recovery only.
- The exporter writes sensitive outputs under ignored paths by default. Do not commit generated exports.

See [docs/PRIVACY_AND_PUBLICATION.md](docs/PRIVACY_AND_PUBLICATION.md) before publishing derived notes or artifacts.

## License

Original code and documentation in this repository are available under the [MIT License](LICENSE). WeChat, WCDB, SQLCipher, Windows, IDA Pro, and other product names and behaviors described here remain the property of their respective owners.

Attributed adapter portions retain their upstream [Apache-2.0 terms](THIRD_PARTY_NOTICES.md).
