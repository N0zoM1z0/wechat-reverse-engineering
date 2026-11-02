# WeChat 4.2 migration

## Validated artifact and boundaries

- Observed installation build: Windows 4.2.0.12, `Weixin.dll`.
- SHA-256: `2b3677c3f932daaa4ef84c8b2acd0aee12cbe5a779ff9e740c370761e5c291ce`.
- The historical key-setting RVA has not been relocated or validated for this
  module. This path uses read-only runtime structures, not a new breakpoint.
- Validation uses copied DB/WAL families, page-1 HMAC checks, schema reads,
  SQLite `quick_check`, and full/selected-group exports. No capture output,
  account data or client binary is distributed in this repository.

## Why the older pipeline failed

The legacy scanner searched for plaintext `x'<key><salt>'` records. Modern
Config.Cipher buffers hold an XOR-masked representation instead. Absence of
that plaintext pattern does not prove a key is unavailable. The legacy scanner
also repeatedly rescanned each region's final overlap bytes; it now stops after
reading a region tail once.

The previous exporter selected a key against the first database and reused it
for every database. Current captures expose independent raw encryption keys;
each database must authenticate and select its own candidate, including new
message shards created during history import.

SQLCipher compatibility must follow `PRAGMA key`. Applying it before the key
can be ineffective: old metadata could claim compatibility 3 while SQLCipher 4
defaults were used. Historical compatibility labels are not definitive cipher
evidence. New probes configure key-first and report parameters per database.

## Current method

The adapter follows the Config.Cipher traversal in
[wechatauto-replica at the pinned revision](https://github.com/fanyuantaier/wechatauto-replica/blob/bc2e6f2461330eb1a53996d2f2afc18416376b52/wechatauto/db.py).
See [third-party notices](../../../THIRD_PARTY_NOTICES.md) for licensing.

1. Find the ASCII configuration name and pointer/length references.
2. Follow the configuration pointer and its data object at offset `0x88`.
3. Decode with the observed 32-byte repeating XOR mask. Extract 64-hex or 96-hex
   SQLCipher literals, keeping their first 32 key bytes. Save candidates only to
   a local file; no process-memory dumps are written.
4. Authenticate a standard 4096-byte SQLCipher 4 first page: derive its MAC key
   using PBKDF2-HMAC-SHA512, two iterations over the raw encryption key and salt
   XOR `0x3A`; authenticate ciphertext/IV plus the little-endian page number.
5. Confirm the schema with SQLCipher itself, decrypt, and check integrity.
   Candidate recovery alone is not accepted as database-key verification.

The fast path covers encrypted-header pages with 80 reserved bytes. Custom
plaintext-header/explicit-salt databases are not claimed as supported. Legacy
password and compatibility probes remain available with `--key-mode auto`.

## Future builds

Object offsets and the XOR mask are version-dependent. Scan deadlines, bounds,
verification and integrity checks fail visibly on mismatches. Unknown builds
are never automatically given the historical debugger offset. Inspect changed
layouts, update the adapter, and verify new snapshots before extending the
support table.
