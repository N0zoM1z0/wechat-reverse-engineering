# Address Map

Pinned target:

```text
Module:   Weixin.dll
Version:  observed under 4.1.11.54
MD5:      280757000905500d1d024a0c20b6b4ec
SHA-256:  260e7b50797fb52ce6d86af215865b54628904fce67cf629c86190f6878111d8
```

## Key symbols

| IDA VA | RVA | Name | Notes |
|---:|---:|---|---|
| `0x1805D79A0` | `0x5D79A0` | `WCDB_Database_setCipherKey` | Runtime breakpoint target for key capture |
| `0x181432C90` | `0x1432C90` | `WCDB_CipherConfig_ctor` | Cipher configuration construction path |
| `0x181431400` | `0x1431400` | `WCDB_CoreConst_init` | WCDB core constant initialization |
| `0x18003C2D0` | `0x3C2D0` | `RegisterShardedMessageStorageTypes` | Registers sharded message storage |
| `0x1800395D0` | `0x395D0` | `RegisterFixedStorageTypes` | Registers fixed database storage |

## Calling convention at `WCDB_Database_setCipherKey`

Windows x64 register usage:

```text
RCX  database object
RDX  WCDB data object containing key bytes
R8   cipher page size
R9   cipher version
```

Observed WCDB data object layout:

```text
RDX + 0x08    key buffer pointer
RDX + 0x10    key buffer length
```

The capture script reads the pointer/length pair and stores the first candidate key bytes. The key is validated later by SQLCipher; a breakpoint hit alone is not treated as proof.
