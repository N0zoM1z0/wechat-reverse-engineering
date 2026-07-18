# Reversing WeChat 4.x Chat Storage and Building a Practical Exporter

This write-up documents a local reverse-engineering pass against WeChat for Windows 4.x, with one practical goal: export chat records from a real local profile without relying on a prebuilt third-party decryptor.

The final result is a small toolchain that can:

- capture the active WCDB/SQLCipher key with a low-load debugger breakpoint;
- snapshot encrypted WeChat databases safely;
- decrypt the snapshot with SQLCipher;
- parse WeChat 4.x sharded message tables;
- export contacts, sessions, messages, and resource metadata to JSONL/CSV.

I am intentionally not publishing any private key material, account identifiers, or raw chat contents here. Paths and identities are either generic or redacted. The technical details are kept intact.

## Scope and environment

The target was WeChat for Windows 4.x. The main binary entry point was:

```text
C:\Path\To\WeChat\Weixin.exe
```

The interesting module was:

```text
C:\Path\To\WeChat\<version>\Weixin.dll
```

The local account data lived under the standard WeChat 4.x profile layout:

```text
%USERPROFILE%\Documents\xwechat_files\<wxid>\db_storage\
```

The analysis environment was split between Windows and WSL:

- IDA Pro was used for static analysis of `Weixin.dll`.
- WSL hosted the Python exporter and filesystem snapshots.
- Windows PowerShell hosted the key-capture code, because the target process is a Windows process.
- `sqlcipher` was used for database verification and export.

The high-level problem was straightforward: WeChat stores chat history in encrypted WCDB databases. The hard parts were finding the encryption key reliably, identifying the correct SQLCipher parameters, and understanding the new WeChat 4.x message schema well enough to reconstruct conversations.

I also looked at CipherTalk as prior art. I did not reuse its native binaries or copy its implementation, but it was a useful architectural reference: keep key acquisition separate from database export, treat key discovery as a diagnosable subsystem, and validate the key against real databases instead of assuming success after capture.

## First pass: identifying the storage layer

The first static-analysis task was to confirm which database layer WeChat was using. The target binary contains WCDB-related logic, which is consistent with Tencent's own database stack.

The key function I ended up naming in IDA was:

```text
IDA address:      0x1805D79A0
Module offset:    Weixin.dll + 0x5D79A0
Name assigned:    WCDB_Database_setCipherKey
```

This function matched the shape of WCDB's `Database::setCipherKey` path. The important behavior was simple:

- if the supplied key data is empty, the cipher configuration is removed;
- otherwise a `CipherConfig` object is installed;
- the caller supplies a page size and cipher version;
- message-related callers use a 4096-byte cipher page size.

The local IDA database also got a few supporting names:

```text
0x1805D79A0  WCDB_Database_setCipherKey
0x181432C90  WCDB_CipherConfig_ctor
0x181431400  WCDB_CoreConst_init
0x18003C2D0  RegisterShardedMessageStorageTypes
0x1800395D0  RegisterFixedStorageTypes
```

The registration code was useful because it mapped storage names to actual database files. The relevant databases were not one monolithic file. They were spread across several folders:

```text
db_storage/message/message_*.db
db_storage/message/biz_message_*.db
db_storage/message/media_*.db
db_storage/message/message_resource.db
db_storage/session/session.db
db_storage/contact/contact.db
db_storage/hardlink/hardlink.db
```

That list turned out to matter later. My first snapshot was incomplete, and the missing `message_1.db` through `message_5.db` files were exactly where most of the real conversation history lived.

## Understanding the key argument

On Windows x64, function arguments are passed in registers:

```text
RCX  this / database object
RDX  WCDB data object containing the key
R8   cipher page size
R9   cipher version
```

The key argument was not a raw pointer directly in `RDX`; it was a small data object. Static analysis of nearby WCDB data helpers showed the layout:

```text
object + 0x00    vtable / object header
object + 0x08    buffer pointer
object + 0x10    buffer length
```

So at the `WCDB_Database_setCipherKey` entry point, the debugger only needs to read:

```text
key_buffer = *(uint64_t *)(RDX + 0x08)
key_len    = *(uint64_t *)(RDX + 0x10)
```

Then it reads `key_len` bytes at `key_buffer`. In this target, the useful key material was 32 bytes. It is important not to assume that every captured call is the message database key. Startup can call `setCipherKey` several times for different WCDB instances, so the exporter treats captures as candidates and verifies them against the actual database files.

## Why I moved away from full memory scanning

The first working idea was a process-memory scanner. The approach was based on a common SQLCipher/WCDB observation: in some code paths, the process contains strings shaped like:

```text
x'<64 hex raw key><32 hex database salt>'
```

The first 16 bytes of an encrypted SQLCipher database are the salt, so a scanner can read the salt from a target database and search the WeChat process for a nearby key record.

That approach is useful as a diagnostic fallback, but it is not ideal as the main path:

- it scans large parts of process memory;
- it can stress CPU and memory bandwidth;
- it depends on a cached string representation being present;
- it is easy to miss the key if the representation changes.

I kept a throttled fallback scanner with conservative defaults:

```text
1 MB chunks
5 ms sleep between chunks
60 s maximum scan time
```

But for the real exporter I wanted something cleaner: catch the key at the point where WeChat itself passes it to WCDB.

## CDB worked, but not cleanly enough

The next attempt used Microsoft's console debugger, `cdb.exe`, to set a breakpoint at the known `Weixin.dll + 0x5D79A0` offset.

Attach mode was conceptually simple:

```text
attach to Weixin.exe
compute runtime Weixin.dll base
set breakpoint at base + 0x5D79A0
dump RDX-based key object when hit
detach
```

This avoids memory scanning, but there were two practical problems.

First, if WeChat had already opened the database before the debugger attached, there might be no new `setCipherKey` call to catch. The breakpoint is correct, but the event has already happened.

Second, launch mode with a symbolic expression like:

```text
bu Weixin+0x5D79A0
```

was not reliable in this environment because `Weixin` resolved to the executable module rather than `Weixin.dll`. That is fixable, but it pushed the implementation toward more debugger scripting and more fragile process control.

CDB also has lifecycle sharp edges. If a debugger exits incorrectly, it can terminate or disturb the debuggee unless kill-on-exit behavior is controlled. For a repeatable tool, I wanted direct ownership of the debug loop.

## The final key capture path: Windows Debug API

The preferred key capture tool is implemented in PowerShell with embedded C# P/Invoke. It uses the Windows Debug API directly:

```text
CreateProcess(DEBUG_ONLY_THIS_PROCESS)
DebugSetProcessKillOnExit(false)
WaitForDebugEvent(...)
ContinueDebugEvent(...)
DebugActiveProcessStop(...)
```

The important detail is `DebugSetProcessKillOnExit(false)`. The capture tool must be able to detach without killing WeChat.

The capture flow is:

1. Launch `Weixin.exe` as a debuggee.
2. Wait for `LOAD_DLL_DEBUG_EVENT`.
3. Detect the load of `Weixin.dll`.
4. Compute:

   ```text
   breakpoint = Weixin.dll runtime base + 0x5D79A0
   ```

5. Read and save the original byte at the breakpoint.
6. Write `0xCC` (`int3`) at the breakpoint.
7. On breakpoint hit:

   - read thread context;
   - inspect `RDX`, `R8`, `R9`;
   - read the key buffer from `RDX + 8` / `RDX + 16`;
   - save a key candidate;
   - restore the original byte;
   - set `RIP` back to the original instruction address;
   - set the trap flag for a single-step event;
   - continue the process.

8. On the following single-step exception:

   - clear the trap flag;
   - reinsert the breakpoint if more captures are needed.

This is the standard one-byte breakpoint dance. The subtle bug I had to fix was exception continuation status. A single-step event that I intentionally generated must be continued with `DBG_CONTINUE`; it should not be passed back to the process as an unhandled exception. Getting that wrong can destabilize the debuggee.

The tool writes the full capture result to a local sensitive JSON file. The console output only shows a summary:

```json
{
  "Ok": true,
  "CaptureCount": 16,
  "BreakpointEvents": 16,
  "OutFile": "exports\\key-candidates.json"
}
```

The actual key is not printed in normal logs and is not written into exporter metadata.

## SQLCipher parameter discovery

Capturing a 32-byte value is only half the problem. It still has to be applied to SQLCipher in the same way WeChat/WCDB applies it.

I made the exporter probe several combinations instead of guessing:

```text
key modes:
  raw64      PRAGMA key = "x'<64 hex>'"
  raw96      PRAGMA key = "x'<64 hex><32 hex salt>'"
  asciihex   PRAGMA key = '<64 hex>'
  hexkey     PRAGMA hexkey = '<64 hex>'

compatibility:
  3
  4

pragma order:
  key first
  compatibility first
```

For the target profile, the working combination was:

```sql
PRAGMA cipher_compatibility = 3;
PRAGMA hexkey = '<redacted 64 hex key>';
PRAGMA cipher_page_size = 4096;
SELECT count(*) FROM sqlite_master;
```

That last `SELECT` is the validation step. A key is not considered valid just because SQLCipher accepts the PRAGMAs. It must successfully read `sqlite_master`.

After finding a working parameter set on the first message database, the exporter probes or decrypts every database in the snapshot with the same settings. In the full run, all 12 databases decrypted successfully:

```text
decrypted databases: 12
failed databases:    0
cipher compatibility: 3
key mode:             hexkey
```

## Snapshot first, decrypt later

I strongly prefer decrypting a filesystem snapshot rather than reading active WeChat databases in place.

The snapshot logic copies each database family:

```text
<name>.db
<name>.db-wal
<name>.db-shm
```

The WAL files matter. Without them, the base database can be missing recent rows or even appear inconsistent.

The safer workflow is:

1. Close WeChat or terminate only `Weixin.exe` when explicitly allowed.
2. Copy the encrypted database families.
3. Launch WeChat under the Debug API capture tool only long enough to collect the key.
4. Detach/close WeChat.
5. Decrypt the static snapshot.

This keeps the expensive work out of the live WeChat process. SQLCipher export can be I/O-heavy, but it is operating on copied files, not on the running application.

## The snapshot completeness bug

The first successful decrypt looked good at a glance:

```text
contact.db             decrypted
session.db             decrypted
message_0.db           decrypted
biz_message_0.db       decrypted
message_resource.db    decrypted
hardlink.db            decrypted
```

The problem was that it only contained 110 normalized messages. That was obviously too small.

The fix was not cryptographic. It was inventory.

I compared the encrypted snapshot against the live account directory and found additional message shards:

```text
message_1.db
message_2.db
message_3.db
message_4.db
message_5.db
media_0.db
```

After taking a full snapshot and decrypting again, the result changed to:

```text
decrypted databases: 12
contacts:            4105
sessions:            356
messages:            171392
resource rows:       35164
```

This is the sort of bug that is easy to misdiagnose as a parser issue or a wrong key. The lesson is simple: before debugging schema logic, prove that the snapshot contains every relevant shard.

## WeChat 4.x message sharding

WeChat 4.x does not store messages in a single `message` table. Message databases contain tables like:

```text
Name2Id
Msg_<32 hex chars>
```

The `Msg_...` suffix is:

```text
md5(user_name)
```

So the mapping is:

```text
Name2Id.user_name
    -> md5(user_name)
    -> Msg_<md5>
```

For example, if a contact username is:

```text
some-wechat-username
```

then the direct-message table is:

```text
Msg_<md5("some-wechat-username")>
```

The exporter builds this mapping per database, because `Name2Id` row IDs and table availability are local to each shard.

The message columns observed in this WeChat 4.x build were:

```text
local_id
server_id
local_type
sort_seq
real_sender_id
create_time
status
upload_status
download_status
server_seq
origin_source
source
message_content
compress_content
packed_info_data
WCDB_CT_message_content
WCDB_CT_source
```

The important fields for a first usable export are:

```text
local_id          local message id
server_id         server-side id
local_type        message type
real_sender_id    rowid into Name2Id for the sender
create_time       unix timestamp
message_content   text/blob payload
packed_info_data  additional packed metadata
```

For direct chats, the table itself identifies the conversation. For group chats, the table identifies the chatroom, and `real_sender_id` identifies the participant inside that chatroom.

That distinction mattered when looking for one specific contact. The contact first appeared in `message_0.db` only as a group participant:

```text
Name2Id.user_name = <contact username>
is_session        = 0
```

There was no direct-message table for that user in `message_0.db`. The actual private chat appeared in later shards:

```text
message_1.db
message_2.db
message_3.db
```

There, `Name2Id` had the same username with:

```text
is_session = 1
```

and the direct table `Msg_<md5(username)>` existed.

## Parsing message content

Plain text messages are not always stored as clean SQLite `TEXT`. In this build, `message_content` can be:

- ordinary UTF-8 text;
- a BLOB containing UTF-8 text with a small binary prefix/suffix;
- XML-like payloads for richer message types;
- references to media/resource metadata.

The exporter has two layers:

1. A raw normalized export that preserves the original content as faithfully as practical.
2. A readable export that decodes common UTF-8 text payloads and trims obvious binary framing.

For a direct conversation, the readable row shape is:

```text
time_local
time_utc
direction
talker_username
talker_alias
talker_display
sender_username
type
subtype
content_readable
db
table
rowid
id
```

This is intentionally simple. It is enough for text review and spreadsheet work, while the raw JSONL remains available for richer parsers later.

## Contact and session mapping

Contacts are exported from `contact.db`. The observed contact table had fields such as:

```text
username
alias
remark
nick_name
encrypt_username
quan_pin
pin_yin_initial
...
```

A subtle but common trap is assuming that a human-facing handle appears in message tables. It often does not.

In the test profile, the user searched for a contact by alias. The message tables used the internal username instead. The mapping looked like:

```text
alias / user-facing handle  -> contact.alias
internal message id         -> contact.username
display name / remark       -> contact.remark or contact.nick_name
```

So the correct lookup flow is:

```text
search contact aliases/display names
resolve to contact.username
compute md5(contact.username)
search Msg_<md5> across every message_*.db shard
```

Sessions live in `session.db`, mainly in `SessionTable`. They are useful for finding recent conversations and display summaries, but they are not sufficient by themselves. A session can reference a username even when the actual message rows are in a different message shard.

## The exporter pipeline

The final local toolchain has three main pieces.

### 1. Key capture

```text
tools/Capture-WeChatKey-DebugApi.ps1
```

Responsibilities:

- launch WeChat under the Windows Debug API;
- wait for `Weixin.dll`;
- break at `Weixin.dll + 0x5D79A0`;
- read the WCDB key object from `RDX`;
- collect multiple candidates;
- detach safely;
- write sensitive candidates to a local JSON file.

### 2. Snapshot/decrypt/export

```text
tools/wechat_export.py
```

Responsibilities:

- discover relevant `db_storage` databases;
- copy `.db`, `.db-wal`, and `.db-shm`;
- probe SQLCipher key modes and compatibility;
- export decrypted SQLite databases using `sqlcipher_export`;
- export schema metadata;
- normalize contacts, sessions, messages, and resource tables;
- support `--probe-only` for validation without writing plaintext databases.

The key probe is intentionally exhaustive across likely SQLCipher modes:

```text
raw64
raw96
asciihex
hexkey
```

The working mode is stored in metadata, but the key itself is not.

### 3. One-command wrapper

```text
tools/wechat_auto_export.sh
```

Responsibilities:

- optionally terminate existing `Weixin.exe` only when `--kill-wechat` is explicitly passed;
- invoke the Debug API capture tool;
- run a probe-only verification;
- run the full export;
- tighten filesystem permissions on sensitive outputs;
- print final counts.

The wrapper exists mostly to make the workflow repeatable. The individual tools are still useful for debugging.

## Example workflow

A typical manual run looks like this.

First, capture key candidates:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "$(wslpath -w tools/Capture-WeChatKey-DebugApi.ps1)" `
  -WeChatExe "C:\Path\To\WeChat\Weixin.exe" `
  -MaxCaptures 16 `
  -PostFirstIdleSeconds 20 `
  -TimeoutSeconds 180 `
  -OutFile "$(wslpath -w exports/key-candidates.json)"
```

Then snapshot the account databases:

```bash
python3 tools/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-only \
  --out-dir exports/full-snapshot
```

Then verify the key without writing plaintext databases:

```bash
python3 tools/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-dir exports/full-snapshot/snapshot \
  --key-candidates-json exports/key-candidates.json \
  --probe-only \
  --out-dir exports/probe
```

Finally, decrypt and export:

```bash
python3 tools/wechat_export.py \
  --account-path /mnt/c/Users/<user>/Documents/xwechat_files/<wxid> \
  --snapshot-dir exports/full-snapshot/snapshot \
  --key-candidates-json exports/key-candidates.json \
  --out-dir exports/decrypted-full
```

Or use the wrapper:

```bash
tools/wechat_auto_export.sh \
  --kill-wechat \
  --snapshot-dir exports/full-snapshot/snapshot \
  --out-dir exports/decrypted-full
```

## Validation strategy

I used a few checks to avoid fooling myself.

### SQLCipher validation

Every candidate key mode must successfully query:

```sql
SELECT count(*) FROM sqlite_master;
```

A database is not considered decrypted until the resulting plaintext SQLite database can be opened with Python's `sqlite3` module and its schema can be read.

### Snapshot validation

The snapshot file list is compared against the source account directory. This caught the missing `message_1.db` through `message_5.db` shards.

### Export validation

The exporter writes:

```text
metadata.json
schema.json
messages.jsonl
messages.csv
contacts.jsonl
sessions.jsonl
message_resource.jsonl
hardlink.jsonl
plain/
snapshot/
```

For the full run, the final counts were:

```text
decrypted DBs:   12
failed DBs:      0
contacts:        4105
sessions:        356
messages:        171392
resource rows:   35164
```

For a specific direct conversation export, I verified:

```text
raw JSONL rows:       7413
readable JSONL rows:  7413
readable CSV rows:    7413
```

The JSONL and CSV counts must match. CSV physical line count is not a reliable check because message contents can contain newlines.

## Operational details that mattered

### Do not leave a debugger attached

The Debug API path explicitly detaches. It also disables kill-on-exit behavior:

```text
DebugSetProcessKillOnExit(false)
```

This is not optional. A tool that captures secrets from a live process must leave the target in a predictable state.

### Do not print the key

The key candidate JSON is sensitive. It is written to disk because the exporter needs it, but normal console output is only a summary. Metadata records the selected candidate index and SQLCipher mode, not the key.

### Keep permissions tight

Exported data contains decrypted chat records. The tool tightens permissions on sensitive outputs:

```text
chmod -R go-rwx exports/...
```

On Windows, equivalent ACL hardening would be needed for a native-only version.

### Avoid broad memory scanning

The scanner is still useful when debugging, but the default workflow uses an event breakpoint. That keeps CPU and memory pressure low and makes the capture more deterministic.

### Treat rich media as a second phase

The current exporter handles text and basic metadata well. Image, voice, file, and rich XML message types need deeper parsing across `message_resource.db`, `hardlink.db`, media databases, and filesystem resources. The exporter preserves enough raw data to make that possible later, but it does not pretend every message type is fully decoded.

## What I would improve next

The current implementation is practical, but there are obvious next steps.

First, I would make snapshot inventory stricter. The tool should emit a warning if source `message_*.db` files exist but are absent from the snapshot, and it should summarize shard coverage explicitly.

Second, I would split message decoding into pluggable handlers:

```text
type 1      text
type 3      image
type 34     voice
type 47     sticker
type 50     call
type 10000  system message
large custom packed/XML types
```

Third, I would add contact display enrichment for group chats. The current mapping can identify `real_sender_id`, but polished group exports need per-chatroom member display names.

Fourth, I would add a Windows-native packaging option. The current WSL/PowerShell split is convenient for development, but a single signed Windows binary plus a Python-free export runtime would be easier for non-research users.

## Closing notes

The core of the project was not any single trick. The useful result came from combining several small pieces:

- static analysis to find the WCDB key-setting function;
- a precise breakpoint instead of broad process scanning;
- SQLCipher parameter probing instead of hardcoded assumptions;
- complete snapshot inventory;
- schema-driven message parsing;
- verification at every step.

The main takeaway is that WeChat 4.x chat export is less about "finding the key" in isolation and more about building a reliable pipeline around the key. Once the breakpoint capture and SQLCipher mode are correct, the remaining work is database engineering: copy the right files, decrypt them consistently, understand the sharding scheme, and never trust a partial snapshot.
