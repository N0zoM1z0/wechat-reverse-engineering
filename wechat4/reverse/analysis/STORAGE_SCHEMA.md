# WeChat 4.x Storage Schema Notes

WeChat 4.x local account data is organized under:

```text
%USERPROFILE%\Documents\xwechat_files\<wxid>\db_storage\
```

Relevant database families:

```text
message/message_*.db
message/biz_message_*.db
message/media_*.db
message/message_resource.db
session/session.db
contact/contact.db
hardlink/hardlink.db
```

Always snapshot the full database family:

```text
name.db
name.db-wal
name.db-shm
```

## Message sharding

Message databases contain a mapping table and sharded message tables:

```text
Name2Id
Msg_<md5(user_name)>
```

The exporter maps:

```text
Name2Id.user_name -> md5(user_name) -> Msg_<md5>
```

Common message columns:

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

For direct chats, the table name identifies the conversation. For group chats, the table identifies the chatroom and `real_sender_id` identifies the participant through the local `Name2Id` table.

## Contact/session mapping

Contact display fields and message identifiers are not interchangeable. A public alias or remark usually maps to an internal `contact.username`, and message tables use that internal username.

Lookup flow:

```text
contact alias / remark / nick_name
  -> contact.username
  -> md5(contact.username)
  -> Msg_<md5> across all message_*.db shards
```

`session.db` is useful for recent conversation summaries, but a session row is not enough to locate all historical messages. Always search every message shard.
