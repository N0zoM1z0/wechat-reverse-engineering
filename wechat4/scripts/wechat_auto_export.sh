#!/usr/bin/env bash
set -euo pipefail

account_path=""
snapshot_dir=""
out_dir="exports/decrypted-$(date +%Y%m%d-%H%M%S)"
key_file="exports/key-candidates-$(date +%Y%m%d-%H%M%S).json"
wechat_exe=""
max_captures=16
timeout_seconds=180
post_first_idle_seconds=20
kill_wechat=0
probe_first=1

usage() {
  local code="${1:-0}"
  printf '%s\n' \
    "Usage: tools/wechat_auto_export.sh [options]" \
    "" \
    "Options:" \
    "  --account-path PATH       required WSL account wxid_* path" \
    "  --snapshot-dir PATH       required existing encrypted snapshot directory" \
    "  --out-dir PATH            export output directory" \
    "  --key-file PATH           sensitive key-candidate JSON path" \
    "  --wechat-exe PATH         required Windows Weixin.exe path" \
    "  --max-captures N          breakpoint captures to collect" \
    "  --timeout-seconds N       key capture timeout" \
    "  --kill-wechat             terminate existing Weixin.exe before capture" \
    "  --no-probe                skip probe-only verification before export" \
    "  -h, --help                show this help"
  exit "$code"
}

while (($#)); do
  case "$1" in
    --account-path) account_path="$2"; shift 2 ;;
    --snapshot-dir) snapshot_dir="$2"; shift 2 ;;
    --out-dir) out_dir="$2"; shift 2 ;;
    --key-file) key_file="$2"; shift 2 ;;
    --wechat-exe) wechat_exe="$2"; shift 2 ;;
    --max-captures) max_captures="$2"; shift 2 ;;
    --timeout-seconds) timeout_seconds="$2"; shift 2 ;;
    --kill-wechat) kill_wechat=1; shift ;;
    --no-probe) probe_first=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage 1 ;;
  esac
done

if [[ ! -d "$snapshot_dir" ]]; then
  if [[ -z "$snapshot_dir" ]]; then
    echo "error: --snapshot-dir is required" >&2
    exit 1
  fi
  echo "error: snapshot directory not found: $snapshot_dir" >&2
  exit 1
fi

if [[ -z "$account_path" ]]; then
  echo "error: --account-path is required" >&2
  exit 1
fi

if [[ -z "$wechat_exe" ]]; then
  echo "error: --wechat-exe is required" >&2
  exit 1
fi

mkdir -p "$(dirname "$key_file")" "$out_dir"

if [[ "$kill_wechat" == "1" ]]; then
  cmd.exe /c "taskkill /IM Weixin.exe /T /F" >/dev/null 2>&1 || true
fi

powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File "$(wslpath -w tools/Capture-WeChatKey-DebugApi.ps1)" \
  -WeChatExe "$wechat_exe" \
  -MaxCaptures "$max_captures" \
  -PostFirstIdleSeconds "$post_first_idle_seconds" \
  -TimeoutSeconds "$timeout_seconds" \
  -OutFile "$(wslpath -w "$key_file")"

if [[ "$probe_first" == "1" ]]; then
  python3 tools/wechat_export.py \
    --account-path "$account_path" \
    --snapshot-dir "$snapshot_dir" \
    --key-candidates-json "$key_file" \
    --probe-only \
    --out-dir "$out_dir/probe"
fi

python3 tools/wechat_export.py \
  --account-path "$account_path" \
  --snapshot-dir "$snapshot_dir" \
  --key-candidates-json "$key_file" \
  --out-dir "$out_dir"

chmod -R go-rwx "$key_file" "$out_dir"

python3 - "$out_dir" <<'PY'
import csv
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
metadata = json.loads((out_dir / "metadata.json").read_text(encoding="utf-8"))
messages_jsonl = sum(1 for _ in (out_dir / "messages.jsonl").open(encoding="utf-8")) if (out_dir / "messages.jsonl").exists() else 0
messages_csv = 0
if (out_dir / "messages.csv").exists():
    with (out_dir / "messages.csv").open(encoding="utf-8-sig", newline="") as handle:
        messages_csv = sum(1 for _ in csv.DictReader(handle))

print(json.dumps({
    "output_dir": str(out_dir),
    "decrypted_databases": len(metadata.get("decrypted_databases", [])),
    "failed_databases": len(metadata.get("failed_databases", [])),
    "contacts": metadata.get("contacts"),
    "sessions": metadata.get("sessions"),
    "messages_metadata": metadata.get("messages"),
    "messages_jsonl": messages_jsonl,
    "messages_csv": messages_csv,
    "resource_rows": metadata.get("resource_rows"),
}, ensure_ascii=False, indent=2))
PY
