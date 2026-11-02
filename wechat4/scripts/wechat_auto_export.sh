#!/usr/bin/env bash
set -euo pipefail
umask 077
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
account_path=""
snapshot_dir=""
out_dir="exports/decrypted-$(date +%Y%m%d-%H%M%S)"
key_file=""
key_method="config"
process_id=""
wechat_exe=""
cipher_rva=""
max_captures=16
timeout_seconds=60
kill_wechat=0
probe_first=1

usage() {
  cat <<'HELP'
Usage: wechat_auto_export.sh --account-path PATH [options]
  --snapshot-dir PATH       Reuse an encrypted snapshot; otherwise copy live DB families
  --out-dir PATH            Sensitive export directory (default: exports/decrypted-TIMESTAMP)
  --key-file PATH           Existing candidates to reuse, or a new capture destination
  --key-method METHOD       config (default, read-only) or debug-api (legacy)
  --process-id PID          Main Weixin process for config capture; otherwise auto-detect
  --timeout-seconds N       Capture deadline (default: 60)
  --wechat-exe PATH         Required for debug-api only
  --cipher-rva RVA          Required verified build-specific offset for debug-api
  --max-captures N          Number of legacy breakpoint captures (default: 16)
  --kill-wechat             Explicitly terminate WeChat before debug-api capture only
  --no-probe                Skip the separate probe pass (export still verifies every DB)
  -h, --help                Show this help
Run from any working directory. Install sqlcipher 4 and scripts/requirements.txt first.
HELP
}
error() { echo "error: $*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --account-path|--snapshot-dir|--out-dir|--key-file|--key-method|--process-id|--timeout-seconds|--wechat-exe|--cipher-rva|--max-captures)
      (($# >= 2)) || error "missing value for $1"
      [[ -n "$2" && "$2" != --* ]] || error "missing value for $1"
      case "$1" in
        --account-path) account_path="$2" ;;
        --snapshot-dir) snapshot_dir="$2" ;;
        --out-dir) out_dir="$2" ;;
        --key-file) key_file="$2" ;;
        --key-method) key_method="$2" ;;
        --process-id) process_id="$2" ;;
        --timeout-seconds) timeout_seconds="$2" ;;
        --wechat-exe) wechat_exe="$2" ;;
        --cipher-rva) cipher_rva="$2" ;;
        --max-captures) max_captures="$2" ;;
      esac
      shift 2 ;;
    --kill-wechat) kill_wechat=1; shift ;;
    --no-probe) probe_first=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) error "unknown argument: $1" ;;
  esac
done
[[ -n "$account_path" ]] || error "--account-path is required"
[[ "$key_method" == config || "$key_method" == debug-api ]] || error "--key-method must be config or debug-api"
[[ -z "$snapshot_dir" || -d "$snapshot_dir" ]] || error "snapshot directory not found: $snapshot_dir"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || error "timeout must be a positive integer"
[[ "$max_captures" =~ ^[1-9][0-9]*$ ]] || error "max-captures must be a positive integer"
[[ -z "$process_id" || "$process_id" =~ ^[1-9][0-9]*$ ]] || error "process-id must be a positive integer"
if [[ "$key_method" == config && "$kill_wechat" == 1 ]]; then
  error "--kill-wechat is only valid with --key-method debug-api"
fi
key_file="${key_file:-$out_dir/key-candidates.json}"
if [[ "$key_method" == debug-api && ! -f "$key_file" ]]; then
  [[ -n "$wechat_exe" && -n "$cipher_rva" ]] || error "debug-api requires --wechat-exe and --cipher-rva for the exact build"
  [[ "$cipher_rva" =~ ^(0x[0-9a-fA-F]+|[0-9]+)$ ]] || error "cipher-rva must be a hexadecimal or decimal offset"
fi
mkdir -p "$(dirname -- "$key_file")" "$out_dir"
if [[ ! -f "$key_file" ]]; then
  if [[ "$key_method" == config ]]; then
    capture_args=(-File "$(wslpath -w "$script_dir/Get-WeChat4ConfigKeys.ps1")" -OutFile "$(wslpath -w "$key_file")" -TimeoutSeconds "$timeout_seconds")
    if [[ -n "$process_id" ]]; then capture_args+=(-ProcessId "$process_id"); fi
    powershell.exe -NoProfile -ExecutionPolicy Bypass "${capture_args[@]}"
  else
    if [[ "$kill_wechat" == 1 ]]; then cmd.exe /c "taskkill /IM Weixin.exe /T /F" >/dev/null 2>&1 || true; fi
    powershell.exe -NoProfile -ExecutionPolicy Bypass \
      -File "$(wslpath -w "$script_dir/Capture-WeChatKey-DebugApi.ps1")" \
      -WeChatExe "$wechat_exe" -SetCipherKeyOffset "$cipher_rva" \
      -MaxCaptures "$max_captures" -TimeoutSeconds "$timeout_seconds" \
      -OutFile "$(wslpath -w "$key_file")"
  fi
fi
chmod go-rwx "$key_file"
if [[ -z "$snapshot_dir" ]]; then
  python3 "$script_dir/wechat_export.py" --account-path "$account_path" --snapshot-only --out-dir "$out_dir"
  snapshot_dir="$out_dir/snapshot"
fi
export_args=(--account-path "$account_path" --snapshot-dir "$snapshot_dir" --key-candidates-json "$key_file")
if [[ "$key_method" == config ]]; then export_args+=(--key-mode raw64); fi
if [[ "$probe_first" == 1 ]]; then
  python3 "$script_dir/wechat_export.py" "${export_args[@]}" --probe-only --out-dir "$out_dir/probe"
fi
python3 "$script_dir/wechat_export.py" "${export_args[@]}" --out-dir "$out_dir"
chmod -R go-rwx "$out_dir"
