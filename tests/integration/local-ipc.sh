#!/usr/bin/env bash
# Local smoke test; no VPN, Docker or TUN required.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT
mkdir -p "$tmp/runtime" "$tmp/agent" "$tmp/manager/tls"
go build -o "$tmp/supervisor" ./runtime/cmd/supervisor
go build -o "$tmp/agent-bin" ./agent/cmd/control-agent
go build -o "$tmp/manager-bin" ./backend/cmd/manager
RUNTIME_SOCKET="$tmp/runtime/control.sock" RUNTIME_IPC_KEY="$tmp/runtime/agent.key" OPENVPN_CONFIG_PATH="$tmp/missing.conf" "$tmp/supervisor" > "$tmp/runtime.log" 2>&1 &
pids+=("$!")
AGENT_STATE_DIR="$tmp/agent/state" RUNTIME_CONFIG_DIR="$tmp/runtime/config" AGENT_SOCKET="$tmp/agent/control.sock" AGENT_IPC_KEY="$tmp/agent/manager.key" RUNTIME_SOCKET="$tmp/runtime/control.sock" RUNTIME_IPC_KEY="$tmp/runtime/agent.key" OPENVPN_MANAGER_WRITE_ENABLED=false "$tmp/agent-bin" > "$tmp/agent.log" 2>&1 &
pids+=("$!")
MANAGER_TLS_DIR="$tmp/manager/tls" MANAGER_STATE_DIR="$tmp/manager/state" AGENT_STATE_DIR="$tmp/agent/state" RUNTIME_CONFIG_DIR="$tmp/runtime/config" AGENT_SOCKET="$tmp/agent/control.sock" AGENT_IPC_KEY="$tmp/agent/manager.key" WEB_DIR="$tmp" OPENVPN_MANAGER_WRITE_ENABLED=false "$tmp/manager-bin" > "$tmp/manager.log" 2>&1 &
pids+=("$!")
ready=0
for _ in $(seq 1 100); do
  if curl -ksS --connect-timeout 1 --max-time 2 https://127.0.0.1:9443/api/v1/meta > "$tmp/meta.json" 2>/dev/null && grep -q '"runtimeAvailable":true' "$tmp/meta.json"; then ready=1; break; fi
  sleep .15
done
if [ "$ready" != 1 ]; then cat "$tmp/runtime.log" "$tmp/agent.log" "$tmp/manager.log" >&2; exit 1; fi
grep -q '"runtimeState":"UNINITIALIZED"' "$tmp/meta.json"
grep -q '"effectiveWriteAllowed":false' "$tmp/meta.json"
unauth=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$tmp/agent/control.sock" http://agent/v1/status)
[ "$unauth" = 401 ] || { echo "unsigned agent call accepted: $unauth"; exit 1; }
mut=$(curl -ksS -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:9443/api/v1/vpn/start)
[ "$mut" = 401 ] || { echo "unauthenticated mutation not rejected: $mut"; exit 1; }
locked=$(curl -ksS -o /dev/null -w '%{http_code}' -X POST -H "Origin: https://127.0.0.1:9443" -H 'Content-Type: application/json' --data '{"token":"nope","username":"admin","password":"strongpassword123"}' https://127.0.0.1:9443/api/v1/setup/start)
[ "$locked" = 423 ] || { echo "bootstrap mutation not locked: $locked"; exit 1; }
old_runtime="${pids[0]}"
kill "${pids[1]}" && wait "${pids[1]}" 2>/dev/null || true
AGENT_STATE_DIR="$tmp/agent/state" RUNTIME_CONFIG_DIR="$tmp/runtime/config" AGENT_SOCKET="$tmp/agent/control.sock" AGENT_IPC_KEY="$tmp/agent/manager.key" RUNTIME_SOCKET="$tmp/runtime/control.sock" RUNTIME_IPC_KEY="$tmp/runtime/agent.key" OPENVPN_MANAGER_WRITE_ENABLED=false "$tmp/agent-bin" > "$tmp/agent-restart.log" 2>&1 &
pids[1]="$!"
ready=0
for _ in $(seq 1 100); do
  if curl -ksS --connect-timeout 1 --max-time 2 https://127.0.0.1:9443/api/v1/meta 2>/dev/null | grep -q '"runtimeAvailable":true'; then ready=1; break; fi
  sleep .15
done
[ "$ready" = 1 ] || { cat "$tmp/agent-restart.log" >&2; exit 1; }
kill -0 "$old_runtime"
echo 'PASS: Manager->Agent->Runtime signed status, unsigned=401, unauthenticated=401, bootstrap-locked=423, Agent restart leaves Runtime running'
