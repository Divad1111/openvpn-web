# Implementation status (2026-11-08)

**Do not deploy as a production VPN until the pending integration items are resolved.**

## Implemented in code

- Phase 0: signed OpenVPN CE 2.7.9 source build; three Docker images + Compose.
- Phase 1: independent Runtime process and signed nonce-protected Unix IPC, Manager → Agent → Runtime; initial state and diagnostics.
- Phase 2: SQLite auth, Argon2id (system libargon2), setup token, TOTP verification, secure sessions, CSRF and Origin checks, Manager + Agent Docker write-mode checks.
- Phase 3: Easy-RSA 3.2.7 pinned installer, CA/server/client operations, IP/CIDR validation, generated TCP OpenVPN config and certificate publish, runtime start/stop/reload, scoped container NAT rules.
- Phase 4: client list, one-time .ovpn export, CRL revoke with active-session kick, runtime connection list and admin audit API, Vue pages for these flows.
- Phase 5 (partial): authenticated/TOTP/Docker-write-gated **encrypted backup creation, integrity validation and download**, plus a one-shot **offline Docker recovery utility** with filesystem snapshot/rollback journal. SQLite uses a consistent backup API rather than copying live WAL files. Agent PKI and Manager master key/DB are independently encrypted with Argon2id + AES-256-GCM, then bundled into one `.ovpnbackup` archive; Manager only sees Agent ciphertext.
- Phase 5 offline restore implementation: on-demand `recovery` Compose profile (not a fourth running service); full decryption/manifest verification occurs only in offline recovery tool after lifecycle locks prove the three services have stopped. Per-volume staging, rollback copies and an explicit journal support operator-led recovery. A unit test exercises restore/rollback and rejects active services.

## Incomplete / not yet verified

- Phase 3: TUN/iptables real-world connectivity on Synology DS920+ **NOT TESTED**; configuration can fail depending on DSM firewall/netfilter, IPv4 forwarding and router topology.
- Phase 3: Easy-RSA 3.2.7 CA creation now supplies distinct `--passin` and `--passout` file paths because Easy-RSA requires both for encrypted CA creation; the Docker smoke test has a 180-second timeout. The complete signing/revoke workflow still requires CI and real-runtime validation.
- Phase 4: end-to-end client connect, revoke and reconnect were not executed against a real OpenVPN server; implementation is not production certified.
- Phase 5: **encrypted backup creation/download and a one-shot offline restore command are implemented but not yet production-validated**. Full cross-volume *atomic* rollback in the event of a sudden power loss is not guaranteed; persistent journals and rollback copies require operator intervention. Offline disaster recovery on a new NAS and a complete backup round-trip on real DS920+ hardware remain **untested**. Online restore remains disabled in Web. Do not assume an encrypted backup can be restored safely until the NAS recovery exercise is completed.
- No full browser E2E test or external security assessment has been completed. The offline restore test uses synthetic PKI and does NOT prove DSM filesystem behavior.
- Build pipeline and Vue TypeScript compilation require GitHub CI (authoring environment lacks network-accessible npm packages and Docker CLI).

## Security decisions

- Defaults to `OPENVPN_MANAGER_WRITE_ENABLED=false`. Only exact literal `true` in BOTH manager and control-agent permits mutations.
- Switching mode requires `docker compose up -d --no-deps --force-recreate manager control-agent`, **not** `docker compose restart`.
- Runtime remains running during mode switches; no Docker Socket or `privileged: true`.
- Always require login+TOTP and CSRF/Origin checks for sensitive operations. No Web override.
- Runtime supervisor is allowed an extremely limited fixed operation set; scoped NAT rules run in the runtime container namespace, not the NAS host namespace.

## Developer verification

```bash
go test ./...
go test -race ./...
go vet ./...
bash tests/integration/local-ipc.sh
# Offline restore unit test (synthetic PKI, no real NAS):
go test ./internal/recovery -run TestOfflineRestoreAndRollback -v
# On Docker-capable Linux/CI:
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example build
docker run --rm --entrypoint /usr/local/sbin/openvpn openvpn-ce:2.7.9-local --version
```

Do not mark the remaining sections as complete until there are recorded test logs from Linux CI and Synology DS920+ hardware.
