# Codex / AI Coding Agent Instructions

## Source of truth
Read [docs/DESIGN.md](docs/DESIGN.md) before writing code. This is a new project: do not assume the specified features already exist. Implement work in the Phase 0 → Phase 5 order defined in §15. Complete and test each phase before starting the next. Write Chinese developer documentation; code identifiers and machine-readable errors are English.

## Product goal
Build a web manager for **official OpenVPN Community Edition 2.7.9** on Synology DS920+ (linux/amd64), Docker Compose, **TCP/IPv4**, independently built from official release source. Do not substitute Access Server or a third-party OpenVPN server image.

## Non-negotiable security constraints
1. Docker environment variable `OPENVPN_MANAGER_WRITE_ENABLED` defaults to `false`; only exact literal `true` grants an upper bound of write authority. Missing/invalid values mean read-only.
2. The web app **must not** expose any write-mode toggle, override API, or undocumented initialization bypass. Initial setup requires write mode too.
3. Both **manager** and **control-agent** independently enforce the write gate. Every state-changing operation and private-key/profile export is gated; fail closed on discrepancies or unavailability. UI disabling is not a security boundary.
4. Toggling requires editing Docker Compose/.env and recreating **manager and control-agent**, not just `docker compose restart`; a running OpenVPN runtime and existing sessions must remain unaffected.
5. Do not mount Docker socket; do not use `privileged: true` by default. Manager never receives NET_ADMIN, CA private key or runtime-control privileges. Runtime gets only explicitly required /dev/net/tun and capabilities.
6. No arbitrary shell/exec endpoints, arbitrary OpenVPN configuration injection, or user-controlled host paths. Use allowlisted typed operations and protected, authenticated IPC.
7. CA private key must remain encrypted and must not enter runtime, git, images, logs, API payloads or browser storage. Client .ovpn export is an audited, TOTP-protected, short-lived, one-time sensitive operation.
8. Management surface must default to loopback/private LAN HTTPS, never publicly exposed by default.
9. OpenVPN source and third-party tools must have pinned versions and verifiable provenance (OpenVPN release signature check); reject build on signature failure.
10. Every configuration apply must validate, version, log, and support error recovery/rollback; never reset PKI automatically.
11. Do not state DS920+ compatibility, real VPN connectivity, or Docker build success without actual tests.

## Implementation workflow
- First task: **Phase 0 only** (Docker multi-stage builds, Compose, Go/Vue scaffolding, README, tests). Follow the prompt at the end of §16 in docs/DESIGN.md.
- Create cohesive, reviewable increments. Each change needs positive, negative, and bypass tests where applicable.
- Run Go tests, frontend type checks/tests, Docker build validations where feasible, and record what could not run.
- Keep security-sensitive policy centralized in backend policy and independently in agent; do not duplicate ad hoc UI-only checks.
- If a design requirement conflicts with DSM/kernel/iptables reality, document the failing test, propose secure alternatives, then revise the design/ADR before implementation; never enlarge privileges silently.
- Update docs and examples when adding env vars or API routes.

## Definition of done for a phase
- Source builds or the untested blocker is explicit.
- Security constraints relevant to the phase have automated tests.
- README commands are consistent with actual Compose service names.
- No real credentials, secrets, keys, .ovpn files, local data volumes or .env files committed.
- Clearly state what is implemented, what is simulated, and what still requires an actual DS920+ test.
