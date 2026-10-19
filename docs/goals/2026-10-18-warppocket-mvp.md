# Goal: WarpPocket MVP

Status: active
Source: docs/origin.md; reviewed conversation plan; user request to implement, commit and push.
Last updated: 2026-10-19

## Objective
Ship one Windows EXE providing verified WARP SOCKS5 at 127.0.0.1:25344, persistent endpoints and non-disruptive strategy search.

## Execution Directive
Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied. Stop substantive work at a proven external blocker and record the exact evidence and smallest unlock.

## Frozen Contract

### Required Outcomes
- R1: Prove headless registration/profile -> SOCKS5 -> WARP trace and independent HTTPS; switch endpoints after full stop, reuse profiles, probe with a separate identity without changing the primary process or traffic.
  - Source: reviewed plan, mandatory network gate.
  - Acceptance: explicit opt-in E2E succeeds; failure is reported without false connected status.
  - Primary evidence: scripts/e2e_network.py and focused unit tests.
  - Status: verified
  - Evidence: root cause fixed (24-bit `reserved` client id). Opt-in gate passed locally on 2026-10-19 (gate-report-2026-10-19.json): primary 188.114.96.1:4500 verified (417.19 ms); after full stop 188.114.97.1:4500 verified (327.0 ms); saved profile reused without registration (pid 1340599); separate probe verified on 188.114.96.1:4500 while primary HTTPS ran continuously (6 requests, 0 failures, pid/port/profile unchanged); cleanup_verified. 64 offline tests pass with 3 platform skips.
- R2: Persistent bounded sequential search, cancellation-safe controller and minimal Tk GUI.
  - Source: reviewed plan steps 6-8.
  - Acceptance: successful strategies persist; background search never replaces the primary; all owned processes stop on cancel/close.
  - Primary evidence: finder/controller/UI tests and runtime smoke.
  - Status: pending
  - Evidence: R1 gate passed 2026-10-19; implementation is the current checkpoint. The controller must also call ProfileService.ensure_reserved for primary/probe.
- R3: Windows onefile build, offline packaged smoke, documentation and Windows 10 acceptance.
  - Source: reviewed plan step 9 and done criteria.
  - Acceptance: Actions builds standalone EXE with the patched helper; offline smoke verifies resources and helper lifecycle; clean Windows 10 acceptance recorded separately.
  - Primary evidence: GitHub Actions and explicit Windows 10/VM test.
  - Status: pending
  - Evidence: pending.
- R4: Commit and push the verified deliverable to git@github.com:0FL01/WarpPocket.git and inspect Actions.
  - Source: latest user implementation request.
  - Acceptance: commit exists on origin; Actions result or concrete blocker reported.
  - Primary evidence: git commit SHA, remote SHA and workflow run.
  - Status: verified
  - Evidence: reconnect fix e2f61d78 + Actions run 39224555542 (Linux Python 3.12.15/3.13.16, Windows Python 3.13.16). Reserved-support change set 19af8157 pushed; Actions run 39235875257 succeeded on all three jobs, including the native Windows job that builds the patched helper with Go 1.26 and passes 64 tests.

### Constraints
- No false connected status: success still requires warp=on/plus plus an independent HTTPS resource. GUI is now permitted because the R1 gate passed.
- Separate persistent primary/probe identities; sequential trials; at most two wireproxy processes; no further WARP registrations (both identities already exist).
- Explicit TLS-verified HTTPS via socks5h; no direct/DNS fallback; loopback listeners only.
- Private profiles/accounts/runtime files; no secrets in Git, cache, logs or CI artifacts.
- Windows Job Objects assigned at process creation; no unmanaged fallback. No admin/drivers/system routing changes.
- User accepted Cloudflare terms and authorized both identities. Temporary authorized root testing on 192.168.1.10 is finished; host cleanup verified (zero workspaces/processes, port 25344 free); no Proxmox packages/services/routes/DNS/firewall changes.

### Non-goals
- Future transport abstraction, MASQUE, parallel scanners, system VPN, tray/updater/installer/signing, adjacent projects, changes to docs/origin.md.

## Change Envelope
- Target: this repository root, src/warppocket, tests, scripts, vendor metadata/licenses, dependency locks, README and .github/workflows.
- Consumers: headless E2E (done); controller/Tk and Windows packaging next.
- Allowed: Python stdlib, requests[socks], pinned PyInstaller, pinned Go build of patched wireproxy, verified wgcf; private runtime data in the user data directory.
- Forbidden: tracked helper binaries, private profiles/accounts, live registration in ordinary CI, edits outside the repository.

## Current Checkpoint
- Closes: R2 (bounded sequential finder, cancellation-safe controller, minimal Tk GUI).
- Smallest next action: implement endpoints.py + strategy_finder.py with tests; then controller.py (including ensure_reserved for primary/probe); then ui.py/__main__.py with tests.
- Expected evidence: focused unit tests, headless GUI smoke on Linux, then packaged smoke and Windows CI.
- Stop or replan if: a frozen outcome proves unavailable; then record exact evidence and the smallest unlock.

## Current State
- Resolved: R1 verified (reserved root cause fixed; patched helper built from pinned sources; opt-in gate passed locally). Vendor pipeline builds the patched helper in CI.
- Last relevant evidence: 64 offline tests pass (3 platform skips); gate-report-2026-10-19.json; helper build prints its SHA256.
- Blocker: none for R1. Windows 10 manual acceptance still outstanding for R3.
- Next: R2 implementation, then R3.

## Root cause and fix (2026-10-19)
- Cloudflare WARP requires the 3-byte `reserved` client id inside WireGuard messages. `wgcf` does not emit it; upstream `wireproxy` has no support (issue #72).
- Send-side support alone kept failing: capture showed the server mirrors the client id back in the reserved field, and upstream classification `binary.LittleEndian.Uint32(packet[:4])` then rejects responses ("unknown type").
- Fix (mirrors sing-box ClientBind): send-side copy of `reserved` into outgoing headers plus receive-side clearing of bytes 1..3 before classification, in `conn/bind_std.go` and `conn/bind_windows.go` of pinned wireguard-go v0.0.0-20250521234502-f333402bd9cb.
- Control: sing-box 1.14.3 with `peers.reserved` passed trace/gstatic/example/socks5h on the same profile/endpoint while wireproxy failed; after the receive-side fix the patched wireproxy passed both on Proxmox and locally.
- Production path: `scripts/build_wireproxy.py` builds the patched helper from pinned wireproxy 1.1.3 sources and prints its SHA256; CI does this per platform. sing-box was rejected for production (GPL-3.0, size) but remains the reference implementation for this mechanism.

## R1 gate evidence (2026-10-19)

Command:
`.venv/bin/python scripts/e2e_network.py --data-dir /home/stfu/.local/share/warppocket-e2e --report .../gate-report-2026-10-19.json --endpoint 188.114.96.1:4500 --endpoint 188.114.97.1:4500 --endpoint 188.114.98.1:4500 --endpoint 188.114.99.1:4500 --endpoint 162.159.192.1:2408 --endpoint 162.159.193.1:2408 --endpoint 162.159.195.1:2408`

Results: passed=true; primary_verified 188.114.96.1:4500 417.19 ms; first_process_stopped; second endpoint 188.114.97.1:4500 327.0 ms; profile_reused_without_registration pid 1340599; probe_profile_ready; probe_verified 188.114.96.1:4500; primary_preserved (pid/port/profile unchanged); cleanup_verified; primary_requests=6; probe_attempts=2.

Operational notes: `engage.cloudflareclient.com:2408` consistently times out in the tested networks; working candidates were in 188.114.9x.1:4500. Cache now holds last_good=188.114.97.1:4500. The finder must weigh these ranges highly. Safe reports stay only in the local private data directory; profiles are never committed or printed.

## Material Decisions
- 2026-10-18: source compatible with Python >=3.12; Windows runtime pinned to 3.13.16 because maintained 3.12 releases have no official Windows installer.
- 2026-10-18: origin is the user-specified SSH remote; no nested WarpPocket directory.
- 2026-10-19: reserved support is achieved by building patched wireproxy from pinned sources rather than replacing the transport or shipping a forked module (the fork lacks tun/netstack).
- 2026-10-19: imports accept `Reserved`; `ensure_reserved` fills it via the Cloudflare API when an account exists.
- 2026-10-19: remote Proxmox testing was temporary; all remote artifacts removed and configuration untouched.

## Checkpoint History
- 2026-10-18: contract frozen; headless implementation and offline tests; first bounded network trials failed.
- 2026-10-18: R4 verified (push + Actions 39165431267); Windows test correction checked rendered redaction instead of a flag.
- 2026-10-19: user authorized remote testing; two networks reproduced the failure; API flags, DNS/MTU variants, old helper and fresh probe excluded as causes; remote cleanup verified.
- 2026-10-19: root cause identified (reserved) and confirmed with a sing-box control; receive-side fix ported; production build pipeline and CI Go build added.
- 2026-10-19: opt-in gate passed locally; reserved-support change set committed/pushed with Actions verification.

## Completion
- Resolved outcomes: R1 verified; R4 verified. R2/R3 pending. Windows 10 acceptance outstanding.
- Final status: active, continuing with R2.
