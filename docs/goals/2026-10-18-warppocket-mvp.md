# Goal: WarpPocket MVP

Status: blocked
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
  - Status: verified
  - Evidence: bounded sequential finder (30 candidates / 180 s deadline, probe-only while connected, active tunnel untouched), cancellation-safe controller with operation ids, mandatory ensure_reserved for primary/probe, and Tk UI implemented. Commit 215fac3 and Actions run 39237908290 verified the initial GUI. Packaging work reproduced and fixed missing consent prompts, cancel/late-result persistence, disconnect/reconnect ownership and stale monitor races; the deadline interrupts the in-flight trial. Current local full suite: 154 tests OK (3 Windows-only skips). Real controller gate reused both profiles without registration: primary 188.114.97.1:4500 unchanged, 21 HTTPS requests / 0 failures during a 15.33 s probe search, 1 saved result, maximum 2 helpers, profiles unchanged and cleanup verified (private controller-gate-2026-10-19.json).
- R3: Windows onefile build, offline packaged smoke, documentation and Windows 10 acceptance.
  - Source: reviewed plan step 9 and done criteria.
  - Acceptance: Actions builds standalone EXE with the patched helper; offline smoke verifies resources and helper lifecycle; clean Windows 10 acceptance recorded separately.
  - Primary evidence: GitHub Actions and explicit Windows 10/VM test.
  - Status: blocked
  - Evidence: packaging and offline acceptance verified by Actions run 39241371383 at 4e8885dc074eb59dd9351218ff3629c8780f913d (all four jobs successful). Native Windows passed 154 tests (4 platform skips); onefile EXE passed real GUI/resources/SOCKS checks and graceful cleanup. GUI-only termination killed inner PID 812, not launcher 2828; helper 3708 exited and port 49546 closed before emergency cleanup. EXE artifact 12182205547 (29,392,538 bytes), safe JSON artifact 12182111124. Downloaded EXE SHA256 matches its checksum file and CI: 4c48304ec7e3161f4281bf6a0a1383a62ef8444ee3851a78a69c35b930909d2d. Only clean Windows 10 acceptance is unresolved; no such OS/VM is available through the authorized environment.
- R4: Commit and push the verified deliverable to git@github.com:0FL01/WarpPocket.git and inspect Actions.
  - Source: latest user implementation request.
  - Acceptance: commit exists on origin; Actions result or concrete blocker reported.
  - Primary evidence: git commit SHA, remote SHA and workflow run.
  - Status: verified
  - Evidence: packaging commit c59f13d and native clock/deadline correction 4e8885d pushed to origin/master. Actions run 39241371383 succeeded on Linux Python 3.12.15/3.13.16, Windows Python 3.13.16 and the native Windows onefile packaging job; EXE/checksum and safe smoke artifacts inspected and downloaded.

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
- Consumers: headless E2E and controller/Tk (implemented); packaging/WarpPocket.spec and native Windows packaged smoke.
- Allowed: Python stdlib, requests[socks], pinned PyInstaller, pinned Go build of patched wireproxy, verified wgcf; private runtime data in the user data directory.
- Forbidden: tracked helper binaries, private profiles/accounts, live registration in ordinary CI, edits outside the repository.

## Current Checkpoint
- Closes: only the remaining R3 clean Windows 10 acceptance; implementation, packaged smoke and publication are verified.
- Smallest next action: requires an authorized clean Windows 10 x64 environment with a standard user account. Run the verified EXE without Python/WireGuard/admin, verify real SOCKS HTTPS, uninterrupted primary traffic during probe search, reconnect and close cleanup, using the existing identities rather than registering new ones.
- Expected evidence: an actual Windows 10 acceptance report. Server 2022 CI and Linux network evidence are not substitutes.
- Stop condition: that OS/access is unavailable; no remaining code edit can supply the missing runtime observation.

## Current State
- Resolved: R1, R2 and R4; R3 implementation/build/offline smoke/documentation/publication. Vendor pipeline builds the patched helper in CI. Temporary local diagnostic tools/config copies removed; persistent primary/probe profiles preserved.
- Last relevant evidence: 154 offline tests pass locally (3 Windows-only skips) and on native Windows (4 platform skips); Linux CI and Xvfb GUI smoke pass. Real controller network gate: 21 primary requests / 0 failures during probe search. Run 39241371383 passed the packaged GUI-only crash proof. Downloaded EXE/checksum and all three smoke JSON reports verified; no private profiles/configs are in the artifacts.
- Blocker: clean Windows 10 acceptance requires an actual OS/VM and standard-account access. This Linux host has none of virsh, qemu-system-x86_64, VBoxManage, wine, pwsh or gh available; the provided native runner is Windows Server 2022, not Windows 10.
- Next: resume R3 only when the missing Windows 10 environment is available; no known implementation or CI blocker remains.

## External Blocker: R3 Windows 10 acceptance
- Observed missing dependency: actual clean Windows 10 x64 with authorized interactive/network access under a non-elevated account.
- Available alternatives checked: local Linux real-network gate and GUI smoke; native Windows Server 2022 tests, packaged launch from a Unicode/spaces path, graceful close and inner-GUI-only crash test. All pass, but none establishes the required Windows 10 result. Local VM/Windows tooling is absent; no Windows 10 endpoint or runner is supplied.
- Smallest unlock: access to that OS/environment, then the acceptance described above. No new registrations, paid resources, VM/service/network reconfiguration or unapproved remote access was used to manufacture this evidence.

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
- 2026-10-19: R2 verified: finder/controller/Tk UI implemented with 103 tests, live UI smoke and CI (Xvfb + native Windows) green; goal updated for R3.
- 2026-10-19: R3 implementation added with real GUI smoke, pinned PyInstaller spec, native crash-driver tests and artifact workflow. Reproduced R2 consent/cancellation/ownership/deadline regressions fixed; local full suite 147 tests OK. Native packaged CI is next.
- 2026-10-19: first native CI exposed timestamp-clock mismatch and early timeout; deterministic regressions and fixes added (154 tests OK). Real controller/probe network gate passed without new registration; native CI retry is next.
- 2026-10-19: corrected native run 39241371383 passed all four jobs; EXE and checksum published, downloaded and verified. Graceful GUI cleanup and GUI-only crash proof passed. R3 blocked solely on the unavailable clean Windows 10 environment.

## Completion
- Resolved outcomes: R1 verified; R2 verified; R4 verified. R3 build/offline acceptance/publication verified, but required Windows 10 acceptance remains blocked.
- Commands/artifacts: local `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q` (154 OK); native `python -m PyInstaller --noconfirm --clean packaging/WarpPocket.spec` and `python scripts/ci_smoke.py --exe dist/WarpPocket.exe --out build/smoke` (run 39241371383, successful); artifact/checksum verification above.
- Constraint and diff-scope check: no new WARP registrations, no secret/runtime uploads or tracked binaries, no changes to docs/origin.md or system networking; existing profiles and active-primary guarantees preserved.
- Final status: blocked only by missing Windows 10 acceptance access, not a completed MVP claim.
