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
  - Status: in_progress
  - Evidence: 2026-10-18, registration/generation succeeded; all 30 candidate HTTPS checks failed with health_timeout. Valid saved profile reused without registration. Additional SOCKS TCP CONNECT to literal 1.1.1.1:443 failed after 5.03s, without DNS; helper configtest exit 0 and profile/account keys match. Cleanup verified. No successful WARP HTTPS or dual-profile continuity is claimed.
- R2: Persistent bounded sequential search, cancellation-safe controller and minimal Tk GUI.
  - Source: reviewed plan steps 6-8.
  - Acceptance: successful strategies persist; background search never replaces the primary; all owned processes stop on cancel/close.
  - Primary evidence: finder/controller/UI tests and runtime smoke.
  - Status: blocked
  - Evidence: R1 must pass before GUI implementation.
- R3: Windows onefile build, offline packaged smoke, documentation and Windows 10 acceptance.
  - Source: reviewed plan step 9 and done criteria.
  - Acceptance: Actions builds standalone EXE; owner-crash smoke verifies Job Objects; clean Windows 10 acceptance recorded separately.
  - Primary evidence: GitHub Actions and explicit Windows 10/VM test.
  - Status: blocked
  - Evidence: R1 network gate blocks GUI/onefile delivery; Windows 10 manual acceptance also remains outstanding. Headless Linux/Windows CI is configured separately.
- R4: Commit and push the verified deliverable to git@github.com:0FL01/WarpPocket.git and inspect Actions.
  - Source: latest user implementation request.
  - Acceptance: commit exists on origin; Actions result or concrete blocker reported.
  - Primary evidence: git commit SHA, remote SHA and workflow run.
  - Status: in_progress
  - Evidence: implementation bafa87a248d24f8402c99ccd3931e93b5f6a69b0 and test correction 396fd708d8caf0879b4e4c84852e879639cad5f0 pushed to origin/master. Actions run https://github.com/0FL01/WarpPocket/actions/runs/39165431267 succeeded on Linux Python 3.12.15/3.13.16 and Windows Python 3.13.16. Final documentation-only checkpoint does not change tested code/workflow.

### Constraints
- No GUI before R1 network gate. Stop at confirmed registration/transport incompatibility rather than conceal it.
- Separate persistent primary/probe identities; sequential trials; at most two wireproxy processes.
- Explicit TLS-verified HTTPS via socks5h; no direct/DNS fallback; loopback listeners only.
- Private profiles/accounts/runtime files; no secrets in Git, cache, logs or CI artifacts.
- Windows Job Objects assigned at process creation; no unmanaged fallback. No admin/drivers/system routing changes.
- User explicitly accepted Cloudflare terms and authorized up to two registrations on 2026-10-18, correcting an earlier import-only answer.
- On 2026-10-19 the user explicitly authorized direct SSH testing as root on Proxmox host 192.168.1.10, including WARP registration, and required host cleanup. Use one private temporary workspace and isolated venv; do not change Proxmox/VM/container configuration, packages, services, routes, DNS or firewall. Reuse the saved primary; the separately authorized probe is the second and final registration, for the gate or a causal old-versus-fresh-profile diagnostic. Preserve reusable secrets only in the local private data directory, never in Git; remove remote test processes/files afterwards.

### Non-goals
- Future transport abstraction, MASQUE, parallel scanners, system VPN, tray/updater/installer/signing, adjacent projects, changes to docs/origin.md.

## Change Envelope
- Target: this repository root, src/warppocket, tests, scripts, vendor metadata/licenses, dependency locks, README and .github/workflows.
- Consumers: headless E2E first; later controller/Tk and Windows packaging.
- Allowed: Python stdlib, requests[socks], pinned PyInstaller, verified upstream helpers; private runtime data in the user data directory required by the reviewed plan.
- Remote R1 experiment: user-approved /root/warppocket-e2e-* workspace on 192.168.1.10, transferred source/verified helpers/locked wheels, private copies of test profiles, and an isolated venv only. All remote test artifacts must be removed after retrieval of results.
- Forbidden: tracked helper binaries, private profiles/accounts, live registration in ordinary CI, source/configuration edits outside the repository or to adjacent projects.

## Current Checkpoint
- Closes: R1 on the newly authorized provider-direct host; R4 baseline remains verified.
- Smallest next action: Linux TIME_WAIT preflight fix and both real-helper reconnect/live foreign listener tests pass locally. Commit/push it for native Windows verification while repeating the older-helper control. Native startup/configtest of the old helper succeeds; the previous data comparison did not reach its listener and is inconclusive. No production dependency downgrade is justified.
- Expected evidence: WARP HTTPS plus independent resource, endpoint switch, profile reuse and primary/probe continuity; or a precise changed-network failure. Record helper/process/port and workspace cleanup in either case.
- Stop or replan if: no approved experiment can unlock R1, or host isolation/cleanup cannot be maintained. Do not start GUI or new transports before R1 succeeds.

## Current State
- Resolved: pinned dependencies/helpers, private storage and safe diagnostics, strict profiles/import, native process ownership, WireProxy backend, HTTPS health checks, opt-in E2E, offline tests and headless CI.
- Last relevant evidence: local suite ran 52 tests (49 passed, 3 native-Windows skips); after the Windows test correction its module passed locally and the full Actions suite succeeded on all three jobs. Native Windows ran 52 tests (50 passed, 2 POSIX-only skips), including actual helper, owner-crash job cleanup, handle accounting and private DACL. The real gate failed on 30 endpoints, then confirmed no configs, live owned helper or port 25344 remained.
- Blocker: responsive endpoint supports handshake/TCP and occasional TCP DNS, but no completed acceptance HTTPS. Primary warp_enabled was explicitly enabled and verified true; unchanged regenerated configuration and original-profile remote retest still fail, including a 15-second diagnostic. The fresh, separately authorized probe was created through the working local API, enabled/verified true and tested remotely on 30 candidates with zero HTTPS successes. Thus an old/disabled identity alone does not explain the failure. Every remote workspace/process/capture was removed.
- Next: use one older upstream helper as a controlled implementation comparison and bypass DNS only for clearly labelled numeric-HTTPS diagnostics, never as a connected-status shortcut. Continue R2/R3 only if the real gate succeeds.

### Failed network checkpoint (2026-10-18)

The primary was created by the explicitly authorized initial command:

```sh
.venv/bin/python scripts/e2e_network.py --data-dir /home/stfu/.local/share/warppocket-e2e --accept-tos --accept-probe-tos --report /home/stfu/.local/share/warppocket-e2e/last-report.json
```

The subsequent expanded trial reused that profile, without a new registration:

```sh
set --
for endpoint in \
  8.6.112.1:2408 8.34.70.1:2408 8.34.146.1:2408 8.35.211.1:2408 \
  8.39.125.1:2408 8.39.204.1:2408 8.39.214.1:2408 8.47.69.1:2408 \
  188.114.97.1:2408 188.114.98.1:2408 188.114.99.1:2408 \
  162.159.192.2:2408 162.159.193.2:2408 162.159.195.2:2408 \
  162.159.192.1:4500 162.159.193.1:500 162.159.193.1:4500 \
  162.159.195.1:500 162.159.195.1:4500 162.159.192.1:1701 \
  162.159.193.1:3476 162.159.195.1:854 188.114.96.1:500 188.114.99.1:4500
do
  set -- "$@" --endpoint "$endpoint"
done
.venv/bin/python scripts/e2e_network.py --data-dir /home/stfu/.local/share/warppocket-e2e --report /home/stfu/.local/share/warppocket-e2e/last-report.json "$@"
```

Result: exit 1, `no_working_endpoint`, 30 `candidate_failed/health_timeout` events, `cleanup_verified`, zero primary HTTPS successes and zero probe attempts. The private report and reusable primary profile remain only in the external data directory, not Git. Configuration validation and a no-DNS TCP CONNECT diagnostic excluded invalid helper syntax and a purely hostname-resolution failure; neither is connectivity acceptance evidence. Further endpoint/profile creation loops are not justified by this result.

## Material Decisions
- 2026-10-18: source compatible with Python >=3.12; Windows runtime pinned to 3.13.16 because maintained 3.12 releases have no official Windows installer.
- 2026-10-18: origin is the user-specified SSH remote; no nested WarpPocket directory.
- 2026-10-19: user authorized direct, careful WARP testing on 192.168.1.10 with mandatory cleanup. Read-only preflight confirmed Python 3.13.5, venv/SSL, sufficient disk and no listener on 25344. No system package or network changes are needed.
- 2026-10-19: because the existing identity failed on two networks, advance the already authorized probe registration only for a fresh-identity comparison if the longer-timeout diagnostic still fails. Do not create any further identity or replace primary. Narrow packet capture is limited to the owned helper's UDP socket and a selected WARP endpoint; retain no capture on the host after cleanup.
- 2026-10-19: temporary structured API diagnostic uses the pinned wgcf v2.3.1 SDK in approved local temporary storage only, never an application dependency. API GET proves warp_enabled=false; the author's archived Python client explicitly PATCHes this field true after registration. Test only that intended WARP-enabling operation on the same identity under the user's existing consent, verify response, and do not claim it fixes transport until HTTPS passes.

## Checkpoint History
- 2026-10-18: contract frozen before implementation.
- 2026-10-18: R1 headless code and offline tests implemented; real registration succeeded, but bounded network trials failed. GUI work stopped as required. R4 remains actionable through commit/push and native CI.
- 2026-10-18: R4 verified by SSH push and successful Actions run 39165431267. Initial Windows run exposed a test assuming a context-suppression flag even when no exception context exists; corrected it to check that the full rendered exception contains no secret. Production process code unchanged. All native Windows ownership/privacy checks passed. Overall objective remains blocked on real network data traffic.
- 2026-10-19: R1 reopened because the user provided and authorized a different network/host; remote execution is limited to an isolated removable test workspace.
- 2026-10-19: remote Debian lacks ensurepip; isolated venv bootstrapped from transferred pip code/hashed wheels without system installation. Remote gate reused primary, failed six endpoints and verified cleanup. Both temporary workspaces were removed; no probe registration occurred.
- 2026-10-19: causal capture (owned socket/endpoint only) found no UDP replies on 162.159.192.1:2408, but handshake and TCP data on 188.114.96.1:4500. Longer timeout did not complete domain HTTPS. Probe registration failed without a persisted account; private diagnostic saved locally. Capture/workspace/processes removed. Next checkpoint splits tunneled DNS and TLS instead of declaring all transport unavailable.
- 2026-10-19: TCP DNS to 8.8.8.8 returns valid A answers through WARP, while domain and numeric HTTPS still fail; IPv4-only/other resolver/MTU1200 did not fix it. API read via exact SDK succeeded locally and exposed warp_enabled=false with active device. Next experiment enables that flag, not another blind endpoint/registration loop. Source/test code remains unchanged.
- 2026-10-19: primary PATCH/verification GET confirmed warp_enabled=true, but HTTPS still failed with original profile and longer timeout; fresh generate produced no changed fields. Standard Python requests API GET also succeeds locally. Probe registration succeeded locally after the remote TLS failure, with distinct identity; its false WARP flag was enabled and verified true. Remote bounded 30-candidate probe trial still produced zero successes, cleanup confirmed. No further identities will be created; next control varies the helper implementation, not random endpoints.
- 2026-10-19: independent curl with helper 1.1.3 verified TLS to literal 1.1.1.1 but received no HTTP response in 35s; domain DNS failed. Old helper control did not start via backend, although native --version/configtest exit 0 and foreground stays running. A local minimal reproduction proves backend incorrectly reports a closed TIME_WAIT socket as port_busy; SO_REUSEADDR binding succeeds. Fix the owning backend preflight and explicit reconnect test before interpreting more network failures.

## Completion
- Resolved outcomes: R4 baseline verified. R1 in progress on the newly authorized remote network; R2/R3 still depend on its result. No waiver or MVP completion claimed.
- Commands/artifacts: local offline suite, focused process-manager suite, real network gate and no-DNS diagnostic, pushed implementation/test commits and successful Actions run linked above.
- Constraint/scope check: only planned headless paths, tests, dependencies/licenses, CI and documentation changed; origin.md content preserved; helpers and real secrets excluded from Git; no GUI before the gate, no new transport or system network changes.
- Final status: active after the user provided the external network unlock. Successful WARP data traffic, background continuity, GUI, EXE and Windows 10 acceptance remain unverified/unimplemented as applicable.
