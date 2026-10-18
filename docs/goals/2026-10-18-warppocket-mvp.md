# Goal: WarpPocket MVP

Status: active
Source: docs/origin.md; reviewed conversation plan; user request to implement, commit and push.
Last updated: 2026-10-18

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
  - Status: blocked
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
  - Evidence: SSH remote is configured and accessible; initial headless commit/push and native Windows Actions verification are next.

### Constraints
- No GUI before R1 network gate. Stop at confirmed registration/transport incompatibility rather than conceal it.
- Separate persistent primary/probe identities; sequential trials; at most two wireproxy processes.
- Explicit TLS-verified HTTPS via socks5h; no direct/DNS fallback; loopback listeners only.
- Private profiles/accounts/runtime files; no secrets in Git, cache, logs or CI artifacts.
- Windows Job Objects assigned at process creation; no unmanaged fallback. No admin/drivers/system routing changes.
- User explicitly accepted Cloudflare terms and authorized up to two registrations on 2026-10-18, correcting an earlier import-only answer.

### Non-goals
- Future transport abstraction, MASQUE, parallel scanners, system VPN, tray/updater/installer/signing, adjacent projects, changes to docs/origin.md.

## Change Envelope
- Target: this repository root, src/warppocket, tests, scripts, vendor metadata/licenses, dependency locks, README and .github/workflows.
- Consumers: headless E2E first; later controller/Tk and Windows packaging.
- Allowed: Python stdlib, requests[socks], pinned PyInstaller, verified upstream helpers.
- Forbidden: tracked helper binaries, private profiles/accounts, live registration in ordinary CI, changes outside the repository.

## Current Checkpoint
- Closes: R4; preserves the R1 blocker without expanding transport scope.
- Smallest next action: run the final offline suite, commit/push the headless deliverable and inspect native Windows/Linux Actions. Fix only confirmed failures of this path.
- Expected evidence: pushed SHA and Actions jobs; no EXE/MVP completion claim.
- Stop or replan if: no approved in-scope action can unlock R1; do not start GUI or new transports.

## Current State
- Resolved: pinned dependencies/helpers, private storage and safe diagnostics, strict profiles/import, native process ownership, WireProxy backend, HTTPS health checks, opt-in E2E, offline tests and headless CI.
- Last relevant evidence: `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v` ran 52 tests successfully (49 passed, 3 native-Windows skips) after the final E2E cleanup edit. Actual Linux helper starts/stops offline. The real gate failed on 30 endpoints, then confirmed no configs, live owned helper or port 25344 remained.
- Blocker: no working WARP data path in this environment. Registration works, but the 30-candidate trial and literal-IP SOCKS TCP check failed. Exact cause is unknown; this does not prove universal WireGuard blocking. Probe was not registered because primary never passed.
- Next: finish R4. Unlock R1 with a working endpoint/profile or a network where WireGuard data traffic succeeds; rerun the opt-in gate with separate probe consent. Then implement R2/R3 and obtain clean Windows 10 acceptance.

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

## Checkpoint History
- 2026-10-18: contract frozen before implementation.
- 2026-10-18: R1 headless code and offline tests implemented; real registration succeeded, but bounded network trials failed. GUI work stopped as required. R4 remains actionable through commit/push and native CI.

## Completion
- Pending. Headless implementation exists; successful WARP data traffic, background continuity, GUI, EXE and Windows 10 acceptance are not claimed.
