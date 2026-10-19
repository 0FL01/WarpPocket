# Goal: Embedded ordered WARP DNS

Status: complete
Source: user DNS request and approved implementation plan; «реализовать и коммит пуш».
Last updated: 2026-10-19

## Objective
Ship a rolling EXE which resolves proxied domains through 83.220.169.155, then 212.109.195.93, using 9.9.9.9 only after both primary resolver stages fail.

## Execution Directive
Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied. Stop substantive work at a proven external blocker and record the exact evidence and smallest unlock.

## Frozen Contract
### Required Outcomes
- R1: Apply the embedded DNS list to every new primary/probe runtime configuration, including existing/imported profiles.
  - Source: approved plan, backend configuration step.
  - Acceptance: the ordered DNS list is present; original profiles, identities and Reserved remain unchanged.
  - Primary evidence: backend/profile tests.
  - Status: verified
  - Evidence: backend renders a dataclasses.replace runtime copy with the exact ordered list. Backend/profile tests verify both roles, saved/imported files and all other profile fields; real existing-profile gate confirms both profiles/accounts unchanged.
- R2: Ordered lookup-wide failover inside the tunneled resolver.
  - Source: user «если оба мертвы то fallback на 9.9.9.9» and approved resolver plan.
  - Acceptance: A/AAAA share a server stage; addresses or NXDOMAIN/NODATA stop failover, while transport errors/SERVFAIL/REFUSED advance to the next stage. Each stage is bounded to 1 second, the three-stage lookup to 3 seconds; UDP/TCP share the budget. Cancellation closes DNS I/O and prevents later stages; no host resolver/direct fallback.
  - Primary evidence: deterministic native Go DNS behavior tests against the patched pinned module, plus existing-profile real HTTPS gate.
  - Status: verified
  - Evidence: exact-anchor patch preserves upstream parsing/tunnel dialers and adds one-server lookup views with per-call exchange injection. Seven native Go test groups (23 scenarios) pass, including real virtual-netstack UDP/TCP cancellation and shared deadlines; both Linux and Windows helpers compile. Real WARP HTTPS gate passes on 188.114.96.1:4500 (327.79 ms) and 188.114.97.1:4500 (333.25 ms), with 4 primary requests during probe, primary preserved, no registration, unchanged profile/account bytes and cleanup verified (private dns-gate-2026-10-19.json).
- R3: Integrate and publish the verified implementation.
  - Source: approved plan and explicit commit/push request; existing rolling release requirement.
  - Acceptance: health connect-timeout accommodates DNS failover (5 seconds); pinned helper build runs native Go tests; Linux/Windows gates and packaged smoke pass; commit is on origin/master and rolling contains only the matching WarpPocket.exe.
  - Primary evidence: relevant/full tests, GitHub Actions, rolling tag/asset and downloaded EXE.
  - Status: verified
  - Evidence: 177 local Python tests OK (3 platform skips); native Windows passes 177 tests (4 platform skips). Vendor tests verify native host targeting and abort-before-build on native test failure. Production build --platform all ran native DNS tests and built both helpers. Commit 9c08438fc127599c0d1aae45334e8ed7e9380548 is on origin/master; Actions run 39252795307 passed all five jobs, including native Linux/Windows DNS gates, packaged normal-close/GUI-only-crash smoke and rolling publication. Public rolling tag/release body match that commit/run; only WarpPocket.exe is attached. Downloaded release EXE (29,395,768 bytes) matches the same-run tested CI artifact byte-for-byte.

### Constraints
- Keep upstream source versions/hashes pinned and reserved support intact. Patch only the isolated source copy, never the global Go module cache.
- All destination DNS/data traffic stays on WARP netstack; no OS DNS/routing/firewall changes or additional local DNS service.
- Preserve primary/probe isolation, active-connection ownership, cancellation and the 30-candidate/180-second search budget.
- No new WARP registrations, tracked binaries/private profiles, secrets in logs or release sidecars. Use the existing identities for the real gate.
- Release only WarpPocket.exe; existing success/master gating and stale-publication protection remain unchanged.

### Non-goals
- System-wide DNS, DoH/DoT, browser-owned DoH, new GUI settings, bootstrap hostname resolution before WARP, Windows 10 acceptance from the separate MVP goal.

## Change Envelope
- Target: src/warppocket/backend.py and healthcheck.py; scripts/build_wireproxy.py and checked-in netstack patch/test payloads; vendor/wireproxy-build.json; affected tests; README and this contract.
- Native Go tests may be copied to the already-owned temporary wireguard-go module and run with host GOOS/GOARCH before cross-compilation.
- Allowed generated artifacts: ignored helper/build outputs and private local reports. Forbidden: committed binaries, accounts/config secrets and extra release assets.

## Current Checkpoint
- Closed: R1/R2/R3. Implementation, local/live verification, native CI and rolling publication are complete.
- Closure evidence: run 39252795307 succeeded; the downloaded rolling EXE matches its tested artifact, and the rolling tag matches the pushed implementation commit.
- Next: none for this frozen objective; stop substantive work.

## Current State
- Resolved: R1, R2 and R3; no source profile migrations or system DNS changes.
- Last relevant evidence: 177 Python tests OK locally and on Windows; seven native Go DNS test groups/23 scenarios; both helpers built with Go 1.26.9. Real existing-profile HTTPS/probe gate and cleanup passed. All five native CI/publication jobs succeeded, and the release EXE matches the tested artifact.
- Blocker: none.
- Next: none; the approved DNS objective is complete.

## Material Decisions
- A responding negative NXDOMAIN/NODATA is terminal, not an excuse to bypass the primary DNS; SERVFAIL/REFUSED keep the existing retry classification.
- Override only the disposable runtime profile. No migration, key changes or hot replacement of the active tunnel.
- Helper policy/tests and Python runtime configuration/tests are independent implementation workstreams.

## Checkpoint History
- 2026-10-19: contract frozen from the approved plan; implementation started.
- 2026-10-19: R1/R2 verified locally, including virtual UDP/TCP tests and real WARP gate; full Python suite 177 OK and both helper targets built. Native publication is next.
- 2026-10-19: 9c08438 pushed; run 39252795307 passed all five jobs. Verified the rolling tag, sole EXE attachment and downloaded binary equality; R3 verified and closure check passed.

## Completion
- Resolved outcomes: R1/R2/R3 verified.
- Commands and artifacts: local full unittest suite (177 OK); scripts/build_wireproxy.py --platform all (native DNS tests and both targets); private existing-profile dns-gate-2026-10-19.json (passed, unchanged profiles/accounts, no registrations, cleanup verified); Actions run 39252795307 and https://github.com/0FL01/WarpPocket/releases/download/rolling/WarpPocket.exe (download matches tested artifact).
- Constraint and diff-scope check: pinned upstream versions/hashes and Reserved support unchanged; no global Go-cache edits, system/direct DNS fallback, profile migrations, registrations, tracked binaries/secrets or release sidecars. Existing search/ownership and rolling gates preserved. The separate Windows 10 MVP gate is outside this objective.
- Final status: complete.
