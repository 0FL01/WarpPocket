# Goal: Serve every SOCKS destination through WARP

Status: in progress
Source: user-approved plan and instruction "Реализовать и коммит пуш" with successful GitHub Actions publication as acceptance
Last updated: 2026-10-20

## Objective

Remove the hardcoded RU/RF/SU and VK split routing entirely so that every destination accepted by the SOCKS5 listener is served through the WARP tunnel, restoring the pinned upstream Landlock sandbox and preserving ordered DNS, Reserved support, handshake junk, worker ownership and automatic recovery.

## Execution Directive

Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied.

## Frozen Contract

### Required Outcomes

- R1: All SOCKS destipations use the WARP dialer and ordered resolver; no host-direct dialer, no route classifier and no fallback remain in the prepared engine.
  - Source: approved plan, changes 1-2.
  - Acceptance: prepared `Socks5Config.SpawnRoutine` contains only the tunnel dialer/resolver plus the explicit CONNECT-only rule; generated routing artifacts do not exist.
  - Primary evidence: native `TestWarpPocketPolicy` gate and tools generator tests.
  - Status: verified
  - Evidence: preparation installed `reserved-support+ordered-dns+handshake-junk`; generated `routine.go` contains `WithDial(vt.Tnet.DialContext)`, `WithResolver(vt)`, `PermitCommand{EnableConnect: true}` and no `WithDialAndRequest`/router; `warppocket_routing*.go` are absent; native resolve test proves `.рф`/punycode/ASCII/literal handling through the real `VirtualTun.Resolve`.
- R2: The Linux network sandbox returns to the pinned upstream policy; SOCKS keeps only its listener bind and shared host TCP stays denied.
  - Source: approved plan, change 3.
  - Acceptance: prepared `cmd/wireproxy/main.go` matches the upstream `lockNetwork` verbatim and contains no relaxation, no `landlocksyscall` import.
  - Primary evidence: `TestWarpPocketPolicySource` over the prepared sources.
  - Status: verified
  - Evidence: `TestWarpPocketPolicySource` and `TestWarpOnlySOCKSOptionsAndPreservedSandbox` pass; preparation fails closed if the reviewed sandbox text changes.
- R3: The shipped EXE refuses BIND and UDP ASSOCIATE, and the opt-in network gate proves former split destinations and literal IPs stay on WARP.
  - Source: approved plan, changes 5-6.
  - Acceptance: offline smoke exercises the real worker's SOCKS refusals; the opt-in gate establishes verified HTTPS for `ya.ru`, `vk.com` and `1.1.1.1` without any engine-owned host TCP connection.
  - Primary evidence: `internal/smoke` tests, Linux same-EXE smoke and the explicit network gate.
  - Status: in progress
- R4: Commit and push only this work; the pushed revision completes the existing Actions workflow including rolling publication.
  - Source: latest user instruction.
  - Acceptance: remote master contains the implementation and its Actions run concludes successfully with published release.
  - Primary evidence: git revision/remote comparison and GitHub Actions run/jobs.
  - Status: pending

### Constraints

- Preserve profile/account bytes, keepalive values, strict import validation, Reserved processing, handshake junk, primary/probe ownership, ordered five-stage DNS, health and recovery contracts.
- Preserve dependency versions/hashes, the single shipped EXE, and the ignored `build/deps` generation model; preparation must fail before publication on any gate failure.
- Do not modify the untracked `WarpPocket-Crayon-Design/`, completed historical goal documents, or remote services. Do not expose secrets or raw engine output.

### Non-goals

- System-wide VPN/TUN routing, UDP/QUIC proxying, new settings or PAC files, DNS server changes, dependency upgrades, WARP transport changes, account registration.

## Change Envelope

- Target: pinned-source preparation (`tools/internal/prepare`), affected payloads/tests, `internal/smoke`, `internal/acceptance`, `internal/ui`, `vendor/wireproxy-build.json`, `README.md` and this contract.
- Allowed artifacts: source/tests/docs and ignored build/test outputs. No new dependencies.

## Current Checkpoint

- Closed: R1-R2 and the local parts of R3 except the opt-in network gate.
- Next: complete R3 evidence, then R4.

## Current State

- Baseline: `a9113ae`; only pre-existing untracked design directory.
- Evidence: tools tests/race, source preparation with all three native gates, application tests/vet/race and cross-build pass.
- Blocker: none.
