# Goal: Serve every SOCKS destination through WARP

Status: complete
Source: user-approved plan and instruction "Реализовать и коммит пуш" with successful GitHub Actions publication as acceptance
Last updated: 2026-10-20

## Objective

Remove the hardcoded RU/RF/SU and VK split routing entirely so that every destination accepted by the SOCKS5 listener is served through the WARP tunnel, restoring the pinned upstream Landlock sandbox and preserving ordered DNS, Reserved support, handshake junk, worker ownership and automatic recovery.

## Execution Directive

Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied.

## Frozen Contract

### Required Outcomes

- R1: All SOCKS destinations use the WARP dialer and ordered resolver; no host-direct dialer, no route classifier and no fallback remain in the prepared engine.
  - Source: approved plan, changes 1-2.
  - Acceptance: prepared `Socks5Config.SpawnRoutine` contains only the tunnel dialer/resolver plus the explicit CONNECT-only rule; generated routing artifacts do not exist.
  - Primary evidence: native `TestWarpPocketPolicy` gate and tools generator tests.
  - Status: verified
  - Evidence: preparation installed `reserved-support+ordered-dns+handshake-junk`; generated `routine.go` contains `WithDial(vt.Tnet.DialContext)`, `WithResolver(vt)`, `PermitCommand{EnableConnect: true}` and no `WithDialAndRequest`/router; `warppocket_routing*.go` are absent. `TestWarpPocketPolicyResolveNames` drives the real `VirtualTun.Resolve` over a loopback DNS fixture: raw lowercase/uppercase `.рф` with a root dot become `xn--e1afmkfd.xn--p1ai`, punycode and ASCII pass through unchanged, a literal IP never reaches DNS, and an over-long Unicode label is rejected before DNS.
- R2: The Linux network sandbox returns to the pinned upstream policy; SOCKS keeps only its listener bind and shared host TCP stays denied.
  - Source: approved plan, change 3.
  - Acceptance: prepared `cmd/wireproxy/main.go` matches the upstream `lockNetwork` verbatim and contains no relaxation, no `landlocksyscall` import.
  - Primary evidence: `TestWarpPocketPolicySource` over the prepared sources.
  - Status: verified
  - Evidence: the upstream `lockNetwork` text is kept as an exact-once identity anchor, so preparation fails closed if the reviewed sandbox ever changes. `TestWarpPocketPolicySource` reads the prepared `main.go`/`routine.go` and rejects `warpPocketNetworkPolicy`, `AccessNetBindTCP`, `AccessNetSet`, `landlocksyscall`, request-aware dialing and every surviving routing symbol. `TestWarpOnlySOCKSOptionsAndPreservedSandbox` checks the same invariants in the tools module.
- R3: The shipped EXE refuses BIND and UDP ASSOCIATE, and the opt-in network gate proves former split destinations and literal IPs stay on WARP.
  - Source: approved plan, changes 5-6.
  - Acceptance: offline smoke exercises the real worker's SOCKS refusals; the opt-in gate establishes verified HTTPS for `ya.ru`, `vk.com` and `1.1.1.1` without any engine-owned host TCP connection.
  - Primary evidence: `internal/smoke` tests, Linux same-EXE smoke and the explicit network gate.
  - Status: verified
  - Evidence: `verifySOCKSPolicy` proves the live worker answers BIND and UDP ASSOCIATE with `RepRuleFailure` (0x02) using numeric destinations before `socks_started` is reported; Linux and Windows smoke both report `socks_started: true`. The opt-in gate with the existing private primary/probe passed: `former_direct_hosts_https_via_warp: true`, `numeric_ip_https_warp_no_host_tcp: true`, `passed: true`, `max_workers: 2`, `profiles_unchanged: true`, `cleanup_verified: true`, recovery 26.59s on endpoint `188.114.96.1:4500`. A literal-IP trace additionally required exactly one `warp=on/plus`.
- R4: Commit and push only this work; the pushed revision completes the existing Actions workflow including rolling publication.
  - Source: latest user instruction.
  - Acceptance: remote master contains the implementation and its Actions run concludes successfully with published release.
  - Primary evidence: git revision/remote comparison and GitHub Actions run/jobs.
  - Status: verified
  - Evidence: implementation `8d8dac9503b193b84974a084f4d62f337995bde3` is remote master. [Actions run 39333206804](https://github.com/0FL01/WarpPocket/actions/runs/39333206804) attempt 1 failed only in `TestDriverSuccessUsesExactPIDAndGUIOnlyProofBeforeClosingJob`: the fake launch finished inside one ~15.6ms Windows monotonic-clock step, so `StartToReadyMS` was recorded as 0. The fake launch now spans one clock step while the strict positive-measurement assertion is kept; attempt 2 completed successfully with Windows 2022, Ubuntu 24.04, native Windows package/smoke and rolling publication all green. The package smoke reported `ok: true`, `cleanup.ok: true` and `executable_bytes: 18644480`, equal to the published `WarpPocket.exe` asset (SHA-256 `28a5fbb87962e552671e72aad1d6c5b8543eb4641d7c6a21d8f0acdf44fe46ba`, target `8d8dac9`).

### Constraints

- Preserve profile/account bytes, keepalive values, strict import validation, Reserved processing, handshake junk, primary/probe ownership, ordered five-stage DNS, health and recovery contracts.
- Preserve dependency versions/hashes, the single shipped EXE, and the ignored `build/deps` generation model; preparation must fail before publication on any gate failure.
- Do not modify the untracked `WarpPocket-Crayon-Design/`, completed historical goal documents, or remote services. Do not expose secrets or raw engine output.

### Non-goals

- System-wide VPN/TUN routing, UDP/QUIC proxying, new settings or PAC files, DNS server changes, dependency upgrades, WARP transport changes, account registration.

## Change Envelope

- Target: pinned-source preparation (`tools/internal/prepare`), affected payloads/tests, `internal/smoke`, `internal/acceptance`, `internal/ui`, `vendor/wireproxy-build.json`, `README.md` and this contract.
- Allowed artifacts: source/tests/docs and ignored build/test outputs. No new dependencies.
- Documented exception: `tools/internal/smoke/smoke_test.go` only makes the fake launch span one Windows clock step; no smoke assertion, report field or production behavior is weakened.

## Current Checkpoint

- Closed: R1-R4 with local gates, the opt-in network gate, the full native Windows/Ubuntu workflow and rolling publication verified. The closure commit changes only this evidence document and the documented tools-test harness exception; its delivery workflow is also followed before the final user report.

## Current State

- Baseline: `a9113ae`; only pre-existing untracked design directory.
- Evidence: tools tests/race, source preparation with all three native gates, application tests/vet/race, explicit network gate, Windows package smoke and the published release are all green.
- Blocker: none.
