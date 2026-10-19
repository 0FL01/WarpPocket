# Goal: Ship WARP-compatible handshake junk and recovery diagnostics

Status: active
Source: user-approved RECON plan and instruction to implement, commit, push and verify GitHub Actions
Last updated: 2026-10-20

## Objective

Deliver the fixed four-datagram handshake preamble and bounded recovery diagnostics in the existing Windows EXE, preserving WireGuard/WARP and application contracts, then verify the pushed revision's complete delivery workflow.

## Execution Directive

Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied.

## Frozen Contract

### Required Outcomes

- R1: Every actual outbound initiation gets four separate random UDP datagrams of 64 <= size < 128 bytes on its existing bind/endpoint; other WireGuard packets remain unchanged except established Reserved processing.
  - Source: approved plan, Changes 2.
  - Acceptance: common bind wrapper covers initial/repeated initiations, standard and Windows default binds, batching, errors and concurrent shutdown without new timers/processes/sockets.
  - Primary evidence: native `TestWarpPocketJunk` gate, Linux race run and Windows Actions gate.
  - Status: in_progress
  - Evidence: Linux preparation/native gate and explicit junk race gate passed, including IPv4/IPv6 same-source-port/Reserved loopback and the real upstream retry timer. Windows cross-build passed; native WinRingBind evidence awaits Actions.
- R2: Bounded private diagnostics distinguish periodic health failures, process exit, recovery start reason and verified recovery, without arbitrary error text or cancellation failures.
  - Source: approved plan, Changes 1.
  - Acceptance: existing logger and controller callback record only allowlisted events outside the controller mutex, with recovery behavior unchanged.
  - Primary evidence: controller/diagnostics unit tests and race tests.
  - Status: verified
  - Evidence: controller/diagnostics focused tests, 20 repeated race runs, full application tests and race suite passed. Tests assert exact event order, cancellation/stale suppression, unlocked callbacks, allowlist, private bounded rotation and concurrent writes.
- R3: Preparation installs the wrapper reproducibly and rejects failed native junk gates before publication; README describes behavior, limitations, comparison and rollback.
  - Source: approved plan, Changes 3-4.
  - Acceptance: exact-anchor/payload/gate tests pass, dependency pins and preserved policy payloads are unchanged, root application regression gates pass.
  - Primary evidence: tools tests, source preparation, application tests/vet and existing smoke.
  - Status: in_progress
  - Evidence: tools tests and race suite, exact-anchor/payload/failure-before-publication checks, all three native preparation gates, application tests/vet/race and Windows cross-build passed. README updated; native packaged smoke awaits Actions.
- R4: Commit and push only this work and follow the exact pushed revision through successful Linux/Windows verification, Windows packaging/smoke and rolling publication.
  - Source: latest user instruction.
  - Acceptance: remote master contains the implementation and its Actions run concludes successfully, including all delivery jobs.
  - Primary evidence: Git revision/remote comparison and GitHub Actions run/jobs.
  - Status: in_progress
  - Evidence: remote master matched baseline before implementation; delivery pending after successful local gates.

### Constraints

- Preserve profile/account bytes, keepalive values, strict import validation, Reserved, primary/probe ownership, DNS-only-through-WARP and fixed split routing; no new registration or DIRECT fallback.
- Preserve dependency versions/hash, existing policy payload digests and the single shipped EXE. Generated `build/deps` is changed only by preparation.
- Do not modify the unrelated untracked `WarpPocket-Crayon-Design/`, operations repository or remote services. Do not expose secrets or raw engine output.

### Non-goals

- Full AmneziaWG framing/header protection, timing changes, new transport/settings/UI or recovery redesign.
- Claiming DPI causation or that synthetic/CI success proves the reported 5-10 minute symptom fixed.

## Change Envelope

- Target: existing controller/logger and pinned-source preparation, embedded junk implementation/tests, README and this contract.
- Expected paths: `internal/controller/recovery.go`, controller tests, `internal/diagnostics/`, `tools/internal/prepare/`, `vendor/wireproxy-build.json`, `README.md`.
- Allowed artifacts: source/tests/docs and ignored build/test outputs. No new dependencies, public profile fields, services, identities or retained traffic logs.
- Delivery: commit and push `master`; inspect complete existing Actions workflow. No force push.

## Current Checkpoint

- Closes: R1, R3, R4.
- Smallest next action: commit/push the verified implementation and inspect its exact Actions revision through Windows tests/package/smoke and rolling publication.
- Expected evidence: complete successful Linux/Windows workflow, including actual WinRingBind loopback.
- Stop or replan if: a job fails; inspect its logs and correct the concrete in-scope cause before delivery is considered verified.

## Current State

- Baseline: `6d7de04`; only pre-existing untracked design directory.
- Resolved: implementation and all local gates. Only the existing native CI/delivery gates remain.
- Blocker: no known implementation/delivery blocker. The affected Windows machine/network is not exposed by available tools; its 60-minute baseline/junk acceptance cannot be substituted by Server 2022 CI.
- Next: push and follow Actions. Local instrumented comparison EXEs are retained under ignored `build/handshake-junk-comparison/`; neither is a natively smoke-tested release artifact.
- Baseline EXE SHA256: `4a56cccf14841aad7a9fd8a80417ffe15a5578323543641ab1c43e9fa511b301` (diagnostics added, old prepared engine, no junk).
- Junk EXE SHA256: `48dec45c7fb6061b245e7279afbce7605721503c920c253c703da69dc0d3d2ad` (same diagnostic sources, new prepared engine).

## Material Decisions

- 2026-10-20: Use the existing bind seam, fixed four-packet policy, current Reserved rewrite (including junk's three reserved bytes), synchronous serialized sends and native preparation gates. Actual affected-network efficacy remains a separate explicitly unverified acceptance, not a claim of this delivery.

## Checkpoint History

- 2026-10-20: Contract frozen from the approved plan and latest delivery instruction; no tracked source changes at baseline.
- 2026-10-20: First preparation correctly stopped before publication when the new test incorrectly required privileged Linux `SetMark(0)` success. Replaced that assertion with exact argument/error delegation on a test bind, preserving unprivileged operation. Actual loopback IPv4/IPv6 and worker retry then passed; no production bypass added.
- 2026-10-20: Local gates green: `go -C tools test -mod=readonly -count=1 ./...`; preparation; `go test -mod=readonly -count=1 ./...`; `go vet -mod=readonly ./...`; full root/tools `-race -count=1`; explicit prepared wireproxy `-race . -run '^TestWarpPocketJunk' -count=1 -v`; Windows CGO=0 x64 cross-build. Existing policy payloads, dependency pins, profiles and unrelated design directory are untouched. Native graphical/Windows smoke remains with existing CI.

## Completion

- Resolved outcomes: pending.
- Commands and artifacts: pending.
- Constraint and diff-scope check: pending.
- Final status: active.
