# Goal: Ship WARP-compatible handshake junk and recovery diagnostics

Status: complete
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
  - Status: verified
  - Evidence: Linux preparation/native gate and explicit junk race gate passed, including IPv4/IPv6 same-source-port/Reserved loopback and the real upstream retry timer. Windows job [118311524864](https://github.com/0FL01/WarpPocket/actions/runs/39325894637/job/118311524864) passed the native junk gate with actual `*conn.WinRingBind BatchSize=1` and `StdNetBind`, both IPv4/IPv6, plus real worker retry (5.15s).
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
  - Status: verified
  - Evidence: tools tests and race suite, exact-anchor/payload/failure-before-publication checks, all three native preparation gates, application tests/vet/race and Windows cross-build passed. README updated. Native package job [118313315130](https://github.com/0FL01/WarpPocket/actions/runs/39325894637/job/118313315130) passed actual Gio/clipboard/picker/import, same-EXE engine, graceful cleanup and forced-owner-termination cleanup; smoke reported `ok: true` and `cleanup.ok: true`.
- R4: Commit and push only this work and follow the exact pushed revision through successful Linux/Windows verification, Windows packaging/smoke and rolling publication.
  - Source: latest user instruction.
  - Acceptance: remote master contains the implementation and its Actions run concludes successfully, including all delivery jobs.
  - Primary evidence: Git revision/remote comparison and GitHub Actions run/jobs.
  - Status: verified
  - Evidence: pushed implementation `9d6fe47fad65011b7ec14a9d55f653756b9bb4a8` and verified remote master plus rolling tag at that SHA. [Actions run 39325894637](https://github.com/0FL01/WarpPocket/actions/runs/39325894637) completed successfully on attempt 1: Windows tests, Ubuntu tests, native Windows package/smoke and rolling publication all succeeded. The public release contained exactly `WarpPocket.exe` (18,656,256 bytes), matching native smoke's executable size.

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

- Closed: R1-R4, with all local and native implementation delivery evidence successful.
- No substantive work remains. The closure commit changes only this evidence document; its delivery workflow is also followed before the final user report.

## Current State

- Baseline: `6d7de04`; only pre-existing untracked design directory.
- Resolved: implementation, all local gates, native Windows/Ubuntu verification, Windows package/smoke and rolling publication. Implementation run `39325894637` completed successfully.
- Blocker: none for this implementation/delivery. The affected Windows machine/network is not exposed by available tools; its 60-minute baseline/junk efficacy acceptance is explicitly unverified and cannot be substituted by Server 2022 CI.
- Delivered: [tested Windows EXE](https://github.com/0FL01/WarpPocket/releases/download/rolling/WarpPocket.exe). Local instrumented comparison EXEs are retained under ignored `build/handshake-junk-comparison/`; neither is a natively smoke-tested release artifact.
- Baseline EXE SHA256: `4a56cccf14841aad7a9fd8a80417ffe15a5578323543641ab1c43e9fa511b301` (diagnostics added, old prepared engine, no junk).
- Junk EXE SHA256: `48dec45c7fb6061b245e7279afbce7605721503c920c253c703da69dc0d3d2ad` (same diagnostic sources, new prepared engine).

## Material Decisions

- 2026-10-20: Use the existing bind seam, fixed four-packet policy, current Reserved rewrite (including junk's three reserved bytes), synchronous serialized sends and native preparation gates. Actual affected-network efficacy remains a separate explicitly unverified acceptance, not a claim of this delivery.

## Checkpoint History

- 2026-10-20: Contract frozen from the approved plan and latest delivery instruction; no tracked source changes at baseline.
- 2026-10-20: First preparation correctly stopped before publication when the new test incorrectly required privileged Linux `SetMark(0)` success. Replaced that assertion with exact argument/error delegation on a test bind, preserving unprivileged operation. Actual loopback IPv4/IPv6 and worker retry then passed; no production bypass added.
- 2026-10-20: Local gates green: `go -C tools test -mod=readonly -count=1 ./...`; preparation; `go test -mod=readonly -count=1 ./...`; `go vet -mod=readonly ./...`; full root/tools `-race -count=1`; explicit prepared wireproxy `-race . -run '^TestWarpPocketJunk' -count=1 -v`; Windows CGO=0 x64 cross-build. Existing policy payloads, dependency pins, profiles and unrelated design directory are untouched. Native graphical/Windows smoke remains with existing CI.
- 2026-10-20: Pushed implementation `9d6fe47` to master. Windows native junk, application tests and vet passed; loopback logs explicitly prove WinRingBind rather than fallback. Remaining delivery is monitored in run `39325894637`.
- 2026-10-20: Run `39325894637` completed successfully on attempt 1, with all four jobs successful. Native packaged smoke confirmed graceful/forced cleanup, stopped owned engines and closed port. Remote master/rolling matched the implementation revision and the public release exposed the single tested EXE. Closure comparison found only approved source/tests/docs, unchanged dependency pins/policy payloads and the untouched unrelated design directory.

## Completion

- Resolved outcomes: R1-R4 verified.
- Commands and artifacts: all local checks listed above; successful native [implementation run](https://github.com/0FL01/WarpPocket/actions/runs/39325894637), Windows [smoke artifact](https://github.com/0FL01/WarpPocket/actions/runs/39325894637/artifacts/12222158619) and [EXE artifact](https://github.com/0FL01/WarpPocket/actions/runs/39325894637/artifacts/12222377426); published rolling EXE.
- Constraint and diff-scope check: only the approved 13 source/test/doc files; no new dependency, profile format, identity, timer, process, socket or fallback. Existing DNS/routing/ownership/private-storage gates pass. `git diff --check` and staged added-line secret-pattern checks passed. Untracked design work is retained.
- Final status: complete for implementation and verified delivery, not a claim of affected-network DPI resilience.
