# Goal: automatic recovery of an established WARP session

Status: active
Source: user «делай копию плана в цель и Реализовать и коммит пуш»; the corrected six-part autoreconnect/keepalive plan from the preceding audit.
Last updated: 2026-10-19

## Objective
After loss of a previously verified primary connection, recover verified WARP automatically on the same 127.0.0.1:25344 without further user interaction. Reuse the existing primary identity, sequential candidate finder and owned same-EXE engines. Manual Disconnect/Close always cancel the intent. Copy the approved corrected plan here, implement, verify, commit and push.

## Execution Directive
Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied.

## Frozen Contract

### Required Outcomes
- R1: safe cross-layer failure propagation before retries.
  - Source: corrected plan step 1; audit cleanup/cancellation and local-error findings.
  - Acceptance: process.ErrStop remains proxy_cleanup_failed; cleanup errors outrank cancellation/deadlines in Backend/Finder/Controller and latch an application-wide launch block, including cancelled searches. Known local launch/config/ownership/health-setup errors and occupied ports are terminal, not network exhaustion. A closed done channel or Alive=false never substitutes for checked Stop.
  - Primary evidence: backend/finder/controller injected cleanup/local-error tests, including simultaneous cancellation/budget expiry.
  - Status: verified
  - Evidence: backend/finder/controller injected regressions pass with race detection: retained nil-result ErrStop, simultaneous cancellation/deadline and cleanup failure, checked Stop after dead-process observation, and terminal local/unknown errors. Finder failed progress is synchronous only after checked cleanup and before the actual budget deadline. Controller latches cleanup failure even for obsolete/cancelled Connect/Search and rejects further launches.
- R2: one cancellable post-verification monitor/recovery owner.
  - Source: corrected plan step 3.
  - Acceptance: initial Connect stays one-shot; verified handoff supplies a profile clone and one session token to the existing monitor. Loss cancels/settles probe and stops old primary before replacement. Disconnect cancels before cleanup-related early returns; Close cancels and waits outside the controller mutex. Late results cannot activate, write cache or overlap identities. Healthy connected probe search remains available. No repeated profile/API/consent calls during recovery.
  - Primary evidence: deterministic controller lifecycle, cleanup, cancellation, cache and probe regressions; offline native-process recovery.
  - Status: verified
  - Evidence: controller lifecycle/virtual-time regressions pass for initial one-shot failure, normal connected probe, loss/replacement, cancel during old Stop/probe settlement/backoff/late success, cache guards and concurrent Close. The ordinary offline native-process integration passes on Linux and Windows in run 39309173932 with actual Controller/Manager/Backend and a synthetic SOCKS child; real saved-profile acceptance also automatically replaces its stopped primary without repeated profile/API calls.
- R3: progress to another existing WARP endpoint, without hot retry or flapping reset.
  - Source: corrected plan step 4 and user request to find another path if the current one is dead.
  - Acceptance: reuse Finder.Connect and Candidates; one canonical queue of at most 30 including old active, 180-second bounded cycles, preserved cursor and retry of deadline-partial last candidate. Health loss demotes old active; process exit allows it once first per new episode. First cycle immediate; subsequent cancellable pauses 2/5/10/20/30 seconds capped at 30, retained across unstable reconnects. Reset queue/backoff only after two consecutive full periodic health successes of the same primary. Successful current verification alone updates connection/cache; failure cycles do not.
  - Primary evidence: virtual-time slow-prefix/partial-deadline/alternate-B/flapping/cancel tests plus existing strict health tests.
  - Status: verified
  - Evidence: deterministic alternate-A/B, canonical total-30 cap, slow-prefix traversal to the 28th candidate over multiple cycles, deadline-partial retry, cumulative progress accounting, capped 2/5/10/20/30-second backoff, flapping and two-periodic-success reset tests pass. Strict health/DNS/TLS tests and real post-recovery full HTTPS verification pass; failed cycles do not write cache.
- R4: conservative keepalive default without rewriting existing profiles.
  - Source: corrected plan step 2.
  - Acceptance: newly generated application profiles use PersistentKeepalive=25; existing/imported values, including disabled zero and nondefault values, remain unchanged. No runtime zero override, parser metadata or migration; reuse built-in WireGuard keepalive support.
  - Primary evidence: profile generation fixtures and existing/imported profile/runtime preservation tests.
  - Status: verified
  - Evidence: native generation fixtures require 25; missing/explicit-zero/nondefault imported and saved profiles retain their values and bytes through load and runtime rendering. No runtime zero override or existing profile rewrite is introduced. Profile/backend race tests pass.
- R5: truthful recovery UI in the existing Crayon window.
  - Source: corrected plan step 5 and audit consent/notice/progress findings.
  - Acceptance: keep four connection states; Recovering implies Connecting, clears obsolete endpoint/latency/error, displays «Восстанавливаем соединение…» and enabled «Отключиться». Search/import are disabled, progress indeterminate even during probe settlement. Recovery events invalidate old probe consent/checkbox/notices/progress; batched events cannot leave stale stopped/cancelled/saved text. Recovery success uses a restored notice; cache warning has priority without disconnect. All recovery presentation resets after success/terminal/disconnect/close/new attempt.
  - Primary evidence: UI event/input/consent tests and rendered Connecting+Recovering at 100/125/150% DPI.
  - Status: verified
  - Evidence: UI event, pointer/keyboard, consent, batching, warning-priority and recovery-exit tests pass with race detection. Actual GPU rendering passes all 24 fixtures including Connecting + Recovering at 100/125/150% DPI. Real Linux Gio/same-EXE graceful smoke and native packaged Windows Gio/clipboard/import/picker/graceful/GUI-only-crash smoke pass in run 39309173932.
- R6: verified and delivered implementation, including real owned-process recovery.
  - Source: corrected plan step 6; user requires implementation, commit and push.
  - Acceptance: normal Linux/Windows tests exercise actual Controller+Manager+Backend with synthetic SOCKS subprocess: owned-primary exit leads to a different live PID, same port, verified Connected, retention beyond old trial deadline and cleanup. Preserve primary/probe continuity and routing assertions in the opt-in Linux real-network gate before killing only its primary; then require new live primary/full fresh health, zero API calls, unchanged identity files and max two engines. Existing root/tools/race/vet/render/native Windows packaged and EXE-only delivery gates pass. Commit/push the verified change and document detection/TCP limits honestly.
  - Primary evidence: targeted and broad Go gates, offline native recovery, opt-in existing-profile network gate, successful native Windows CI and matching tested rolling EXE.
  - Status: in_progress
  - Evidence: root and independent tools tests/race/vet pass; ordinary real-process recovery passes on Linux and Windows, including same fixed port/new live PID and survival beyond its old trial budget. Actual existing-profile network gate passes: 55 requests/zero failures on one continuous primary stream during probe, then owned-primary exit and automatic verified replacement in 14.966 seconds (an observation, not an SLA), max two engines/one of each role, no API/registration, unchanged identity files and cleanup. Feature commit 6755bf23e8df8a391918502854b8613b27af76b1 is pushed; run 39309173932 passes Linux, Windows and the native Windows package (18,273,280-byte EXE, all graceful/GUI-only-crash checks). Publication is correctly skipped on the feature branch. Only master publication and matching tested-EXE verification remain.

### Constraints
- Same local SOCKS 127.0.0.1:25344, existing WARP transport and strict TLS/remote SOCKS DNS/independent-resource health checks. No direct/system-DNS/environment-proxy fallback, new service or weakening of five-stage DNS or RU/VK split routing.
- At most one primary and one distinct probe engine; no same-identity overlap. Checked cleanup precedes replacement. Private files, atomic persistence, Windows atomic Job Objects/restricted handles and Linux process groups remain.
- Recovery uses only the validated in-memory profile clone; no registrations, API calls or profile/account rewrite. Test real networking only on the existing private identities; do not print or commit secrets.
- «Seamless» means without further clicks, not preservation of old TCP streams through engine death. Existing 30-second monitor/two-failure policy remains; long checks can make detection about two minutes. 180 seconds is one candidate-cycle budget, not an end-to-end restoration guarantee.
- One delivered EXE and existing successful-master-only rolling publisher. Preserve user design input, .venv, private data and completed historical goals.

### Non-goals
- MASQUE/new transport, DIRECT failover, another identity/worker, persistent blacklist/scoring/retry history, generic retry framework, new settings/screen/fifth state, new CI/publisher infrastructure or unrelated Windows 10 acceptance.

## Change Envelope
- internal/backend, finder, health and their tests for error semantics and deadline accounting; internal/profile generation/tests for the new-profile default.
- internal/controller and tests for guarded session ownership, recovery queue/cursor/backoff, settlement, cancellation and cache discipline; internal/model/state.go and internal/ui/tests for additive recovery presentation.
- One offline external backend-package integration test reusing its TestMain synthetic engine and sequential fixed-port test binary, so different Go package test binaries do not race for port 25344.
- Existing internal/acceptance/network_test.go opt-in gate, README and this goal. Existing command/process/storage/API interfaces, source pins, dependencies and workflow/publisher remain unless a concrete regression caused by this diff requires a minimal documented correction.
- No generated binaries, runtime state, private keys, test fixtures from real profiles or design directory added to Git. Use a feature branch until local/native gates pass.

## Copied Corrected Implementation Plan
1. **Safety first.** Preserve ErrStop as cleanup failure; classify startup results before cancellation/budget handling. Separate terminal local setup/launch errors from bounded candidate failures and strict remote health failures. Latch cleanup failure from Connect/Search/Stop, including cancelled results, and block every internal/public launch. Do not infer cleanup success from a dead process or done signal.
2. **Keepalive.** Set 25 seconds only in newly generated application profiles. Preserve existing/imported zero and nonzero values and their bytes. Do not add a heartbeat worker, runtime override, migration or WireGuard patch.
3. **One monitor owner.** Keep initial connect preparation one-shot. At verified commit hand prepared profile clone and instance to one post-verification session using the existing health cancellation handle plus session ID/done and per-search done. On loss cancel probe, checked-stop old primary and await search settlement outside the mutex. Recheck session/cancellation/latch before starting. Disconnect cancels first and drains owners; Close cancels, shuts down the manager and joins owners before runtime cleanup. No recursive Connect, duplicate monitor or worker self-wait.
4. **Minimal alternate path.** Use the existing Candidates/Connect, not preliminary Search. Preserve one <=30 queue/cursor across 180-second cycles and partial last trials. Demote old endpoint after health loss; allow one first retry after process death. Keep 2/5/10/20/30-second cancellable backoff through flapping; reset only after two consecutive successful periodic checks, not the Connect verification. Exhausted queues rebuild existing sampling without resetting backoff. Cache only current verified success.
5. **UI.** Add Recovering to snapshots, not a fifth State. Show recovery/disconnect and disable search/import; recovery overrides old probe progress. Recognizable events in the existing model clear obsolete consent/notices and preserve cache-warning priority, including transitions batched between frames.
6. **Evidence and delivery.** Add failure-capable/probe-owning controller fakes and focused virtual-time tests; offline real-process recovery in the normal backend test binary; extend the existing live Linux gate after prior continuity/routing proofs (new live PID barrier, same port, full fresh HTTPS, no API/profile change). Calculate overall test timeout from phase budgets (about eleven minutes), not by shortening production budgets. Run targeted then root/tools/race/vet, recovery render and existing native Windows package gates; update README, commit/push and verify final delivery.

## Current Checkpoint
- Closes: R6 master delivery; implementation and native verification are complete.
- Smallest next action: fast-forward the verified autorecovery branch into master and require the existing successful-master-only publisher.
- Expected evidence: successful master Linux/Windows/package/publication gates; compare the sole rolling EXE with that same run's tested artifact.
- Replan if: a concrete mandatory gate exposes a mismatch; fix the smallest in-scope cause without weakening contracts.

## Current State
- Baseline: 27d44834e2276c125a68c94cda9e0c0369b88f41; verified feature commit 6755bf23e8df8a391918502854b8613b27af76b1 is pushed on autorecovery, ready for master delivery.
- Last evidence: local root/tools tests/race/vet, 24 rendered frames, Linux Gio smoke and real saved-profile recovery all pass. Run 39309173932 also passes native Linux/Windows tests and packaged Windows Gio lifecycle/owner-crash checks. No policy/source pins/dependencies/workflow/publisher or historical goals changed; private profiles/accounts and design input remain untouched.
- Blocker: none.
- Next: verified master/rolling delivery.

## Material Decisions
- 2026-10-19: use the conservative new-profile-only 25-second keepalive default; zero remains a supported explicit disabled value in existing/imported profiles.
- 2026-10-19: reuse the existing monitor and Finder APIs, preserving candidate progress through bounded cycles and unstable success rather than adding a recovery service or ranking database.

## Checkpoint History
- 2026-10-19: corrected audited plan copied here at user request; execution begins on the existing verified Go/Gio baseline.
- 2026-10-19: R1–R5 implemented and locally verified, including failure precedence/latch, single-owner recovery, progressive candidate/backoff behavior, new-profile-only keepalive and truthful UI. R6 local real-process/live-network/render gates pass; native Windows delivery is next. No new registrations or identity-file changes.
- 2026-10-19: feature 6755bf2 is pushed; run 39309173932 passes all required feature-branch jobs, including ordinary native Windows controller recovery and packaged Gio/engine lifecycle. Only master publication and downloaded-EXE comparison remain.

## Completion
- Implementation and local/native verification complete; verified master/rolling delivery remains. No final completion claim yet.
