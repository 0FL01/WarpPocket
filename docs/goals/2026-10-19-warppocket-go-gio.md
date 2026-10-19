# Goal: Go-only WarpPocket with the Crayon Gio interface

Status: active
Source: approved Go/Gio migration plan; user «Делай копию плана в цель, выкидываем полность Python из бекенда/гуя, оставляем python только для тестов, но основнйо стек будет на Golang; breaking changes approved».
Last updated: 2026-10-19

## Objective
Replace the Python/Tk application and Python build/publication tools with Go, shipping one native Windows WarpPocket.exe with a Gio interface matching WarpPocket-Crayon-Design. Retain verified WARP SOCKS, split routing, ordered DNS, persistent identities and safe operation/process ownership. Python is allowed only for tests, not the backend, GUI, build or release path.

## Execution Directive
Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied. Stop substantive work at a proven external blocker and record the exact evidence and smallest unlock.

## Frozen Contract

### Required Outcomes
- R1: Native Go executable and embedded self-worker engine; Go source preparation and builds.
  - Source: approved migration plan stages 1–2; one shipped binary/no Python runtime.
  - Acceptance: WarpPocket.exe starts Gio or its own `--engine` mode; no embedded/extracted wireproxy.exe, wgcf.exe, Python, Tk, PyInstaller or WebView. Pinned, hash-verified isolated source preparation applies the existing reserved/DNS/routing/sandbox patches and executes native policy gates before builds. Root replacements include both patched modules.
  - Primary evidence: native Windows Gio frame gate early, Go preparation/native policy tests, same-EXE worker smoke and build/resource inspection.
  - Status: in_progress
  - Evidence: isolated Go preparation/native DNS/routing/sandbox/worker gates pass; real same-EXE Linux smoke passes, Windows CGO-disabled build succeeds. Early real Windows Gio frame gate 39274301008 passed. Full native Windows engine/GUI integration gate remains.
- R2: Go data/profile/API implementation without silent legacy-data loss.
  - Source: approved migration plan stages 3–4 and existing privacy/registration contract.
  - Acceptance: existing data directories, schema-1 cache, account.toml/profile.conf, import validation and instance locks remain usable. Atomic private files/DACLs, read-only unknown cache versions, distinct clamped identities and partial-registration safety retained. Native context-bound TLS-verified WARP API replaces wgcf CLI and preserves required Android/uTLS behavior. Saved profile+Reserved requires no registration/API call.
  - Primary evidence: Go fixture/HTTP/TLS/storage tests and opt-in reuse of existing private identities without registration or rewriting them.
  - Status: in_progress
  - Evidence: Go storage/profile/API race and TLS-wire tests pass. Real saved primary/probe files reused byte-for-byte with a denying API implementation: zero API calls, no registration or profile rewrite. Native Windows DACL/lock execution remains in the full gate.
- R3: Go lifecycle/controller/health/search behavioral parity.
  - Source: approved migration plan stages 2 and 5; existing verified network/process contract.
  - Acceptance: loopback-only 127.0.0.1:25344; at most two same-EXE workers, sequential probe on separate identity, owner-crash cleanup and atomic-at-create Windows jobs, cancellation/late-result safety, no identity overlap on reconnect. Verified HTTPS via remote SOCKS DNS without direct/env fallback, bounded bodies, 30 s health, 30 candidates/180 s search, persistence only for current successful operations, per-instance monitor. DIRECT/DNS policies unchanged.
  - Primary evidence: native process/controller/network tests, races where supported, actual HTTPS and primary continuity during probe, graceful/crash smoke before emergency cleanup.
  - Status: in_progress
  - Evidence: Go process/controller/finder/health race tests and real Linux Go controller gate pass: 58 verified HTTPS requests, zero failures, one continuous primary stream throughout a 15.329 s probe, saved result, same primary, max two workers, unchanged profiles and cleanup. DIRECT hostname sockets and IP-only WARP behavior proven against the real worker. Windows atomic jobs/owner-crash tests remain in the full gate.
- R4: Real Gio Crayon GUI, not a demo or browser UI.
  - Source: design replacement request and approved migration plan stage 6.
  - Acceptance: light one-window vertical Crayon layout, actual OS titlebar, status/help, read-only SOCKS address/copy feedback, two large action buttons, truthful progress, endpoint/notices/footer and Settings menu. Checkbox-gated consent, native import, diagnostics/terms/licenses, keyboard and DPI handling. Real controller snapshots, no simulated endpoints/timers/auto-connect search. Workers never mutate widget state; picker does not deadlock shutdown.
  - Primary evidence: UI/input/layout tests, Cyrillic and 100/125/150% layouts, actual Windows Gio frame/clipboard/dialog lifecycle checks and packaged smoke.
  - Status: in_progress
  - Evidence: real Crayon Gio window, native input/clipboard-command/consent/progress tests and 21 rendered state/DPI frames pass locally; early Windows frames verified. Full smoke includes real Windows clipboard roundtrip, selection/import of an owned Unicode-name profile, then a second picker and deferred main-window close/cancellation. Those native Windows integration checks still await a passing run. Local same-EXE smoke passes under X11; an isolated minimal Gio window reproduced this host's Wayland EGL hang, so no application/ownership guard was weakened to bypass it.
- R5: Go-only delivery, tested EXE-only rolling release and measured footprint.
  - Source: approved migration plan stages 7–8; user requires Go stack, one lighter binary and existing automatic releases.
  - Acceptance: no runtime Python or Python build/release invocation; Linux/Windows Go CI, native policy and packaged same-EXE smoke pass. Master-only success-gated serialized rolling publication preserves stale-build/draft safeguards and attaches only matching WarpPocket.exe. Record actual EXE size/startup/all-process working-set comparison with the prior 29,484,399-byte build; do not invent a size or GPU compatibility claim. README describes new Go commands/limits.
  - Primary evidence: workflow and tool tests; downloaded release compared with the same-run tested artifact; measured baseline/new footprint; source/dependency inspection.
  - Status: in_progress
  - Evidence: independent Go preparation/smoke/publisher tools and local policy/race tests pass. Final Windows CGO-disabled cross-build is 18,221,568 bytes vs 29,484,399-byte baseline; startup/all-process working set remain unmeasured until native CI. Superseded Python runtime/build/publication and tests have been ported/removed on the isolated migration branch; canonical CI and release are Go-only, but master/rolling are deliberately unchanged until native parity. First full native run 39282304288 passed Linux but exposed non-canonical paths in portable smoke fixtures on Windows; reproduced using a local output-path alias and fixed in fixtures without relaxing containment checks. Native retry is required.

### Constraints
- Breaking changes to implementation/public internal APIs are approved. Do not silently destroy or migrate private user identities; preserve profiles/accounts/import safety and cache compatibility described below.
- One binary is not one process: GUI/controller owns up to two self-worker processes from os.Executable. Secrets go only into private normalized runtime files, never argv/env/logs/artifacts. Engine mode precedes GUI and instance-lock startup and does not open another GUI.
- Windows Job Objects assigned at process creation, KILL_ON_JOB_CLOSE, restricted inherited NUL handles, no unmanaged fallback. POSIX process groups and worker sandbox isolation remain; do not apply worker Landlock/pledge to the GUI.
- DNS stays inside WARP for both routes: 83.220.169.155 -> 212.109.195.93 -> 194.87.196.13 -> 45.151.102.219 -> 9.9.9.9; 1 s/server, 5 s/lookup, lookup-wide A/AAAA stages. Addresses/terminal negatives stop failover. TCP CONNECT to approved RU/RF/SU/VK hostname roots uses checked public numeric host TCP; all other names/IP literals use WARP. No route fallback/system DNS/proxy/routes/firewall changes.
- Health requires warp=on/plus and independent verified HTTPS, remote SOCKS hostname resolution, embedded CA roots, no TLS bypass, no environment proxy, bounded 16 KiB response/30 s total/7 s establishment/5 s read budgets.
- Existing primary/probe identities already exist. No new real WARP registration for development/acceptance. Registration implementation is exercised with mocked services and requires separate explicit consent per role.
- Only WarpPocket.exe is published as a release asset. Safe JSON smoke reports are internal CI artifacts only. No private files, helper binaries, dependencies/build outputs or design reference directory added accidentally to Git.
- Historical completed DNS/split-routing goals and the unrelated Windows 10 MVP blocker are not reopened. Do not claim Windows Server 2022 proves clean Windows 10 acceptance.

### Non-goals
- New transport/MASQUE, system VPN, WebView, PAC, GeoIP/SNI/reverse-DNS inference, updater/tray/installer/signing, downloadable rules/settings UI, WARP+ license UI, broad dependency refactoring or unrelated projects.
- Removing the user's .venv, private data, design reference or historical documentation. Python test files may remain when they test the Go deliverable; obsolete Python runtime tests must not masquerade as Go coverage.

## Change Envelope
- Root go.mod/go.sum and a narrow .gitattributes LF rule for digest-pinned embedded payloads; cmd/warppocket; internal model/storage/profile/process/backend/health/finder/controller/ui/smoke/resources; independent tools module with prepare/smoke/release commands and tests; moved embedded Go patch/test payloads; vendor metadata/licenses; Go/Python tests; workflow; README and this goal.
- Remove superseded Python runtime, non-test Python build/publication scripts, PyInstaller spec/runtime requirements/pyproject after local Go parity is verified on the isolated migration branch; require full native parity before master delivery. The design reference is read-only input, not a new embedded browser stack.
- Go 1.26.9; Gio and Gio extensions v0.10.3; existing pinned wireproxy/WireGuard sources and hash verification. Native source copies under ignored build/deps, never patched global Go module cache. Only narrow TOML/uTLS/native API dependencies justified by the approved port.

## Copied Implementation Plan
1. **Bootstrap before mass port.** Create root and independent tools modules. Port pinned source download/extraction/exact-anchor patches and native tests to tools/cmd/prepare. Move conflicting source payloads into embedded data files ignored by Go package discovery. Root replaces both github.com/windtf/wireproxy and golang.zx2c4.com/wireguard. Convert copied upstream command into importable worker.Run while retaining its sandbox. Run an actual native Windows Gio frame gate early, not merely a cross-compile. Use a migration branch for intermediate commits so incomplete binaries never replace the master rolling release.
2. **Same-EXE worker and ownership.** Dispatch fixed `--engine` before Gio/normal instance lock; accept only the private config/role arguments, not arbitrary upstream CLI modes. Launch os.Executable, keep helper fatal exits contained to workers, preserve atomic Windows Job Object assignment and Linux groups. Test port conflicts, cancellation, late start, shutdown/crash and handle/config cleanup.
3. **Model, private storage and legacy profiles.** Keep LOCALAPPDATA/WarpPocket or XDG/warppocket, settings.json version 1 and its last_good/preferred/fallbacks (max three); validate finite latency, zoned timestamps, role and endpoint fields. Unknown cache version remains read-only. Protected current-user Windows DACL / Unix 0700+0600, atomic writes; byte-0 length-1 Windows instance lock or flock Unix, never delete the lock file. Strict <=64 KiB single-peer WireGuard import, no interpolation/hooks/listeners/unknown fields/scoped IPs; validate 32-byte keys, addresses/DNS/full routes/MTU/keepalive/PSK/Reserved. Identity clamps private-key bytes. Runtime-only DNS override; import invalidates the affected cache/account just as before.
4. **Native WARP service.** Parse the four legacy TOML account fields with a small pinned parser. Narrow per-account context-bound HTTP client; preserve wgcf 2.3.1 v0a5641 Android headers and TLS 1.2/uTLS ClientHello rather than importing its CLI/Cobra/Viper. Verified TLS/no redirects/no envproxy, response/time limits. Save account before generation; ambiguous/partial registration never automatically repeats POST. Existing profiles and Reserved bypass API. Mock registration; live tests reuse existing identities.
5. **Health, finder and controller.** Port typed snapshots/events and four states; searching/busy remain orthogonal. Remote SOCKS DNS, embedded CA roots, trace plus independent HTTPS, existing budgets and candidate order/dedup/seeds. Separate primary/probe, current-operation commits, late success cleanup, cleanup before reconnect, monitor bound to its instance, cache-write warning without disconnect or false Saved, successful connection detached from trial deadline. UI invalidation is concurrent-safe, widgets remain UI-owned.
6. **Crayon Gio UI.** HANDOFF + actual CSS + PNG are authoritative over stale dark DESIGN.md. Light ~442 dp vertical window, native titlebar, vector crayon drawing/status dot; bundled Regular/Bold/Mono Cyrillic faces only. Real state labels/actions, one-line routing hint, truthful completed/total/found progress (trying means checked-1; preserve found when omitted), indeterminate connect, copy feedback separate from persistent notices. Settings and checkbox consent overlay; one native explorer picker worker with all window events forwarded. Abort close while picker is active, cancel network immediately, finish close once picker returns; never wait for an uncancellable picker inside DestroyEvent. Keyboard, wrapping and 100/125/150% layouts tested.
7. **Go smoke, CI and publication.** Go preparation/build/test pipeline; Linux EGL/Xvfb render, native Windows GUI/frame/clipboard/import, Unicode/spaces path. Smoke uses synthetic loopback profile and reports actual Gio frame, same-EXE engine/SOCKS and graceful cleanup. Crash driver kills retained GUI PID only, verifies engine/port death before emergency cleanup; no PyInstaller launcher assumptions. Port publisher guards and tests: master push only, all gates successful, serialized publication, stale-SHA guard, resumable first draft, raw EXE only, token-safe. Build Windows CGO_ENABLED=0 with -trimpath and -ldflags="-s -w -H windowsgui"; retain default Gio renderer fallbacks.
8. **Remove old runtime and close.** Delete Python backend/GUI/build/release path and PyInstaller packaging only after required Go behavior passes. Keep Python only for useful tests, not source compatibility theatre. Update README, measure old/new footprint without claiming unmeasured improvement, run native/live/packaged gates, commit/push and compare the published EXE with its tested artifact. Stop after closure.

## Current Checkpoint
- Closes: native Windows parity portions of R1–R4 and measured R5 footprint.
- Smallest next action: confirm the corrected detached native launch on the migration branch, then inspect Windows storage/process tests, real clipboard/profile import/picker/same-EXE crash smoke and all-process measurements against the pinned old EXE.
- Expected evidence: successful Linux/Windows Go tests and native packaged smoke plus safe footprint comparison. Only then deliver master and compare its sole rolling EXE asset with the tested artifact.
- Replan if: an observed native failure exposes a concrete ABI, graphics or ownership cause; diagnose it rather than weakening a gate or publishing the bootstrap demo.

## Current State
- Baseline: b3239e85e8ffcc2ce1d4f9d3286922f6d1ac31ea; old Windows EXE 29,484,399 bytes. Existing primary/probe private identities and verified split-routing/DNS behavior are available for reuse.
- Last evidence: all root/tool race tests and vet pass; freshly prepared DNS/routing/sandbox/worker gates pass after old source-payload removal; 21 native rendered state/DPI frames and real X11 same-EXE smoke pass. Real saved-profile network gate remains 58 requests/zero errors with no API/registration. Full Windows cross-build succeeds. Go-only retirement is pushed as de4b409; LF checkout attributes fixed native payload digests. Native diagnostics from run 39288154565 identified the remaining working-set mismatch exactly: CREATE_NO_WINDOW allocated a conhost.exe for each console-subsystem test helper, giving four owned processes rather than two. Use DETACHED_PROCESS with the same explicit NUL handles/suspended job assignment to avoid allocating consoles; retain the exact two-process working-set/owner-crash assertion. Native retry still required. Owned temporary diagnostics/failed synthetic smoke workspaces removed; user data/design/.venv untouched.
- Blocker: no established local blocker. GitHub reports critical Actions/Pages/Webhooks degradation (incident 8tzbpcnl75jp, 2026-10-19 15:49 UTC), delaying queue/result updates; the observed Windows test failure remains actionable and a corrected native retry is required.
- Next: corrected canonical Go-only CI on migration branch; native smoke/footprint, then master/rolling delivery if all gates pass.

## Material Decisions
- 2026-10-19: latest user permits breaking changes and Python tests only; runtime/build/publication move to Go. Self-worker architecture preserves isolation without shipping helper executables. Smaller/lighter is measured, not assumed from language alone.
- 2026-10-19: Crayon light HANDOFF/CSS/mockups take precedence over stale dark design-system text. No preview demo behavior is part of the product.
- 2026-10-19: retire the old runtime only on the isolated migration branch after local Go parity; do not merge or replace the verified rolling EXE until the native Windows/core/GUI/lifecycle and footprint gates pass.
- 2026-10-19: Windows checkout must preserve exact LF bytes of embedded, digest-pinned Go payloads; enforce this in .gitattributes, never by accepting a changed source hash. Native memory fixtures must acknowledge execution rather than equating ResumeThread with application readiness.
- 2026-10-19: the smoke launcher detaches from consoles rather than hiding newly allocated consoles. This prevents test-only conhost.exe workers from contaminating exact owned-process/footprint proof; explicit NUL-only handles, suspended safety-job assignment and GUI-only termination remain unchanged.

## Checkpoint History
- 2026-10-19: approved plan copied here with the latest Python-tests-only amendment; implementation begins.
- 2026-10-19: shared Go values and initial real Gio layout/frame gate implemented; Linux native frames and Windows pure-Go cross-build pass. Native Windows execution next, before full integration.
- 2026-10-19: early native Windows frames verified (39274301008); core Go storage/API/process/controller/UI and isolated preparation integrated. Real Go network acceptance passed without API/registration, with 58 uninterrupted primary HTTPS requests during probe and transport/cleanup proof. Full Windows native integration and measured comparison are next.
- 2026-10-19: Go-only source/tools/CI retirement and local closure gates pass. Native Windows tool-fixture alias failure reproduced/fixed without changing validation; X11 smoke passes after isolating a compositor-only EGL hang. Corrected native pipeline and measured Windows acceptance remain mandatory before master publication.
- 2026-10-19: de4b409 published the Go-only migration branch; Linux canonical CI passed. Remaining observed native payload-line-ending and synthetic readiness failures addressed without dropping tests or weakening digest/working-set requirements; rerun native CI next.
- 2026-10-19: native structured process identities disproved an engine-readiness explanation for the count mismatch and identified two hidden console hosts. Detached launch added; native owner-crash/count checks are retained for the next run.

## Completion
- Pending required outcomes; no migration completion claim yet.
