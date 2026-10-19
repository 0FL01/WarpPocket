# Goal: Hardcoded RU/VK split routing and five-stage DNS

Status: active
Source: approved conversation plans; user «Реализовать и коммит пуш».
Last updated: 2026-10-19

## Objective
Ship the existing Windows EXE with hardcoded TCP SOCKS split routing: RU/RF/SU and the agreed VK roots direct, everything else through WARP, with four primary DNS servers and Quad9 last.

## Execution Directive
Complete the frozen Required Outcomes using the listed Change Envelope and Primary Evidence. Work on the smallest unresolved outcome. Do not add requirements from reviews, tests, tools, speculative risks, or optional source text. Finish when every required outcome is resolved and affected constraints remain satisfied.

## Frozen Contract
### Required Outcomes
- R1: Hardcoded hostname-based routing in the existing SOCKS helper.
  - Source: approved split-routing plan.
  - Acceptance: proper descendants of ru/su/xn--p1ai and exact/subdomains of vk.com, vkontakte.com, vk.cc, vk.link, vk.me, userapi.com, vk-cdn.net, vkuser.net, vkuseraudio.com/net, vkuservideo.com/net and vkuserlive.com/net use the host TCP dialer; other hosts and IP literals use WARP. IDNA/case/root-dot normalization is supported. No cross-route fallback; direct targets must be numeric and reject loopback/private/link-local/non-unicast/CGNAT addresses after unmapping.
  - Primary evidence: native routing tests through the actual SOCKS options and a real existing-profile transport check.
   - Status: verified
   - Evidence: six native routing test groups cover domain/IDNA boundaries, public numeric guards, context/concurrency, no route fallback and actual SOCKS ServeConn; a seventh group verifies the command's sandbox policy. Real existing-profile gate passed on 2026-10-19: ya.ru -> 77.88.44.242 and vk.com -> 87.240.132.78 each created one helper-owned host TCP socket, TLS verified (HTTP 200 and 418 respectively). IP-only requests to those same addresses created no host TCP and stayed on WARP; www.cloudflare.com and final warp=on/independent HTTPS checks remained WARP. This proves transport selection, not exemption from website anti-bot responses.
- R2: Ordered DNS 83.220.169.155 -> 212.109.195.93 -> 194.87.196.13 -> 45.151.102.219 -> 9.9.9.9.
  - Source: latest DNS amendment and approved plan.
  - Acceptance: 1 s per server / 5 s overall; A/AAAA share a stage, Quad9 only after four operational failures, addresses/negative answers stop failover, cancellation prevents later stages. Existing tunneled resolver remains in both routing branches; health timeout becomes (7,5), with existing 30 s health / 180 s finder budgets retained. Runtime profile copies only, no persisted-file migration.
  - Primary evidence: native DNS tests and backend/health tests.
   - Status: verified
   - Evidence: seven native DNS test groups pass with all five stages, partial-family outcomes, negative replies, retries/cancellation and shared UDP/TCP/overall deadlines. Runtime/backend/health tests verify five DNS addresses, (7,5) timeout and unchanged saved/imported profiles for both roles. Real gate used the production helper and existing primary/probe files; no registration, profile/account bytes unchanged, owned helper/config/port cleanup verified.
- R3: Minimal user-facing explanation, verified builds, commit/push and EXE-only rolling publication.
  - Source: approved plan and latest implementation request.
  - Acceptance: one static UI hint plus README; existing tests/native gates/packaged smoke pass on Linux/Windows; origin and rolling tag match the implementation and release contains only matching WarpPocket.exe.
  - Primary evidence: tests, GitHub Actions, git SHAs and downloaded release EXE compared with the tested artifact.
   - Status: in_progress
   - Evidence: static UI hint and README implemented; local full suite 182 tests OK (3 Windows-only skips), both native policy gates and Linux/Windows cross-builds pass. Native CI, commit/push and matching rolling EXE remain to be verified.

### Constraints
- Same 127.0.0.1:25344 ingress, owned helper processes, primary/probe separation and shutdown guarantees; CONNECT only, no new listener/process/system proxy or routing changes.
- DNS remains tunneled for DIRECT and WARP names; no host DNS, TLS interception, IP/ASN classification or automatic route fallback. Host TCP receives only a checked numeric address; 10 s establishment timeout, not connection-lifetime timeout.
- Pinned source versions/digests unchanged; exact build anchors, isolated source copies, no global Go cache patching. Both DNS and routing native gates run before cross-build.
- No new WARP registrations or private data in Git/logs/artifacts; use existing identities for opt-in network checks.
- New rules take effect at next helper start; no profile/key rewrite or active-tunnel hot replacement.

### Non-goals
- PAC, configuration UI, downloadable rules, GeoIP, reverse DNS, SNI sniffing, UDP/QUIC/WebRTC routing, always-on listener, system DNS changes, unrelated clean Windows 10 acceptance or old completed DNS-goal changes.

## Change Envelope
- scripts/build_wireproxy.py; new scripts/wireproxy_routing.go and tests/wireproxy_routing_test.go; existing DNS payload/tests; vendor recipe identifier; backend/health/UI and affected tests; README and this contract. The isolated upstream command's network sandbox and its native test payload are included only to enable the required DIRECT TCP capability while preserving filesystem and bind restrictions.
- Existing CI/publisher remains unless an observed failure requires the smallest repair. Do not modify docs/origin.md, persisted profiles/accounts or tracked binaries.

## Current Checkpoint
- Closes: R3 native CI and EXE-only rolling publication.
- Smallest next action: commit/push the locally verified implementation, inspect all native test/build/smoke jobs, and compare the published rolling EXE with the same-run tested artifact.
- Expected evidence: successful five-job workflow, origin/rolling SHA match and a release containing only matching WarpPocket.exe.

## Current State
- Baseline: clean 6250baa; approved previous DNS feature complete, rolling EXE already automated.
- Evidence: 182 Python tests pass; native DNS/routing/command-sandbox tests pass before both target builds. Real transport proof passed with production Linux helper SHA256 e34c99d521ef764122e9bd089118b8bcd153c0e1c468d06cb529af5fd9a6a0b5; private split-routing-gate-2026-10-19.json records route/HTTPS/profile-preservation/cleanup checks.
- Blocker: none. The diagnosed upstream Landlock denial is repaired while retaining filesystem and listener restrictions.
- Next: commit/push, native Linux/Windows CI, packaged smoke and EXE-only release verification.

## Material Decisions
- DNS is intentionally still WARP-only for DIRECT names; only the destination TCP transport bypasses WARP. IP-only requests default to WARP. VK allowlist is finite; external third-party dependencies are not broadly bypassed.
- 2026-10-19: R1 live proof exposed upstream Landlock V4 denying all outgoing TCP for SOCKS (numeric public IP resolved correctly; connect returned permission denied). Permit the new DIRECT capability by leaving connect decisions to the checked router only when SOCKS is configured; retain Landlock filesystem isolation and the exact bind allowlist. Non-SOCKS configurations keep the original network restriction. No sandbox is disabled wholesale, and no host DNS or new listener is introduced.

## Completion
- R1 and R2 verified locally; R3 awaits pushed native CI and rolling publication. No final completion claim yet.
