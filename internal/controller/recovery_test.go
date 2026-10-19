package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
)

// Unlike the older progress-only search fake, this finder owns an actual fake
// probe until its callback AND checked Stop finish. Tests can therefore observe
// real role overlap and the cancellation-versus-settlement boundary.
type recoveryFinder struct {
	mu        sync.Mutex
	b         *workers
	endpoints []model.Endpoint
	queues    [][]model.Endpoint
	startedAt []time.Time
	connect   func(context.Context, model.Profile, []model.Endpoint, finder.Progress, int) (*backend.Instance, float64, int, error)
	search    func(context.Context, *backend.Instance) (finder.Outcome, error)
}

func (f *recoveryFinder) Candidates(model.Profile, model.Cache, []model.Endpoint, int) ([]model.Endpoint, error) {
	return append([]model.Endpoint(nil), f.endpoints...), nil
}
func (f *recoveryFinder) Alive(i *backend.Instance) bool { return f.b.alive(i) }
func (f *recoveryFinder) Connect(ctx context.Context, p model.Profile, candidates []model.Endpoint, progress finder.Progress) (*backend.Instance, float64, int, error) {
	f.mu.Lock()
	f.queues = append(f.queues, append([]model.Endpoint(nil), candidates...))
	f.startedAt = append(f.startedAt, time.Now())
	n := len(f.queues)
	f.mu.Unlock()
	if f.connect != nil {
		return f.connect(ctx, p, candidates, progress, n)
	}
	return f.success(ctx, p, candidates[0], 1)
}
func (f *recoveryFinder) success(ctx context.Context, p model.Profile, endpoint model.Endpoint, checked int) (*backend.Instance, float64, int, error) {
	i, err := f.b.Start(ctx, p, endpoint, model.Primary, backend.SOCKSPort)
	return i, 12, checked, err
}
func (f *recoveryFinder) Search(ctx context.Context, p model.Profile, role string, _ model.Cache, _ []model.Endpoint, _ finder.Progress) (finder.Outcome, error) {
	i, err := f.b.Start(ctx, p, f.endpoints[0], role, 0)
	if err != nil {
		return finder.Outcome{}, err
	}
	var outcome finder.Outcome
	if f.search != nil {
		outcome, err = f.search(ctx, i)
	} else {
		outcome = finder.Outcome{Results: []model.CheckResult{model.NewResult(i.Endpoint, 1, role)}, Checked: 1}
	}
	if cleanup := f.b.Stop(i); cleanup != nil {
		return finder.Outcome{}, cleanup
	}
	return outcome, err
}
func (f *recoveryFinder) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.queues) }
func (f *recoveryFinder) queue(n int) []model.Endpoint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.Endpoint(nil), f.queues[n]...)
}
func (f *recoveryFinder) times() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.startedAt...)
}

func recoveryFixture(t *testing.T, health finder.Check) (*Controller, *memoryStore, *fakeProfiles, *workers, *recoveryFinder) {
	t.Helper()
	s, p, b := &memoryStore{}, &fakeProfiles{}, &workers{}
	f := &recoveryFinder{b: b, endpoints: []model.Endpoint{
		{Host: "188.114.96.1", Port: 4500}, {Host: "188.114.97.1", Port: 4500}, {Host: "188.114.98.1", Port: 4500},
	}}
	if health == nil {
		health = func(context.Context, int) (float64, error) { return 1, nil }
	}
	c := New(s, p, b, f, b, health, Options{HealthInterval: time.Second})
	t.Cleanup(c.Close)
	return c, s, p, b, f
}
func active(c *Controller) *backend.Instance   { c.mu.Lock(); defer c.mu.Unlock(); return c.active }
func killFake(b *workers, i *backend.Instance) { b.mu.Lock(); b.live[i] = false; b.mu.Unlock() }
func cacheWrites(s *memoryStore) int           { s.mu.Lock(); defer s.mu.Unlock(); return s.writes }
func exhausted() error                         { return model.E("no_working_endpoint", "No verified endpoint.") }
func unhealthy() error                         { return model.E("health_timeout", "HTTPS timeout.") }
func unsafeCleanup() error                     { return model.E("proxy_cleanup_failed", "Cleanup could not be confirmed.") }

func TestInitialFailureNeverStartsAutomaticRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, _, f := recoveryFixture(t, nil)
		f.connect = func(context.Context, model.Profile, []model.Endpoint, finder.Progress, int) (*backend.Instance, float64, int, error) {
			return nil, 0, 0, exhausted()
		}
		c.Connect(false)
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if f.count() != 1 || c.Status().State != model.Failed || c.Status().Recovering || c.Status().Busy || cacheWrites(s) != 0 {
			t.Fatal("an initial failure became a persistent recovery session")
		}
	})
}

func TestConsecutiveHealthFailureCounterResets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		c, _, _, b, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
			checks++
			if checks%2 != 0 {
				return 0, unhealthy()
			}
			return 1, nil
		})
		c.Connect(false)
		synctest.Wait()
		initial := active(c)
		for range 8 {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		if f.count() != 1 || active(c) != initial || !b.alive(initial) || c.Status().Recovering {
			t.Fatal("non-consecutive failures triggered recovery")
		}
	})
}

func TestHealthLossUsesAlternativeWithoutRepeatingProfilePreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		c, s, p, b, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
			checks++
			if checks <= 2 {
				return 0, unhealthy()
			}
			return 1, nil
		})
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		c.PollEvents()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		current := active(c)
		if current == nil || current == old || current.Endpoint != f.endpoints[1] || b.alive(old) || f.queue(1)[len(f.queue(1))-1] != old.Endpoint {
			t.Fatal("health loss did not prioritize another endpoint after checked cleanup")
		}
		if c.Status().State != model.Connected || c.Status().Recovering || cacheWrites(s) != 2 {
			t.Fatal("verified recovery was not committed")
		}
		events := c.PollEvents()
		if !eventWith(events, "state", "recovery_started") || !eventWith(events, "state", "recovered") || eventWith(events, "saved", "") {
			t.Fatal("recovery event contract is not distinct from initial saved")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.calls) != 1 || p.reservedCalls != 1 || b.maximumPrimary != 1 {
			t.Fatal("recovery re-prepared the identity or overlapped primary")
		}
	})
}

func TestRecoveryCarriesCompletedCursorAndRepeatsDeadlinePartial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		f.connect = func(ctx context.Context, p model.Profile, endpoints []model.Endpoint, progress finder.Progress, n int) (*backend.Instance, float64, int, error) {
			if n == 1 {
				return f.success(ctx, p, endpoints[0], 1)
			}
			if n == 2 {
				// Failed is cumulative, while trying includes a deadline-partial
				// candidate. Only the completed first entry can be consumed.
				progress(model.Event{Stage: "failed", Checked: 1})
				progress(model.Event{Stage: "trying", Checked: 2})
				return nil, 0, 2, exhausted()
			}
			return f.success(ctx, p, endpoints[0], 1)
		}
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		killFake(b, old)
		time.Sleep(time.Second)
		synctest.Wait()
		if !c.Status().Recovering || f.count() != 2 || cacheWrites(s) != 1 {
			t.Fatal("failed recovery cycle wrote cache or did not wait")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if f.queue(1)[0] != old.Endpoint || f.queue(2)[0] != f.endpoints[1] || active(c).Endpoint != f.endpoints[1] {
			t.Fatal("partial candidate was skipped or failed prefix retried")
		}
		if b.maximumPrimary != 1 {
			t.Fatal("primary overlapped across cycles")
		}
	})
}

func TestSlowPrefixEventuallyReachesLiveTailAcrossBoundedCycles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		f.endpoints = nil
		for n := range 30 {
			f.endpoints = append(f.endpoints, model.Endpoint{Host: fmt.Sprintf("188.114.96.%d", n+1), Port: 4500})
		}
		winner := f.endpoints[28]
		f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, progress finder.Progress, n int) (*backend.Instance, float64, int, error) {
			if n == 1 {
				return f.success(ctx, p, queue[0], 1)
			}
			for checked, endpoint := range queue {
				if endpoint == winner {
					return f.success(ctx, p, endpoint, checked+1)
				}
				if checked == 5 {
					return nil, 0, checked + 1, exhausted()
				}
				time.Sleep(30 * time.Second)
				progress(model.Event{Stage: "failed", Checked: checked + 1})
			}
			return nil, 0, len(queue), exhausted()
		}
		c.Connect(false)
		synctest.Wait()
		killFake(b, active(c))
		for range 20 {
			time.Sleep(time.Minute)
			synctest.Wait()
			if current := active(c); current != nil && current.Endpoint == winner {
				break
			}
		}
		if current := active(c); current == nil || current.Endpoint != winner || cacheWrites(s) != 2 {
			t.Fatal("bounded cycles starved the live candidate behind a slow prefix")
		}
		if f.count() < 6 {
			t.Fatal("slow-prefix test did not span multiple cycles")
		}
	})
}

func TestFlappingPreservesCursorAndBackoffUntilTwoPeriodicSuccesses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, _, b, f := recoveryFixture(t, nil)
		c.Connect(false)
		synctest.Wait()
		killFake(b, active(c))
		time.Sleep(time.Second)
		synctest.Wait()
		firstRecovery := active(c)
		if firstRecovery == nil || f.count() != 2 {
			t.Fatal("initial episode was not immediate")
		}
		killFake(b, firstRecovery)
		time.Sleep(time.Second)
		synctest.Wait()
		if !c.Status().Recovering || f.count() != 2 {
			t.Fatal("flap bypassed the cancellable delay")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		secondRecovery := active(c)
		if secondRecovery == nil || secondRecovery.Endpoint != f.endpoints[1] || f.count() != 3 {
			t.Fatal("flap repeated the same endpoint instead of advancing")
		}
		// One periodic success is insufficient to reset the episode.
		time.Sleep(time.Second)
		synctest.Wait()
		killFake(b, secondRecovery)
		time.Sleep(time.Second)
		synctest.Wait()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if f.count() != 3 {
			t.Fatal("one periodic success reset backoff")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		thirdRecovery := active(c)
		if thirdRecovery == nil || thirdRecovery.Endpoint != f.endpoints[2] {
			t.Fatal("second flap did not retain candidate progress")
		}
		// After two periodic successes a new crash is a genuinely new episode:
		// the healthy old endpoint is tried once immediately.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		killFake(b, thirdRecovery)
		time.Sleep(time.Second)
		synctest.Wait()
		if f.count() != 5 || active(c) == nil || active(c).Endpoint != thirdRecovery.Endpoint {
			t.Fatal("stable connection did not reset the recovery episode")
		}
	})
}

func TestRecoveryBackoffCapsAndCannotBeBypassedByQueueRebuild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, progress finder.Progress, n int) (*backend.Instance, float64, int, error) {
			if n == 1 {
				return f.success(ctx, p, queue[0], 1)
			}
			for checked := range queue {
				progress(model.Event{Stage: "failed", Checked: checked + 1})
			}
			return nil, 0, len(queue), exhausted()
		}
		c.Connect(false)
		synctest.Wait()
		killFake(b, active(c))
		time.Sleep(time.Second)
		synctest.Wait()
		for _, delay := range []time.Duration{2, 5, 10, 20, 30, 30} {
			time.Sleep(delay * time.Second)
			synctest.Wait()
		}
		times := f.times()
		if len(times) != 8 || cacheWrites(s) != 1 {
			t.Fatal("bounded exhaustion either spun or modified cache")
		}
		for n, delay := range []time.Duration{2, 5, 10, 20, 30, 30} {
			if times[n+2].Sub(times[n+1]) != delay*time.Second {
				t.Fatal("queue rebuild reset or bypassed capped backoff")
			}
		}
		c.Disconnect()
		synctest.Wait()
		count := f.count()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if f.count() != count || c.Status().State != model.Disconnected || c.Status().Busy || c.Status().Recovering {
			t.Fatal("manual disconnect resurrected during backoff")
		}
	})
}

func TestRecoveryWaitsForCancelledProbeCleanupBeforeNewPrimary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		cancelSeen, release := make(chan struct{}), make(chan struct{})
		f.search = func(ctx context.Context, i *backend.Instance) (finder.Outcome, error) {
			<-ctx.Done()
			close(cancelSeen)
			<-release
			return finder.Outcome{Results: []model.CheckResult{model.NewResult(i.Endpoint, 1, model.Probe)}, Checked: 1}, nil
		}
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		c.StartSearch(false)
		synctest.Wait()
		killFake(b, old)
		time.Sleep(time.Second)
		synctest.Wait()
		<-cancelSeen
		if f.count() != 1 || !c.Status().Recovering || !c.Status().Searching || b.maximum != 2 {
			t.Fatal("recovery did not wait for its real probe owner")
		}
		close(release)
		synctest.Wait()
		cache, _ := s.LoadCache()
		if f.count() != 2 || c.Status().State != model.Connected || c.Status().Searching || cache.Preferred != nil || cacheWrites(s) != 2 || b.maximumPrimary != 1 {
			t.Fatal("late cancelled probe result escaped settlement")
		}
		for _, e := range c.PollEvents() {
			if e.Type == "search_done" && e.Saved {
				t.Fatal("cancelled probe advertised saved results")
			}
		}
	})
}

func TestDisconnectDuringRecoveryCleanupAlwaysCancelsIntent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		entered, release := make(chan struct{}), make(chan struct{})
		b.stopError = func(i *backend.Instance) error {
			if i == old {
				select {
				case <-entered:
				default:
					close(entered)
				}
				<-release
			}
			return nil
		}
		killFake(b, old)
		time.Sleep(time.Second)
		synctest.Wait()
		<-entered
		c.Disconnect()
		c.Disconnect()
		c.Connect(false)
		synctest.Wait()
		if !c.Status().Busy || c.Status().State != model.Disconnected || c.Status().Recovering || f.count() != 1 {
			t.Fatal("cleanup ignored disconnect or allowed overlapping primary")
		}
		close(release)
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		if f.count() != 1 || c.Status().Busy || cacheWrites(s) != 1 {
			t.Fatal("cleanup completion restarted a cancelled session")
		}
	})
}

func TestCancelledLateRecoverySuccessIsStoppedWithoutCacheOrStateResurrection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		started, release := make(chan struct{}), make(chan struct{})
		var late *backend.Instance
		f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, _ finder.Progress, n int) (*backend.Instance, float64, int, error) {
			i, latency, checked, err := f.success(ctx, p, queue[0], 1)
			if n > 1 {
				late = i
				close(started)
				<-release
			}
			return i, latency, checked, err
		}
		c.Connect(false)
		synctest.Wait()
		killFake(b, active(c))
		time.Sleep(time.Second)
		synctest.Wait()
		<-started
		c.Disconnect()
		c.Connect(false)
		synctest.Wait()
		if f.count() != 2 || !c.Status().Busy {
			t.Fatal("late recovery stopped owning the primary identity")
		}
		close(release)
		synctest.Wait()
		if b.alive(late) || cacheWrites(s) != 1 || c.Status().State != model.Disconnected || c.Status().Recovering || c.Status().Busy {
			t.Fatal("late cancelled verification escaped cleanup")
		}
	})
}

func TestCleanupFailureOutranksCancelledConnectAndSearchAndBlocksEveryLaunch(t *testing.T) {
	for _, operation := range []string{"connect", "search", "recovery", "probe", "primary_stop"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, _, _, b, f := recoveryFixture(t, nil)
				started, release := make(chan struct{}), make(chan struct{})
				if operation == "connect" || operation == "recovery" {
					f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, _ finder.Progress, n int) (*backend.Instance, float64, int, error) {
						if operation == "recovery" && n == 1 {
							return f.success(ctx, p, queue[0], 1)
						}
						close(started)
						<-ctx.Done()
						<-release
						return nil, 0, 1, unsafeCleanup()
					}
				} else if operation != "primary_stop" {
					f.search = func(ctx context.Context, _ *backend.Instance) (finder.Outcome, error) {
						close(started)
						<-ctx.Done()
						<-release
						return finder.Outcome{}, unsafeCleanup()
					}
				}
				switch operation {
				case "connect":
					c.Connect(false)
				case "search":
					c.StartSearch(false)
				default:
					c.Connect(false)
					synctest.Wait()
					if operation == "probe" {
						c.StartSearch(false)
					} else {
						if operation == "primary_stop" {
							b.stopError = func(*backend.Instance) error { close(started); <-release; return unsafeCleanup() }
						}
						killFake(b, active(c))
						time.Sleep(time.Second)
					}
				}
				synctest.Wait()
				<-started
				c.Disconnect()
				close(release)
				synctest.Wait()
				before := f.count()
				c.Connect(false)
				c.StartSearch(false)
				synctest.Wait()
				time.Sleep(time.Minute)
				synctest.Wait()
				if !c.Status().Busy || c.Status().Code != "proxy_cleanup_failed" || c.Status().State != model.Failed || c.Status().Recovering || f.count() != before {
					t.Fatal("cancelled cleanup failure did not latch the global launch block")
				}
				// Permit the Close backstop to finish; the historical failure must
				// remain observable rather than becoming a false successful close.
				b.mu.Lock()
				b.stopError = nil
				b.mu.Unlock()
				c.Close()
				if model.Code(c.CloseError()) != "proxy_cleanup_failed" {
					t.Fatal("close erased the unsafe cleanup result")
				}
			})
		})
	}
}

func TestRecoveryTreatsLocalFailuresAsTerminalAndPreservesCache(t *testing.T) {
	for _, code := range []string{"port_busy", "proxy_config_failed", "proxy_owner_invalid", "proxy_launch_failed", "health_setup_failed", "unknown"} {
		t.Run(code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, s, _, b, f := recoveryFixture(t, nil)
				f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, _ finder.Progress, n int) (*backend.Instance, float64, int, error) {
					if n == 1 {
						return f.success(ctx, p, queue[0], 1)
					}
					if code == "unknown" {
						return nil, 0, 0, errors.New("not a network exhaustion")
					}
					return nil, 0, 0, model.E(code, "Local failure.")
				}
				c.Connect(false)
				synctest.Wait()
				killFake(b, active(c))
				time.Sleep(time.Second)
				synctest.Wait()
				time.Sleep(time.Hour)
				synctest.Wait()
				if f.count() != 2 || c.Status().State != model.Failed || c.Status().Busy || c.Status().Recovering || cacheWrites(s) != 1 {
					t.Fatal("local failure was hidden as network exhaustion")
				}
			})
		})
	}
}

func TestRecoveredCacheWriteFailureKeepsConnectionAndWarningWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, _ := recoveryFixture(t, nil)
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		c.PollEvents()
		s.mu.Lock()
		s.fail = true
		s.mu.Unlock()
		killFake(b, old)
		time.Sleep(time.Second)
		synctest.Wait()
		events := c.PollEvents()
		if active(c) == nil || !b.alive(active(c)) || c.Status().State != model.Connected || c.Status().Recovering || len(events) < 2 {
			t.Fatal("cache failure stopped a verified recovered connection")
		}
		if events[len(events)-2].Code != "recovered" || events[len(events)-1].Type != "warning" || events[len(events)-1].Code != "cache_write_failed" || eventWith(events, "saved", "") {
			t.Fatal("recovered cache warning lost precedence or falsely claimed saved")
		}
	})
}

func TestConcurrentCloseCancelsRecoveryAndWaitsForProbeOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		cancelled, release := make(chan struct{}), make(chan struct{})
		f.search = func(ctx context.Context, _ *backend.Instance) (finder.Outcome, error) {
			<-ctx.Done()
			close(cancelled)
			<-release
			return finder.Outcome{Cancelled: true}, nil
		}
		c.Connect(false)
		synctest.Wait()
		c.StartSearch(false)
		synctest.Wait()
		killFake(b, active(c))
		time.Sleep(time.Second)
		synctest.Wait()
		<-cancelled
		closed := make(chan struct{})
		go func() { c.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-c.closeDone:
			t.Fatal("close returned before the probe finished cleanup")
		default:
		}
		close(release)
		// sync.Once's contended mutex is not a durable synctest wait. Establish
		// the blocked owner above, then exercise concurrent idempotent callers
		// after releasing the explicitly gated cleanup dependency.
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() { defer wg.Done(); c.Close() }()
		}
		wg.Wait()
		<-closed
		synctest.Wait()
		if c.CloseError() != nil || s.clears != 1 || f.count() != 1 || c.Status().Recovering {
			t.Fatal("close restarted recovery or skipped owned cleanup")
		}
	})
}

func TestRecoveryQueueCanonicalDedupAndTotalCapIncludesOldEndpoint(t *testing.T) {
	for _, reason := range []string{"connection_lost", "proxy_exited"} {
		c, _, _, _, f := recoveryFixture(t, nil)
		old := model.Endpoint{Host: "example.com", Port: 2408}
		f.endpoints = []model.Endpoint{{Host: "EXAMPLE.COM.", Port: 2408}, old}
		for n := range 40 {
			f.endpoints = append(f.endpoints, model.Endpoint{Host: fmt.Sprintf("188.114.96.%d", n+1), Port: 4500})
		}
		queue, err := c.recoveryCandidates(context.Background(), 0, model.Profile{}, old, reason)
		if err != nil || len(queue) != 30 {
			t.Fatal("recovery queue does not respect total cap")
		}
		if reason == "proxy_exited" && queue[0] != old || reason == "connection_lost" && queue[29] != old {
			t.Fatal("old endpoint has incorrect loss-specific priority")
		}
		if len(slices.Compact(append([]model.Endpoint(nil), queue...))) != 30 {
			t.Fatal("duplicate endpoint in recovery queue")
		}
		seen := map[model.Endpoint]bool{}
		for _, endpoint := range queue {
			if seen[endpoint] {
				t.Fatal("canonical duplicate")
			}
			seen[endpoint] = true
		}
	}
}
