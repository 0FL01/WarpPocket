package controller

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
)

type memoryStore struct {
	mu             sync.Mutex
	cache          model.Cache
	writes, clears int
	fail           bool
}

func (s *memoryStore) LoadCache() (model.Cache, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache.Clone(), nil
}
func (s *memoryStore) UpdateCache(update func(model.Cache) model.Cache) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return model.E("cache_write_failed", "write failed")
	}
	s.cache = update(s.cache.Clone())
	s.writes++
	return nil
}
func (s *memoryStore) ClearRuntime() error { s.mu.Lock(); defer s.mu.Unlock(); s.clears++; return nil }

type fakeProfiles struct {
	mu            sync.Mutex
	calls         []string
	err           error
	reservedCalls int
}

func (p *fakeProfiles) EnsureProfile(ctx context.Context, role string, consent bool) (model.Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, role)
	return model.Profile{}, p.err
}
func (p *fakeProfiles) EnsureReserved(ctx context.Context, role string) (model.Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reservedCalls++
	return model.Profile{Endpoint: model.Endpoint{Host: "188.114.96.1", Port: 4500}}, ctx.Err()
}

type workers struct {
	mu                      sync.Mutex
	live                    map[*backend.Instance]bool
	started                 int
	stopGate                <-chan struct{}
	stopStarted             chan struct{}
	once                    sync.Once
	stopError               func(*backend.Instance) error
	maximum, maximumPrimary int
}

func (b *workers) Start(ctx context.Context, p model.Profile, e model.Endpoint, role string, port int) (*backend.Instance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live == nil {
		b.live = make(map[*backend.Instance]bool)
	}
	i := &backend.Instance{Endpoint: e, Port: port, Role: role}
	b.live[i] = true
	b.started++
	live, primary := 0, 0
	for instance, alive := range b.live {
		if alive {
			live++
			if instance.Role == model.Primary {
				primary++
			}
		}
	}
	b.maximum = max(b.maximum, live)
	b.maximumPrimary = max(b.maximumPrimary, primary)
	return i, nil
}
func (b *workers) Stop(i *backend.Instance) error {
	if i == nil {
		return nil
	}
	b.mu.Lock()
	stopError := b.stopError
	b.mu.Unlock()
	if stopError != nil {
		if err := stopError(i); err != nil {
			return err
		}
	}
	if b.stopStarted != nil {
		b.once.Do(func() { close(b.stopStarted) })
	}
	if b.stopGate != nil {
		<-b.stopGate
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.live[i] = false
	return nil
}
func (b *workers) alive(i *backend.Instance) bool { b.mu.Lock(); defer b.mu.Unlock(); return b.live[i] }
func (b *workers) Shutdown() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.live {
		b.live[i] = false
	}
	return nil
}

type scriptFinder struct {
	b                             *workers
	connectGate, searchGate       <-chan struct{}
	connectStarted, searchStarted chan struct{}
	connectOnce, searchOnce       sync.Once
	connectErr                    error
	results                       []model.CheckResult
}

func (f *scriptFinder) Candidates(p model.Profile, c model.Cache, e []model.Endpoint, limit int) ([]model.Endpoint, error) {
	return []model.Endpoint{p.Endpoint}, nil
}
func (f *scriptFinder) Alive(i *backend.Instance) bool { return f.b.alive(i) }
func (f *scriptFinder) Connect(ctx context.Context, p model.Profile, e []model.Endpoint, progress finder.Progress) (*backend.Instance, float64, int, error) {
	if f.connectErr != nil {
		return nil, 0, 0, f.connectErr
	}
	i, _ := f.b.Start(context.Background(), p, e[0], model.Primary, 25344)
	if f.connectStarted != nil {
		f.connectOnce.Do(func() { close(f.connectStarted) })
	}
	if f.connectGate != nil {
		<-f.connectGate
	} // intentionally hands back late success
	return i, 12, 1, nil
}
func (f *scriptFinder) Search(ctx context.Context, p model.Profile, role string, c model.Cache, e []model.Endpoint, progress finder.Progress) (finder.Outcome, error) {
	if f.searchStarted != nil {
		f.searchOnce.Do(func() { close(f.searchStarted) })
	}
	if f.searchGate != nil {
		<-f.searchGate
	} // intentionally returns non-cancelled data
	results := append([]model.CheckResult(nil), f.results...)
	for n := range results {
		results[n].Role = role
	}
	return finder.Outcome{Results: results, Checked: 2}, nil
}
func wait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition timed out")
}
func fixture(t *testing.T, opts Options) (*Controller, *memoryStore, *fakeProfiles, *workers, *scriptFinder) {
	t.Helper()
	s := &memoryStore{}
	p := &fakeProfiles{}
	b := &workers{}
	f := &scriptFinder{b: b, results: []model.CheckResult{model.NewResult(model.Endpoint{Host: "188.114.97.1", Port: 4500}, 10, model.Probe)}}
	if opts.HealthInterval == 0 {
		opts.HealthInterval = time.Hour
	}
	c := New(s, p, b, f, b, func(context.Context, int) (float64, error) { return 1, nil }, opts)
	t.Cleanup(c.Close)
	return c, s, p, b, f
}
func eventWith(events []model.Event, kind, code string) bool {
	for _, e := range events {
		if e.Type == kind && (code == "" || e.Code == code) {
			return true
		}
	}
	return false
}

func TestConnectCommitsVerifiedLastGood(t *testing.T) {
	c, s, _, _, _ := fixture(t, Options{})
	old := model.NewResult(model.Endpoint{Host: "8.6.112.1", Port: 500}, 99, model.Probe)
	s.cache.Preferred = &old
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	cache, _ := s.LoadCache()
	if cache.LastGood == nil || cache.LastGood.Role != model.Primary || cache.Preferred != nil {
		t.Fatal("cache transition failed")
	}
	if c.Status().LatencyMS != 12 || !eventWith(c.PollEvents(), "saved", "") {
		t.Fatal("verified state not published")
	}
}
func TestConsentRequiredPublishedOnce(t *testing.T) {
	c, _, p, _, _ := fixture(t, Options{})
	p.err = model.E("consent_required", "consent")
	c.Connect(false)
	wait(t, func() bool { s := c.Status(); return s.State == model.Failed && !s.Busy })
	count := 0
	for _, e := range c.PollEvents() {
		if e.Type == "state" && e.Code == "consent_required" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("consent prompt count=%d", count)
	}
}
func TestCacheFailureKeepsConnectionWithoutSaved(t *testing.T) {
	c, s, _, b, _ := fixture(t, Options{})
	s.fail = true
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	events := c.PollEvents()
	if eventWith(events, "saved", "") || !eventWith(events, "warning", "cache_write_failed") {
		t.Fatal("false saved notification")
	}
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if !b.alive(active) {
		t.Fatal("cache failure stopped verified connection")
	}
}
func TestConnectFailureDoesNotWriteCache(t *testing.T) {
	c, s, _, _, f := fixture(t, Options{})
	f.connectErr = model.E("no_working_endpoint", "none")
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Failed && !c.Status().Busy })
	if c.Status().Code != "no_working_endpoint" || s.writes != 0 {
		t.Fatal("failure committed data")
	}
}
func TestLateConnectionStoppedBeforeIdentityReuse(t *testing.T) {
	c, s, _, b, f := fixture(t, Options{})
	release := make(chan struct{})
	defer close(release)
	f.connectGate = release
	f.connectStarted = make(chan struct{})
	c.Connect(false)
	<-f.connectStarted
	c.Disconnect()
	c.Connect(false)
	if !c.Status().Busy {
		t.Fatal("late primary no longer owns identity")
	}
	b.mu.Lock()
	starts := b.started
	b.mu.Unlock()
	if starts != 1 {
		t.Fatal("duplicate primary")
	}
	release <- struct{}{}
	wait(t, func() bool { return !c.Status().Busy })
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, live := range b.live {
		if live {
			t.Fatal("late worker leaked")
		}
	}
	if s.writes != 0 || c.Status().State != model.Disconnected {
		t.Fatal("late success published")
	}
}
func TestDisconnectDoesNotAllowReconnectBeforeStop(t *testing.T) {
	c, _, _, b, _ := fixture(t, Options{})
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	release := make(chan struct{})
	defer close(release)
	b.stopGate = release
	b.stopStarted = make(chan struct{})
	c.Disconnect()
	<-b.stopStarted
	c.Connect(false)
	b.mu.Lock()
	starts := b.started
	b.mu.Unlock()
	if starts != 1 || !c.Status().Busy {
		t.Fatal("reconnected before old worker stopped")
	}
	release <- struct{}{}
	wait(t, func() bool { return !c.Status().Busy })
}
func TestConnectedSearchUsesProbeAndPreservesPrimary(t *testing.T) {
	c, s, p, b, _ := fixture(t, Options{})
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	c.PollEvents()
	c.mu.Lock()
	primary := c.active
	c.mu.Unlock()
	c.StartSearch(false)
	wait(t, func() bool { return !c.Status().Searching })
	cache, _ := s.LoadCache()
	if cache.Preferred == nil || cache.Preferred.Role != model.Probe || cache.LastGood.Role != model.Primary {
		t.Fatal("wrong search role/cache")
	}
	c.mu.Lock()
	same := c.active == primary
	c.mu.Unlock()
	if !same || !b.alive(primary) {
		t.Fatal("search replaced primary")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) != 2 || p.calls[1] != model.Probe {
		t.Fatal("probe identity not ensured")
	}
}
func TestDisconnectedSearchUsesPrimary(t *testing.T) {
	c, s, _, _, _ := fixture(t, Options{})
	c.StartSearch(false)
	wait(t, func() bool { return !c.Status().Searching })
	cache, _ := s.LoadCache()
	if cache.Preferred == nil || cache.Preferred.Role != model.Primary || cache.LastGood != nil {
		t.Fatal("standalone search semantics changed")
	}
}
func TestCancelDiscardsLateSearchSuccess(t *testing.T) {
	c, s, _, _, f := fixture(t, Options{})
	release := make(chan struct{})
	defer close(release)
	f.searchGate = release
	f.searchStarted = make(chan struct{})
	c.StartSearch(false)
	<-f.searchStarted
	c.CancelSearch()
	release <- struct{}{}
	wait(t, func() bool { return !c.Status().Searching })
	if s.writes != 0 || !eventWith(c.PollEvents(), "search_cancelled", "") {
		t.Fatal("late cancelled result persisted")
	}
}
func TestConnectRejectedDuringStandaloneSearch(t *testing.T) {
	c, _, _, b, f := fixture(t, Options{})
	release := make(chan struct{})
	defer close(release)
	f.searchGate = release
	f.searchStarted = make(chan struct{})
	c.StartSearch(false)
	<-f.searchStarted
	c.Connect(false)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started != 0 || !eventWith(c.PollEvents(), "error", "search_active") {
		t.Fatal("concurrent primary operations")
	}
}
func TestEmptyOrUnsavedSearchNeverClaimsSaved(t *testing.T) {
	for _, empty := range []bool{true, false} {
		c, s, _, _, f := fixture(t, Options{})
		if empty {
			f.results = nil
		} else {
			s.fail = true
		}
		c.StartSearch(false)
		wait(t, func() bool { return !c.Status().Searching })
		for _, e := range c.PollEvents() {
			if e.Type == "search_done" && e.Saved {
				t.Fatal("false search saved")
			}
		}
	}
}
func TestOldMonitorCannotTouchNewConnection(t *testing.T) {
	c, _, _, b, _ := fixture(t, Options{})
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	c.mu.Lock()
	old := c.active
	oldID := c.sessionID
	c.mu.Unlock()
	c.Disconnect()
	wait(t, func() bool { return !c.Status().Busy })
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	if _, current := c.beginRecovery(context.Background(), oldID, old); current {
		t.Fatal("stale monitor entered recovery for a newer session")
	}
	c.mu.Lock()
	current := c.active
	c.mu.Unlock()
	if current == old || !b.alive(current) || c.Status().State != model.Connected {
		t.Fatal("stale monitor changed newer connection")
	}
}
func TestTwoHealthFailuresStopAndAutomaticallyReplacePrimary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, profiles, b, _ := fixture(t, Options{HealthInterval: time.Second})
		checks := 0
		c.health = func(context.Context, int) (float64, error) {
			checks++
			if checks <= 2 {
				return 0, model.E("health_timeout", "timeout")
			}
			return 1, nil
		}
		c.Connect(false)
		synctest.Wait()
		c.mu.Lock()
		old := c.active
		c.mu.Unlock()
		if old == nil {
			t.Fatal("initial primary missing")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if !b.alive(old) || c.Status().State != model.Connected {
			t.Fatal("one failure stopped primary")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		c.mu.Lock()
		replacement := c.active
		c.mu.Unlock()
		if replacement == nil || replacement == old || b.alive(old) || !b.alive(replacement) || replacement.Port != 25344 || c.Status().Recovering {
			t.Fatal("two failures did not replace the owned primary automatically")
		}
		profiles.mu.Lock()
		defer profiles.mu.Unlock()
		if len(profiles.calls) != 1 || profiles.reservedCalls != 1 {
			t.Fatal("recovery repeated profile/API preparation")
		}
		if b.maximumPrimary != 1 {
			t.Fatal("primary identities overlapped")
		}
	})
}
func TestConcurrentCloseWaitsForOwnedCleanup(t *testing.T) {
	c, s, _, b, _ := fixture(t, Options{})
	c.Connect(false)
	wait(t, func() bool { return c.Status().State == model.Connected })
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if c.CloseError() != nil || s.clears != 1 {
		t.Fatal("close was not idempotent")
	}
	c.Connect(false)
	c.StartSearch(false)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, live := range b.live {
		if live {
			t.Fatal("close leaked worker")
		}
	}
}
