package finder

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/model"
)

type fakeBackend struct {
	mu       sync.Mutex
	live     map[*backend.Instance]bool
	sequence []string
	current  *backend.Instance
	busy     bool
}

func (b *fakeBackend) Start(ctx context.Context, p model.Profile, endpoint model.Endpoint, role string, port int) (*backend.Instance, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.busy {
		return nil, model.E("port_busy", "busy")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for _, live := range b.live {
		if live {
			return nil, errors.New("overlapping trial")
		}
	}
	if b.live == nil {
		b.live = make(map[*backend.Instance]bool)
	}
	if port == 0 {
		port = 44000
	}
	i := &backend.Instance{Endpoint: endpoint, Port: port, Role: role}
	b.live[i] = true
	b.current = i
	b.sequence = append(b.sequence, "start")
	return i, nil
}
func (b *fakeBackend) Stop(i *backend.Instance) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live[i] {
		b.live[i] = false
		b.sequence = append(b.sequence, "stop")
	}
	return nil
}
func (b *fakeBackend) alive(i *backend.Instance) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.live[i]
}
func endpoints() []model.Endpoint {
	return []model.Endpoint{{Host: "188.114.96.1", Port: 4500}, {Host: "188.114.97.1", Port: 4500}, {Host: "188.114.98.1", Port: 4500}}
}
func fakeFinder(b *fakeBackend, health Check, options Options) *Finder {
	f := New(b, health, options)
	f.isAlive = b.alive
	return f
}

func TestCandidatesOrderAndBounds(t *testing.T) {
	f := New(nil, nil, Options{})
	ep := endpoints()
	preferred := model.NewResult(ep[0], 1, model.Probe)
	last := model.NewResult(ep[1], 2, model.Primary)
	candidates, err := f.Candidates(model.Profile{Endpoint: ep[2]}, model.Cache{Preferred: &preferred, LastGood: &last, Fallbacks: []model.CheckResult{preferred}}, nil, 100)
	if err != nil || len(candidates) != 30 {
		t.Fatal("candidate cap failed")
	}
	for n := range ep {
		if candidates[n] != ep[n] {
			t.Fatal("saved order changed")
		}
	}
	seen := make(map[model.Endpoint]bool)
	for _, endpoint := range candidates {
		if seen[endpoint] {
			t.Fatal("duplicate")
		}
		seen[endpoint] = true
	}
	if len(prefixes) != 15 || len(ports) != 54 {
		t.Fatal("pinned pools changed")
	}
	candidates, err = f.Candidates(model.Profile{}, model.Cache{}, []model.Endpoint{ep[0], ep[0], ep[1]}, 30)
	if err != nil || len(candidates) != 2 {
		t.Fatal("explicit candidates were sampled or not deduplicated")
	}
	if _, err := f.Candidates(model.Profile{}, model.Cache{}, []model.Endpoint{{Host: "bad host", Port: 1}}, 30); err == nil {
		t.Fatal("invalid endpoint accepted")
	}
}

func TestSearchRanksSequentiallyAndReleasesAll(t *testing.T) {
	b := &fakeBackend{}
	n := 0
	f := fakeFinder(b, func(context.Context, int) (float64, error) { n++; return float64(40 - n*10), nil }, Options{})
	out, err := f.Search(context.Background(), model.Profile{}, model.Probe, model.Cache{}, endpoints(), nil)
	if err != nil || out.Cancelled || out.Checked != 3 || len(out.Results) != 3 {
		t.Fatal("search failed")
	}
	if out.Results[0].LatencyMS != 10 || out.Results[2].LatencyMS != 30 || out.Results[0].Role != model.Probe {
		t.Fatal("ranking failed")
	}
	for _, live := range b.live {
		if live {
			t.Fatal("trial survived")
		}
	}
	if len(b.sequence) != 6 {
		t.Fatal("trial ownership sequence")
	}
}

func TestConnectKeepsVerifiedFixedPort(t *testing.T) {
	b := &fakeBackend{}
	calls := 0
	f := fakeFinder(b, func(context.Context, int) (float64, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("timeout")
		}
		return 12, nil
	}, Options{Deadline: 40 * time.Millisecond})
	i, latency, checked, err := f.Connect(context.Background(), model.Profile{}, endpoints(), nil)
	if err != nil || i == nil || latency != 12 || checked != 2 || i.Port != 25344 || !b.alive(i) {
		t.Fatal("verified worker not retained")
	}
	time.Sleep(70 * time.Millisecond)
	if !b.alive(i) {
		t.Fatal("old deadline killed active primary")
	}
	_ = b.Stop(i)
}

func TestBudgetStopsOnlyInflightTrial(t *testing.T) {
	b := &fakeBackend{}
	f := fakeFinder(b, func(ctx context.Context, _ int) (float64, error) { <-ctx.Done(); return 0, ctx.Err() }, Options{Deadline: 30 * time.Millisecond})
	started := time.Now()
	out, err := f.Search(context.Background(), model.Profile{}, model.Probe, model.Cache{}, endpoints(), nil)
	if err != nil || out.Checked != 1 || len(out.Results) != 0 || out.Cancelled || time.Since(started) > time.Second {
		t.Fatal("wall deadline failed")
	}
	if b.alive(b.current) {
		t.Fatal("deadline leaked helper")
	}
}

func TestCancelledSearchDiscardsEarlierSuccesses(t *testing.T) {
	b := &fakeBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	f := fakeFinder(b, func(context.Context, int) (float64, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return 1, nil
	}, Options{})
	out, err := f.Search(ctx, model.Profile{}, model.Primary, model.Cache{}, endpoints(), nil)
	if err != nil || !out.Cancelled || len(out.Results) != 0 || out.Checked != 2 || b.alive(b.current) {
		t.Fatal("cancelled results/process survived")
	}
}

func TestBusyPortAbortsAndAllFailuresReport(t *testing.T) {
	for _, busy := range []bool{true, false} {
		b := &fakeBackend{busy: busy}
		f := fakeFinder(b, func(context.Context, int) (float64, error) { return 0, errors.New("no reply") }, Options{})
		_, _, checked, err := f.Connect(context.Background(), model.Profile{}, endpoints(), nil)
		want := "no_working_endpoint"
		if busy {
			want = "port_busy"
		}
		if model.Code(err) != want {
			t.Fatalf("wrong code %s", model.Code(err))
		}
		if busy && checked != 1 {
			t.Fatal("busy port retried")
		}
		if b.alive(b.current) {
			t.Fatal("failed worker leaked")
		}
	}
}

func TestPrecancellationAndKeepLimit(t *testing.T) {
	b := &fakeBackend{}
	f := fakeFinder(b, func(context.Context, int) (float64, error) { return 1, nil }, Options{Keep: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := f.Search(ctx, model.Profile{}, model.Primary, model.Cache{}, endpoints(), nil)
	if err != nil || !out.Cancelled || out.Checked != 0 || len(b.sequence) != 0 {
		t.Fatal("precancel started process")
	}
	out, err = f.Search(context.Background(), model.Profile{}, model.Primary, model.Cache{}, endpoints(), nil)
	if err != nil || out.Checked != 1 || len(out.Results) != 1 {
		t.Fatal("success limit ignored")
	}
}
