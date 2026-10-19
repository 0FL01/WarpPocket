package finder

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

type faultBackend struct {
	fakeBackend
	starts, stops atomic.Int32
	beforeStart   func(context.Context) error
	afterStart    func(context.Context, *backend.Instance) error
	stopError     func() error
}

func (b *faultBackend) Start(ctx context.Context, p model.Profile, endpoint model.Endpoint, role string, port int) (*backend.Instance, error) {
	b.starts.Add(1)
	if b.beforeStart != nil {
		if err := b.beforeStart(ctx); err != nil {
			return nil, err
		}
	}
	i, err := b.fakeBackend.Start(ctx, p, endpoint, role, port)
	if err == nil && b.afterStart != nil {
		err = b.afterStart(ctx, i)
	}
	return i, err
}

func (b *faultBackend) Stop(i *backend.Instance) error {
	b.stops.Add(1)
	if err := b.fakeBackend.Stop(i); err != nil {
		return err
	}
	if b.stopError != nil {
		return b.stopError()
	}
	return nil
}

func newFaultFinder(b *faultBackend, health Check, options Options) *Finder {
	f := New(b, health, options)
	f.isAlive = b.alive
	return f
}

func invokeFinder(f *Finder, ctx context.Context, connect bool, progress Progress) (Outcome, *backend.Instance, error) {
	if connect {
		i, _, checked, err := f.Connect(ctx, model.Profile{}, endpoints(), progress)
		return Outcome{Checked: checked}, i, err
	}
	out, err := f.Search(ctx, model.Profile{}, model.Probe, model.Cache{}, endpoints(), progress)
	return out, nil, err
}

func TestTerminalStartupFailuresOutrankEndedContextsAndNeverTryNextEndpoint(t *testing.T) {
	for _, startupErr := range []error{
		model.E("proxy_cleanup_failed", "cleanup"),
		model.E("proxy_launch_failed", "launch"),
		model.E("proxy_config_failed", "config"),
		model.E("proxy_port_failed", "port"),
		model.E("port_busy", "busy"),
		model.E("proxy_owner_invalid", "owner"),
		model.E("proxy_arguments_invalid", "arguments"),
		model.E("endpoint_invalid", "endpoint"),
		model.E("future_start_error", "unknown safe startup error"),
		errors.New("unknown startup error"),
	} {
		for _, mode := range []string{"active", "cancelled", "parent deadline", "internal budget"} {
			for _, connect := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/connect=%t", model.Code(startupErr), mode, connect), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					if mode == "parent deadline" {
						cancel()
						ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
					}
					defer cancel()
					options := Options{}
					if mode == "internal budget" {
						options.Deadline = 10 * time.Millisecond
					}
					b := &faultBackend{beforeStart: func(budget context.Context) error {
						if mode == "cancelled" {
							cancel()
						}
						if mode != "active" {
							<-budget.Done()
						}
						return startupErr
					}}
					f := newFaultFinder(b, func(context.Context, int) (float64, error) {
						t.Error("health ran after terminal startup failure")
						return 0, nil
					}, options)
					failed := 0
					out, i, err := invokeFinder(f, ctx, connect, func(e model.Event) {
						if e.Stage == "failed" {
							failed++
						}
					})
					if err != startupErr || out.Checked != 1 || out.Cancelled || i != nil || b.starts.Load() != 1 || failed != 0 {
						t.Fatalf("terminal start error lost or retried: code=%s checked=%d starts=%d failed=%d", model.Code(err), out.Checked, b.starts.Load(), failed)
					}
				})
			}
		}
	}
}

func TestOnlyBoundedStartupFailureCodesAdvanceCandidates(t *testing.T) {
	for _, code := range []string{"proxy_start_failed", "proxy_start_timeout"} {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/connect=%t", code, connect), func(t *testing.T) {
				b := &faultBackend{}
				b.beforeStart = func(context.Context) error {
					if b.starts.Load() < 3 {
						return model.E(code, "bounded readiness failure")
					}
					return nil
				}
				f := newFaultFinder(b, func(context.Context, int) (float64, error) { return 1, nil }, Options{})
				failed := 0
				out, i, err := invokeFinder(f, context.Background(), connect, func(e model.Event) {
					if e.Stage == "failed" {
						failed++
					}
				})
				if i != nil {
					defer b.Stop(i)
				}
				if err != nil || out.Checked != 3 || b.starts.Load() != 3 || failed != 2 || (connect && i == nil) || (!connect && len(out.Results) != 1) {
					t.Fatal("bounded readiness failures did not advance to the verified candidate")
				}
			})
		}
	}

	for _, startupErr := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, connect := range []bool{false, true} {
			b := &faultBackend{beforeStart: func(context.Context) error { return startupErr }}
			f := newFaultFinder(b, func(context.Context, int) (float64, error) { return 0, nil }, Options{})
			out, _, err := invokeFinder(f, context.Background(), connect, nil)
			if !errors.Is(err, startupErr) || out.Checked != 1 || b.starts.Load() != 1 {
				t.Fatal("unexpected startup context error was treated as endpoint exhaustion")
			}
		}
	}
}

func TestStartupContextErrorsDistinguishParentFromInternalBudget(t *testing.T) {
	for _, parentDeadline := range []bool{false, true} {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprintf("parent=%t/connect=%t", parentDeadline, connect), func(t *testing.T) {
				ctx := context.Background()
				options := Options{Deadline: 10 * time.Millisecond}
				if parentDeadline {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
					defer cancel()
					options.Deadline = time.Second
				}
				b := &faultBackend{beforeStart: func(budget context.Context) error {
					<-budget.Done()
					return budget.Err()
				}}
				f := newFaultFinder(b, func(context.Context, int) (float64, error) { return 0, nil }, options)
				failed := 0
				out, _, err := invokeFinder(f, ctx, connect, func(e model.Event) {
					if e.Stage == "failed" {
						failed++
					}
				})
				want := ""
				if connect {
					want = "no_working_endpoint"
					if parentDeadline {
						want = "timeout"
					}
				}
				if model.Code(err) != want || out.Cancelled != (!connect && parentDeadline) || out.Checked != 1 || failed != 0 || b.starts.Load() != 1 {
					t.Fatal("parent cancellation and internal exhaustion were conflated or a partial trial advanced the cursor")
				}
			})
		}
	}
}

func TestHealthSetupAndCleanupFailuresOutrankCancellationAndBudget(t *testing.T) {
	for _, mode := range []string{"active", "cancelled", "budget"} {
		for _, cleanupFails := range []bool{false, true} {
			for _, connect := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/cleanup=%t/connect=%t", mode, cleanupFails, connect), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					b := &faultBackend{}
					if cleanupFails {
						b.stopError = func() error { return model.E("proxy_cleanup_failed", "cleanup") }
					}
					f := newFaultFinder(b, func(budget context.Context, _ int) (float64, error) {
						if mode == "cancelled" {
							cancel()
						}
						if mode != "active" {
							<-budget.Done()
						}
						return 0, model.E("health_setup_failed", "local health setup")
					}, Options{Deadline: 10 * time.Millisecond})
					out, i, err := invokeFinder(f, ctx, connect, nil)
					want := "health_setup_failed"
					if cleanupFails {
						want = "proxy_cleanup_failed"
					}
					if model.Code(err) != want || i != nil || out.Checked != 1 || b.starts.Load() != 1 || b.stops.Load() != 1 || b.alive(b.current) {
						t.Fatal("terminal health/cleanup failure was hidden, retried, or cleanup was skipped")
					}
				})
			}
		}
	}
}

func TestFailedRollbackAndTrialReleaseAlwaysReturnCleanupFailure(t *testing.T) {
	for _, stage := range []string{"startup rollback", "health failure", "late success", "process exited"} {
		for _, deadline := range []bool{false, true} {
			for _, connect := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/deadline=%t/connect=%t", stage, deadline, connect), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					b := &faultBackend{stopError: func() error { return model.E("proxy_cleanup_failed", "cleanup") }}
					end := func(budget context.Context) {
						if !deadline {
							cancel()
						}
						<-budget.Done()
					}
					if stage == "startup rollback" {
						b.afterStart = func(budget context.Context, _ *backend.Instance) error {
							end(budget)
							return model.E("proxy_start_timeout", "readiness")
						}
					}
					f := newFaultFinder(b, func(budget context.Context, _ int) (float64, error) {
						end(budget)
						if stage == "health failure" {
							return 0, model.E("health_timeout", "remote timeout")
						}
						return 1, nil
					}, Options{Deadline: 10 * time.Millisecond})
					if stage == "process exited" {
						f.isAlive = func(*backend.Instance) bool { return false }
					}
					failed := 0
					out, i, err := invokeFinder(f, ctx, connect, func(e model.Event) {
						if e.Stage == "failed" {
							failed++
						}
					})
					if model.Code(err) != "proxy_cleanup_failed" || out.Checked != 1 || i != nil || b.starts.Load() != 1 || b.stops.Load() != 1 || failed != 0 {
						t.Fatal("cleanup error was hidden by cancellation, deadline, failed keep, or process exit")
					}
				})
			}
		}
	}
}

func TestRemoteHealthFailuresContinueOnlyAfterCheckedCleanup(t *testing.T) {
	for _, code := range []string{"health_failed", "health_timeout", "health_tls", "warp_not_enabled", "external_unavailable", "health_response_large"} {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/connect=%t", code, connect), func(t *testing.T) {
				b := &faultBackend{}
				calls := 0
				f := newFaultFinder(b, func(context.Context, int) (float64, error) {
					calls++
					if calls == 1 {
						return 0, model.E(code, "remote verification failed")
					}
					return 1, nil
				}, Options{Keep: 1})
				failed := 0
				out, i, err := invokeFinder(f, context.Background(), connect, func(e model.Event) {
					if e.Stage == "failed" {
						failed++
						if b.stops.Load() != 1 || b.alive(b.current) || e.Endpoint != endpoints()[0] {
							t.Error("failed progress ran before checked trial cleanup")
						}
					}
				})
				if i != nil {
					defer b.Stop(i)
				}
				if err != nil || out.Checked != 2 || b.starts.Load() != 2 || failed != 1 || (connect && i == nil) || (!connect && len(out.Results) != 1) {
					t.Fatal("remote health failure stopped sequential candidate verification")
				}
			})
		}
	}
}

func TestDeadlinePartialTrialHasNoFailedOrFoundProgress(t *testing.T) {
	for _, phase := range []string{"startup", "health failure", "late health success", "cleanup"} {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/connect=%t", phase, connect), func(t *testing.T) {
				b := &faultBackend{}
				var budget context.Context
				b.beforeStart = func(ctx context.Context) error {
					budget = ctx
					if phase == "startup" {
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				}
				if phase == "cleanup" {
					b.stopError = func() error { <-budget.Done(); return nil }
				}
				f := newFaultFinder(b, func(ctx context.Context, _ int) (float64, error) {
					if phase != "cleanup" {
						end, _ := ctx.Deadline()
						// A socket can reach its deadline before ctx.Err is set.
						for time.Now().Before(end) {
						}
					}
					if phase == "late health success" {
						return 1, nil
					}
					return 0, model.E("health_timeout", "socket deadline")
				}, Options{Deadline: 10 * time.Millisecond})
				completed := 0
				out, i, err := invokeFinder(f, context.Background(), connect, func(e model.Event) {
					if e.Stage == "failed" || e.Stage == "found" {
						completed++
					}
				})
				want := ""
				if connect {
					want = "no_working_endpoint"
				}
				if model.Code(err) != want || out.Cancelled || out.Checked != 1 || i != nil || len(out.Results) != 0 || completed != 0 || b.starts.Load() != 1 || b.alive(b.current) {
					t.Fatal("deadline-partial candidate advanced the cursor, survived, or became a fatal local error")
				}
				if phase != "startup" && b.stops.Load() != 1 {
					t.Fatal("partial trial did not check Stop exactly once")
				}
			})
		}
	}
}

type deadlineBeforeTimerContext struct {
	context.Context
	end time.Time
}

func (c deadlineBeforeTimerContext) Deadline() (time.Time, bool) { return c.end, true }

func TestKeepAndBudgetAccountingCheckActualDeadlineBeforeContextTimer(t *testing.T) {
	ctx := deadlineBeforeTimerContext{Context: context.Background(), end: time.Now().Add(-time.Millisecond)}
	if ctx.Err() != nil || !errors.Is(contextFailure(ctx), context.DeadlineExceeded) || terminalStartup(context.DeadlineExceeded, context.Background(), ctx) != nil {
		t.Fatal("deadline accounting depended on the context timer firing")
	}
	b := &fakeBackend{}
	i, err := b.Start(context.Background(), model.Profile{}, endpoints()[0], model.Primary, backend.SOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	trial := watch(ctx, b, i)
	if !errors.Is(trial.keep(), context.DeadlineExceeded) || trial.release() != nil || b.alive(i) {
		t.Fatal("late verification retained a worker before its budget timer fired")
	}
}
