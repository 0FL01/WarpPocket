// Package finder performs bounded sequential checks with a single identity.
// The successful connection alone transfers ownership out of its trial budget.
package finder

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/model"
)

const DefaultLimit = 30
const DefaultKeep = 3
const DefaultDeadline = 180 * time.Second

type Backend interface {
	Start(context.Context, model.Profile, model.Endpoint, string, int) (*backend.Instance, error)
	Stop(*backend.Instance) error
}
type Check func(context.Context, int) (float64, error)
type Progress func(model.Event)
type Options struct {
	Limit, Keep int
	Deadline    time.Duration
}
type Outcome struct {
	Results   []model.CheckResult
	Checked   int
	Cancelled bool
}
type Finder struct {
	backend Backend
	health  Check
	options Options
	isAlive func(*backend.Instance) bool
}

func New(b Backend, health Check, options Options) *Finder {
	if options.Limit == 0 {
		options.Limit = DefaultLimit
	}
	if options.Keep == 0 {
		options.Keep = DefaultKeep
	}
	if options.Deadline == 0 {
		options.Deadline = DefaultDeadline
	}
	options.Limit = min(options.Limit, DefaultLimit)
	options.Keep = min(options.Keep, DefaultKeep)
	options.Deadline = min(options.Deadline, DefaultDeadline)
	return &Finder{backend: b, health: health, options: options, isAlive: func(i *backend.Instance) bool { return i != nil && i.Process != nil && i.Process.Alive() }}
}

func argumentsError() error {
	return model.E("finder_arguments_invalid", "Некорректные параметры поиска стратегии.")
}
func (f *Finder) Alive(i *backend.Instance) bool { return f.isAlive(i) }
func (f *Finder) budget(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || f.backend == nil || f.health == nil || f.options.Deadline <= 0 || f.options.Limit < 1 || f.options.Keep < 1 {
		return nil, nil, argumentsError()
	}
	budget, cancel := context.WithTimeout(ctx, f.options.Deadline)
	return budget, cancel, nil
}

// Socket deadlines can fire before a context's timer goroutine sets Err. A
// partial final trial must not be reported as fully failed or kept as verified.
func contextFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if end, ok := ctx.Deadline(); ok && !time.Now().Before(end) {
		return context.DeadlineExceeded
	}
	return nil
}

// Only post-launch readiness failures are endpoint trials. Local/unknown start
// failures remain terminal even if cancellation or the trial budget also fires.
func terminalStartup(err error, parent, budget context.Context) error {
	switch model.Code(err) {
	case "proxy_start_failed", "proxy_start_timeout":
		return nil
	case "cancelled", "timeout":
		if contextFailure(parent) != nil || contextFailure(budget) != nil {
			return nil
		}
	}
	return err
}

// A context may expire during a socket read. Its callback owns only this trial;
// keep atomically detaches a verified primary before its old deadline expires.
type trial struct {
	ctx       context.Context
	backend   Backend
	instance  *backend.Instance
	mu        sync.Mutex
	kept      bool
	once      sync.Once
	err       error
	stopWatch func() bool
	watchOnce sync.Once
	done      chan struct{}
}

func watch(ctx context.Context, b Backend, i *backend.Instance) *trial {
	t := &trial{ctx: ctx, backend: b, instance: i, done: make(chan struct{})}
	t.stopWatch = context.AfterFunc(ctx, func() {
		defer close(t.done)
		t.mu.Lock()
		defer t.mu.Unlock()
		if !t.kept {
			t.stop()
		}
	})
	return t
}
func (t *trial) stop() { t.once.Do(func() { t.err = t.backend.Stop(t.instance) }) }
func (t *trial) endWatch() {
	t.watchOnce.Do(func() {
		if !t.stopWatch() {
			<-t.done
		}
	})
}
func (t *trial) release() error {
	t.endWatch()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.kept {
		t.stop()
	}
	return t.err
}
func (t *trial) keep() error {
	t.mu.Lock()
	if err := contextFailure(t.ctx); err != nil {
		t.mu.Unlock()
		return err
	}
	t.kept = true
	t.mu.Unlock()
	t.endWatch()
	return nil
}

func (f *Finder) Search(ctx context.Context, p model.Profile, role string, cache model.Cache, explicit []model.Endpoint, progress Progress) (out Outcome, err error) {
	if !model.ValidRole(role) {
		return out, argumentsError()
	}
	budget, cancel, err := f.budget(ctx)
	if err != nil {
		return out, err
	}
	defer cancel()
	candidates, err := f.Candidates(p, cache, explicit, f.options.Limit)
	if err != nil {
		return out, err
	}
	for _, endpoint := range candidates {
		if contextFailure(ctx) != nil {
			return Outcome{Checked: out.Checked, Cancelled: true}, nil
		}
		if contextFailure(budget) != nil {
			break
		}
		out.Checked++
		if progress != nil {
			progress(model.Event{Stage: "trying", Endpoint: endpoint, Checked: out.Checked, Limit: f.options.Limit, Found: model.Count(len(out.Results))})
		}
		instance, trialErr := f.backend.Start(budget, p, endpoint, role, 0)
		var latency float64
		if trialErr != nil {
			if instance != nil {
				if cleanupErr := f.backend.Stop(instance); cleanupErr != nil {
					return out, cleanupErr
				}
			}
			if fatal := terminalStartup(trialErr, ctx, budget); fatal != nil {
				return out, fatal
			}
		} else if instance != nil {
			t := watch(budget, f.backend, instance)
			latency, trialErr = f.health(budget, instance.Port)
			if trialErr == nil && !f.Alive(instance) {
				trialErr = model.E("proxy_exited", "Прокси завершился во время проверки.")
			}
			if cleanupErr := t.release(); cleanupErr != nil {
				return out, cleanupErr
			}
			if model.Code(trialErr) == "health_setup_failed" {
				return out, trialErr
			}
		} else {
			return out, argumentsError()
		}
		if contextFailure(ctx) != nil {
			return Outcome{Checked: out.Checked, Cancelled: true}, nil
		}
		if contextFailure(budget) != nil {
			break
		}
		if trialErr != nil {
			if progress != nil {
				progress(model.Event{Stage: "failed", Endpoint: endpoint, Checked: out.Checked, Limit: f.options.Limit, Code: model.Code(trialErr)})
			}
		} else {
			out.Results = append(out.Results, model.NewResult(endpoint, latency, role))
			if progress != nil {
				progress(model.Event{Stage: "found", Endpoint: endpoint, Checked: out.Checked, Limit: f.options.Limit, Found: model.Count(len(out.Results))})
			}
		}
		if len(out.Results) >= f.options.Keep {
			break
		}
	}
	if contextFailure(ctx) != nil {
		return Outcome{Checked: out.Checked, Cancelled: true}, nil
	}
	sort.SliceStable(out.Results, func(i, j int) bool { return out.Results[i].LatencyMS < out.Results[j].LatencyMS })
	return out, nil
}

func (f *Finder) Connect(ctx context.Context, p model.Profile, candidates []model.Endpoint, progress Progress) (*backend.Instance, float64, int, error) {
	budget, cancel, err := f.budget(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	defer cancel()
	checked := 0
	for _, endpoint := range candidates {
		if err := contextFailure(ctx); err != nil {
			return nil, 0, checked, err
		}
		if contextFailure(budget) != nil || checked == DefaultLimit {
			break
		}
		if err := endpoint.Validate(); err != nil {
			return nil, 0, checked, err
		}
		checked++
		if progress != nil {
			progress(model.Event{Stage: "trying", Endpoint: endpoint, Checked: checked})
		}
		instance, trialErr := f.backend.Start(budget, p, endpoint, model.Primary, backend.SOCKSPort)
		if trialErr != nil {
			if instance != nil {
				if cleanupErr := f.backend.Stop(instance); cleanupErr != nil {
					return nil, 0, checked, cleanupErr
				}
			}
			if fatal := terminalStartup(trialErr, ctx, budget); fatal != nil {
				return nil, 0, checked, fatal
			}
		} else if instance != nil {
			t := watch(budget, f.backend, instance)
			latency, verifyErr := f.health(budget, instance.Port)
			trialErr = verifyErr
			if trialErr == nil && !f.Alive(instance) {
				trialErr = model.E("proxy_exited", "Прокси завершился во время проверки.")
			}
			if trialErr == nil {
				trialErr = t.keep()
			}
			if cleanupErr := t.release(); cleanupErr != nil {
				return nil, 0, checked, cleanupErr
			}
			if model.Code(trialErr) == "health_setup_failed" {
				return nil, 0, checked, trialErr
			}
			if trialErr == nil {
				if progress != nil {
					progress(model.Event{Stage: "found", Endpoint: endpoint, Checked: checked})
				}
				return instance, latency, checked, nil
			}
		} else {
			return nil, 0, checked, argumentsError()
		}
		if err := contextFailure(ctx); err != nil {
			return nil, 0, checked, err
		}
		if contextFailure(budget) != nil {
			break
		}
		if progress != nil {
			progress(model.Event{Stage: "failed", Endpoint: endpoint, Checked: checked, Code: model.Code(trialErr)})
		}
	}
	return nil, 0, checked, model.E("no_working_endpoint", "Ни один ограниченно проверенный endpoint не прошёл проверку.")
}
