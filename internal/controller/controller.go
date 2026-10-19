// Package controller serializes application intent and ownership. Workers may
// publish typed values, never mutate GUI widgets or commit a cancelled result.
package controller

import (
	"context"
	"sync"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
)

type Store interface {
	LoadCache() (model.Cache, error)
	UpdateCache(func(model.Cache) model.Cache) error
	ClearRuntime() error
}
type Profiles interface {
	EnsureProfile(context.Context, string, bool) (model.Profile, error)
	EnsureReserved(context.Context, string) (model.Profile, error)
}
type Finder interface {
	Candidates(model.Profile, model.Cache, []model.Endpoint, int) ([]model.Endpoint, error)
	Search(context.Context, model.Profile, string, model.Cache, []model.Endpoint, finder.Progress) (finder.Outcome, error)
	Connect(context.Context, model.Profile, []model.Endpoint, finder.Progress) (*backend.Instance, float64, int, error)
	Alive(*backend.Instance) bool
}
type Manager interface{ Shutdown() error }
type Options struct {
	HealthInterval time.Duration
	HealthFailures int
	Log            func(string, model.Endpoint)
}

type Controller struct {
	mu                                        sync.Mutex
	store                                     Store
	profiles                                  Profiles
	backend                                   finder.Backend
	finder                                    Finder
	manager                                   Manager
	health                                    finder.Check
	options                                   Options
	life                                      context.Context
	cancelLife                                context.CancelFunc
	wg                                        sync.WaitGroup
	closeOnce                                 sync.Once
	closeDone                                 chan struct{}
	closed, disconnecting, cleanupFailed      bool
	closeErr                                  error
	cleanupErr                                error
	state                                     model.State
	recovering                                bool
	code, message                             string
	active                                    *backend.Instance
	result                                    *model.CheckResult
	sequence, connectID, searchID             uint64
	sessionID                                 uint64
	sessionDone, searchDone                   chan struct{}
	connectCancel, searchCancel, healthCancel context.CancelFunc
	searchRole                                string
	events                                    []model.Event
}

func New(store Store, profiles Profiles, b finder.Backend, f Finder, manager Manager, health finder.Check, options Options) *Controller {
	if options.HealthInterval <= 0 {
		options.HealthInterval = 30 * time.Second
	}
	if options.HealthFailures <= 0 {
		options.HealthFailures = 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{store: store, profiles: profiles, backend: b, finder: f, manager: manager, health: health, options: options,
		life: ctx, cancelLife: cancel, closeDone: make(chan struct{}), state: model.Disconnected}
}

func (c *Controller) Status() model.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := model.Snapshot{State: c.state, Code: c.code, Message: c.message, Searching: c.searchID != 0,
		Busy:       c.disconnecting || c.cleanupFailed || c.recovering || c.connectCancel != nil && c.state != model.Connected || c.sessionID != 0 && c.state != model.Connected,
		Recovering: c.recovering, SearchRole: c.searchRole}
	if c.result != nil {
		s.Endpoint = c.result.Endpoint
		s.LatencyMS = c.result.LatencyMS
	}
	return s
}
func (c *Controller) PollEvents() []model.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events
	c.events = nil
	return events
}
func (c *Controller) emit(event model.Event) {
	if event.Found != nil {
		event.Found = model.Count(*event.Found)
	}
	c.events = append(c.events, event)
}
func (c *Controller) emitState() {
	event := model.Event{Type: "state", State: c.state, Code: c.code, Message: c.message}
	if c.result != nil {
		event.Endpoint = c.result.Endpoint
	}
	c.emit(event)
}
func (c *Controller) warning(err error) {
	c.emit(model.Event{Type: "warning", Code: model.Code(err), Message: model.SafeMessage(err)})
}
func (c *Controller) spawn(fn func()) { c.wg.Add(1); go func() { defer c.wg.Done(); fn() }() }

func (c *Controller) Connect(consent bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.state == model.Connecting || c.state == model.Connected || c.disconnecting || c.cleanupFailed || c.connectCancel != nil || c.sessionID != 0 {
		return
	}
	if c.searchID != 0 {
		c.emit(model.Event{Type: "error", Code: "search_active", Message: "Дождитесь завершения поиска или отмените его."})
		return
	}
	c.sequence++
	id := c.sequence
	c.connectID = id
	ctx, cancel := context.WithCancel(c.life)
	c.connectCancel = cancel
	c.state = model.Connecting
	c.recovering = false
	c.code = ""
	c.message = ""
	c.emitState()
	c.spawn(func() { c.connect(ctx, id, consent) })
}

func (c *Controller) connectCurrent(id uint64) bool {
	return !c.closed && !c.cleanupFailed && c.connectID == id && c.state == model.Connecting && !c.recovering
}
func (c *Controller) connect(ctx context.Context, id uint64, consent bool) {
	var instance *backend.Instance
	defer func() {
		if instance != nil {
			c.stop(instance)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.connectID == id {
			if c.connectCancel != nil {
				c.connectCancel()
			}
			c.connectCancel = nil
			c.connectID = 0
		}
	}()
	_, err := c.profiles.EnsureProfile(ctx, model.Primary, consent)
	if err != nil {
		c.connectFailure(ctx, id, err)
		return
	}
	p, err := c.profiles.EnsureReserved(ctx, model.Primary)
	if err != nil {
		c.connectFailure(ctx, id, err)
		return
	}
	cache, warning := c.store.LoadCache()
	if warning != nil {
		c.mu.Lock()
		if c.connectCurrent(id) {
			c.warning(warning)
		}
		c.mu.Unlock()
	}
	candidates, err := c.finder.Candidates(p, cache, nil, finder.DefaultLimit)
	if err != nil {
		c.connectFailure(ctx, id, err)
		return
	}
	progress := func(event model.Event) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.connectCurrent(id) && ctx.Err() == nil {
			event.Type = "connect_progress"
			c.emit(event)
		}
	}
	var latency float64
	instance, latency, _, err = c.finder.Connect(ctx, p, candidates, progress)
	if err != nil {
		c.connectFailure(ctx, id, err)
		return
	}
	c.mu.Lock()
	if !c.connectCurrent(id) || ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	if !c.finder.Alive(instance) {
		c.mu.Unlock()
		c.connectFailure(ctx, id, model.E("proxy_exited", "Сетевой компонент завершился во время проверки."))
		return
	}
	c.publishConnection(instance, latency, false)
	if c.connectCancel != nil {
		c.connectCancel()
	}
	c.connectCancel = nil
	c.connectID = 0
	monitorCtx, cancel := context.WithCancel(c.life)
	c.healthCancel = cancel
	c.sessionID = id
	done := make(chan struct{})
	c.sessionDone = done
	owned := instance
	instance = nil
	prepared := p.Clone()
	c.spawn(func() { c.monitor(monitorCtx, id, prepared, owned, done) })
	c.mu.Unlock()
	if c.options.Log != nil {
		c.options.Log("connected", owned.Endpoint)
	}
}

func (c *Controller) connectFailure(ctx context.Context, id uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latchCleanup(err) {
		return
	}
	if !c.connectCurrent(id) {
		return
	}
	if ctx.Err() != nil || model.Code(err) == "cancelled" {
		c.state = model.Disconnected
		c.code = ""
		c.message = ""
	} else {
		c.state = model.Failed
		c.code = model.Code(err)
		c.message = model.SafeMessage(err)
	}
	c.emitState()
}

func (c *Controller) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.active = nil
	c.result = nil
	c.state = model.Disconnected
	c.recovering = false
	c.code = ""
	c.message = ""
	if c.connectCancel != nil {
		c.connectCancel()
	}
	if c.searchCancel != nil {
		c.searchCancel()
	}
	if c.healthCancel != nil {
		c.healthCancel()
	}
	c.emitState()
	// Cancellation must happen even during an earlier cleanup/drain. The
	// monitor is the sole post-verification owner, not this public method.
	if c.disconnecting {
		return
	}
	c.disconnecting = true
	sessionDone, searchDone := c.sessionDone, c.searchDone
	c.spawn(func() {
		if sessionDone != nil {
			<-sessionDone
		}
		if searchDone != nil {
			<-searchDone
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.disconnecting = false
		c.emitState()
	})
}

func (c *Controller) StartSearch(consent bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.searchID != 0 {
		return
	}
	if c.state == model.Connecting || c.connectCancel != nil || c.disconnecting || c.cleanupFailed || c.sessionID != 0 && c.state != model.Connected {
		c.emit(model.Event{Type: "error", Code: "busy", Message: "Дождитесь завершения подключения или очистки."})
		return
	}
	role := model.Primary
	if c.state == model.Connected {
		role = model.Probe
	}
	c.sequence++
	id := c.sequence
	c.searchID = id
	c.searchRole = role
	ctx, cancel := context.WithCancel(c.life)
	c.searchCancel = cancel
	done := make(chan struct{})
	c.searchDone = done
	c.emit(model.Event{Type: "search_started", Role: role})
	c.spawn(func() {
		defer func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.endSearch(id)
			if c.searchDone == done {
				c.searchDone = nil
			}
			close(done)
		}()
		c.search(ctx, id, role, consent)
	})
}
func (c *Controller) CancelSearch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.searchCancel != nil {
		c.searchCancel()
	}
}
func (c *Controller) searchCurrent(id uint64) bool {
	return !c.closed && !c.cleanupFailed && c.searchID == id
}
func (c *Controller) endSearch(id uint64) {
	if c.searchID == id {
		if c.searchCancel != nil {
			c.searchCancel()
		}
		c.searchID = 0
		c.searchCancel = nil
		c.searchRole = ""
	}
}
func (c *Controller) search(ctx context.Context, id uint64, role string, consent bool) {
	var p model.Profile
	var err error
	if role == model.Probe {
		_, err = c.profiles.EnsureProfile(ctx, role, consent)
	}
	if err == nil {
		p, err = c.profiles.EnsureReserved(ctx, role)
	}
	if err != nil {
		c.searchFailure(ctx, id, err)
		return
	}
	cache, warning := c.store.LoadCache()
	if warning != nil {
		c.mu.Lock()
		if c.searchCurrent(id) {
			c.warning(warning)
		}
		c.mu.Unlock()
	}
	progress := func(event model.Event) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.searchCurrent(id) && ctx.Err() == nil {
			event.Type = "search_progress"
			c.emit(event)
		}
	}
	outcome, err := c.finder.Search(ctx, p, role, cache, nil, progress)
	if err != nil {
		c.searchFailure(ctx, id, err)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Cancellation and persistence share this critical section. No late result
	// can overwrite preferred after CancelSearch, Disconnect or Close returns.
	if !c.searchCurrent(id) || ctx.Err() != nil || outcome.Cancelled {
		c.endSearch(id)
		if !c.closed && !c.recovering {
			c.emit(model.Event{Type: "search_cancelled"})
		}
		return
	}
	if len(outcome.Results) == 0 {
		c.endSearch(id)
		c.emit(model.Event{Type: "search_done", Checked: outcome.Checked, Found: model.Count(0), Code: "no_working_endpoint", Message: "Рабочие эндпоинты не найдены; сохранённые варианты не изменены."})
		return
	}
	best := outcome.Results[0]
	warning = c.store.UpdateCache(func(cache model.Cache) model.Cache {
		seen := map[model.Endpoint]bool{best.Endpoint: true}
		rest := make([]model.CheckResult, 0, 3)
		for _, r := range append(append([]model.CheckResult(nil), outcome.Results[1:]...), cache.Fallbacks...) {
			if !seen[r.Endpoint] && len(rest) < 3 {
				seen[r.Endpoint] = true
				rest = append(rest, r)
			}
		}
		cache.Preferred = &best
		cache.Fallbacks = rest
		return cache
	})
	c.endSearch(id)
	c.emit(model.Event{Type: "search_done", Found: model.Count(len(outcome.Results)), Checked: outcome.Checked, Saved: warning == nil, Role: role, Best: best.Endpoint})
	if warning != nil {
		c.warning(warning)
	}
}
func (c *Controller) searchFailure(ctx context.Context, id uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latchCleanup(err) {
		c.endSearch(id)
		return
	}
	if ctx.Err() != nil || !c.searchCurrent(id) {
		c.endSearch(id)
		if !c.closed && !c.recovering {
			c.emit(model.Event{Type: "search_cancelled"})
		}
		return
	}
	c.endSearch(id)
	c.emit(model.Event{Type: "search_done", Found: model.Count(0), Code: model.Code(err), Message: model.SafeMessage(err)})
}

func (c *Controller) stop(instance *backend.Instance) error {
	if err := c.backend.Stop(instance); err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		// A Stop error is unsafe irrespective of its backend representation.
		if !c.latchCleanup(err) {
			err = model.E("proxy_cleanup_failed", "Не удалось подтвердить остановку сетевого процесса.")
			c.latchCleanup(err)
		}
		return err
	}
	return nil
}

// Close is synchronous and idempotent, including concurrent calls. The UI calls
// it outside its event loop and waits for the resulting completion signal.
func (c *Controller) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancelLife()
		if c.connectCancel != nil {
			c.connectCancel()
		}
		if c.searchCancel != nil {
			c.searchCancel()
		}
		if c.healthCancel != nil {
			c.healthCancel()
		}
		c.active = nil
		c.result = nil
		c.state = model.Disconnected
		c.recovering = false
		c.mu.Unlock()
		managerErr := c.manager.Shutdown()
		c.wg.Wait()
		var runtimeErr error
		if managerErr == nil {
			runtimeErr = c.store.ClearRuntime()
		}
		c.mu.Lock()
		if managerErr != nil {
			c.closeErr = managerErr
		} else if runtimeErr != nil {
			c.closeErr = runtimeErr
		} else {
			c.closeErr = c.cleanupErr
		}
		c.mu.Unlock()
		close(c.closeDone)
	})
	<-c.closeDone
}
func (c *Controller) CloseError() error { c.mu.Lock(); defer c.mu.Unlock(); return c.closeErr }
