package controller

import (
	"context"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
)

// latchCleanup is called under mu, even for cancelled/superseded operations.
// Losing the operation's intent does not prove its engine has been stopped.
func (c *Controller) latchCleanup(err error) bool {
	if model.Code(err) != "proxy_cleanup_failed" {
		return false
	}
	first := !c.cleanupFailed
	c.cleanupFailed = true
	if c.cleanupErr == nil {
		c.cleanupErr = err
	}
	if c.connectCancel != nil {
		c.connectCancel()
	}
	if c.searchCancel != nil {
		c.searchCancel()
	}
	if c.healthCancel != nil {
		c.healthCancel()
	}
	c.active, c.result, c.recovering = nil, nil, false
	if !c.closed {
		c.state, c.code, c.message = model.Failed, model.Code(err), model.SafeMessage(err)
		if first {
			c.warning(err)
			c.emitState()
		}
	}
	return true
}

// publishConnection and its caller's current/context/liveness checks are one
// critical section. A cache write failure never stops a verified connection.
func (c *Controller) publishConnection(instance *backend.Instance, latency float64, recovered bool) {
	result := model.NewResult(instance.Endpoint, latency, model.Primary)
	warning := c.store.UpdateCache(func(cache model.Cache) model.Cache {
		cache.LastGood, cache.Preferred = &result, nil
		keep := make([]model.CheckResult, 0, 3)
		seen := map[model.Endpoint]bool{result.Endpoint: true}
		for _, r := range cache.Fallbacks {
			if !seen[r.Endpoint] && len(keep) < 3 {
				keep = append(keep, r)
				seen[r.Endpoint] = true
			}
		}
		cache.Fallbacks = keep
		return cache
	})
	c.active, c.result = instance, &result
	c.state, c.recovering, c.code, c.message = model.Connected, false, "", ""
	if recovered {
		c.emit(model.Event{Type: "state", State: model.Connected, Code: "recovered", Endpoint: result.Endpoint})
	} else {
		c.emitState()
	}
	if warning != nil {
		c.warning(warning)
	} else if !recovered {
		c.emit(model.Event{Type: "saved"})
	}
}

func (c *Controller) sessionCurrent(ctx context.Context, id uint64) bool {
	return !c.closed && !c.cleanupFailed && c.sessionID == id && ctx.Err() == nil
}

// One monitor owns every post-verification instance in a user session. The
// public active pointer is only a view; Disconnect cancels/drains this owner.
func (c *Controller) monitor(ctx context.Context, id uint64, p model.Profile, owned *backend.Instance, done chan struct{}) {
	defer func() {
		if owned != nil {
			c.stop(owned)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessionID == id {
			if c.healthCancel != nil {
				c.healthCancel()
			}
			c.sessionID, c.healthCancel, c.sessionDone = 0, nil, nil
		}
		close(done)
	}()
	var episode recoveryEpisode
	for {
		reason, err := c.monitorConnection(ctx, id, owned, &episode)
		if err != nil {
			c.sessionFailure(ctx, id, err)
			return
		}
		if reason == "" {
			return
		}
		searchDone, current := c.beginRecovery(ctx, id, owned)
		if !current {
			return
		}
		if c.options.Log != nil {
			c.options.Log(reason, owned.Endpoint)
		}
		oldEndpoint := owned.Endpoint
		err = c.stop(owned)
		owned = nil
		if err != nil {
			return
		}
		if searchDone != nil {
			select {
			case <-ctx.Done():
				return
			case <-searchDone:
			}
		}
		owned, err = c.recover(ctx, id, p, oldEndpoint, reason, &episode)
		if err != nil {
			c.sessionFailure(ctx, id, err)
			return
		}
	}
}

func (c *Controller) monitorConnection(ctx context.Context, id uint64, owned *backend.Instance, episode *recoveryEpisode) (string, error) {
	failures := 0
	timer := time.NewTimer(c.options.HealthInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", nil
		case <-timer.C:
		}
		c.mu.Lock()
		current := c.sessionCurrent(ctx, id) && c.active == owned && c.state == model.Connected
		c.mu.Unlock()
		if !current {
			return "", nil
		}
		if !c.finder.Alive(owned) {
			episode.stable = 0
			return "proxy_exited", nil
		}
		_, err := c.health(ctx, owned.Port)
		c.logHealthFailure(ctx, id, owned, err)
		if model.Code(err) == "health_setup_failed" || model.Code(err) == "proxy_cleanup_failed" {
			return "", err
		}
		if ctx.Err() != nil {
			return "", nil
		}
		if err != nil {
			failures++
			episode.stable = 0
		} else {
			failures = 0
			if episode.active {
				episode.stable++
				if episode.stable >= 2 {
					*episode = recoveryEpisode{}
				}
			}
		}
		if failures >= c.options.HealthFailures {
			return "connection_lost", nil
		}
		timer.Reset(c.options.HealthInterval)
	}
}

func (c *Controller) logHealthFailure(ctx context.Context, id uint64, owned *backend.Instance, err error) {
	if c.options.Log == nil {
		return
	}
	code := model.Code(err)
	switch code {
	case "health_failed", "health_timeout", "health_tls", "warp_not_enabled", "external_unavailable", "health_response_large", "health_setup_failed", "proxy_cleanup_failed":
	default:
		return
	}
	// The check may have completed after Disconnect or a superseding session.
	// Only its fixed code and endpoint can escape, never error text or mu.
	c.mu.Lock()
	current := c.sessionCurrent(ctx, id) && c.active == owned && c.state == model.Connected
	c.mu.Unlock()
	if current {
		c.options.Log(code, owned.Endpoint)
	}
}

func (c *Controller) beginRecovery(ctx context.Context, id uint64, owned *backend.Instance) (<-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sessionCurrent(ctx, id) || c.active != owned || c.state != model.Connected {
		return nil, false
	}
	c.active, c.result = nil, nil
	c.state, c.recovering, c.code, c.message = model.Connecting, true, "", ""
	if c.searchCancel != nil {
		c.searchCancel()
	}
	c.emit(model.Event{Type: "state", State: model.Connecting, Code: "recovery_started"})
	return c.searchDone, true
}

func (c *Controller) sessionFailure(ctx context.Context, id uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latchCleanup(err) || !c.sessionCurrent(ctx, id) {
		return
	}
	c.active, c.result, c.recovering = nil, nil, false
	c.state, c.code, c.message = model.Failed, model.Code(err), model.SafeMessage(err)
	if c.searchCancel != nil {
		c.searchCancel()
	}
	if c.healthCancel != nil {
		c.healthCancel()
	}
	c.emitState()
}

type recoveryEpisode struct {
	queue                  []model.Endpoint
	cursor, pauses, stable int
	active                 bool
}

var recoveryDelays = [...]time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

func (e *recoveryEpisode) delay() time.Duration {
	if e.pauses == 0 {
		e.pauses = 1
		return 0
	}
	delay := recoveryDelays[min(e.pauses-1, len(recoveryDelays)-1)]
	if e.pauses < len(recoveryDelays)+1 {
		e.pauses++
	}
	return delay
}

func (c *Controller) recoveryCandidates(ctx context.Context, id uint64, p model.Profile, old model.Endpoint, reason string) ([]model.Endpoint, error) {
	cache, warning := c.store.LoadCache()
	if warning != nil {
		c.mu.Lock()
		if c.sessionCurrent(ctx, id) {
			c.warning(warning)
		}
		c.mu.Unlock()
	}
	list, err := c.finder.Candidates(p, cache, nil, finder.DefaultLimit)
	if err != nil {
		return nil, err
	}
	old, err = model.NewEndpoint(old.Host, old.Port)
	if err != nil {
		return nil, err
	}
	seen := map[model.Endpoint]bool{old: true}
	queue := make([]model.Endpoint, 0, finder.DefaultLimit)
	if reason == "proxy_exited" {
		queue = append(queue, old)
	}
	limit := finder.DefaultLimit - 1
	if reason == "proxy_exited" {
		limit = finder.DefaultLimit
	}
	for _, endpoint := range list {
		endpoint, err = model.NewEndpoint(endpoint.Host, endpoint.Port)
		if err != nil {
			return nil, err
		}
		if !seen[endpoint] && len(queue) < limit {
			queue = append(queue, endpoint)
			seen[endpoint] = true
		}
	}
	if reason != "proxy_exited" {
		queue = append(queue, old)
	}
	return queue, nil
}

func (c *Controller) recoveringCurrent(ctx context.Context, id uint64) bool {
	return c.sessionCurrent(ctx, id) && c.state == model.Connecting && c.recovering && c.active == nil && c.searchID == 0
}

func (c *Controller) recover(ctx context.Context, id uint64, p model.Profile, old model.Endpoint, reason string, episode *recoveryEpisode) (kept *backend.Instance, err error) {
	var trial *backend.Instance
	defer func() {
		if trial != nil {
			if cleanupErr := c.stop(trial); cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	for {
		c.mu.Lock()
		current := c.recoveringCurrent(ctx, id)
		c.mu.Unlock()
		if !current {
			return nil, context.Canceled
		}
		if !episode.active || episode.cursor >= len(episode.queue) {
			order := reason
			if episode.active {
				order = "connection_lost"
			}
			episode.queue, err = c.recoveryCandidates(ctx, id, p, old, order)
			if err != nil {
				return nil, err
			}
			episode.active, episode.cursor = true, 0
		}
		if delay := episode.delay(); delay != 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		c.mu.Lock()
		current = c.recoveringCurrent(ctx, id)
		c.mu.Unlock()
		if !current {
			return nil, context.Canceled
		}
		base, completed := episode.cursor, 0
		progress := func(event model.Event) {
			// Finder callbacks are synchronous. Count completed trials locally,
			// not through the GUI queue or the count of deadline-partial starts.
			if event.Stage == "failed" {
				completed = max(completed, event.Checked)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.recoveringCurrent(ctx, id) {
				event.Type = "connect_progress"
				c.emit(event)
			}
		}
		var latency float64
		var checked int
		trial, latency, checked, err = c.finder.Connect(ctx, p.Clone(), episode.queue[base:], progress)
		if err != nil {
			c.mu.Lock()
			fatalCleanup := c.latchCleanup(err)
			c.mu.Unlock()
			if fatalCleanup {
				return nil, err
			}
			if trial != nil {
				cleanupErr := c.stop(trial)
				trial = nil
				if cleanupErr != nil {
					return nil, cleanupErr
				}
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if model.Code(err) != "no_working_endpoint" {
				return nil, err
			}
			episode.cursor = min(base+completed, len(episode.queue))
			continue
		}
		episode.cursor, episode.stable = min(base+checked, len(episode.queue)), 0
		c.mu.Lock()
		if !c.recoveringCurrent(ctx, id) {
			c.mu.Unlock()
			return nil, context.Canceled
		}
		if !c.finder.Alive(trial) {
			c.mu.Unlock()
			cleanupErr := c.stop(trial)
			trial = nil
			if cleanupErr != nil {
				return nil, cleanupErr
			}
			continue
		}
		c.publishConnection(trial, latency, true)
		c.mu.Unlock()
		kept, trial = trial, nil
		if c.options.Log != nil {
			c.options.Log("recovered", kept.Endpoint)
		}
		return kept, nil
	}
}
