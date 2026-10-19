package controller

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/model"
)

type controllerDiagnostic struct {
	code       string
	endpoint   model.Endpoint
	state      model.State
	recovering bool
	active     *backend.Instance
}

type controllerDiagnostics struct {
	mu         sync.Mutex
	entries    []controllerDiagnostic
	underMutex bool
}

func captureDiagnostics(c *Controller) *controllerDiagnostics {
	d := &controllerDiagnostics{}
	c.options.Log = func(code string, endpoint model.Endpoint) { d.record(c, code, endpoint) }
	return d
}

func (d *controllerDiagnostics) record(c *Controller, code string, endpoint model.Endpoint) bool {
	e := controllerDiagnostic{code: code, endpoint: endpoint}
	unlocked := c.mu.TryLock()
	if unlocked {
		e.state, e.recovering, e.active = c.state, c.recovering, c.active
		c.mu.Unlock()
	}
	d.mu.Lock()
	d.entries = append(d.entries, e)
	d.underMutex = d.underMutex || !unlocked
	d.mu.Unlock()
	return unlocked
}

func (d *controllerDiagnostics) expect(t *testing.T, want ...string) []controllerDiagnostic {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.underMutex {
		t.Error("diagnostic callback ran under Controller.mu")
	}
	var codes []string
	for _, entry := range d.entries {
		codes = append(codes, entry.code)
	}
	if !slices.Equal(codes, want) {
		t.Fatalf("diagnostic order = %v, want %v", codes, want)
	}
	return append([]controllerDiagnostic(nil), d.entries...)
}

func TestPeriodicHealthDiagnosticsSingleFailureAndReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		c, s, _, b, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
			checks++
			switch checks {
			case 1:
				return 0, unhealthy()
			case 3:
				return 0, model.E("health_tls", "Synthetic TLS detail must not be logged.")
			default:
				return 1, nil
			}
		})
		d := captureDiagnostics(c)
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		time.Sleep(time.Second)
		synctest.Wait()
		d.expect(t, "connected", "health_timeout")
		if active(c) != old || !b.alive(old) || c.Status().Recovering {
			t.Fatal("a single diagnostic failure changed recovery behavior")
		}
		for range 3 {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		entries := d.expect(t, "connected", "health_timeout", "health_tls")
		for _, e := range entries {
			if e.endpoint != old.Endpoint || e.state != model.Connected || e.recovering || e.active != old {
				t.Fatal("a periodic failure was not associated with its current connection")
			}
		}
		if checks != 4 || f.count() != 1 || active(c) != old || cacheWrites(s) != 1 {
			t.Fatal("successful checks did not reset the consecutive failure counter")
		}
	})
}

func TestRecoveryDiagnosticsHealthLossOrderAndVerifiedPublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		c, s, _, b, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
			checks++
			if checks == 1 {
				return 0, unhealthy()
			}
			if checks == 2 {
				return 0, model.E("warp_not_enabled", "Synthetic trace body must not be logged.")
			}
			return 1, nil
		})
		release := make(chan struct{})
		f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, _ finder.Progress, n int) (*backend.Instance, float64, int, error) {
			if n > 1 {
				select {
				case <-release:
				case <-ctx.Done():
					return nil, 0, 0, ctx.Err()
				}
			}
			return f.success(ctx, p, queue[0], 1)
		}
		d := captureDiagnostics(c)
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		entries := d.expect(t, "connected", "health_timeout", "warp_not_enabled", "connection_lost")
		start := entries[len(entries)-1]
		if start.endpoint != old.Endpoint || start.state != model.Connecting || !start.recovering || start.active != nil {
			t.Fatal("loss reason was logged before confirmed beginRecovery")
		}
		if f.count() != 2 || b.alive(old) || cacheWrites(s) != 1 {
			t.Fatal("unverified recovery was published or old primary was retained")
		}
		close(release)
		synctest.Wait()
		entries = d.expect(t, "connected", "health_timeout", "warp_not_enabled", "connection_lost", "recovered")
		recovered := entries[len(entries)-1]
		current := active(c)
		if current == nil || current == old || current.Endpoint != f.endpoints[1] || !b.alive(current) || cacheWrites(s) != 2 {
			t.Fatal("verified replacement did not retain existing publication behavior")
		}
		if recovered.endpoint != current.Endpoint || recovered.active != current || recovered.state != model.Connected || recovered.recovering {
			t.Fatal("recovered was logged before replacement publication")
		}
	})
}

func TestRecoveryDiagnosticsExitedEngine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		checks := 0
		c, _, _, b, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
			checks++
			return 1, nil
		})
		d := captureDiagnostics(c)
		c.Connect(false)
		synctest.Wait()
		old := active(c)
		killFake(b, old)
		time.Sleep(time.Second)
		synctest.Wait()
		entries := d.expect(t, "connected", "proxy_exited", "recovered")
		if checks != 0 || f.queue(1)[0] != old.Endpoint || active(c) == old || b.maximumPrimary != 1 {
			t.Fatal("exit diagnosis changed health checks, retry order or primary ownership")
		}
		if entries[1].endpoint != old.Endpoint || entries[1].state != model.Connecting || !entries[1].recovering || entries[1].active != nil {
			t.Fatal("process exit was not logged at recovery start")
		}
		if entries[2].endpoint != active(c).Endpoint || entries[2].active != active(c) || entries[2].state != model.Connected {
			t.Fatal("exit replacement was not published before recovered")
		}
	})
}

func TestPeriodicHealthDiagnosticsClosedCodeAllowlist(t *testing.T) {
	for _, code := range []string{
		"health_failed", "health_timeout", "health_tls", "warp_not_enabled", "external_unavailable", "health_response_large", "health_setup_failed", "proxy_cleanup_failed",
	} {
		t.Run(code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, _, _, _, f := recoveryFixture(t, func(context.Context, int) (float64, error) {
					return 0, model.E(code, "Synthetic private error text must not reach the callback.")
				})
				d := captureDiagnostics(c)
				c.Connect(false)
				synctest.Wait()
				endpoint := active(c).Endpoint
				time.Sleep(time.Second)
				synctest.Wait()
				entries := d.expect(t, "connected", code)
				if entries[1].endpoint != endpoint || f.count() != 1 {
					t.Fatal("health diagnosis changed the endpoint or recovery threshold")
				}
				if code == "health_setup_failed" || code == "proxy_cleanup_failed" {
					if c.Status().State != model.Failed || c.Status().Code != code {
						t.Fatal("fatal health error lost its terminal behavior")
					}
				}
			})
		})
	}
	for _, err := range []error{
		errors.New("Synthetic private exception text"), model.E("arbitrary_private_code", "Synthetic private text"),
		context.Canceled, model.E("cancelled", "Cancelled check"), context.DeadlineExceeded,
	} {
		t.Run(model.Code(err), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, _, _, _, _ := recoveryFixture(t, func(context.Context, int) (float64, error) { return 0, err })
				d := captureDiagnostics(c)
				c.Connect(false)
				synctest.Wait()
				time.Sleep(time.Second)
				synctest.Wait()
				d.expect(t, "connected")
			})
		})
	}
}

func TestRecoveryDiagnosticsCancelledHealthIsNotFailure(t *testing.T) {
	for _, code := range []string{"cancelled", "health_timeout", "health_setup_failed", "proxy_cleanup_failed"} {
		t.Run(code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				c, s, _, b, f := recoveryFixture(t, func(ctx context.Context, _ int) (float64, error) {
					close(started)
					<-ctx.Done()
					return 0, model.E(code, "Late synthetic check result")
				})
				d := captureDiagnostics(c)
				c.Connect(false)
				synctest.Wait()
				old := active(c)
				time.Sleep(time.Second)
				synctest.Wait()
				<-started
				c.Disconnect()
				synctest.Wait()
				d.expect(t, "connected")
				if f.count() != 1 || cacheWrites(s) != 1 || b.alive(old) || c.Status().Recovering {
					t.Fatal("cancelled health check restarted or published a connection")
				}
				if code == "proxy_cleanup_failed" {
					if c.Status().Code != code || c.Status().State != model.Failed {
						t.Fatal("diagnostic suppression changed the mandatory cleanup latch")
					}
				} else if c.Status().State != model.Disconnected {
					t.Fatal("cancelled health check became a state failure")
				}
			})
		})
	}
}

func TestRecoveryDiagnosticsCancelledLateReplacementIsNotRecovered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, s, _, b, f := recoveryFixture(t, nil)
		release := make(chan struct{})
		f.connect = func(ctx context.Context, p model.Profile, queue []model.Endpoint, _ finder.Progress, n int) (*backend.Instance, float64, int, error) {
			i, latency, checked, err := f.success(ctx, p, queue[0], 1)
			if n > 1 {
				<-ctx.Done()
				<-release
			}
			return i, latency, checked, err
		}
		d := captureDiagnostics(c)
		c.Connect(false)
		synctest.Wait()
		killFake(b, active(c))
		time.Sleep(time.Second)
		synctest.Wait()
		d.expect(t, "connected", "proxy_exited")
		c.Disconnect()
		synctest.Wait()
		close(release)
		synctest.Wait()
		d.expect(t, "connected", "proxy_exited")
		if f.count() != 2 || active(c) != nil || cacheWrites(s) != 1 || c.Status().State != model.Disconnected || c.Status().Busy {
			t.Fatal("cancelled late verification escaped ownership or publication guards")
		}
	})
}

func TestRecoveryDiagnosticsCallbackCanDisconnectBeforeRecoveryBegins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, _, _, f := recoveryFixture(t, func(context.Context, int) (float64, error) { return 0, unhealthy() })
		c.options.HealthFailures = 1
		d := &controllerDiagnostics{}
		c.options.Log = func(code string, endpoint model.Endpoint) {
			if d.record(c, code, endpoint) && code == "health_timeout" {
				// This public, locking method must be safe inside the callback.
				c.Disconnect()
			}
		}
		c.Connect(false)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		d.expect(t, "connected", "health_timeout")
		if f.count() != 1 || c.Status().State != model.Disconnected || c.Status().Busy {
			t.Fatal("recovery reason was logged despite a rejected beginRecovery")
		}
	})
}

func TestPeriodicHealthDiagnosticsRejectStaleSessionAndInstance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _, _, _, _ := recoveryFixture(t, nil)
		d := captureDiagnostics(c)
		c.Connect(false)
		synctest.Wait()
		owned := active(c)
		c.mu.Lock()
		id := c.sessionID
		c.mu.Unlock()
		c.logHealthFailure(context.Background(), id+1, owned, unhealthy())
		c.logHealthFailure(context.Background(), id, &backend.Instance{Endpoint: owned.Endpoint}, unhealthy())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.logHealthFailure(ctx, id, owned, unhealthy())
		c.Disconnect()
		synctest.Wait()
		c.logHealthFailure(context.Background(), id, owned, unhealthy())
		d.expect(t, "connected")
	})
}
