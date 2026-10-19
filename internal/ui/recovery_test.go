package ui

import (
	"fmt"
	"strings"
	"testing"

	"gioui.org/io/key"
	"github.com/0FL01/WarpPocket/internal/model"
)

func recoveryStarted() model.Event {
	return model.Event{Type: "state", State: model.Connecting, Code: "recovery_started"}
}

func recoverySucceeded() model.Event {
	return model.Event{Type: "state", State: model.Connected, Code: "recovered"}
}

func recoveringSnapshot(searching bool) model.Snapshot {
	return model.Snapshot{State: model.Connecting, Recovering: true, Busy: true, Searching: searching}
}

func recoveredSnapshot() model.Snapshot {
	return model.Snapshot{State: model.Connected, Endpoint: model.Endpoint{Host: "188.114.97.2", Port: 4500}, LatencyMS: 31}
}

func obsoleteProbeEvents() []model.Event {
	return []model.Event{
		{Type: "search_done", Code: "consent_required"},
		{Type: "error", Code: "busy", Message: "Старый компонент остановлен."},
		{Type: "state", State: model.Failed, Code: "connection_lost", Message: "Старое соединение остановлено."},
		{Type: "search_progress", Stage: "trying", Checked: 29, Limit: 30, Found: model.Count(4), Endpoint: model.Endpoint{Host: "188.114.97.1", Port: 4500}},
		{Type: "search_cancelled"},
		{Type: "search_done", Saved: true, Best: model.Endpoint{Host: "188.114.97.1", Port: 4500}},
		{Type: "saved"},
	}
}

func assertNoObsoleteProbe(t *testing.T, v *View) {
	t.Helper()
	if v.consent != "" || v.ack.Value || v.completed != 0 || v.limit != 0 || v.found != 0 || v.progressEndpoint != "" {
		t.Fatalf("obsolete probe presentation: consent=%q ack=%v progress=%d/%d found=%d endpoint=%q", v.consent, v.ack.Value, v.completed, v.limit, v.found, v.progressEndpoint)
	}
}

func TestRecoveryLabelsDisabledControlsAndNativeInput(t *testing.T) {
	for _, searching := range []bool{false, true} {
		t.Run(fmt.Sprintf("settling-probe-%v", searching), func(t *testing.T) {
			c := &testController{state: recoveringSnapshot(searching), events: []model.Event{recoveryStarted()}}
			f := newUIFrame(c)
			f.layout()
			title, _, action, dot := f.view.labels()
			if title != "Восстанавливаем соединение…" || action != "Отключиться" || dot != blue || !f.view.connectEnabled() || f.view.searchEnabled() || f.view.quiescent() {
				t.Fatal("incorrect recovery labels or controls", title, action)
			}
			if f.view.endpointText() != "Активный endpoint: —" {
				t.Fatal("recovery shows an obsolete active endpoint")
			}
			if desc := f.semantic(t, "Найти новую стратегию"); !desc.Disabled {
				t.Fatal("search is not a genuinely disabled native widget")
			}
			f.pointerClick(t, "Найти новую стратегию")
			f.keyboardClick(&f.view.search, key.NameReturn)
			f.view.search.Click() // Programmatic input must pass the same guard.
			f.layout()
			f.pointerClick(t, "Настройки")
			if !f.view.menuOpen {
				t.Fatalf("native menu click did not open menu: %+v", f.semantic(t, "Настройки"))
			}
			for i, label := range []string{"Импорт основного профиля…", "Импорт проверочного профиля…"} {
				if desc := f.semantic(t, label); !desc.Disabled {
					t.Fatal("import is not a genuinely disabled native widget", label)
				}
				f.pointerClick(t, label)
				f.keyboardClick(&f.view.items[i], key.NameReturn)
				f.view.items[i].Click()
				f.layout()
				if f.view.importRequest != "" || f.view.info != "" || len(c.calls) != 0 {
					t.Fatal("blocked search/import produced work or a modal", c.calls)
				}
				if !f.view.menuOpen {
					f.pointerClick(t, "Настройки")
				}
			}
			f.pointerClick(t, "Настройки")
			if desc := f.semantic(t, "Отключиться"); desc.Disabled {
				t.Fatal("recovery disconnect is disabled")
			}
			f.keyboardClick(&f.view.connect, key.NameReturn)
			if len(c.calls) != 1 || c.calls[0] != "disconnect" {
				t.Fatal("native recovery action did not disconnect", c.calls)
			}
		})
	}
}

func TestRecoveryProgressOverridesSettlingProbe(t *testing.T) {
	c := &testController{state: model.Snapshot{State: model.Connected, Searching: true}}
	f := newUIFrame(c)
	c.events = []model.Event{{Type: "search_started", Role: model.Probe}, {Type: "search_progress", Checked: 12, Limit: 30, Found: model.Count(3), Endpoint: model.Endpoint{Host: "188.114.97.1", Port: 4500}}}
	f.layout()
	if head, endpoint, determinate := f.view.progressPresentation(); !determinate || !strings.Contains(head, "12 / 30") || endpoint == "" {
		t.Fatal("ordinary probe progress changed", head, endpoint, determinate)
	}
	c.state = recoveringSnapshot(true)
	c.events = append([]model.Event{recoveryStarted()}, obsoleteProbeEvents()...)
	f.layout()
	assertNoObsoleteProbe(t, f.view)
	// The renderer must prioritize recovery even if counts survive in widget
	// state while a canceled search's snapshot still says Searching.
	f.view.completed, f.view.limit, f.view.found = 29, 30, 4
	f.view.progressEndpoint = "188.114.97.1:4500"
	if head, endpoint, determinate := f.view.progressPresentation(); head != "Восстанавливаем соединение…" || endpoint != "" || determinate {
		t.Fatal("recovery leaked determinate probe progress", head, endpoint, determinate)
	}
	c.state.Searching = false
	f.layout()
	if _, endpoint, determinate := f.view.progressPresentation(); endpoint != "" || determinate {
		t.Fatal("settled recovery became determinate")
	}
	if f.view.notice != "" {
		t.Fatal("obsolete probe notice during recovery", f.view.notice)
	}
}

func TestRecoveryBatchesInvalidateOpenAndQueuedProbeConsent(t *testing.T) {
	for _, opened := range []bool{false, true} {
		for _, order := range []string{"before-start", "during-recovery", "after-success"} {
			t.Run(fmt.Sprintf("open-%v-%s", opened, order), func(t *testing.T) {
				c := &testController{state: model.Snapshot{State: model.Connected}}
				f := newUIFrame(c)
				if opened {
					c.events = []model.Event{{Type: "search_started", Role: model.Probe}, {Type: "search_done", Code: "consent_required"}}
				}
				f.layout()
				if opened {
					f.keyboardClick(&f.view.ack, key.NameSpace)
					if !f.view.ack.Value || f.view.consent != model.Probe {
						t.Fatal("probe consent fixture was not acknowledged through native input")
					}
					f.view.accept.Click() // Already queued when recovery supersedes it.
				}
				f.view.notice = "Старое сообщение."
				c.state = recoveredSnapshot() // Whole recovery completed between frames.
				stale := obsoleteProbeEvents()
				switch order {
				case "before-start":
					c.events = append(stale, recoveryStarted(), recoverySucceeded())
				case "during-recovery":
					c.events = append([]model.Event{recoveryStarted()}, stale...)
					c.events = append(c.events, recoverySucceeded())
				case "after-success":
					c.events = append([]model.Event{recoveryStarted(), recoverySucceeded()}, stale...)
				}
				f.layout()
				assertNoObsoleteProbe(t, f.view)
				if f.view.notice != "Соединение восстановлено." || len(c.calls) != 0 || !strings.Contains(f.view.endpointText(), "188.114.97.2:4500") {
					t.Fatal("batched recovery left an obsolete outcome", f.view.notice, c.calls)
				}
				if title, _, _, _ := f.view.labels(); title != "Подключено через WARP" {
					t.Fatal("final connected snapshot was rendered as recovery", title)
				}
				c.events = obsoleteProbeEvents()
				f.layout()
				assertNoObsoleteProbe(t, f.view)
				if f.view.notice != "Соединение восстановлено." {
					t.Fatal("late canceled probe overwrote restored notice", f.view.notice)
				}
				c.events = append([]model.Event{{Type: "warning", Code: "cache_write_failed", Message: "Не удалось сохранить кеш."}}, obsoleteProbeEvents()...)
				f.layout()
				if f.view.notice != "Не удалось сохранить кеш." || f.view.state.State != model.Connected {
					t.Fatal("cache warning was hidden or disconnected recovery", f.view.notice)
				}
				// Only the new controller search_started makes probe consent current.
				f.keyboardClick(&f.view.search, key.NameReturn)
				if len(c.calls) != 1 || c.calls[0] != "search" {
					t.Fatal("new connected search was not available", c.calls)
				}
				c.events = []model.Event{{Type: "search_started", Role: model.Probe}, {Type: "search_done", Code: "consent_required"}}
				f.layout()
				if f.view.consent != model.Probe || f.view.ack.Value || len(c.calls) != 1 {
					t.Fatal("new probe consent was suppressed or inherited old acknowledgement", c.calls)
				}
				f.keyboardClick(&f.view.accept, key.NameReturn)
				if len(c.calls) != 1 {
					t.Fatal("new consent accepted without its own checkbox", c.calls)
				}
				f.keyboardClick(&f.view.ack, key.NameSpace)
				f.keyboardClick(&f.view.accept, key.NameReturn)
				if len(c.calls) != 2 || c.calls[1] != "search consent" {
					t.Fatal("fresh probe consent did not work", c.calls)
				}
			})
		}
	}
}

func TestRecoveryAndNewProbeConsentInOneBatch(t *testing.T) {
	c := &testController{state: recoveredSnapshot(), events: []model.Event{
		recoveryStarted(), recoverySucceeded(), {Type: "search_cancelled"},
		{Type: "search_started", Role: model.Probe}, {Type: "search_done", Code: "consent_required"},
	}}
	f := newUIFrame(c)
	f.view.consent, f.view.ack.Value = model.Probe, true
	f.view.accept.Click()
	f.layout()
	if f.view.consent != model.Probe || f.view.ack.Value || len(c.calls) != 0 || f.view.notice != "" {
		t.Fatal("batch confused a new probe request with the superseded one", c.calls, f.view.notice)
	}
}

func TestRecoveryCacheWarningWinsInSuccessBatch(t *testing.T) {
	c := &testController{state: recoveredSnapshot(), events: []model.Event{
		recoveryStarted(), recoverySucceeded(),
		{Type: "warning", Code: "cache_write_failed", Message: "Не удалось сохранить кеш."},
	}}
	c.events = append(c.events, obsoleteProbeEvents()...)
	f := newUIFrame(c)
	f.layout()
	assertNoObsoleteProbe(t, f.view)
	if f.view.notice != "Не удалось сохранить кеш." || f.view.state.State != model.Connected || f.view.state.Code != "" || f.view.state.Recovering {
		t.Fatal("cache warning lost priority in a batched recovery", f.view.notice, f.view.state)
	}
	f.layout()
	if f.view.notice != "Не удалось сохранить кеш." {
		t.Fatal("cache warning did not persist after recovery")
	}
}

func TestRecoverySnapshotAndEventPollingAreNotAtomic(t *testing.T) {
	t.Run("snapshot-advances-to-connected-while-polling", func(t *testing.T) {
		c := &testController{state: recoveringSnapshot(true), events: []model.Event{recoveryStarted(), recoverySucceeded()}}
		c.afterPoll = func() { c.state = recoveredSnapshot() }
		f := newUIFrame(c)
		f.layout()
		if f.view.state.State != model.Connected || f.view.state.Recovering || f.view.notice != "Соединение восстановлено." {
			t.Fatal("stale snapshot hid batched recovery success", f.view.state, f.view.notice)
		}
	})
	t.Run("snapshot-invalidates-consent-before-recovery-event-is-polled", func(t *testing.T) {
		c := &testController{state: model.Snapshot{State: model.Connected}, events: []model.Event{{Type: "search_done", Code: "consent_required"}}}
		c.afterPoll = func() {
			c.state = recoveringSnapshot(true)
			c.events = []model.Event{recoveryStarted()}
		}
		f := newUIFrame(c)
		f.layout()
		assertNoObsoleteProbe(t, f.view)
		c.state = recoveredSnapshot()
		c.events = append(c.events, recoverySucceeded())
		f.layout()
		if f.view.notice != "Соединение восстановлено." {
			t.Fatal("delayed recovery events lost success notice", f.view.notice)
		}
	})
}

func TestRecoveryPresentationResetsOnEveryExit(t *testing.T) {
	for _, exit := range []string{"success", "fatal", "disconnect", "manual", "close"} {
		t.Run(exit, func(t *testing.T) {
			c := &testController{state: recoveringSnapshot(true), events: []model.Event{recoveryStarted()}}
			f := newUIFrame(c)
			f.layout()
			f.view.notice = "Устаревший исход."
			f.view.progressEndpoint = "188.114.97.1:4500"
			f.view.completed, f.view.limit, f.view.found = 29, 30, 4
			f.view.consent, f.view.ack.Value = model.Probe, true
			wantNotice := ""
			switch exit {
			case "success":
				c.state, c.events = recoveredSnapshot(), []model.Event{recoverySucceeded()}
				wantNotice = "Соединение восстановлено."
			case "fatal":
				c.state = model.Snapshot{State: model.Failed, Code: "proxy_cleanup_failed", Message: "Не удалось очистить компонент."}
				c.events = []model.Event{{Type: "state", State: model.Failed, Code: c.state.Code, Message: c.state.Message}}
				c.events = append(c.events, obsoleteProbeEvents()...)
				wantNotice = c.state.Message
			case "disconnect":
				c.state = model.Snapshot{State: model.Disconnected}
				c.events = append([]model.Event{{Type: "state", State: model.Disconnected}}, obsoleteProbeEvents()...)
			case "manual":
				c.state = model.Snapshot{State: model.Connecting, Busy: true}
				c.events = []model.Event{{Type: "state", State: model.Connecting}}
			case "close":
				f.view.closing = true
				f.view.info, f.view.menuOpen, f.view.importRequest = "Старый диалог", true, model.Probe
				c.events = append([]model.Event{recoverySucceeded()}, obsoleteProbeEvents()...)
			}
			f.layout()
			assertNoObsoleteProbe(t, f.view)
			if title, _, _, _ := f.view.labels(); title == "Восстанавливаем соединение…" || f.view.notice != wantNotice {
				t.Fatal("recovery presentation did not reset", title, f.view.notice)
			}
			if exit == "manual" {
				title, _, action, _ := f.view.labels()
				if title != "Подключаемся…" || action != "Отменить" {
					t.Fatal("new manual attempt inherited recovery labels", title, action)
				}
				c.state = model.Snapshot{State: model.Failed, Code: "consent_required"}
				c.events = []model.Event{{Type: "state", State: model.Failed, Code: "consent_required"}}
				f.layout()
				if f.view.consent != model.Primary || f.view.ack.Value {
					t.Fatal("new initial primary consent was not handled normally")
				}
			}
			if exit == "close" && (f.view.info != "" || f.view.menuOpen || f.view.importRequest != "" || f.view.connectEnabled() || f.view.searchEnabled()) {
				t.Fatal("closing retained recovery UI/input")
			}
		})
	}
}
