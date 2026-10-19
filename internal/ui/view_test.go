package ui

import (
	"image"
	"strings"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"github.com/0FL01/WarpPocket/internal/model"
)

type testController struct {
	state     model.Snapshot
	events    []model.Event
	calls     []string
	afterPoll func()
}

func (c *testController) Status() model.Snapshot { return c.state }
func (c *testController) PollEvents() []model.Event {
	e := c.events
	c.events = nil
	if c.afterPoll != nil {
		hook := c.afterPoll
		c.afterPoll = nil
		hook()
	}
	return e
}
func (c *testController) Connect(consent bool) {
	if consent {
		c.calls = append(c.calls, "connect consent")
	} else {
		c.calls = append(c.calls, "connect")
	}
}
func (c *testController) Disconnect() { c.calls = append(c.calls, "disconnect") }
func (c *testController) StartSearch(consent bool) {
	if consent {
		c.calls = append(c.calls, "search consent")
	} else {
		c.calls = append(c.calls, "search")
	}
}
func (c *testController) CancelSearch() { c.calls = append(c.calls, "cancel search") }
func (c *testController) Close()        { c.calls = append(c.calls, "close") }

type uiFrame struct {
	router input.Router
	ops    op.Ops
	view   *View
	now    time.Time
}

func newUIFrame(c *testController) *uiFrame {
	return &uiFrame{view: NewView(c, func() string { return "Safe diagnostics" }, "Licenses"), now: time.Unix(100, 0)}
}
func (f *uiFrame) layout() layout.Dimensions {
	f.ops.Reset()
	f.view.Update()
	gtx := layout.Context{Ops: &f.ops, Source: f.router.Source(), Now: f.now, Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Constraints: layout.Exact(image.Pt(442, 760))}
	dims := f.view.Layout(gtx)
	f.router.Frame(&f.ops)
	return dims
}

func (f *uiFrame) keyboardClick(tag any, name key.Name) {
	f.router.Source().Execute(key.FocusCmd{Tag: tag})
	f.layout()
	f.router.Queue(key.Event{Name: name, State: key.Press}, key.Event{Name: name, State: key.Release})
	f.layout()
}

func (f *uiFrame) semantic(t *testing.T, label string) input.SemanticDesc {
	t.Helper()
	// Text can have a larger semantic clip than its clickable parent; honor
	// ancestor bounds and disabled state when exercising native hit areas.
	var find func([]input.SemanticNode, bool, image.Rectangle) (input.SemanticDesc, bool)
	find = func(nodes []input.SemanticNode, disabled bool, bounds image.Rectangle) (input.SemanticDesc, bool) {
		for _, node := range nodes {
			desc := node.Desc
			desc.Disabled = disabled || desc.Disabled
			desc.Bounds = desc.Bounds.Intersect(bounds)
			if node.Desc.Label == label {
				return desc, true
			}
			if desc, ok := find(node.Children, desc.Disabled, desc.Bounds); ok {
				return desc, true
			}
		}
		return input.SemanticDesc{}, false
	}
	if desc, ok := find(f.router.AppendSemantics(nil), false, image.Rect(0, 0, 442, 760)); ok {
		return desc
	}
	t.Fatalf("missing native semantic label %q", label)
	return input.SemanticDesc{}
}

func (f *uiFrame) pointerClick(t *testing.T, label string) {
	t.Helper()
	bounds := f.semantic(t, label).Bounds
	if bounds.Empty() {
		t.Fatalf("no native hit area for %q", label)
	}
	pos := f32.Pt(float32(bounds.Min.X+bounds.Dx()/2), float32(bounds.Min.Y+bounds.Dy()/2))
	f.router.Queue(
		pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: pos},
		pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: pos},
	)
	f.layout()
}

func TestStateActionsAndRoutingHint(t *testing.T) {
	if SOCKSAddress != "127.0.0.1:25344" || RoutingHint != "Весь трафик через прокси — WARP, без исключений" {
		t.Fatal("changed network explanation")
	}
	for _, tc := range []struct {
		state               model.State
		searching, busy     bool
		title, action, call string
		enabled             bool
	}{
		{model.Disconnected, false, false, "Отключено", "Подключиться", "connect", true},
		{model.Connecting, false, true, "Подключаемся…", "Отменить", "disconnect", true},
		{model.Connected, true, false, "Подключено через WARP", "Отключиться", "disconnect", true},
		{model.Failed, false, false, "Не удалось подключиться", "Попробовать снова", "connect", true},
		{model.Disconnected, true, false, "Отключено", "Подключиться", "", false},
		{model.Disconnected, false, true, "Отключено", "Подключиться", "", false},
	} {
		t.Run(string(tc.state)+tc.call, func(t *testing.T) {
			c := &testController{state: model.Snapshot{State: tc.state, Searching: tc.searching, Busy: tc.busy}}
			f := newUIFrame(c)
			f.layout()
			title, _, action, _ := f.view.labels()
			if title != tc.title || action != tc.action || f.view.connectEnabled() != tc.enabled {
				t.Fatal(title, action)
			}
			f.view.connect.Click()
			f.layout()
			if tc.call == "" {
				if len(c.calls) != 0 {
					t.Fatal(c.calls)
				}
			} else if len(c.calls) != 1 || c.calls[0] != tc.call {
				t.Fatal(c.calls)
			}
		})
	}
}

func TestProgressUsesCompletedAndPreservesFound(t *testing.T) {
	c := &testController{state: model.Snapshot{State: model.Connected, Searching: true}}
	f := newUIFrame(c)
	c.events = []model.Event{{Type: "search_started", Role: model.Probe}, {Type: "search_progress", Stage: "trying", Checked: 3, Limit: 30, Found: model.Count(1)}}
	f.layout()
	if f.view.completed != 2 || f.view.limit != 30 || f.view.found != 1 {
		t.Fatal("incorrect in-flight progress")
	}
	c.events = []model.Event{{Type: "search_progress", Stage: "failed", Checked: 3, Limit: 30}}
	f.layout()
	if f.view.completed != 3 || f.view.found != 1 {
		t.Fatal("failed stage reset previous successes")
	}
	f.view.search.Click()
	f.layout()
	if len(c.calls) != 1 || c.calls[0] != "cancel search" {
		t.Fatal(c.calls)
	}
	c.state = model.Snapshot{State: model.Disconnected}
	f.view.search.Click()
	f.layout()
	if c.calls[1] != "search" {
		t.Fatal("standalone search changed to connect", c.calls)
	}
}

func TestConsentRequiresCheckboxAndCorrectRole(t *testing.T) {
	for _, role := range []string{model.Primary, model.Probe} {
		t.Run(role, func(t *testing.T) {
			c := &testController{state: model.Snapshot{State: model.Failed}}
			kind := "state"
			if role == model.Probe {
				kind = "search_done"
				c.state.State = model.Connected
			}
			c.events = []model.Event{{Type: kind, Code: "consent_required"}}
			f := newUIFrame(c)
			f.layout()
			if f.view.consent != role || f.view.ack.Value {
				t.Fatal("consent did not open safely")
			}
			f.view.accept.Click()
			f.layout()
			if len(c.calls) != 0 || f.view.consent != role {
				t.Fatal("unchecked agreement accepted")
			}
			f.view.connect.Click()
			f.layout()
			if len(c.calls) != 0 {
				t.Fatal("underlying button active during consent")
			}
			f.view.ack.Value = true
			f.view.accept.Click()
			f.layout()
			want := "connect consent"
			if role == model.Probe {
				want = "search consent"
			}
			if len(c.calls) != 1 || c.calls[0] != want || f.view.consent != "" {
				t.Fatal(c.calls)
			}
		})
	}
	c := &testController{}
	f := newUIFrame(c)
	f.view.consent = model.Primary
	f.view.decline.Click()
	f.layout()
	if len(c.calls) != 0 || f.view.consent != "" {
		t.Fatal("decline created account")
	}
}

func TestClipboardFeedbackDoesNotHideWarning(t *testing.T) {
	c := &testController{events: []model.Event{{Type: "warning", Message: "Не удалось сохранить кеш."}}}
	f := newUIFrame(c)
	f.layout()
	f.view.copy.Click()
	f.layout()
	mime, content, ok := f.router.WriteClipboard()
	if !ok || mime != "application/text" || string(content) != SOCKSAddress {
		t.Fatal("wrong native clipboard command")
	}
	if !f.now.Before(f.view.copyUntil) {
		t.Fatal("no copy feedback")
	}
	f.now = f.now.Add(2 * time.Second)
	f.layout()
	if f.now.Before(f.view.copyUntil) || f.view.notice != "Не удалось сохранить кеш." {
		t.Fatal("copy overwrote persistent warning")
	}
}

func TestMenuImportAndSavedMessages(t *testing.T) {
	c := &testController{state: model.Snapshot{State: model.Connected}}
	f := newUIFrame(c)
	f.layout()
	f.view.items[0].Click()
	f.layout()
	if f.view.importRequest != "" || f.view.info != "" {
		t.Fatal("disabled import created a request or a modal")
	}
	f.view.info = ""
	c.state.State = model.Disconnected
	f.view.items[1].Click()
	f.layout()
	if f.view.importRequest != model.Probe {
		t.Fatal("wrong import role")
	}
	for i, want := range map[int]string{2: "Safe diagnostics", 3: "https://www.cloudflare.com/application/terms/", 4: "Licenses"} {
		f.view.info = ""
		f.view.items[i].Click()
		f.layout()
		if !strings.Contains(f.view.info, want) {
			t.Fatal("missing menu action", i)
		}
	}
	f.view.info = ""
	c.events = []model.Event{{Type: "search_done", Saved: false, Message: "Запись не выполнена."}}
	f.layout()
	if f.view.notice != "Запись не выполнена." {
		t.Fatal("failed write reported saved")
	}
	c.events = []model.Event{{Type: "search_done", Saved: true, Best: model.Endpoint{Host: "188.114.97.1", Port: 4500}}}
	f.layout()
	if !strings.Contains(f.view.notice, "следующего подключения") {
		t.Fatal("search result falsely applied now")
	}
}

func TestNativeKeyboardAndModalEscape(t *testing.T) {
	c := &testController{state: model.Snapshot{State: model.Disconnected}}
	f := newUIFrame(c)
	f.layout()
	f.router.Source().Execute(key.FocusCmd{Tag: &f.view.connect})
	f.layout()
	f.router.Queue(key.Event{Name: key.NameReturn, State: key.Press}, key.Event{Name: key.NameReturn, State: key.Release})
	f.layout()
	if len(c.calls) != 1 || c.calls[0] != "connect" {
		t.Fatal("keyboard connect failed", c.calls)
	}
	f.view.consent = model.Primary
	f.layout()
	f.router.Queue(key.Event{Name: key.NameEscape, State: key.Press})
	f.layout()
	if f.view.consent != "" || len(c.calls) != 1 {
		t.Fatal("Escape did not safely decline")
	}
	if f.view.closing = true; f.view.connectEnabled() || f.view.searchEnabled() || f.view.quiescent() {
		t.Fatal("closing UI still interactive")
	}
}

func TestLongMessagesAndDPILayout(t *testing.T) {
	for _, scale := range []float32{1, 1.25, 1.5} {
		for _, snapshot := range []model.Snapshot{
			{State: model.Disconnected}, {State: model.Connecting}, {State: model.Connected}, {State: model.Failed},
			{State: model.Connecting, Recovering: true, Busy: true, Searching: true},
		} {
			snapshot.Message = strings.Repeat("Подробная безопасная ошибка без секретов. ", 20)
			c := &testController{state: snapshot}
			v := NewView(c, nil, "Лицензии")
			v.Update()
			v.notice = c.state.Message
			var ops op.Ops
			size := image.Pt(int(442*scale), int(620*scale))
			gtx := layout.Context{Ops: &ops, Metric: unit.Metric{PxPerDp: scale, PxPerSp: scale}, Constraints: layout.Exact(size), Now: time.Unix(100, 0)}
			if dims := v.Layout(gtx); dims.Size != size {
				t.Fatalf("layout escaped window at %v: %v", scale, dims)
			}
		}
	}
}
