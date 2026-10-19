// Package ui is the one-window native Gio interface. Controller work never runs
// in a layout callback; all widget and modal state belongs to the event loop.
package ui

import (
	"fmt"
	"image"
	"image/color"
	"io"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/io/clipboard"
	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/0FL01/WarpPocket/internal/model"
)

const SOCKSAddress = "127.0.0.1:25344"
const RoutingHint = "RU/РФ/SU и VK — напрямую; остальное — WARP"

type Controller interface {
	Status() model.Snapshot
	PollEvents() []model.Event
	Connect(consent bool)
	Disconnect()
	StartSearch(probeConsent bool)
	CancelSearch()
	Close()
}

type View struct {
	controller                  Controller
	theme                       *material.Theme
	state                       model.Snapshot
	connect, search, copy, menu widget.Clickable
	items                       [5]widget.Clickable
	accept, decline, dismiss    widget.Clickable
	ack                         widget.Bool
	list, modalList             widget.List
	menuOpen                    bool
	consent, info, notice       string
	completed, limit, found     int
	progressEndpoint            string
	copyUntil                   time.Time
	closing, dialogBusy         bool
	importRequest               string
	diagnostics                 func() string
	licenses                    string
}

func NewView(controller Controller, diagnostics func() string, licenses string) *View {
	v := &View{controller: controller, theme: newTheme(), diagnostics: diagnostics, licenses: licenses}
	v.list.Axis = layout.Vertical
	v.modalList.Axis = layout.Vertical
	return v
}

func (v *View) Update() {
	v.state = v.controller.Status()
	for _, e := range v.controller.PollEvents() {
		switch e.Type {
		case "state", "error":
			if e.Code == "consent_required" {
				v.consent = model.Primary
				v.ack.Value = false
			} else if e.Message != "" {
				v.notice = e.Message
			}
		case "search_started":
			v.completed, v.limit, v.found = 0, 0, 0
			v.progressEndpoint = "Подготавливаем профиль…"
		case "connect_progress", "search_progress":
			v.completed = e.Checked
			if e.Stage == "trying" && v.completed > 0 {
				v.completed--
			}
			if e.Limit > 0 {
				v.limit = e.Limit
			}
			if e.Found != nil {
				v.found = *e.Found
			}
			v.progressEndpoint = e.Endpoint.String()
		case "search_cancelled":
			v.notice = "Поиск отменён; сохранённые варианты не изменены."
		case "search_done":
			if e.Code == "consent_required" {
				v.consent = model.Probe
				v.ack.Value = false
			} else if e.Saved {
				v.notice = "Сохранено для следующего подключения: " + e.Best.String()
			} else if e.Message != "" {
				v.notice = e.Message
			} else {
				v.notice = "Поиск завершён без изменения сохранённых стратегий."
			}
		case "warning":
			v.notice = e.Message
		case "saved":
			v.notice = "Стратегия сохранена для следующего подключения."
		}
	}
}

func (v *View) labels() (title, help, action string, dot color.NRGBA) {
	switch v.state.State {
	case model.Connecting:
		return "Подключаемся…", "Проверяем WARP и доступность интернета.", "Отменить", blue
	case model.Connected:
		return "Подключено через WARP", "Прокси готов. Настройте SOCKS5 в нужном приложении.", "Отключиться", green
	case model.Failed:
		return "Не удалось подключиться", v.state.Message, "Попробовать снова", red
	default:
		return "Отключено", "Нажмите кнопку для подключения.", "Подключиться", red
	}
}
func (v *View) connectEnabled() bool {
	if v.closing || v.dialogBusy {
		return false
	}
	if v.state.State == model.Connecting || v.state.State == model.Connected {
		return true
	}
	return !v.state.Searching && !v.state.Busy
}
func (v *View) searchEnabled() bool {
	return !v.closing && !v.dialogBusy && v.state.State != model.Connecting && (!v.state.Busy || v.state.Searching)
}
func (v *View) quiescent() bool {
	return !v.closing && !v.dialogBusy && !v.state.Busy && !v.state.Searching && v.state.State != model.Connecting && v.state.State != model.Connected
}
func (v *View) connectAction() {
	if !v.connectEnabled() {
		return
	}
	if v.state.State == model.Connected || v.state.State == model.Connecting {
		v.controller.Disconnect()
	} else {
		v.controller.Connect(false)
	}
}
func (v *View) searchAction() {
	if !v.searchEnabled() {
		return
	}
	if v.state.Searching {
		v.controller.CancelSearch()
	} else {
		v.controller.StartSearch(false)
	}
}
func (v *View) label(size unit.Sp, value string, c color.NRGBA, bold bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		l := material.Label(v.theme, size, value)
		l.Color = c
		if bold {
			l.Font.Weight = font.Bold
		}
		return l.Layout(gtx)
	}
}
func gap(dp unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: dp}.Layout) }
func (v *View) button(gtx layout.Context, button *widget.Clickable, text string, size unit.Sp, enabled bool) layout.Dimensions {
	if !enabled {
		gtx = gtx.Disabled()
	}
	b := material.Button(v.theme, button, text)
	b.TextSize = size
	b.Color = ink
	b.Background = white
	b.CornerRadius = 2
	if button.Hovered() {
		b.Background = rgb(0xf3f6fb)
	}
	line := border
	if !enabled {
		b.Color = muted
		b.Background = rgb(0xf5f5f5)
		line = rgb(0xd9dde5)
	}
	if gtx.Focused(button) {
		line = blue
	}
	return widget.Border{Color: line, Width: 1.5, CornerRadius: 2}.Layout(gtx, b.Layout)
}

func (v *View) Layout(gtx layout.Context) layout.Dimensions {
	paint.Fill(gtx.Ops, white)
	for {
		e, ok := gtx.Event(key.Filter{Name: key.NameEscape})
		if !ok {
			break
		}
		if e.(key.Event).State == key.Press {
			if v.consent != "" {
				v.consent = ""
				v.ack.Value = false
			} else {
				v.info = ""
				v.menuOpen = false
			}
		}
	}
	if v.consent == "" && v.info == "" {
		for v.connect.Clicked(gtx) {
			v.connectAction()
		}
		for v.search.Clicked(gtx) {
			v.searchAction()
		}
		for v.copy.Clicked(gtx) {
			gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(SOCKSAddress))})
			v.copyUntil = gtx.Now.Add(1800 * time.Millisecond)
		}
		for v.menu.Clicked(gtx) {
			v.menuOpen = !v.menuOpen
		}
		for i := range v.items {
			for v.items[i].Clicked(gtx) {
				v.menuOpen = false
				switch i {
				case 0, 1:
					if !v.quiescent() {
						v.info = "Отключитесь и дождитесь завершения операций перед импортом."
					} else if i == 0 {
						v.importRequest = model.Primary
					} else {
						v.importRequest = model.Probe
					}
				case 2:
					if v.diagnostics != nil {
						v.info = v.diagnostics()
					}
				case 3:
					v.info = "Cloudflare WARP\nУсловия использования:\nhttps://www.cloudflare.com/application/terms/"
				case 4:
					v.info = v.licenses
				}
			}
		}
	}
	base := gtx
	if v.consent != "" || v.info != "" {
		base = gtx.Disabled()
	}
	children := []layout.StackChild{layout.Expanded(func(_ layout.Context) layout.Dimensions { return v.mainLayout(base) })}
	if v.consent != "" || v.info != "" {
		// An expanded overlay provides the full window's minimum constraints:
		// Center then positions the modal, instead of measuring it at (0,0).
		children = append(children, layout.Expanded(v.modal))
	} else if v.menuOpen {
		children = append(children, layout.Stacked(v.menuLayout))
	}
	return layout.Stack{}.Layout(gtx, children...)
}

func (v *View) mainLayout(gtx layout.Context) layout.Dimensions {
	title, help, action, dot := v.labels()
	search := "Найти новую стратегию"
	if v.state.Searching {
		search = "Отменить поиск"
	}
	copyText := "Копировать"
	if gtx.Now.Before(v.copyUntil) {
		copyText = "Скопировано"
	}
	return v.list.Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: 8, Top: 2, Bottom: 2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					b := material.Button(v.theme, &v.menu, "Настройки")
					b.TextSize = 14
					b.Color = ink
					b.Background = rgb(0xfafafa)
					b.Inset = layout.UniformInset(5)
					return layout.W.Layout(gtx, b.Layout)
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: 24, Right: 24, Top: 22, Bottom: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(v.label(36, "WarpPocket", ink, true)), gap(8), layout.Rigid(v.label(13, "Простой локальный SOCKS5 через WARP.", muted, false)))
								}),
								layout.Rigid(doodle))
						}), gap(22),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									size := gtx.Dp(13)
									paint.FillShape(gtx.Ops, dot, clip.Ellipse{Max: image.Pt(size, size)}.Op(gtx.Ops))
									return layout.Dimensions{Size: image.Pt(size, size)}
								}),
								layout.Rigid(layout.Spacer{Width: 10}.Layout), layout.Flexed(1, v.label(18, title, ink, true)))
						}), gap(6),
						layout.Rigid(v.label(14, help, muted, false)), gap(18),
						layout.Rigid(v.label(12, "SOCKS5 ПРОКСИ", muted, false)), gap(6),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									return widget.Border{Color: rgb(0xc8cfe0), Width: 1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Inset{Top: 10, Bottom: 10, Left: 4, Right: 4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											l := material.Label(v.theme, 16, SOCKSAddress)
											l.Alignment = text.Middle
											l.Font.Typeface = "Go Mono"
											l.Font.Weight = font.Bold
											return l.Layout(gtx)
										})
									})
								}), layout.Rigid(layout.Spacer{Width: 8}.Layout), layout.Rigid(func(gtx layout.Context) layout.Dimensions { return v.button(gtx, &v.copy, copyText, 13, !v.closing) }))
						}), gap(8),
						layout.Rigid(v.label(11, RoutingHint, muted, false)), gap(18),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return v.button(gtx, &v.connect, action, 20, v.connectEnabled())
						}), gap(10),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							gtx.Constraints.Min.X = gtx.Constraints.Max.X
							return v.button(gtx, &v.search, search, 16, v.searchEnabled())
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if v.state.Searching || v.state.State == model.Connecting {
								return layout.Inset{Top: 14}.Layout(gtx, v.progress)
							}
							return layout.Dimensions{}
						}), gap(18),
						layout.Rigid(v.label(13, v.endpointText(), muted, false)), gap(7),
						layout.Rigid(v.label(13, v.notice, muted, false)), gap(14),
						layout.Rigid(v.label(12, "Локальный SOCKS5-прокси. Только TCP; не системный VPN.", muted, false)),
					)
				})
			}),
		)
	})
}
func (v *View) endpointText() string {
	if v.state.State == model.Connected && v.state.Endpoint.Host != "" {
		return fmt.Sprintf("Активный endpoint: %s · %.0f мс", v.state.Endpoint, v.state.LatencyMS)
	}
	return "Активный endpoint: —"
}
func (v *View) progress(gtx layout.Context) layout.Dimensions {
	return widget.Border{Color: border, Width: 1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(11).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			head := "Проверка подключения…"
			if v.state.Searching {
				if v.limit > 0 {
					head = fmt.Sprintf("Проверено %d / %d · найдено %d", v.completed, v.limit, v.found)
				} else {
					head = "Подготавливаем поиск…"
				}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(v.label(13, head, ink, false)), gap(8), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				width, height := gtx.Constraints.Max.X, gtx.Dp(10)
				paint.FillShape(gtx.Ops, rgb(0xf3f6fb), clip.Rect{Max: image.Pt(width, height)}.Op())
				start, fill := 0, width/4
				if v.state.Searching && v.limit > 0 {
					fill = width * min(v.completed, v.limit) / v.limit
				} else if width > 0 {
					// Indeterminate activity, not a fabricated percentage or count.
					start = int(gtx.Now.UnixMilli()%2000)*(width+fill)/2000 - fill
				}
				for x := max(0, start); x < min(width, start+fill); x += max(1, gtx.Dp(16)) {
					paint.FillShape(gtx.Ops, yellow, clip.Rect{Min: image.Pt(x, 0), Max: image.Pt(min(x+gtx.Dp(10), width, start+fill), height)}.Op())
				}
				return layout.Dimensions{Size: image.Pt(width, height)}
			}), gap(7), layout.Rigid(v.label(12, v.progressEndpoint, muted, false)))
		})
	})
}
func (v *View) menuLayout(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 32, Left: 8, Right: 8}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Max.X = min(gtx.Constraints.Max.X, gtx.Dp(370))
		return widget.Border{Color: border, Width: 1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, white, clip.Rect{Max: gtx.Constraints.Max}.Op())
			labels := []string{"Импорт основного профиля…", "Импорт проверочного профиля…", "Диагностика", "Условия Cloudflare", "Лицензии компонентов"}
			var children []layout.FlexChild
			for i, label := range labels {
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return v.button(gtx, &v.items[i], label, 14, !v.closing)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	})
}
func (v *View) modal(gtx layout.Context) layout.Dimensions {
	paint.Fill(gtx.Ops, color.NRGBA{A: 110})
	for v.decline.Clicked(gtx) {
		v.consent = ""
		v.ack.Value = false
	}
	for v.dismiss.Clicked(gtx) {
		v.info = ""
	}
	for v.accept.Clicked(gtx) {
		if v.ack.Value && v.consent != "" && !v.closing {
			role := v.consent
			v.consent = ""
			v.ack.Value = false
			if role == model.Probe {
				v.controller.StartSearch(true)
			} else {
				v.controller.Connect(true)
			}
		}
	}
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Max.X = min(gtx.Constraints.Max.X, gtx.Dp(408))
		gtx.Constraints.Min = image.Point{}
		return widget.Border{Color: ink, Width: 2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Background{}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				paint.FillShape(gtx.Ops, rgb(0xfffdf7), clip.Rect{Max: gtx.Constraints.Min}.Op())
				return layout.Dimensions{Size: gtx.Constraints.Min}
			}, func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(20).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return v.modalList.Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
						if v.consent == "" {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(v.label(14, v.info, ink, false)), gap(16), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return v.button(gtx, &v.dismiss, "Закрыть", 14, true)
							}))
						}
						body := "Для Cloudflare WARP нужно зарегистрировать устройство. Приватный профиль будет сохранён только локально.\n\nУсловия: https://www.cloudflare.com/application/terms/"
						if v.consent == model.Probe {
							body = "Для поиска без разрыва подключения нужна отдельная идентичность WARP. Она регистрируется только после согласия.\n\nУсловия: https://www.cloudflare.com/application/terms/"
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(v.label(28, "!", rgb(0xb68c00), true)), gap(8), layout.Rigid(v.label(24, "Нужно согласие", ink, true)), gap(12), layout.Rigid(v.label(14, body, ink, false)), gap(16), layout.Rigid(material.CheckBox(v.theme, &v.ack, "Я понимаю и хочу продолжить").Layout), gap(18), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Spacing: layout.SpaceBetween}.Layout(gtx, layout.Rigid(func(gtx layout.Context) layout.Dimensions { return v.button(gtx, &v.decline, "Отмена", 14, true) }), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return v.button(gtx, &v.accept, "Продолжить", 14, v.ack.Value && !v.closing)
							}))
						}))
					})
				})
			})
		})
	})
}
