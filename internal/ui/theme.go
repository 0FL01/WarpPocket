package ui

import (
	"image"
	"image/color"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/font/opentype"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/goregular"
)

var (
	ink    = rgb(0x20232b)
	muted  = rgb(0x6d7380)
	blue   = rgb(0x2f68cb)
	yellow = rgb(0xf0cf53)
	green  = rgb(0x3d995a)
	red    = rgb(0xd85a50)
	border = rgb(0xb8c5df)
	white  = rgb(0xffffff)
)

func rgb(value uint32) color.NRGBA {
	return color.NRGBA{R: byte(value >> 16), G: byte(value >> 8), B: byte(value), A: 255}
}

func newTheme() *material.Theme {
	var faces []font.FontFace
	for _, data := range [][]byte{goregular.TTF, gobold.TTF, gomono.TTF} {
		collection, err := opentype.ParseCollection(data)
		if err != nil {
			panic("invalid embedded font")
		}
		faces = append(faces, collection...)
	}
	theme := material.NewTheme()
	theme.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(faces))
	theme.Face = "Go"
	theme.Palette = material.Palette{Bg: white, Fg: ink, ContrastBg: blue, ContrastFg: white}
	return theme
}

func doodle(gtx layout.Context) layout.Dimensions {
	scale := float32(gtx.Dp(100)) / 100
	point := func(x, y float32) f32.Point { return f32.Pt(x*scale, y*scale) }
	var p clip.Path
	p.Begin(gtx.Ops)
	// Deliberately hand-drawn person and monitor, not a raster/browser asset.
	p.MoveTo(point(12, 34))
	p.CubeTo(point(-3, 10), point(31, 5), point(32, 28))
	p.CubeTo(point(32, 45), point(15, 45), point(12, 34))
	p.MoveTo(point(17, 27))
	p.LineTo(point(18, 27))
	p.MoveTo(point(25, 26))
	p.LineTo(point(26, 26))
	p.MoveTo(point(17, 33))
	p.QuadTo(point(22, 37), point(27, 32))
	p.MoveTo(point(22, 42))
	p.LineTo(point(22, 65))
	p.LineTo(point(13, 83))
	p.MoveTo(point(22, 65))
	p.LineTo(point(35, 81))
	p.MoveTo(point(22, 47))
	p.LineTo(point(10, 58))
	p.MoveTo(point(22, 47))
	p.LineTo(point(37, 53))
	p.MoveTo(point(44, 20))
	p.LineTo(point(88, 17))
	p.LineTo(point(91, 47))
	p.LineTo(point(46, 50))
	p.LineTo(point(44, 20))
	p.MoveTo(point(39, 55))
	p.LineTo(point(88, 52))
	p.MoveTo(point(51, 62))
	p.LineTo(point(84, 59))
	p.MoveTo(point(68, 51))
	p.LineTo(point(70, 81))
	p.MoveTo(point(59, 82))
	p.LineTo(point(80, 80))
	p.MoveTo(point(89, 23))
	p.QuadTo(point(100, 25), point(97, 37))
	paint.FillShape(gtx.Ops, rgb(0xe2b928), clip.Stroke{Path: p.End(), Width: 2.5 * scale}.Op())
	return layout.Dimensions{Size: gtx.Constraints.Constrain(image.Pt(gtx.Dp(unit.Dp(100)), gtx.Dp(unit.Dp(90))))}
}
