module github.com/0FL01/WarpPocket

go 1.26.0

toolchain go1.26.9

require (
	gioui.org v0.10.3
	gioui.org/x v0.10.3
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/image v0.26.0
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0
)

require (
	gioui.org/shader v1.0.9 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-text/typesetting v0.3.5 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	golang.org/x/exp/shiny v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/windtf/wireproxy => ./build/deps/wireproxy

replace golang.zx2c4.com/wireguard => ./build/deps/wireguard-go
