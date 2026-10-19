module github.com/0FL01/WarpPocket

go 1.26.0

toolchain go1.26.9

require (
	gioui.org v0.10.3
	gioui.org/x v0.10.3
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/refraction-networking/utls v1.8.2
	github.com/windtf/wireproxy v1.1.3
	golang.org/x/image v0.26.0
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0
)

require (
	gioui.org/shader v1.0.9 // indirect
	github.com/MakeNowJust/heredoc/v2 v2.0.1 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-text/typesetting v0.3.5 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/landlock-lsm/go-landlock v0.6.0 // indirect
	github.com/things-go/go-socks5 v0.0.5 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp/shiny v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
	suah.dev/protect v1.2.3 // indirect
)

replace github.com/windtf/wireproxy => ./build/deps/wireproxy

replace golang.zx2c4.com/wireguard => ./build/deps/wireguard-go
