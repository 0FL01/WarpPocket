// Copied into the isolated, pinned wireproxy package by the WarpPocket build.
// Only SOCKS TCP transport is split; destination DNS stays on VirtualTun.
package wireproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/things-go/go-socks5"
	"golang.org/x/net/idna"
)

const warpPocketDirectConnectTimeout = 10 * time.Second

// Read-only lookup policy, not registration policy: ordinary DNS labels may
// contain consecutive interior hyphens. Leading/trailing hyphens are checked
// below. Never use a partially converted name when ToASCII reports an error.
var warpPocketIDNA = idna.New(
	idna.MapForLookup(), idna.Transitional(false), idna.CheckHyphens(false),
	idna.BidiRule(), idna.VerifyDNSLength(true),
)

// Exact roots and dot-delimited descendants only; this is not a keyword list.
var warpPocketDirectRoots = [...]string{
	"vk.com", "vkontakte.com", "vk.cc", "vk.link", "vk.me",
	"userapi.com", "vk-cdn.net", "vkuser.net",
	"vkuseraudio.com", "vkuseraudio.net",
	"vkuservideo.com", "vkuservideo.net",
	"vkuserlive.com", "vkuserlive.net",
}

var warpPocketCGNAT = netip.MustParsePrefix("100.64.0.0/10")

func warpPocketDirectHost(host string) (string, bool) {
	if !utf8.ValidString(host) {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	name, err := warpPocketIDNA.ToASCII(host)
	if err != nil {
		return "", false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return "", false
			}
		}
	}
	for _, tld := range []string{"ru", "su", "xn--p1ai"} {
		if strings.HasSuffix(name, "."+tld) {
			return name, true
		}
	}
	for _, root := range warpPocketDirectRoots {
		if name == root || strings.HasSuffix(name, "."+root) {
			return name, true
		}
	}
	return "", false
}

type warpPocketDial func(context.Context, string, string) (net.Conn, error)

type warpPocketSOCKSRouter struct {
	lookup     func(context.Context, string) (context.Context, net.IP, error)
	warpDial   warpPocketDial
	directDial warpPocketDial
}

func newWarpPocketSOCKSRouter(vt *VirtualTun) *warpPocketSOCKSRouter {
	return &warpPocketSOCKSRouter{
		lookup:     vt.Resolve,
		warpDial:   vt.Tnet.DialContext,
		directDial: (&net.Dialer{Timeout: warpPocketDirectConnectTimeout}).DialContext,
	}
}

func (r *warpPocketSOCKSRouter) options() []socks5.Option {
	return []socks5.Option{
		socks5.WithDial(r.warpDial),
		socks5.WithDialAndRequest(r.Dial),
		socks5.WithResolver(r),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
	}
}

func (r *warpPocketSOCKSRouter) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	if canonical, direct := warpPocketDirectHost(name); direct {
		name = canonical
	}
	// Both branches use the same existing, ordered WARP resolver. In particular,
	// DIRECT never introduces net.DefaultResolver or a second hostname lookup.
	resolved, ip, err := r.lookup(ctx, name)
	if canceled := ctx.Err(); canceled != nil {
		return ctx, nil, canceled
	}
	return resolved, ip, err
}

func (r *warpPocketSOCKSRouter) Dial(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, errors.New("unsupported SOCKS network")
	}
	host := ""
	if request != nil && request.RawDestAddr != nil {
		host = request.RawDestAddr.FQDN
	}
	if _, direct := warpPocketDirectHost(host); !direct {
		return r.warpDial(ctx, network, addr)
	}
	target, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, errors.New("DIRECT requires a resolved numeric destination")
	}
	ip := target.Addr().Unmap()
	if target.Addr().Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || warpPocketCGNAT.Contains(ip) {
		return nil, errors.New("DIRECT destination is local or non-unicast")
	}
	// Preserve the supplied port and numeric destination. A failed selected
	// route is returned as an error, never retried through the other dialer.
	return r.directDial(ctx, network, addr)
}
