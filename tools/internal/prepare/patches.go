package prepare

import (
	"embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Payloads are data, not packages in this module. In particular the original
// netstack, wireproxy and command tests must not enter tools' package discovery.
//
//go:embed payload/*
var payloads embed.FS

type replacement struct {
	old, new, label string
}

type sourcePatch struct {
	tree, path string
	edits      []replacement
}

func replaceOnce(text, old, new, label string) (string, error) {
	if old == "" || strings.Count(text, old) != 1 {
		return "", fmt.Errorf("patch anchor %s matched %d times, expected exactly one; upstream sources changed", label, strings.Count(text, old))
	}
	return strings.Replace(text, old, new, 1), nil
}

func patchSources(proxy, guard string, pins buildPins) error {
	plan, err := planPatches(proxy, guard, pins, payloads.ReadFile)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(plan))
	for path := range plan {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	// All anchors, replacement targets and embedded payloads have been checked
	// before the first write to either isolated source tree.
	for _, path := range paths {
		if err := os.WriteFile(path, plan[path], 0o600); err != nil {
			return fmt.Errorf("write patched source %s: %w", path, err)
		}
	}
	return nil
}

type payloadSpec struct {
	name, tree, path, pkg, function string
}

var sourcePayloads = []payloadSpec{
	{"wireproxy_dns.go.txt", "guard", "tun/netstack/warppocket_dns.go", "netstack", "LookupContextHost"},
	{"wireproxy_dns_test.go.txt", "guard", "tun/netstack/warppocket_dns_test.go", "netstack", "TestWarpPocketDNSOrderedFailover"},
	{"wireproxy_routing.go.txt", "proxy", "warppocket_routing.go", "wireproxy", "newWarpPocketSOCKSRouter"},
	{"wireproxy_routing_test.go.txt", "proxy", "warppocket_routing_test.go", "wireproxy", "TestWarpPocketRoutingSOCKSProtocol"},
	{"wireproxy_sandbox_test.go.txt", "proxy", "cmd/wireproxy/warppocket_sandbox_test.go", "worker", "TestWarpPocketRoutingNetworkSandbox"},
	{"wireproxy_worker_test.go.txt", "proxy", "cmd/wireproxy/warppocket_worker_test.go", "worker_test", "TestWarpPocketRoutingWorkerEntry"},
	{"wireproxy_junk.go.txt", "proxy", "warppocket_junk.go", "wireproxy", "newWarpPocketJunkBind"},
	{"wireproxy_junk_test.go.txt", "proxy", "warppocket_junk_test.go", "wireproxy", "TestWarpPocketJunkInitiation"},
}

func planPatches(proxy, guard string, pins buildPins, readPayload func(string) ([]byte, error)) (map[string][]byte, error) {
	roots := map[string]string{"proxy": proxy, "guard": guard}
	plan := make(map[string][]byte)
	for _, patch := range pinnedPatches() {
		path := filepath.Join(roots[patch.tree], filepath.FromSlash(patch.path))
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read patch source %s: %w", path, err)
		}
		text := string(data)
		for _, edit := range patch.edits {
			text, err = replaceOnce(text, edit.old, edit.new, patch.path+" "+edit.label)
			if err != nil {
				return nil, err
			}
		}
		plan[path] = []byte(text)
	}
	modPath := filepath.Join(proxy, "go.mod")
	mod, err := os.ReadFile(modPath)
	if err != nil {
		return nil, fmt.Errorf("read wireproxy go.mod: %w", err)
	}
	text, err := patchGoMod(string(mod), pins.Wireguard.Version)
	if err != nil {
		return nil, err
	}
	plan[modPath] = []byte(text)
	for _, spec := range sourcePayloads {
		data, err := readPayload("payload/" + spec.name)
		if err != nil {
			return nil, fmt.Errorf("read embedded payload %s: %w", spec.name, err)
		}
		if err := validatePayload(spec, data); err != nil {
			return nil, err
		}
		path := filepath.Join(roots[spec.tree], filepath.FromSlash(spec.path))
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return nil, fmt.Errorf("payload target must not already exist: %s", path)
		}
		plan[path] = data
	}
	return plan, nil
}

func validatePayload(spec payloadSpec, data []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), spec.name, data, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("invalid embedded payload %s: %w", spec.name, err)
	}
	if file.Name.Name != spec.pkg {
		return fmt.Errorf("embedded payload %s must use package %s", spec.name, spec.pkg)
	}
	count := 0
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == spec.function {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("embedded payload %s must define %s exactly once", spec.name, spec.function)
	}
	return nil
}

func patchGoMod(text, version string) (string, error) {
	for _, anchor := range []string{"module github.com/windtf/wireproxy\n", "\t" + wireguardModule + " " + version + "\n"} {
		if _, err := replaceOnce(text, anchor, anchor, "go.mod pinned module"); err != nil {
			return "", err
		}
	}
	if strings.Contains(text, "replace "+wireguardModule) || strings.Contains(text, "replace (") {
		return "", fmt.Errorf("unexpected upstream module replacement; refusing to patch")
	}
	return strings.TrimRight(text, "\n") + "\n\nreplace " + wireguardModule + " => ../wireguard-go\n", nil
}

// Exact pinned anchors retain the established Reserved/DNS/routing and worker
// transformations. The common bind is wrapped before constructing the device.
func pinnedPatches() []sourcePatch {
	return []sourcePatch{
		{"proxy", "config.go", []replacement{
			{configStructOld, strings.Replace(configStructOld, "\tAllowedIPs   []netip.Prefix\n", "\tAllowedIPs   []netip.Prefix\n\tReserved     *[3]uint8\n", 1), "PeerConfig.Reserved"},
			{"\t\tif sectionKey, err := section.GetKey(\"Endpoint\"); err == nil {\n", configReservedNew, "Reserved parsing"},
			{configImportsOld, strings.Replace(configImportsOld, "\t\"strings\"\n", "\t\"strconv\"\n\t\"strings\"\n", 1), "strconv import"},
		}},
		{"proxy", "wireguard.go", []replacement{
			{"\tdev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, \"\"))\n", wireguardBindNew, "bind"},
		}},
		{"proxy", "routine.go", []replacement{{routingOptionsOld, routingOptionsNew, "SOCKS routing options"}}},
		{"proxy", "cmd/wireproxy/main.go", []replacement{
			{routingNetworkOld, routingNetworkNew, "DIRECT network sandbox"},
			{"\t\"github.com/landlock-lsm/go-landlock/landlock\"\n", "\t\"github.com/landlock-lsm/go-landlock/landlock\"\n\tlandlocksyscall \"github.com/landlock-lsm/go-landlock/landlock/syscall\"\n", "Landlock access flags"},
			{"package main\n", "package worker\n", "importable worker package"},
			{"\t\"net/http\"\n", "", "remove optional HTTP service"},
			{"\t\"os/exec\"\n", "", "remove upstream daemon launch"},
			{"\t\"github.com/akamensky/argparse\"\n", "", "remove upstream argument parser"},
			{workerDefaultsOld, "", "remove upstream defaults and version"},
			{workerConfigPathOld, "", "remove config-path discovery"},
			{workerMainOld, workerRunNew, "fixed Run(configPath) entry"},
		}},
		{"guard", "conn/conn.go", []replacement{
			{connInterfaceOld, connInterfaceOld + `
	// SetReservedForEndpoint stores the three reserved bytes that Cloudflare
	// WARP requires after the WireGuard message type for this endpoint.
	SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte)
`, "Bind interface"},
		}},
		{"guard", "conn/bind_std.go", []replacement{
			{"\tblackhole4 bool\n\tblackhole6 bool\n}\n", "\tblackhole4 bool\n\tblackhole6 bool\n\n\treservedAccess      sync.RWMutex\n\treservedForEndpoint map[netip.AddrPort][3]uint8\n}\n", "StdNetBind fields"},
			{"\treturn &StdNetBind{\n\t\tudpAddrPool: sync.Pool{", "\treturn &StdNetBind{\n\t\treservedForEndpoint: make(map[netip.AddrPort][3]uint8),\n\t\tudpAddrPool: sync.Pool{", "NewStdNetBind"},
			{stdReceiveOld, stdReceiveNew, "Receive masking"},
			{stdSendOld, stdSendNew, "Send injection"},
			{"\nfunc (s *StdNetBind) BatchSize() int {", stdMethodNew, "SetReservedForEndpoint"},
		}},
		{"guard", "conn/bind_windows.go", []replacement{
			{winStructOld, strings.Replace(winStructOld, "\tisOpen atomic.Uint32 // 0, 1, or 2\n", "\tisOpen atomic.Uint32 // 0, 1, or 2\n\n\treservedAccess      sync.RWMutex\n\treservedForEndpoint map[WinRingEndpoint][3]uint8\n", 1), "WinRingBind fields"},
			{winSendOld, winSendNew, "Send injection"},
			{fmt.Sprintf(winReceiveOld, "v4"), fmt.Sprintf(winReceiveNew, "v4"), "v4 Receive masking"},
			{fmt.Sprintf(winReceiveOld, "v6"), fmt.Sprintf(winReceiveNew, "v6"), "v6 Receive masking"},
			{"\nfunc (bind *WinRingBind) BatchSize() int {", winMethodNew, "SetReservedForEndpoint"},
		}},
		{"guard", "tun/netstack/tun.go", []replacement{
			{dnsLookupPrefix, "func (tnet *Net) lookupContextHostAtServer(ctx context.Context, host string, exchange warpDNSExchange) ([]string, error) {\n", "lookup stage entry"},
			{"\t\"strings\"\n", "", "relocated host-validation import"},
			{"qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {", "qtype dnsmessage.Type, exchange warpDNSExchange) (dnsmessage.Parser, string, error) {", "tryOneName exchange dependency"},
			{dnsTryExchangeOld, dnsTryExchangeNew, "per-stage retries"},
			{"tnet.tryOneName(ctx, host+\".\", dnsmessage.TypeA)", "tnet.tryOneName(ctx, host+\".\", dnsmessage.TypeA, exchange)", "A exchange"},
			{"tnet.tryOneName(ctx, host+\".\", dnsmessage.TypeAAAA)", "tnet.tryOneName(ctx, host+\".\", dnsmessage.TypeAAAA, exchange)", "AAAA exchange"},
			{"lane := make(chan result, lanes)\n\tvar lastErr error\n", "lane := make(chan result, lanes)\n\tvar lastErr error\n\tvar negativeErr error\n", "negative response state"},
			{dnsResultErrorOld, dnsResultErrorNew, "negative response precedence"},
			{"\tif len(addrs) == 0 && lastErr != nil {\n\t\treturn nil, lastErr\n\t}\n", "\tif len(addrs) == 0 {\n\t\tif negativeErr != nil {\n\t\t\treturn nil, negativeErr\n\t\t}\n\t\tif lastErr != nil {\n\t\t\treturn nil, lastErr\n\t\t}\n\t}\n", "negative response return"},
			{dnsExchangeLoopOld, dnsExchangeLoopNew, "shared UDP/TCP deadline"},
			{dnsConnectionDeadlineOld, dnsConnectionDeadlineNew, "cancel DNS connection"},
			{"\t\tc.Close()\n\t\tif err != nil {\n\t\t\tif err == context.Canceled {", "\t\tstop()\n\t\tc.Close()\n\t\tif err != nil {\n\t\t\tif ctx.Err() != nil {\n\t\t\t\terr = ctx.Err()\n\t\t\t}\n\t\t\tif err == context.Canceled {", "DNS I/O cleanup"},
		}},
	}
}

const configStructOld = `type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}
`

const configImportsOld = `import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
`

const configReservedNew = `		if sectionKey, err := section.GetKey("Reserved"); err == nil {
			parts := strings.Split(sectionKey.String(), ",")
			if len(parts) != 3 {
				return errors.New("Reserved should contain exactly three bytes")
			}
			var reserved [3]uint8
			for index, part := range parts {
				value, err := strconv.Atoi(strings.TrimSpace(part))
				if err != nil || value < 0 || value > 255 {
					return errors.New("Reserved entries should be bytes")
				}
				reserved[index] = uint8(value)
			}
			peer.Reserved = &reserved
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
`

const wireguardBindNew = `	bind := conn.NewDefaultBind()
	if len(deviceConf.Peers) == 1 && deviceConf.Peers[0].Reserved != nil && deviceConf.Peers[0].Endpoint != nil {
		if address, parseErr := netip.ParseAddrPort(*deviceConf.Peers[0].Endpoint); parseErr == nil {
			bind.SetReservedForEndpoint(address, *deviceConf.Peers[0].Reserved)
		}
	}
	bind = newWarpPocketJunkBind(bind)
	dev := device.NewDevice(tun, bind, device.NewLogger(logLevel, ""))
`

const routingOptionsOld = `	options := []socks5.Option{
		socks5.WithDial(vt.Tnet.DialContext),
		socks5.WithResolver(vt),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	}
`

const routingOptionsNew = `	options := newWarpPocketSOCKSRouter(vt).options()
	options = append(options,
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	)
`

const routingNetworkOld = `func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxy.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxy.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxy.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.SNIConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	panicIfError(landlock.V4.BestEffort().RestrictNet(rules...))
}
`

const routingNetworkNew = `func warpPocketNetworkPolicy(sections []wireproxy.RoutineSpawner, infoAddr *string) (landlock.Config, []landlock.Rule) {
	var rules, bindRules []landlock.Rule
	allowDirect := false
	allowBind := func(port uint16) {
		rule := landlock.BindTCP(port)
		rules = append(rules, rule)
		bindRules = append(bindRules, rule)
	}
	if infoAddr != nil && *infoAddr != "" {
		allowBind(extractPort(*infoAddr))
	}
	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxy.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxy.HTTPConfig:
			allowBind(extractPort(section.BindAddress))
		case *wireproxy.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxy.Socks5Config:
			allowBind(extractPort(section.BindAddress))
			allowDirect = true
		case *wireproxy.SNIConfig:
			allowBind(extractPort(section.BindAddress))
		}
	}
	if allowDirect {
		// DIRECT needs outbound TCP on arbitrary destination ports. Landlock
		// cannot express hostname/public-IP rules: the checked SOCKS router
		// owns those decisions. Keep the bind allowlist and filesystem locks.
		return landlock.MustConfig(landlock.AccessNetSet(landlocksyscall.AccessNetBindTCP)).BestEffort(), bindRules
	}
	return landlock.V4.BestEffort(), rules
}

func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {
	policy, rules := warpPocketNetworkPolicy(sections, infoAddr)
	panicIfError(policy.RestrictNet(rules...))
}
`

const connInterfaceOld = `	// Send writes one or more packets in bufs to address ep. The length of
	// bufs must not exceed BatchSize().
	Send(bufs [][]byte, ep Endpoint) error
`

const stdReceiveOld = `		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
`

const stdReceiveNew = `		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		// Cloudflare WARP mirrors the 24-bit client id in the reserved header
		// field of its responses. Clear it so the device reads the exact WireGuard
		// message type. For ordinary peers the bytes are already zero.
		if sizes[i] > 3 {
			clear(bufs[i][1:4])
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
`

const stdSendOld = `	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)
`

const stdSendNew = `	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	s.reservedAccess.RLock()
	reserved, reservedFound := s.reservedForEndpoint[netip.AddrPortFrom(endpoint.DstIP(), uint16(endpoint.(*StdNetEndpoint).Port()))]
	s.reservedAccess.RUnlock()
	if reservedFound {
		for i := range bufs {
			if len(bufs[i]) > 3 {
				copy(bufs[i][1:4], reserved[:])
			}
		}
	}
	var (
		retried bool
		err     error
	)
`

const stdMethodNew = `
// SetReservedForEndpoint stores the reserved bytes for one destination.
func (s *StdNetBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	s.reservedAccess.Lock()
	if s.reservedForEndpoint == nil {
		s.reservedForEndpoint = make(map[netip.AddrPort][3]uint8)
	}
	s.reservedForEndpoint[destination] = reserved
	s.reservedAccess.Unlock()
}

func (s *StdNetBind) BatchSize() int {`

const winStructOld = `type WinRingBind struct {
	v4, v6 afWinRingBind
	mu     sync.RWMutex
	isOpen atomic.Uint32 // 0, 1, or 2
}
`

const winSendOld = `	bind.mu.RLock()
	defer bind.mu.RUnlock()
	for _, buf := range bufs {
		switch nend.family {
`

const winSendNew = `	bind.mu.RLock()
	defer bind.mu.RUnlock()
	bind.reservedAccess.RLock()
	reserved, reservedFound := bind.reservedForEndpoint[*nend]
	bind.reservedAccess.RUnlock()
	for _, buf := range bufs {
		if reservedFound && len(buf) > 3 {
			copy(buf[1:4], reserved[:])
		}
		switch nend.family {
`

const winReceiveOld = `	n, ep, err := bind.%s.Receive(bufs[0], &bind.isOpen)
	sizes[0] = n
	eps[0] = ep
	return 1, err
`

const winReceiveNew = `	n, ep, err := bind.%s.Receive(bufs[0], &bind.isOpen)
	sizes[0] = n
	if n > 3 {
		// Cloudflare WARP mirrors the 24-bit client id in the reserved header
		// field of its responses; clear it before the device reads the type.
		clear(bufs[0][1:4])
	}
	eps[0] = ep
	return 1, err
`

const winMethodNew = `
// SetReservedForEndpoint stores the reserved bytes for one destination.
func (bind *WinRingBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	endpoint, err := bind.ParseEndpoint(destination.String())
	if err != nil {
		return
	}
	win, ok := endpoint.(*WinRingEndpoint)
	if !ok {
		return
	}
	bind.reservedAccess.Lock()
	if bind.reservedForEndpoint == nil {
		bind.reservedForEndpoint = make(map[WinRingEndpoint][3]uint8)
	}
	bind.reservedForEndpoint[*win] = reserved
	bind.reservedAccess.Unlock()
}

func (bind *WinRingBind) BatchSize() int {`

const dnsLookupPrefix = `func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
`

const dnsTryExchangeOld = `		for _, server := range tnet.dnsServers {
			p, h, err := tnet.exchange(ctx, server, q, time.Second*5)
`

const dnsTryExchangeNew = `		for _, server := range tnet.dnsServers {
			if ctx.Err() != nil {
				return dnsmessage.Parser{}, "", warpDNSContextError(ctx, name)
			}
			p, h, err := exchange(ctx, server, q, warpDNSStageTimeout)
			if ctx.Err() != nil {
				return dnsmessage.Parser{}, "", warpDNSContextError(ctx, name)
			}
`

const dnsResultErrorOld = `		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}
`

const dnsResultErrorNew = `		if result.error != nil {
			var dnsErr *net.DNSError
			if errors.As(result.error, &dnsErr) && dnsErr.IsNotFound {
				negativeErr = result.error
			}
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}
`

const dnsExchangeLoopOld = `	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

`

const dnsExchangeLoopNew = `	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, useUDP := range []bool{true, false} {
		if ctx.Err() != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
		}

`

const dnsConnectionDeadlineOld = `		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
`

const dnsConnectionDeadlineNew = `		stop := context.AfterFunc(ctx, func() { c.Close() })
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				stop()
				c.Close()
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
`
