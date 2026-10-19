// Copied into the isolated, pinned wireguard-go/tun/netstack module by the
// WarpPocket build. The original DNS parsing and tunnel dialers stay in use.
package netstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	warpDNSStageTimeout  = time.Second
	warpDNSLookupTimeout = 5 * time.Second
)

// The dependency is per call, never a mutable process-wide test hook. In
// production it is always the original Net.exchange using tunneled sockets.
type warpDNSExchange func(context.Context, netip.Addr, dnsmessage.Question, time.Duration) (dnsmessage.Parser, dnsmessage.Header, error)

func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	return tnet.lookupOrderedDNS(ctx, host, tnet.exchange)
}

func warpDNSContextError(ctx context.Context, host string) error {
	err := ctx.Err()
	return &net.DNSError{Err: err.Error(), Name: host, IsTimeout: errors.Is(err, context.DeadlineExceeded)}
}

func (tnet *Net) lookupOrderedDNS(ctx context.Context, host string, exchange warpDNSExchange) ([]string, error) {
	if ctx.Err() != nil {
		return nil, warpDNSContextError(ctx, host)
	}
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
	if len(tnet.dnsServers) == 0 {
		return nil, &net.DNSError{Err: "no DNS servers configured", Name: host}
	}

	ctx, cancel := context.WithTimeout(ctx, warpDNSLookupTimeout)
	defer cancel()
	var lastErr error
	for _, server := range tnet.dnsServers {
		if ctx.Err() != nil {
			return nil, warpDNSContextError(ctx, host)
		}
		stage, stop := context.WithTimeout(ctx, warpDNSStageTimeout)
		// Only immutable lookup configuration is copied. The exchange closure
		// remains bound to the real Net and therefore its original WARP stack.
		resolver := &Net{
			dnsServers: []netip.Addr{server},
			hasV4:      tnet.hasV4,
			hasV6:      tnet.hasV6,
		}
		addrs, err := resolver.lookupContextHostAtServer(stage, host, exchange)
		stop()
		if ctx.Err() != nil {
			return nil, warpDNSContextError(ctx, host)
		}
		if len(addrs) != 0 {
			return addrs, nil
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, err
		}
		if err == nil {
			err = &net.DNSError{Err: errNoAnswerFromDNSServer.Error(), Name: host, Server: server.String()}
		}
		lastErr = err
	}
	return nil, lastErr
}
