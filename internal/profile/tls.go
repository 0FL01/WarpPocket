package profile

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The ClientHello below is pinned to wgcf v2.3.1 cloudflare/api.go, not a generic
// browser preset. Session caches belong to a client, never to account auth.
func newTransport(roots *x509.CertPool) *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	cache := utls.NewLRUClientSessionCache(64)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
		MaxIdleConns:          4,
		MaxConnsPerHost:       2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			raw.Close()
			return nil, err
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, err := handshakeTLS(handshakeCtx, raw, host, roots, cache)
		if err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	return transport
}

func handshakeTLS(ctx context.Context, raw net.Conn, host string, roots *x509.CertPool, cache utls.ClientSessionCache) (*utls.UConn, error) {
	conn := utls.UClient(raw, &utls.Config{
		ServerName: host, RootCAs: roots, ClientSessionCache: cache,
		MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(clientHelloSpec()); err != nil {
		return nil, err
	}
	conn.HandshakeState.Hello.SessionId = nil
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	for _, extension := range conn.Extensions {
		if ticket, ok := extension.(*utls.SessionTicketExtension); ok && len(ticket.Ticket) != 0 {
			id := make([]byte, 32)
			if _, err := rand.Read(id); err != nil {
				return nil, err
			}
			conn.HandshakeState.Hello.SessionId = id
			if err := conn.MarshalClientHello(); err != nil {
				return nil, err
			}
			break
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func clientHelloSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS12,
		CipherSuites: []uint16{
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}
