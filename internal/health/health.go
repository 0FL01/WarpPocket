// Package health verifies HTTPS through explicit SOCKS5 remote-name resolution.
// Neither the environment proxy nor the host resolver is a failover path.
package health

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/trust"
	"golang.org/x/net/proxy"
)

const TraceURL = "https://www.cloudflare.com/cdn-cgi/trace"
const IndependentURL = "https://www.gstatic.com/generate_204"
const FallbackURL = "https://www.apple.com/library/test/success.html"
const OverallTimeout = 30 * time.Second
const ConnectTimeout = 7 * time.Second
const ReadTimeout = 5 * time.Second
const maxResponse = 16384

// deadlineConn bounds each read as well as a slow-drip response's total time.
type deadlineConn struct {
	net.Conn
	ctx  context.Context
	stop func() bool
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	end := time.Now().Add(ReadTimeout)
	if limit, ok := c.ctx.Deadline(); ok && limit.Before(end) {
		end = limit
	}
	if err := c.Conn.SetReadDeadline(end); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *deadlineConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}

func transport(port int, roots *x509.CertPool) (*http.Transport, error) {
	if port < 1 || port > 65535 || roots == nil {
		return nil, model.E("health_failed", "Некорректные параметры проверки SOCKS5.")
	}
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: ConnectTimeout})
	if err != nil {
		return nil, model.E("health_failed", "Не удалось подготовить проверку SOCKS5.")
	}
	remote := dialer.(proxy.ContextDialer)
	return &http.Transport{
		// Proxy is deliberately nil, never ProxyFromEnvironment.
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			establish, cancel := context.WithTimeout(ctx, ConnectTimeout)
			defer cancel()
			conn, err := remote.DialContext(establish, network, address)
			if err != nil {
				return nil, err
			}
			bounded := &deadlineConn{Conn: conn, ctx: ctx}
			bounded.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
			return bounded, nil
		},
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   ConnectTimeout,
		ResponseHeaderTimeout: ReadTimeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}, nil
}

func Check(ctx context.Context, port int) (float64, error) {
	roots, err := trust.Pool()
	if err != nil {
		return 0, model.E("health_tls", "Встроенные TLS-сертификаты недоступны.")
	}
	t, err := transport(port, roots)
	if err != nil {
		return 0, err
	}
	defer t.CloseIdleConnections()
	return check(ctx, &http.Client{Transport: t, CheckRedirect: noRedirect}, [3]string{TraceURL, IndependentURL, FallbackURL}, OverallTimeout)
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func check(ctx context.Context, client *http.Client, urls [3]string, budget time.Duration) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	request := func(url string) (int, []byte, error) {
		if err := ctx.Err(); err != nil {
			return 0, nil, contextError(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil || req.URL.Scheme != "https" {
			return 0, nil, model.E("health_failed", "Проверка требует HTTPS через SOCKS5.")
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, nil, classify(ctx, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
		if ctx.Err() != nil {
			return 0, nil, contextError(ctx.Err())
		}
		if err != nil {
			return 0, nil, classify(ctx, err)
		}
		if len(body) > maxResponse {
			return 0, nil, model.E("health_response_large", "Некорректный ответ проверочного ресурса.")
		}
		return response.StatusCode, body, nil
	}
	started := time.Now()
	status, body, err := request(urls[0])
	latency := float64(time.Since(started)) / float64(time.Millisecond)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK || !validTrace(body) {
		return 0, model.E("warp_not_enabled", "Прокси не подтвердил работу через WARP.")
	}
	for n, url := range urls[1:] {
		status, body, err = request(url)
		if err != nil {
			if ctx.Err() != nil || model.Code(err) == "health_response_large" {
				return 0, err
			}
			continue
		}
		if n == 0 && status == http.StatusNoContent && len(body) == 0 || n == 1 && status == http.StatusOK && bytes.Contains(bytes.ToLower(body), []byte("<body>success</body>")) {
			return latency, nil
		}
	}
	return 0, model.E("external_unavailable", "WARP отвечает, но независимый HTTPS-ресурс недоступен.")
}

func validTrace(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	count, valid := 0, false
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		if key == "warp" {
			count++
			valid = value == "on" || value == "plus"
		}
	}
	return scanner.Err() == nil && count == 1 && valid
}

func contextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return model.E("cancelled", "Операция отменена.")
	}
	return model.E("health_timeout", "Время проверки HTTPS через SOCKS5 истекло.")
}

func classify(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return contextError(ctx.Err())
	}
	var certificate *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	if errors.As(err, &certificate) || errors.As(err, &header) {
		return model.E("health_tls", "Проверка TLS через SOCKS5 не пройдена.")
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return contextError(context.DeadlineExceeded)
	}
	return model.E("health_failed", "HTTPS через SOCKS5 недоступен; прямое соединение не используется.")
}
