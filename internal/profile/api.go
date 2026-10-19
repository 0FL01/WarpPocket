package profile

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/trust"
)

const (
	APIVersion     = "v0a5641"
	apiBase        = "https://api.cloudflareclient.com"
	maxAPIResponse = 40960
	reservedHint   = "Не удалось получить идентификатор WARP-клиента. Проверьте доступ к API Cloudflare или импортируйте профиль с полем Reserved."
)

// Client uses verified direct TLS, the pinned wgcf 2.3.1 Android fingerprint,
// bounded responses, context deadlines and per-request account authorization.
type Client struct {
	http *http.Client
	base string
}

func NewClient() *Client {
	roots, err := trust.Pool()
	if err != nil {
		// An invalid embedded bundle must fail certificate verification, never
		// silently select a system store or unverified TLS.
		roots = x509.NewCertPool()
	}
	return newClient(apiBase, roots)
}

func newClient(base string, roots *x509.CertPool) *Client {
	transport := newTransport(roots)
	return &Client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

type deviceResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config      *deviceConfig `json:"config"`
	WarpEnabled *bool         `json:"warp_enabled"`
}

type deviceConfig struct {
	ClientID    string `json:"client_id"`
	WarpEnabled *bool  `json:"warp_enabled"`
	Interface   struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			Host  string `json:"host"`
			V4    string `json:"v4"`
			V6    string `json:"v6"`
			Ports []int  `json:"ports"`
		} `json:"endpoint"`
	} `json:"peers"`
}

func (c *Client) Register(ctx context.Context) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	fail := func() (Account, error) {
		return Account{}, apiFailure(ctx, "registration_failed", "Регистрация WARP не завершилась. Можно импортировать совместимый профиль.")
	}
	if ctx.Err() != nil {
		return fail()
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fail()
	}
	secret[0] &= 248
	secret[31] = secret[31]&127 | 64
	private, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return fail()
	}
	request := struct {
		FCMToken     string `json:"fcm_token"`
		InstallID    string `json:"install_id"`
		Key          string `json:"key"`
		Locale       string `json:"locale"`
		Model        string `json:"model"`
		TOS          string `json:"tos"`
		SerialNumber string `json:"serial_number"`
		OSVersion    string `json:"os_version"`
		KeyType      string `json:"key_type"`
		TunnelType   string `json:"tunnel_type"`
	}{Key: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), Locale: "en_US", Model: "PC", TOS: time.Now().Format(time.RFC3339Nano), OSVersion: "16.0.0", KeyType: "curve25519", TunnelType: "wireguard"}
	body, err := json.Marshal(request)
	if err != nil {
		return fail()
	}
	var response deviceResponse
	if err := c.request(ctx, http.MethodPost, "", "", body, &response); err != nil {
		return fail()
	}
	account := Account{PrivateKey: base64.StdEncoding.EncodeToString(secret[:]), DeviceID: response.ID, AccessToken: response.Token, LicenseKey: response.Account.License}
	if !validAccount(&account) {
		return fail()
	}
	return account, nil
}

func (c *Client) Generate(ctx context.Context, account Account) (model.Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	fail := func() (model.Profile, error) {
		return model.Profile{}, apiFailure(ctx, "generation_failed", "Не удалось получить профиль WARP; аккаунт сохранён для повторной генерации.")
	}
	if !validAccount(&account) {
		return fail()
	}
	config, err := c.fetchConfig(ctx, account)
	if err != nil || config == nil || len(config.Peers) == 0 {
		return fail()
	}
	reserved, ok := decodeReserved(config.ClientID)
	if !ok {
		return fail()
	}
	p := model.Profile{PrivateKey: account.PrivateKey, PublicKey: config.Peers[0].PublicKey, DNS: []string{"1.1.1.1", "1.0.0.1"}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1280, Keepalive: 25, Reserved: &reserved}
	v4, err := apiAddress(config.Interface.Addresses.V4, false)
	if err != nil {
		return fail()
	}
	p.Addresses = append(p.Addresses, v4)
	if config.Interface.Addresses.V6 != "" {
		v6, err := apiAddress(config.Interface.Addresses.V6, true)
		if err != nil {
			return fail()
		}
		p.Addresses = append(p.Addresses, v6)
		p.DNS = append(p.DNS, "2606:4700:4700::1111", "2606:4700:4700::1001")
		p.AllowedIPs = append(p.AllowedIPs, "::/0")
	}
	endpoint := config.Peers[0].Endpoint
	if endpoint.Host != "" {
		p.Endpoint, err = model.ParseEndpoint(endpoint.Host)
	} else {
		host := endpoint.V4
		if host == "" {
			host = endpoint.V6
		}
		if bare, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = bare
		}
		port := 2408
		if len(endpoint.Ports) != 0 {
			port = endpoint.Ports[0]
		}
		p.Endpoint, err = model.NewEndpoint(host, port)
	}
	if err != nil {
		return fail()
	}
	text, err := Render(p, nil)
	if err != nil {
		return fail()
	}
	return Parse([]byte(text))
}

func apiAddress(value string, ipv6 bool) (string, error) {
	prefix, err := parsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is6() != ipv6 {
		return "", invalidProfile()
	}
	// Ensure mapped IPv6 addresses cannot masquerade as IPv4 interface addresses.
	if prefix.Addr().Is4In6() {
		return "", invalidProfile()
	}
	return prefix.String(), nil
}

func (c *Client) Reserved(ctx context.Context, account Account) ([3]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !validAccount(&account) {
		return [3]byte{}, apiFailure(ctx, "reserved_unavailable", reservedHint)
	}
	config, err := c.fetchConfig(ctx, account)
	if err == nil && config != nil {
		if reserved, ok := decodeReserved(config.ClientID); ok {
			return reserved, nil
		}
	}
	return [3]byte{}, apiFailure(ctx, "reserved_unavailable", reservedHint)
}

func decodeReserved(value string) ([3]byte, bool) {
	var result [3]byte
	if strings.ContainsAny(value, "\r\n") {
		return result, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, false
	}
	copy(result[:], decoded)
	return result, true
}

func (c *Client) fetchConfig(ctx context.Context, account Account) (*deviceConfig, error) {
	var response deviceResponse
	if err := c.request(ctx, http.MethodGet, account.DeviceID, account.AccessToken, nil, &response); err != nil {
		return nil, err
	}
	if response.Config == nil {
		return nil, invalidProfile()
	}
	config := response.Config
	if (config.WarpEnabled != nil && !*config.WarpEnabled) || (response.WarpEnabled != nil && !*response.WarpEnabled) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var patched deviceResponse
		err := c.request(ctx, http.MethodPatch, account.DeviceID, account.AccessToken, []byte(`{"warp_enabled":true}`), &patched)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Legacy behavior tolerates a failed PATCH if GET supplied usable bytes.
		// A successful PATCH may return only client_id, not the complete config.
		if err == nil && patched.Config != nil {
			if _, ok := decodeReserved(patched.Config.ClientID); ok {
				config.ClientID = patched.Config.ClientID
			}
		}
	}
	return config, nil
}

func (c *Client) request(ctx context.Context, method, deviceID, token string, body []byte, output *deviceResponse) error {
	path := c.base + "/" + APIVersion + "/reg"
	if deviceID != "" {
		path += "/" + url.PathEscape(deviceID)
	}
	request, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if err != nil || request.URL.Scheme != "https" {
		return invalidProfile()
	}
	request.Header.Set("User-Agent", "1.1.1.1/6.38.9-5641 (Android 16.0.0)")
	request.Header.Set("CF-Client-Version", "a-6.38.9-5641")
	request.Header.Set("Connection", "Keep-Alive")
	if body != nil {
		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return invalidProfile()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxAPIResponse {
		return invalidProfile()
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponse+1))
	if err != nil || len(data) > maxAPIResponse || !utf8.Valid(data) || json.Unmarshal(data, output) != nil {
		return invalidProfile()
	}
	return nil
}
