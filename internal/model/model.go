// Package model holds application values, never helper configuration text.
package model

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const Primary = "primary"
const Probe = "probe"

func ValidRole(role string) bool { return role == Primary || role == Probe }

// Error contains only application-owned text, suitable for the UI and logs.
type Error struct{ Code, Message string }

func (e *Error) Error() string     { return e.Message }
func E(code, message string) error { return &Error{Code: code, Message: message} }
func Code(err error) string {
	if err == nil {
		return ""
	}
	var safe *Error
	if errors.As(err, &safe) {
		return safe.Code
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "internal_error"
}
func SafeMessage(err error) string {
	var safe *Error
	if errors.As(err, &safe) {
		return safe.Message
	}
	if errors.Is(err, context.Canceled) {
		return "Операция отменена."
	}
	return "Операция не выполнена. Секретные данные не записаны в диагностику."
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func NewEndpoint(host string, port int) (Endpoint, error) {
	if host == "" || port < 1 || port > 65535 || strings.ContainsAny(host, "%$[]/\\\x00\r\n") {
		return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		var err error
		host, err = idna.Lookup.ToASCII(strings.TrimRight(host, "."))
		if err != nil || len(host) > 253 {
			return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
		}
		host = strings.ToLower(host)
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
				}
			}
		}
	}
	return Endpoint{Host: host, Port: port}, nil
}
func ParseEndpoint(text string) (Endpoint, error) {
	host, rawPort, err := net.SplitHostPort(strings.TrimSpace(text))
	if err != nil {
		return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return Endpoint{}, E("endpoint_invalid", "Некорректный endpoint.")
	}
	return NewEndpoint(host, port)
}
func (e Endpoint) String() string  { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }
func (e Endpoint) Validate() error { _, err := NewEndpoint(e.Host, e.Port); return err }

type Profile struct {
	PrivateKey   string   `json:"-"`
	Addresses    []string `json:"-"`
	DNS          []string `json:"-"`
	PublicKey    string   `json:"-"`
	Endpoint     Endpoint `json:"-"`
	AllowedIPs   []string `json:"-"`
	MTU          int      `json:"-"`
	Keepalive    int      `json:"-"`
	PresharedKey string   `json:"-"`
	Reserved     *[3]byte `json:"-"`
}

func (p Profile) String() string {
	return fmt.Sprintf("Profile{endpoint:%s, secrets:redacted}", p.Endpoint)
}
func (p Profile) Identity() ([32]byte, error) {
	var out [32]byte
	key, err := base64.StdEncoding.Strict().DecodeString(p.PrivateKey)
	if err != nil || len(key) != len(out) {
		return out, E("profile_invalid", "Некорректный WireGuard-профиль.")
	}
	copy(out[:], key)
	out[0] &= 248
	out[31] = out[31]&127 | 64
	return out, nil
}
func (p Profile) Clone() Profile {
	p.Addresses = append([]string(nil), p.Addresses...)
	p.DNS = append([]string(nil), p.DNS...)
	p.AllowedIPs = append([]string(nil), p.AllowedIPs...)
	if p.Reserved != nil {
		value := *p.Reserved
		p.Reserved = &value
	}
	return p
}

type CheckResult struct {
	Endpoint   Endpoint  `json:"endpoint"`
	LatencyMS  float64   `json:"latency_ms"`
	VerifiedAt time.Time `json:"verified_at"`
	Role       string    `json:"role"`
}

func NewResult(endpoint Endpoint, latency float64, role string) CheckResult {
	return CheckResult{Endpoint: endpoint, LatencyMS: latency, VerifiedAt: time.Now().UTC(), Role: role}
}

type Cache struct {
	LastGood  *CheckResult  `json:"last_good"`
	Preferred *CheckResult  `json:"preferred"`
	Fallbacks []CheckResult `json:"fallbacks"`
}

func (c Cache) Clone() Cache {
	if c.LastGood != nil {
		r := *c.LastGood
		c.LastGood = &r
	}
	if c.Preferred != nil {
		r := *c.Preferred
		c.Preferred = &r
	}
	c.Fallbacks = append([]CheckResult(nil), c.Fallbacks...)
	return c
}
