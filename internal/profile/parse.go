// Package profile implements strict WireGuard imports and persistent WARP identities.
package profile

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0FL01/WarpPocket/internal/model"
)

const maxProfileSize = 65536

func invalidProfile() error {
	return model.E("profile_invalid", "Несовместимый профиль: нужен один WireGuard peer, явные DNS-IP и полный IPv4-маршрут; расширения запрещены.")
}

// Parse accepts only a single Interface/Peer pair, not wireproxy configuration.
// No parser error includes source text, keys, paths, or API response contents.
func Parse(data []byte) (model.Profile, error) {
	if len(data) > maxProfileSize || !utf8.Valid(data) || strings.ContainsAny(string(data), "$\x00") {
		return model.Profile{}, invalidProfile()
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	sections := make(map[string]map[string]string)
	section := ""
	previousOption, previousIndent := false, 0
	for _, original := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripComment(original))
		if line == "" {
			previousOption = false
			continue
		}
		indent := len(original) - len(strings.TrimLeftFunc(original, unicode.IsSpace))
		if previousOption && indent > previousIndent {
			return model.Profile{}, invalidProfile()
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return model.Profile{}, invalidProfile()
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if (section != "interface" && section != "peer") || sections[section] != nil {
				return model.Profile{}, invalidProfile()
			}
			sections[section] = make(map[string]string)
			previousOption = false
			continue
		}
		if section == "" {
			return model.Profile{}, invalidProfile()
		}
		name, value, found := strings.Cut(line, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !found || !allowedField(section, name) {
			return model.Profile{}, invalidProfile()
		}
		if _, duplicate := sections[section][name]; duplicate {
			return model.Profile{}, invalidProfile()
		}
		sections[section][name] = value
		previousOption, previousIndent = true, indent
	}
	if len(sections) != 2 {
		return model.Profile{}, invalidProfile()
	}
	i, peer := sections["interface"], sections["peer"]
	private, ok := normalizeKey(i["privatekey"])
	public, publicOK := normalizeKey(peer["publickey"])
	if !ok || !publicOK {
		return model.Profile{}, invalidProfile()
	}
	p := model.Profile{PrivateKey: private, PublicKey: public, MTU: 1280}
	var hasV4, hasV6, defaultV4, defaultV6 bool
	for _, item := range strings.Split(i["address"], ",") {
		prefix, err := parsePrefix(strings.TrimSpace(item))
		if err != nil || prefix.Addr().Zone() != "" {
			return model.Profile{}, invalidProfile()
		}
		hasV4 = hasV4 || prefix.Addr().Is4()
		hasV6 = hasV6 || prefix.Addr().Is6()
		p.Addresses = append(p.Addresses, prefix.String())
	}
	for _, item := range strings.Split(i["dns"], ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil || addr.Zone() != "" || (!hasV6 && addr.Is6()) {
			return model.Profile{}, invalidProfile()
		}
		p.DNS = append(p.DNS, addr.String())
	}
	for _, item := range strings.Split(peer["allowedips"], ",") {
		prefix, err := parsePrefix(strings.TrimSpace(item))
		if err != nil || prefix.Addr().Zone() != "" {
			return model.Profile{}, invalidProfile()
		}
		prefix = prefix.Masked()
		defaultV4 = defaultV4 || prefix.String() == "0.0.0.0/0"
		defaultV6 = defaultV6 || prefix.String() == "::/0"
		p.AllowedIPs = append(p.AllowedIPs, prefix.String())
	}
	if !hasV4 || !defaultV4 || (hasV6 && !defaultV6) {
		return model.Profile{}, invalidProfile()
	}
	if value, present := i["mtu"]; present {
		var err error
		p.MTU, err = strconv.Atoi(value)
		if err != nil {
			return model.Profile{}, invalidProfile()
		}
	}
	if value, present := peer["persistentkeepalive"]; present {
		var err error
		p.Keepalive, err = strconv.Atoi(value)
		if err != nil {
			return model.Profile{}, invalidProfile()
		}
	}
	minimumMTU := 576
	if hasV6 {
		minimumMTU = 1280
	}
	if p.MTU < minimumMTU || p.MTU > 65535 || p.Keepalive < 0 || p.Keepalive > 65535 {
		return model.Profile{}, invalidProfile()
	}
	var err error
	p.Endpoint, err = model.ParseEndpoint(peer["endpoint"])
	if err != nil {
		return model.Profile{}, invalidProfile()
	}
	if value, present := peer["presharedkey"]; present {
		p.PresharedKey, ok = normalizeKey(value)
		if !ok {
			return model.Profile{}, invalidProfile()
		}
	}
	if value, present := peer["reserved"]; present {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return model.Profile{}, invalidProfile()
		}
		var reserved [3]byte
		for index, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" || strings.IndexFunc(part, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
				return model.Profile{}, invalidProfile()
			}
			number, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return model.Profile{}, invalidProfile()
			}
			reserved[index] = byte(number)
		}
		p.Reserved = &reserved
	}
	return p, nil
}

func stripComment(line string) string {
	previousSpace := true
	for index, char := range line {
		if (char == '#' || char == ';') && previousSpace {
			return line[:index]
		}
		previousSpace = unicode.IsSpace(char)
	}
	return line
}

func allowedField(section, name string) bool {
	if section == "interface" {
		return name == "privatekey" || name == "address" || name == "dns" || name == "mtu"
	}
	return name == "publickey" || name == "presharedkey" || name == "allowedips" || name == "endpoint" || name == "persistentkeepalive" || name == "reserved"
}

func normalizeKey(value string) (string, bool) {
	if strings.ContainsAny(value, "\r\n") {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(key), true
}

func parsePrefix(value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, invalidProfile()
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	// Python ipaddress also accepts contiguous dotted IPv4 netmasks/hostmasks.
	host, rawMask, _ := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(host)
	maskAddr, maskErr := netip.ParseAddr(rawMask)
	if err != nil || maskErr != nil || !addr.Is4() || !maskAddr.Is4() {
		return netip.Prefix{}, invalidProfile()
	}
	maskBytes := maskAddr.As4()
	if maskBytes[0] == 0 && maskBytes != [4]byte{} {
		for index := range maskBytes {
			maskBytes[index] = ^maskBytes[index]
		}
	}
	ones, bits := net.IPMask(maskBytes[:]).Size()
	if bits != 32 {
		return netip.Prefix{}, invalidProfile()
	}
	return netip.PrefixFrom(addr, ones), nil
}

func Render(profile model.Profile, override *model.Endpoint) (string, error) {
	profile = profile.Clone()
	if override != nil {
		profile.Endpoint = *override
	}
	// Validate values even for programmatically constructed profiles. Rendering
	// must never turn an untrusted string into extra runtime configuration.
	normalized, err := Parse([]byte(render(profile)))
	if err != nil {
		return "", err
	}
	return render(normalized), nil
}

func render(p model.Profile) string {
	var out strings.Builder
	fmt.Fprintf(&out, "[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n", p.PrivateKey, strings.Join(p.Addresses, ", "), strings.Join(p.DNS, ", "), p.MTU, p.PublicKey, strings.Join(p.AllowedIPs, ", "), p.Endpoint.String(), p.Keepalive)
	if p.Reserved != nil {
		fmt.Fprintf(&out, "Reserved = %d, %d, %d\n", p.Reserved[0], p.Reserved[1], p.Reserved[2])
	}
	if p.PresharedKey != "" {
		fmt.Fprintf(&out, "PresharedKey = %s\n", p.PresharedKey)
	}
	return out.String()
}
