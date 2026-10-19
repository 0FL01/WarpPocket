package engine

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/profile"
)

func TestValidateRuntimeOnly(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	p := model.Profile{PrivateKey: key, PublicKey: key, Addresses: []string{"172.16.0.2/32"},
		DNS:      []string{"83.220.169.155", "212.109.195.93", "194.87.196.13", "45.151.102.219", "9.9.9.9"},
		Endpoint: model.Endpoint{Host: "127.0.0.1", Port: 9}, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1280}
	text, err := profile.Render(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := fmt.Sprintf("%s\n[Socks5]\nBindAddress = 127.0.0.1:25344\n\n[Resolve]\nResolveStrategy = ipv4\n", text)
	path := filepath.Join(t.TempDir(), "primary-00000000000000000000000000000000.conf")
	for name, content := range map[string]string{
		"valid":           good,
		"wildcard":        strings.Replace(good, "127.0.0.1:25344", "0.0.0.0:25344", 1),
		"extra listener":  good + "[Http]\nBindAddress = 127.0.0.1:8080\n",
		"system dns":      strings.Replace(good, "83.220.169.155, 212.109.195.93, 194.87.196.13, 45.151.102.219, 9.9.9.9", "", 1),
		"invalid profile": strings.Replace(good, "[Peer]", "[Peer]\nPostUp = anything", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			err := Validate(path, model.Primary)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected validation: %v", err)
			}
		})
	}
	if Validate(path, model.Probe) == nil || Validate("relative.conf", model.Primary) == nil || Validate(path, "unknown") == nil {
		t.Fatal("invalid worker arguments accepted")
	}
}
