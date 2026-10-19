package profile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/storage"
)

func fixtureKey(seed byte) string {
	var key [32]byte
	for index := range key {
		key[index] = seed + byte(index)
	}
	return base64.StdEncoding.EncodeToString(key[:])
}

func fixtureProfile(seed byte) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 172.16.0.2/32, 2606:4700:110::1/128\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\nPersistentKeepalive = 25\n", fixtureKey(seed), fixtureKey(32))
}

func fixtureAccount(seed byte) Account {
	return Account{PrivateKey: fixtureKey(seed), DeviceID: "synthetic-device", AccessToken: "synthetic-token", LicenseKey: "synthetic-license"}
}

func profileStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(storage.Paths{Root: filepath.Join(t.TempDir(), "Личные данные")})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mustParse(t *testing.T, text string) model.Profile {
	t.Helper()
	profile, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func writeFixture(t *testing.T, store *storage.Store, role, name, text string) {
	t.Helper()
	if err := storage.AtomicWrite(filepath.Join(store.Paths.ProfileDir(role), name), []byte(text)); err != nil {
		t.Fatal(err)
	}
}

type fakeAPI struct {
	register func(context.Context) (Account, error)
	generate func(context.Context, Account) (model.Profile, error)
	reserved func(context.Context, Account) ([3]byte, error)
	posts    atomic.Int32
	gets     atomic.Int32
	reserves atomic.Int32
}

func (f *fakeAPI) Register(ctx context.Context) (Account, error) {
	f.posts.Add(1)
	if f.register == nil {
		return Account{}, errors.New("synthetic-token-should-never-appear")
	}
	return f.register(ctx)
}

func (f *fakeAPI) Generate(ctx context.Context, account Account) (model.Profile, error) {
	f.gets.Add(1)
	if f.generate == nil {
		return model.Profile{}, errors.New("synthetic-token-should-never-appear")
	}
	return f.generate(ctx, account)
}

func (f *fakeAPI) Reserved(ctx context.Context, account Account) ([3]byte, error) {
	f.reserves.Add(1)
	if f.reserved == nil {
		return [3]byte{}, errors.New("synthetic-token-should-never-appear")
	}
	return f.reserved(ctx, account)
}

func TestStrictImportRoundTripAndEndpointOverride(t *testing.T) {
	text := "\ufeff" + fixtureProfile(0) + "Reserved = 0, 0, 0\nPresharedKey = " + fixtureKey(96) + "\n"
	profile := mustParse(t, text)
	if profile.Reserved == nil || *profile.Reserved != [3]byte{} || profile.MTU != 1280 || profile.Keepalive != 25 {
		t.Fatal("optional profile fields were lost")
	}
	rendered, err := Render(profile, nil)
	if err != nil || !reflect.DeepEqual(mustParse(t, rendered), profile) || !strings.HasSuffix(rendered, "\n") {
		t.Fatal("normalized profile did not round trip")
	}
	override := model.Endpoint{Host: "2606:4700:d0::a29f:c001", Port: 500}
	rendered, err = Render(profile, &override)
	if err != nil || mustParse(t, rendered).Endpoint != override || profile.Endpoint == override {
		t.Fatal("runtime endpoint override mutated or failed validation")
	}
	if strings.Contains(fmt.Sprint(profile), profile.PrivateKey) {
		t.Fatal("profile formatting exposed private key")
	}
	profile.DNS = []string{"1.1.1.1\nPostUp = unsafe"}
	if _, err := Render(profile, nil); model.Code(err) != "profile_invalid" {
		t.Fatal("render accepted runtime configuration injection")
	}
}

func TestStrictImportRejectsUnsafeAndIncompatibleInput(t *testing.T) {
	valid := fixtureProfile(0)
	cases := map[string]string{
		"listener section":        valid + "[Socks5]\nBindAddress = 0.0.0.0:1\n",
		"case duplicate":          strings.Replace(valid, "MTU = 1280", "MTU = 1280\nmtu = 1280", 1),
		"duplicate peer":          valid + "[peer]\nPublicKey = bad\n",
		"defaults":                "[DEFAULT]\nMTU = 1280\n" + valid,
		"variable":                strings.Replace(valid, fixtureKey(0), "$PRIVATE_KEY", 1),
		"NUL":                     valid + "\x00",
		"hostname DNS":            strings.Replace(valid, "1.1.1.1, 1.0.0.1", "localhost", 1),
		"scoped DNS":              strings.Replace(valid, "1.1.1.1, 1.0.0.1", "fe80::1%zone", 1),
		"scoped address":          strings.Replace(valid, "2606:4700:110::1/128", "fe80::1%zone/128", 1),
		"pre-section option":      "WGConfig = /synthetic/file\n" + valid,
		"hook":                    strings.Replace(valid, "MTU = 1280", "MTU = 1280\nPostUp = unsafe", 1),
		"missing private key":     strings.Replace(valid, "PrivateKey = "+fixtureKey(0)+"\n", "", 1),
		"bad base64":              strings.Replace(valid, fixtureKey(0), "not-a-key", 1),
		"short key":               strings.Replace(valid, fixtureKey(0), base64.StdEncoding.EncodeToString(make([]byte, 31)), 1),
		"empty PSK":               valid + "PresharedKey =\n",
		"multiline":               strings.Replace(valid, "MTU = 1280", "MTU =\n  1280", 1),
		"IPv4 route required":     strings.Replace(valid, "0.0.0.0/0, ::/0", "10.0.0.0/8, ::/0", 1),
		"IPv4 interface required": strings.Replace(valid, "172.16.0.2/32, ", "", 1),
		"IPv6 route required":     strings.Replace(valid, "0.0.0.0/0, ::/0", "0.0.0.0/0", 1),
		"MTU too small":           strings.Replace(valid, "MTU = 1280", "MTU = 1279", 1),
		"MTU too large":           strings.Replace(valid, "MTU = 1280", "MTU = 65536", 1),
		"keepalive negative":      strings.Replace(valid, "PersistentKeepalive = 25", "PersistentKeepalive = -1", 1),
		"keepalive too large":     strings.Replace(valid, "PersistentKeepalive = 25", "PersistentKeepalive = 65536", 1),
		"bad endpoint":            strings.Replace(valid, "engage.cloudflareclient.com:2408", "::1:2408", 1),
		"invalid port":            strings.Replace(valid, ":2408", ":0", 1),
		"extra address comma":     strings.Replace(valid, "172.16.0.2/32,", "172.16.0.2/32,,", 1),
		"oversize":                valid + strings.Repeat("# padding\n", 7000),
		"invalid UTF8":            valid + string([]byte{0xff}),
	}
	for _, reserved := range []string{"1, 2", "1, 2, 3, 4", "256, 0, 0", "-1, 2, 3", "+1, 2, 3", "0x1, 2, 3", "1, 2, 3.5", "１, 2, 3"} {
		cases["reserved "+reserved] = valid + "Reserved = " + reserved + "\n"
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(text))
			if model.Code(err) != "profile_invalid" || strings.Contains(fmt.Sprint(err), fixtureKey(0)) {
				t.Fatal("unsafe profile was accepted or input leaked")
			}
		})
	}
}

func TestLegacyImportNormalizationAndIPv4Only(t *testing.T) {
	text := strings.ReplaceAll(fixtureProfile(0), "Address = 172.16.0.2/32, 2606:4700:110::1/128", "Address = 172.16.0.2/255.255.0.0")
	text = strings.Replace(text, "MTU = 1280", "MTU = 576 # inline comment", 1)
	text = strings.Replace(text, "0.0.0.0/0, ::/0", "123.4.5.6/0, 10.20.30.40/8", 1)
	text = strings.Replace(text, "engage.cloudflareclient.com:2408", "ENGAGE.CloudflareClient.com.:2408", 1)
	profile := mustParse(t, text)
	if profile.Addresses[0] != "172.16.0.2/16" || profile.AllowedIPs[1] != "10.0.0.0/8" || profile.Endpoint.Host != "engage.cloudflareclient.com" || profile.MTU != 576 {
		t.Fatal("legacy normalization changed")
	}
	if _, err := Parse([]byte(strings.Replace(text, "1.1.1.1, 1.0.0.1", "::1", 1))); err == nil {
		t.Fatal("IPv6 DNS accepted without IPv6 interface")
	}
}

func TestImportEnforcesClampedDistinctIdentities(t *testing.T) {
	store := profileStore(t)
	service := NewService(store, &fakeAPI{})
	writeFixture(t, store, model.Primary, "profile.conf", fixtureProfile(0))
	private, _ := base64.StdEncoding.DecodeString(fixtureKey(0))
	private[0] ^= 7
	private[31] ^= 0xc0
	alternate := strings.Replace(fixtureProfile(0), fixtureKey(0), base64.StdEncoding.EncodeToString(private), 1)
	if err := service.Import([]byte(alternate), model.Probe); model.Code(err) != "profile_same_key" || service.Exists(model.Probe) {
		t.Fatal("same effective X25519 identity was imported")
	}
	writeFixture(t, store, model.Probe, "profile.conf", alternate)
	if _, err := service.Load(model.Primary); model.Code(err) != "profile_same_key" {
		t.Fatal("legacy duplicate identities were loaded")
	}
}

func TestImportCacheInvalidationAndAccountRemoval(t *testing.T) {
	store := profileStore(t)
	service := NewService(store, &fakeAPI{})
	writeFixture(t, store, model.Primary, "profile.conf", fixtureProfile(0))
	primary := model.NewResult(model.Endpoint{Host: "192.0.2.1", Port: 2408}, 1, model.Primary)
	probe := model.NewResult(model.Endpoint{Host: "192.0.2.2", Port: 2408}, 2, model.Probe)
	if err := store.SaveCache(model.Cache{LastGood: &primary, Preferred: &probe, Fallbacks: []model.CheckResult{probe, primary}}); err != nil {
		t.Fatal(err)
	}
	if err := writeAccount(filepath.Join(store.Paths.ProfileDir(model.Probe), "account.toml"), fixtureAccount(64)); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, store, model.Probe, pendingRegistration, "synthetic incomplete marker")
	if err := service.Import([]byte(fixtureProfile(64)+"Reserved = 7, 8, 9\n"), model.Probe); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"account.toml", pendingRegistration} {
		if _, err := os.Lstat(filepath.Join(store.Paths.ProfileDir(model.Probe), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("import retained account or ambiguous registration marker")
		}
	}
	cache, err := store.LoadCache()
	if err != nil || cache.LastGood == nil || cache.LastGood.Role != model.Primary || cache.Preferred != nil || len(cache.Fallbacks) != 1 || cache.Fallbacks[0].Role != model.Primary {
		t.Fatal("probe import invalidated the wrong cache entries")
	}
	loaded, err := service.Load(model.Probe)
	if err != nil || loaded.Reserved == nil || *loaded.Reserved != [3]byte{7, 8, 9} {
		t.Fatal("normalized imported profile lost Reserved")
	}
	if err := service.Import([]byte(fixtureProfile(0)), model.Primary); err != nil {
		t.Fatal(err)
	}
	cache, err = store.LoadCache()
	if err != nil || cache.LastGood != nil || cache.Preferred != nil || len(cache.Fallbacks) != 0 {
		t.Fatal("primary import did not invalidate the full cache")
	}
}

func TestImportDoesNotOverwriteUnknownCacheSchema(t *testing.T) {
	store := profileStore(t)
	unknown := `{"schema_version":2,"untouched":"synthetic future data"}`
	if err := storage.AtomicWrite(store.Paths.Settings(), []byte(unknown)); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, &fakeAPI{})
	if err := service.Import([]byte(fixtureProfile(0)), model.Primary); model.Code(err) != "cache_read_only" || !service.Exists(model.Primary) {
		t.Fatal("import should preserve profile and report read-only cache warning")
	}
	if data, _ := os.ReadFile(store.Paths.Settings()); string(data) != unknown {
		t.Fatal("import rewrote unknown cache schema")
	}
}

func TestSavedProfileAndReservedNeverUseAPI(t *testing.T) {
	store := profileStore(t)
	api := &fakeAPI{}
	service := NewService(store, api)
	text := fixtureProfile(0) + "Reserved = 0, 0, 0\n"
	writeFixture(t, store, model.Primary, "profile.conf", text)
	for _, consent := range []bool{false, true} {
		if _, err := service.EnsureProfile(context.Background(), model.Primary, consent); err != nil {
			t.Fatal(err)
		}
		if _, err := service.EnsureReserved(context.Background(), model.Primary); err != nil {
			t.Fatal(err)
		}
	}
	if api.posts.Load()+api.gets.Load()+api.reserves.Load() != 0 {
		t.Fatal("saved identity triggered network calls")
	}
	if data, _ := os.ReadFile(service.profilePath(model.Primary)); string(data) != text {
		t.Fatal("saved profile was silently rewritten")
	}
}

func TestExistingAndImportedKeepaliveValuesAreNotDefaultedOrRewritten(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        int
	}{
		{"absent", "", 0},
		{"disabled", "PersistentKeepalive = 0\n", 0},
		{"nondefault", "PersistentKeepalive = 17\n", 17},
	} {
		for _, imported := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/imported=%t", tc.name, imported), func(t *testing.T) {
				store := profileStore(t)
				api := &fakeAPI{}
				service := NewService(store, api)
				text := strings.Replace(fixtureProfile(0), "PersistentKeepalive = 25\n", tc.field, 1) + "Reserved = 0, 0, 0\n# retained saved formatting\n"
				if imported {
					if err := service.Import([]byte(text), model.Primary); err != nil {
						t.Fatal(err)
					}
				} else {
					writeFixture(t, store, model.Primary, "profile.conf", text)
				}
				path := service.profilePath(model.Primary)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, load := range []func() (model.Profile, error){
					func() (model.Profile, error) { return service.Load(model.Primary) },
					func() (model.Profile, error) {
						return service.EnsureProfile(context.Background(), model.Primary, false)
					},
					func() (model.Profile, error) { return service.EnsureReserved(context.Background(), model.Primary) },
				} {
					p, err := load()
					if err != nil || p.Keepalive != tc.want {
						t.Fatal("existing/imported keepalive value was changed")
					}
					rendered, err := Render(p, &model.Endpoint{Host: "192.0.2.1", Port: 500})
					if err != nil || mustParse(t, rendered).Keepalive != tc.want {
						t.Fatal("runtime endpoint render changed keepalive")
					}
				}
				if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
					t.Fatal("loading an existing/imported profile rewrote its bytes")
				}
				if api.posts.Load()+api.gets.Load()+api.reserves.Load() != 0 {
					t.Fatal("loading an existing/imported profile made an API call")
				}
			})
		}
	}
}

func TestServiceDoesNotApplyNativeKeepaliveDefaultToOtherGenerators(t *testing.T) {
	store := profileStore(t)
	if err := writeAccount(filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml"), fixtureAccount(0)); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{generate: func(context.Context, Account) (model.Profile, error) {
		p := mustParse(t, fixtureProfile(0))
		p.Keepalive = 0
		return p, nil
	}}
	service := NewService(store, api)
	p, err := service.EnsureProfile(context.Background(), model.Primary, false)
	if err != nil || p.Keepalive != 0 || api.posts.Load() != 0 || api.gets.Load() != 1 {
		t.Fatal("service defaulted an explicitly disabled keepalive from another generator")
	}
	if loaded, err := service.Load(model.Primary); err != nil || loaded.Keepalive != 0 {
		t.Fatal("service did not save the generator's original keepalive value")
	}
}

func TestExplicitConsentAndIncompleteAccountsNeverRegister(t *testing.T) {
	for _, existing := range []string{"none", "corrupt account", "empty account", "marker", "oversize account"} {
		t.Run(existing, func(t *testing.T) {
			store := profileStore(t)
			api := &fakeAPI{}
			service := NewService(store, api)
			want := "account_incomplete"
			switch existing {
			case "none":
				want = "consent_required"
			case "marker":
				writeFixture(t, store, model.Primary, pendingRegistration, "incomplete")
			case "oversize account":
				writeFixture(t, store, model.Primary, "account.toml", strings.Repeat("#", maxProfileSize+1))
			case "corrupt account":
				writeFixture(t, store, model.Primary, "account.toml", "broken = { private_key = 'synthetic' }")
			default:
				writeFixture(t, store, model.Primary, "account.toml", "")
			}
			if _, err := service.EnsureProfile(context.Background(), model.Primary, existing != "none"); model.Code(err) != want {
				t.Fatalf("wrong registration guard: %s", model.Code(err))
			}
			if api.posts.Load() != 0 {
				t.Fatal("missing consent or incomplete account caused a registration")
			}
		})
	}
}

func TestPartialRegistrationPersistsBeforeGenerationAndResumes(t *testing.T) {
	store := profileStore(t)
	account := fixtureAccount(0)
	api := &fakeAPI{
		register: func(context.Context) (Account, error) {
			if _, err := os.Stat(filepath.Join(store.Paths.ProfileDir(model.Primary), pendingRegistration)); err != nil {
				t.Error("POST began without persisted incomplete marker")
			}
			return account, errors.New("synthetic-token-should-never-appear")
		},
	}
	api.generate = func(_ context.Context, got Account) (model.Profile, error) {
		persisted, err := readAccount(filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml"))
		if err != nil || persisted != account || got != account {
			t.Error("generation began before account credentials were saved")
		}
		if api.gets.Load() == 1 {
			return model.Profile{}, errors.New("synthetic-token-should-never-appear")
		}
		return mustParse(t, fixtureProfile(0)), nil
	}
	service := NewService(store, api)
	if _, err := service.EnsureProfile(context.Background(), model.Primary, true); model.Code(err) != "generation_failed" || strings.Contains(err.Error(), account.AccessToken) {
		t.Fatal("partial registration failed unsafely")
	}
	service = NewService(store, api)
	if _, err := service.EnsureProfile(context.Background(), model.Primary, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureProfile(context.Background(), model.Primary, false); err != nil {
		t.Fatal(err)
	}
	if api.posts.Load() != 1 || api.gets.Load() != 2 {
		t.Fatal("partial registration was repeated or saved profile regenerated")
	}
}

func TestAmbiguousPostAndCancellationNeverAutomaticallyRepeat(t *testing.T) {
	for _, mode := range []string{"ambiguous", "cancel before", "cancel after", "cancel with account"} {
		t.Run(mode, func(t *testing.T) {
			store := profileStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api := &fakeAPI{register: func(context.Context) (Account, error) {
				if mode != "ambiguous" {
					cancel()
				}
				if mode == "cancel with account" {
					return fixtureAccount(0), context.Canceled
				}
				return Account{}, errors.New("synthetic-token-should-never-appear")
			}}
			if mode == "cancel before" {
				cancel()
			}
			service := NewService(store, api)
			_, err := service.EnsureProfile(ctx, model.Primary, true)
			if mode == "ambiguous" {
				if model.Code(err) != "registration_failed" {
					t.Fatal("ambiguous post not reported")
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was lost")
			}
			if mode == "cancel before" {
				if api.posts.Load() != 0 {
					t.Fatal("cancelled operation registered")
				}
				if _, err := os.Lstat(filepath.Join(store.Paths.ProfileDir(model.Primary), pendingRegistration)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("pre-cancelled operation created a marker")
				}
				return
			}
			service = NewService(store, api)
			_, err = service.EnsureProfile(context.Background(), model.Primary, true)
			want := "account_incomplete"
			if mode == "cancel with account" {
				want = "generation_failed"
				if _, err := readAccount(filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml")); err != nil {
					t.Fatal("successful credentials were discarded on cancellation")
				}
			}
			if model.Code(err) != want || api.posts.Load() != 1 {
				t.Fatal("ambiguous/cancelled POST was automatically repeated")
			}
		})
	}
}

func TestConcurrentServicesRegisterOnlyOncePerRole(t *testing.T) {
	store := profileStore(t)
	api := &fakeAPI{register: func(context.Context) (Account, error) { return fixtureAccount(0), nil }, generate: func(context.Context, Account) (model.Profile, error) { return mustParse(t, fixtureProfile(0)), nil }}
	secondStore, err := storage.New(store.Paths)
	if err != nil {
		t.Fatal(err)
	}
	services := []*Service{NewService(store, api), NewService(secondStore, api)}
	var group sync.WaitGroup
	for index := range 8 {
		group.Go(func() {
			if _, err := services[index%2].EnsureProfile(context.Background(), model.Primary, true); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if api.posts.Load() != 1 || api.gets.Load() != 1 {
		t.Fatal("same-root concurrent services duplicated registration/generation")
	}
	if _, err := services[0].EnsureProfile(context.Background(), model.Probe, false); model.Code(err) != "consent_required" || api.posts.Load() != 1 {
		t.Fatal("primary consent was incorrectly reused for probe")
	}
}

func TestEnsureReservedPersistsIdentityAndReuses(t *testing.T) {
	store := profileStore(t)
	writeFixture(t, store, model.Primary, "profile.conf", fixtureProfile(0))
	if err := writeAccount(filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml"), fixtureAccount(0)); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{reserved: func(context.Context, Account) ([3]byte, error) { return [3]byte{7, 8, 9}, nil }}
	service := NewService(store, api)
	original := mustParse(t, fixtureProfile(0))
	for range 2 {
		profile, err := service.EnsureReserved(context.Background(), model.Primary)
		if err != nil || profile.Reserved == nil || *profile.Reserved != [3]byte{7, 8, 9} {
			t.Fatal("Reserved was not persisted")
		}
		before, _ := original.Identity()
		after, _ := profile.Identity()
		if before != after {
			t.Fatal("Reserved fetch changed identity")
		}
	}
	if api.reserves.Load() != 1 || api.posts.Load()+api.gets.Load() != 0 {
		t.Fatal("Reserved was unnecessarily fetched twice or registered")
	}
}

func TestEnsureReservedMissingMismatchedAndFailedAccountIsSafe(t *testing.T) {
	for _, mode := range []string{"missing", "mismatched", "failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			store := profileStore(t)
			writeFixture(t, store, model.Primary, "profile.conf", fixtureProfile(0))
			if mode != "missing" {
				seed := byte(0)
				if mode == "mismatched" {
					seed = 64
				}
				if err := writeAccount(filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml"), fixtureAccount(seed)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api := &fakeAPI{reserved: func(context.Context, Account) ([3]byte, error) {
				if mode == "cancelled" {
					cancel()
					return [3]byte{7, 8, 9}, nil
				}
				return [3]byte{}, errors.New("synthetic-token-should-never-appear")
			}}
			service := NewService(store, api)
			_, err := service.EnsureReserved(ctx, model.Primary)
			if mode == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled Reserved result was persisted")
				}
			} else if model.Code(err) != "reserved_unavailable" || strings.Contains(err.Error(), "synthetic-token") {
				t.Fatal("Reserved error was not sanitized")
			}
			if loaded, err := service.Load(model.Primary); err != nil || loaded.Reserved != nil {
				t.Fatal("failed/cancelled Reserved fetch rewrote profile")
			}
			if (mode == "missing" || mode == "mismatched") && api.reserves.Load() != 0 {
				t.Fatal("unavailable account caused API call")
			}
		})
	}
}

func TestRoleValidationAndMissingProfileErrorsAreSafe(t *testing.T) {
	store := profileStore(t)
	api := &fakeAPI{}
	service := NewService(store, api)
	for _, role := range []string{"", "../outside", "Primary", "/tmp/synthetic"} {
		if service.Exists(role) {
			t.Fatal("invalid role exists")
		}
		_, loadErr := service.Load(role)
		_, ensureErr := service.EnsureProfile(context.Background(), role, true)
		_, reservedErr := service.EnsureReserved(context.Background(), role)
		for _, err := range []error{loadErr, ensureErr, reservedErr, service.Import([]byte(fixtureProfile(0)), role)} {
			if model.Code(err) != "profile_role_invalid" {
				t.Fatal("role was not validated before file access")
			}
		}
	}
	if _, err := service.Load(model.Primary); model.Code(err) != "profile_read_failed" || strings.Contains(err.Error(), store.Paths.Root) {
		t.Fatal("missing profile exposed a raw path error")
	}
	if api.posts.Load()+api.gets.Load()+api.reserves.Load() != 0 {
		t.Fatal("invalid roles touched API")
	}
}

func TestAccountLegacyTOMLAndRedaction(t *testing.T) {
	store := profileStore(t)
	path := filepath.Join(store.Paths.ProfileDir(model.Primary), "account.toml")
	text := fmt.Sprintf("private_key = '%s'\ndevice_id = 'synthetic-device'\naccess_token = 'synthetic-token'\nlicense_key = 'synthetic-license'\n", fixtureKey(0))
	writeFixture(t, store, model.Primary, "account.toml", text)
	account, err := readAccount(path)
	if err != nil || account != fixtureAccount(0) {
		t.Fatal("legacy TOML account rejected")
	}
	for _, rendered := range []string{fmt.Sprint(account), fmt.Sprintf("%#v", account)} {
		if strings.Contains(rendered, account.AccessToken) || strings.Contains(rendered, account.PrivateKey) || strings.Contains(rendered, account.DeviceID) {
			t.Fatal("account formatting exposed secrets")
		}
	}
	for _, invalid := range []string{strings.Replace(text, "access_token = 'synthetic-token'", "access_token = 42", 1), text + "private_key = 'duplicate'\n", strings.Replace(text, "synthetic-token", "", 1)} {
		writeFixture(t, store, model.Primary, "account.toml", invalid)
		if _, err := readAccount(path); model.Code(err) != "account_incomplete" {
			t.Fatal("incomplete legacy account was accepted")
		}
	}
}
