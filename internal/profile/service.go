package profile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/storage"
	"github.com/pelletier/go-toml/v2"
)

const pendingRegistration = "registration.pending"

// Account is the four-field legacy wgcf account.toml format. Its formatting and
// JSON representation deliberately do not expose private keys or API tokens.
type Account struct {
	PrivateKey  string `toml:"private_key" json:"-"`
	DeviceID    string `toml:"device_id" json:"-"`
	AccessToken string `toml:"access_token" json:"-"`
	LicenseKey  string `toml:"license_key" json:"-"`
}

func (Account) String() string   { return "Account{secrets:redacted}" }
func (Account) GoString() string { return "Account{secrets:redacted}" }

// API is deliberately per-account: implementations must not cache authorization
// globally. Register may return a valid account together with an error after a
// partial success; Service persists it and can resume generation safely.
type API interface {
	Register(context.Context) (Account, error)
	Generate(context.Context, Account) (model.Profile, error)
	Reserved(context.Context, Account) ([3]byte, error)
}

type Service struct {
	store *storage.Store
	api   API
}

func NewService(store *storage.Store, api API) *Service {
	if api == nil {
		api = NewClient()
	}
	return &Service{store: store, api: api}
}

func roleError(role string) error {
	if !model.ValidRole(role) {
		return model.E("profile_role_invalid", "Некорректная роль профиля.")
	}
	return nil
}

func (s *Service) profilePath(role string) string {
	return filepath.Join(s.store.Paths.ProfileDir(role), "profile.conf")
}

func (s *Service) Exists(role string) bool {
	if !model.ValidRole(role) {
		return false
	}
	info, err := os.Lstat(s.profilePath(role))
	return err == nil && info.Mode().IsRegular()
}

func (s *Service) Load(role string) (model.Profile, error) {
	if err := roleError(role); err != nil {
		return model.Profile{}, err
	}
	var profile model.Profile
	err := s.store.WithProfilesLock(func() error {
		var err error
		profile, err = s.load(role)
		return err
	})
	return profile, err
}

func (s *Service) load(role string) (model.Profile, error) {
	profile, err := readProfile(s.profilePath(role))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return model.Profile{}, profileReadError()
		}
		return model.Profile{}, err
	}
	if err := s.different(role, profile); err != nil {
		return model.Profile{}, err
	}
	return profile, nil
}

func (s *Service) different(role string, profile model.Profile) error {
	otherRole := model.Primary
	if role == model.Primary {
		otherRole = model.Probe
	}
	other, err := readProfile(s.profilePath(otherRole))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	otherIdentity, err := other.Identity()
	if err != nil {
		return err
	}
	if identity == otherIdentity {
		return model.E("profile_same_key", "Основной и проверочный профили должны иметь разные WireGuard-ключи.")
	}
	return nil
}

func (s *Service) EnsureProfile(ctx context.Context, role string, consent bool) (model.Profile, error) {
	if err := roleError(role); err != nil {
		return model.Profile{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.Profile{}, err
	}
	var result model.Profile
	err := s.store.WithProfilesLock(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := os.Lstat(s.profilePath(role)); err == nil {
			var loadErr error
			result, loadErr = s.load(role)
			return loadErr
		} else if !errors.Is(err, os.ErrNotExist) {
			return profileReadError()
		}
		folder := s.store.Paths.ProfileDir(role)
		accountPath := filepath.Join(folder, "account.toml")
		account, err := readAccount(accountPath)
		if errors.Is(err, os.ErrNotExist) {
			if _, markerErr := os.Lstat(filepath.Join(folder, pendingRegistration)); !errors.Is(markerErr, os.ErrNotExist) {
				return incompleteAccount()
			}
			if !consent {
				return model.E("consent_required", "Для регистрации требуется согласие с условиями Cloudflare.")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			// Persist before a potentially ambiguous POST, including cancellation,
			// timeouts, a lost response, or process termination.
			if err := storage.AtomicWrite(filepath.Join(folder, pendingRegistration), []byte("version = 1\nstate = 'incomplete'\n")); err != nil {
				return err
			}
			registered, registrationErr := s.api.Register(ctx)
			if validAccount(&registered) {
				if err := writeAccount(accountPath, registered); err != nil {
					return err
				}
				account = registered
				// An account always takes precedence over a stale marker, so a
				// failed marker removal cannot cause another POST.
				_ = os.Remove(filepath.Join(folder, pendingRegistration))
			} else {
				if err := ctx.Err(); err != nil {
					return err
				}
				_ = registrationErr // never expose SDK/server/transport error text
				return model.E("registration_failed", "Регистрация WARP не завершилась. Автоматический повтор запрещён; можно импортировать совместимый профиль.")
			}
		} else if err != nil {
			return incompleteAccount()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		profile, err := s.api.Generate(ctx, account)
		if err != nil {
			return apiFailure(ctx, "generation_failed", "Не удалось получить профиль WARP; аккаунт сохранён для повторной генерации.")
		}
		text, err := Render(profile, nil)
		if err != nil || !sameAccount(profile, account) {
			return model.E("generation_failed", "Не удалось получить совместимый профиль WARP; аккаунт сохранён для повторной генерации.")
		}
		profile, _ = Parse([]byte(text))
		if err := s.different(role, profile); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := storage.AtomicWrite(s.profilePath(role), []byte(text)); err != nil {
			return err
		}
		result = profile
		return nil
	})
	return result, err
}

func (s *Service) EnsureReserved(ctx context.Context, role string) (model.Profile, error) {
	if err := roleError(role); err != nil {
		return model.Profile{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.Profile{}, err
	}
	var result model.Profile
	err := s.store.WithProfilesLock(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		profile, err := s.load(role)
		if err != nil {
			return err
		}
		if profile.Reserved != nil {
			result = profile
			return nil
		}
		account, err := readAccount(filepath.Join(s.store.Paths.ProfileDir(role), "account.toml"))
		if err != nil || !sameAccount(profile, account) {
			return model.E("reserved_unavailable", "Аккаунт недоступен, поэтому Reserved не получен. Импортируйте профиль с полем Reserved.")
		}
		reserved, err := s.api.Reserved(ctx, account)
		if err != nil {
			return apiFailure(ctx, "reserved_unavailable", reservedHint)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		profile.Reserved = &reserved
		text, err := Render(profile, nil)
		if err != nil {
			return err
		}
		if err := storage.AtomicWrite(s.profilePath(role), []byte(text)); err != nil {
			return err
		}
		result = profile
		return nil
	})
	return result, err
}

// Import is called after active network operations are stopped, while the
// application holds its instance lock. Unknown cache versions remain untouched.
func (s *Service) Import(data []byte, role string) error {
	if err := roleError(role); err != nil {
		return err
	}
	profile, err := Parse(data)
	if err != nil {
		return err
	}
	return s.store.WithProfilesLock(func() error {
		if err := s.different(role, profile); err != nil {
			return err
		}
		text, err := Render(profile, nil)
		if err != nil {
			return err
		}
		if err := storage.AtomicWrite(s.profilePath(role), []byte(text)); err != nil {
			return err
		}
		for _, name := range []string{"account.toml", pendingRegistration} {
			if err := os.Remove(filepath.Join(s.store.Paths.ProfileDir(role), name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return model.E("profile_import_failed", "Профиль сохранён, но не удалось удалить данные прежнего аккаунта.")
			}
		}
		return s.store.UpdateCache(func(cache model.Cache) model.Cache {
			if role == model.Primary {
				return model.Cache{}
			}
			if cache.Preferred != nil && cache.Preferred.Role == model.Probe {
				cache.Preferred = nil
			}
			fallbacks := cache.Fallbacks[:0]
			for _, item := range cache.Fallbacks {
				if item.Role != model.Probe {
					fallbacks = append(fallbacks, item)
				}
			}
			cache.Fallbacks = fallbacks
			return cache
		})
	})
}

func incompleteAccount() error {
	return model.E("account_incomplete", "Сохранённый аккаунт неполон; автоматическая повторная регистрация запрещена. Импортируйте профиль.")
}

func profileReadError() error {
	return model.E("profile_read_failed", "Не удалось прочитать совместимый профиль.")
}

func readProfile(path string) (model.Profile, error) {
	data, err := readPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		// The sentinel is used only internally; public entry points sanitize it.
		return model.Profile{}, err
	}
	if err != nil {
		return model.Profile{}, profileReadError()
	}
	return Parse(data)
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxProfileSize {
		return nil, errors.New("invalid file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxProfileSize+1))
	if err != nil || len(data) > maxProfileSize || !utf8.Valid(data) {
		return nil, errors.New("invalid file")
	}
	return data, nil
}

func validAccount(account *Account) bool {
	key, ok := normalizeKey(account.PrivateKey)
	if !ok || strings.TrimSpace(account.DeviceID) == "" || strings.TrimSpace(account.AccessToken) == "" || strings.ContainsAny(account.DeviceID, "/\\?#%\x00\r\n") || strings.ContainsAny(account.AccessToken, "\x00\r\n") {
		return false
	}
	account.PrivateKey = key
	return true
}

func readAccount(path string) (Account, error) {
	data, err := readPrivate(path)
	if err != nil {
		return Account{}, err
	}
	var account Account
	if toml.Unmarshal(data, &account) != nil || !validAccount(&account) {
		return Account{}, incompleteAccount()
	}
	return account, nil
}

func writeAccount(path string, account Account) error {
	if !validAccount(&account) {
		return incompleteAccount()
	}
	data, err := toml.Marshal(account)
	if err != nil || len(data) > maxProfileSize {
		return incompleteAccount()
	}
	return storage.AtomicWrite(path, data)
}

func sameAccount(profile model.Profile, account Account) bool {
	identity, err := profile.Identity()
	other, otherErr := (model.Profile{PrivateKey: account.PrivateKey}).Identity()
	return err == nil && otherErr == nil && identity == other
}

func apiFailure(ctx context.Context, code, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return model.E(code, message)
}
