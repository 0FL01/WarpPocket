// Package application wires the native controller without initializing a GUI.
// Tests, real opt-in gates and the GUI use the same production dependencies.
package application

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/controller"
	"github.com/0FL01/WarpPocket/internal/diagnostics"
	"github.com/0FL01/WarpPocket/internal/finder"
	"github.com/0FL01/WarpPocket/internal/health"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/process"
	"github.com/0FL01/WarpPocket/internal/profile"
	"github.com/0FL01/WarpPocket/internal/storage"
)

type Application struct {
	Store      *storage.Store
	Profiles   *profile.Service
	Manager    *process.Manager
	Backend    *backend.Backend
	Finder     *finder.Finder
	Controller *controller.Controller
	lock       *storage.Lock
	closeOnce  sync.Once
}

func New(dataDir, executable string) (*Application, error) {
	var paths storage.Paths
	var err error
	if dataDir == "" {
		paths, err = storage.DefaultPaths()
	} else {
		paths.Root, err = filepath.Abs(dataDir)
	}
	if err != nil {
		return nil, err
	}
	lock, err := storage.AcquireLock(paths.Root)
	if err != nil {
		return nil, err
	}
	store, err := storage.New(paths)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if executable == "" {
		executable, err = os.Executable()
	}
	if err != nil {
		_ = lock.Close()
		return nil, model.E("executable_unavailable", "Не удалось найти исполняемый файл приложения.")
	}
	a := &Application{Store: store, Profiles: profile.NewService(store, nil), Manager: process.NewManager(), lock: lock}
	a.Backend = backend.New(store.Paths, a.Manager, executable)
	a.Finder = finder.New(a.Backend, health.Check, finder.Options{})
	logger := diagnostics.New(store.Paths)
	a.Controller = controller.New(store, a.Profiles, a.Backend, a.Finder, a.Manager, health.Check, controller.Options{Log: logger.Event})
	return a, nil
}

func (a *Application) Close() {
	a.closeOnce.Do(func() { a.Controller.Close(); _ = a.Manager.Shutdown(); _ = a.lock.Close() })
}

func (a *Application) Import(data []byte, role string) error {
	s := a.Controller.Status()
	if s.Searching || s.Busy || s.State == model.Connecting || s.State == model.Connected {
		return model.E("busy", "Дождитесь завершения операций перед импортом.")
	}
	return a.Profiles.Import(data, role)
}

func (a *Application) Diagnostics() string {
	return fmt.Sprintf("WarpPocket · Go / Gio\nКаталог данных: %s\nДиагностика: %s\nSOCKS5: 127.0.0.1:25344\nКлючи, токены и содержимое профилей в диагностику не выводятся.", a.Store.Paths.Root, filepath.Join(a.Store.Paths.Logs(), "diagnostics.log"))
}
