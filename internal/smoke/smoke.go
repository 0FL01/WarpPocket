// Package smoke exercises the shipped GUI and same-executable engine without
// Cloudflare registration, Internet traffic or real user profiles.
package smoke

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/0FL01/WarpPocket/internal/application"
	"github.com/0FL01/WarpPocket/internal/backend"
	"github.com/0FL01/WarpPocket/internal/controller"
	"github.com/0FL01/WarpPocket/internal/model"
	"github.com/0FL01/WarpPocket/internal/profile"
	"github.com/0FL01/WarpPocket/internal/resources"
	"github.com/0FL01/WarpPocket/internal/storage"
	"github.com/0FL01/WarpPocket/internal/trust"
	"github.com/0FL01/WarpPocket/internal/ui"
)

type Report struct {
	SchemaVersion int             `json:"schema_version"`
	Mode          string          `json:"mode"`
	OK            bool            `json:"ok"`
	PID           int             `json:"pid"`
	Checks        map[string]bool `json:"checks"`
	ChildPID      int             `json:"child_pid"`
	Port          int             `json:"port"`
	Workspace     string          `json:"workspace"`
	ErrorCode     *string         `json:"error_code"`
}

func syntheticProfile() model.Profile {
	private, public := make([]byte, 32), make([]byte, 32)
	for i := range private {
		private[i], public[i] = byte(i+1), byte(i+33)
	}
	return model.Profile{PrivateKey: base64.StdEncoding.EncodeToString(private), PublicKey: base64.StdEncoding.EncodeToString(public),
		Addresses: []string{"172.16.0.2/32"}, DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0"},
		Endpoint: model.Endpoint{Host: "127.0.0.1", Port: 9}, MTU: 1280, Reserved: &[3]byte{1, 2, 3}}
}

type owner struct {
	*controller.Controller
	app      *application.Application
	instance *backend.Instance
	once     sync.Once
	err      error
}

func (o *owner) Close() {
	o.once.Do(func() {
		o.app.Close()
		o.err = o.app.Backend.Stop(o.instance)
		if o.err == nil {
			o.err = o.Controller.CloseError()
		}
	})
}

func writeReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return storage.AtomicWrite(path, data)
}

func cleanupWorkspace(path, workingDir string) error {
	// The Windows common-file dialog can change the process working directory
	// to the selected profile's directory, preventing its removal until we leave.
	if err := os.Chdir(workingDir); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// Run must execute on the GUI goroutine while main calls app.Main. The ready
// report is emitted only after real frames and a live worker's SOCKS greeting.
// In wait mode CI intentionally kills this GUI PID; normal exit is a failure.
func Run(path string, wait bool) (result error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return model.E("smoke_workspace", "Не удалось подготовить проверку.")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return model.E("smoke_report", "Не удалось записать отчёт проверки.")
	}
	report := Report{SchemaVersion: 2, Mode: "graceful", PID: os.Getpid(), Checks: map[string]bool{}}
	if wait {
		report.Mode = "wait"
	}
	var a *application.Application
	var owned *owner
	defer func() {
		if owned != nil {
			owned.Close()
		} else if a != nil {
			a.Close()
		}
		if report.Workspace != "" {
			if err := cleanupWorkspace(report.Workspace, workingDir); err != nil && result == nil {
				result = model.E("smoke_cleanup", "Не выполнена очистка проверки.")
			}
		}
		if result != nil {
			code := model.Code(result)
			report.ErrorCode, report.OK = &code, false
		}
		if err := writeReport(path, report); err != nil && result == nil {
			result = model.E("smoke_report", "Не удалось записать отчёт проверки.")
		}
	}()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return model.E("smoke_report", "Не удалось подготовить отчёт проверки.")
	}
	report.Workspace, err = os.MkdirTemp(filepath.Dir(path), "runtime-")
	if err != nil {
		return model.E("smoke_workspace", "Не удалось подготовить проверку.")
	}
	a, err = application.New(report.Workspace, "")
	if err != nil {
		return err
	}
	pool, err := trust.Pool()
	if err != nil || len(pool.Subjects()) == 0 || !resources.Ready() {
		return model.E("smoke_resources", "Не найдены встроенные ресурсы.")
	}
	report.Checks["embedded_resources"] = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	instance, err := a.Backend.Start(ctx, syntheticProfile(), model.Endpoint{Host: "127.0.0.1", Port: 9}, model.Primary, 0)
	cancel()
	if err != nil {
		return err
	}
	owned = &owner{Controller: a.Controller, app: a, instance: instance}
	report.ChildPID, report.Port = instance.PID(), instance.Port
	report.Checks["same_executable"], report.Checks["socks_started"] = true, true
	report.Checks["engine_alive"] = instance.Process.Alive()
	ready := false
	native := runtime.GOOS == "windows"
	profilePath := ""
	expected, renderErr := profile.Render(syntheticProfile(), nil)
	if renderErr != nil {
		return renderErr
	}
	if native {
		profilePath = filepath.Join(report.Workspace, "проверка профиля.conf")
		if err := storage.AtomicWrite(profilePath, []byte(expected)); err != nil {
			return err
		}
	}
	end := time.Now().Add(180 * time.Second)
	stage := "window_start"
	var stages []string
	progress := func(next string, frames int) error {
		// Keep the bounded sequence as well as the final error: a timeout must
		// not erase the phase that was actually waiting. Stages contain only
		// fixed probe labels/safe error codes, never clipboard or file contents.
		if len(stages) == 0 || stages[len(stages)-1] != next {
			if len(stages) < 24 {
				stages = append(stages, next)
			}
		}
		data, err := json.MarshalIndent(struct {
			SchemaVersion int      `json:"schema_version"`
			Mode          string   `json:"mode"`
			Stage         string   `json:"stage"`
			Frames        int      `json:"frames"`
			Stages        []string `json:"stages"`
		}{1, report.Mode, next, frames, stages}, "", "  ")
		if err != nil {
			return err
		}
		return storage.AtomicWrite(path+".progress.json", data)
	}
	if err := progress(stage, 0); err != nil {
		return model.E("smoke_report", "Не удалось записать этап проверки.")
	}
	err = ui.Run(owned, ui.Options{Title: "WarpPocket — offline Go/Gio smoke", Diagnostics: a.Diagnostics, Licenses: resources.Licenses, NativeChecks: native, CloseWithPicker: !wait, NativeProfilePath: profilePath,
		Import: func(data []byte, role string) error {
			if err := a.Import(data, role); err != nil {
				return err
			}
			p, err := a.Profiles.Load(role)
			if err != nil {
				return err
			}
			got, err := profile.Render(p, nil)
			if err != nil || got != expected {
				return model.E("native_import", "Импортированный профиль не совпал с проверочным.")
			}
			return nil
		},
		OnFrame: func(info ui.FrameInfo) bool {
			if next := info.NativeStage; next != "" && next != stage {
				stage = next
				if err := progress(stage, info.Count); err != nil {
					result = model.E("smoke_report", "Не удалось записать этап проверки.")
					return true
				}
			}
			if !ready && info.Count >= 3 && (!native || info.NativeChecks) {
				ready = true
				report.Checks["gio_frame"] = info.Width > 0 && info.Height > 0
				if wait {
					report.Checks["engine_alive"] = instance.Process.Alive()
				}
				if native {
					report.Checks["native_clipboard"], report.Checks["native_import"], report.Checks["native_picker"] = true, true, true
				}
				report.OK = all(report.Checks)
				if err := writeReport(path, report); err != nil {
					result = model.E("smoke_report", "Не удалось записать отчёт проверки.")
					return true
				}
			}
			return ready && (!wait || !report.OK || time.Now().After(end))
		}})
	owned.Close()
	if err != nil {
		var appError *model.Error
		if errors.As(err, &appError) {
			return appError
		}
		return model.E("smoke_window", "Не удалось отрисовать окно проверки.")
	}
	if result != nil {
		return result
	}
	report.Checks["window_closed"] = true
	report.Checks["engine_stopped"] = !instance.Process.Alive()
	_, configErr := os.Stat(instance.Config)
	conn, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(instance.Port)), 200*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	report.Checks["runtime_clean"] = os.IsNotExist(configErr) && dialErr != nil && owned.err == nil
	report.OK = ready && all(report.Checks)
	if wait {
		return model.E("wait_ended_without_crash", "Проверка завершилась без внешнего завершения GUI.")
	}
	if !report.OK {
		return model.E("smoke_failed", "Автономная проверка не пройдена.")
	}
	return nil
}
func all(checks map[string]bool) bool {
	for _, value := range checks {
		if !value {
			return false
		}
	}
	return true
}
