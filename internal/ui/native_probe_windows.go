package ui

import (
	"context"
	"os"
	"time"
	"unsafe"

	"github.com/0FL01/WarpPocket/internal/model"
	"golang.org/x/sys/windows"
)

var (
	probeUser32      = windows.NewLazySystemDLL("user32.dll")
	probePostMessage = probeUser32.NewProc("PostMessageW")
	probeSendMessage = probeUser32.NewProc("SendMessageW")
)

// Only cancel this smoke process's own common-file dialog. No foreground-window
// assumptions, title matching, input injection or interaction with another PID.
func completeNativePicker(ctx context.Context, seen chan<- struct{}, allow <-chan struct{}, profilePath string) error {
	var dialog windows.HWND
	callback := windows.NewCallback(func(hwnd windows.HWND, _ uintptr) uintptr {
		var pid uint32
		windows.GetWindowThreadProcessId(hwnd, &pid)
		if pid != uint32(os.Getpid()) {
			return 1
		}
		var name [64]uint16
		if n, _ := windows.GetClassName(hwnd, &name[0], int32(len(name))); n > 0 && windows.UTF16ToString(name[:]) == "#32770" {
			dialog = hwnd
			return 0
		}
		return 1
	})
	for dialog == 0 {
		windows.EnumWindows(callback, nil)
		select {
		case <-ctx.Done():
			return model.E("native_picker", "Нативный диалог не открылся.")
		case <-time.After(20 * time.Millisecond):
		}
	}
	seen <- struct{}{}
	select {
	case <-ctx.Done():
		return model.E("native_picker", "Не выполнена проверка закрытия диалога.")
	case <-allow:
	}
	if profilePath != "" {
		// The smoke-created UTF-16 fixture path is entered into the documented
		// common-dialog filename control. No keyboard injection or foreign UI.
		path, err := windows.UTF16PtrFromString(profilePath)
		if err != nil {
			return model.E("native_import", "Не удалось проверить выбор профиля.")
		}
		probeSendMessage.Call(uintptr(dialog), 0x0468, 0x0480, uintptr(unsafe.Pointer(path)))  // CDM_SETCONTROLTEXT, edt1
		if result, _, _ := probePostMessage.Call(uintptr(dialog), 0x0111, 1, 0); result == 0 { // WM_COMMAND, IDOK
			return model.E("native_import", "Не удалось выбрать проверочный профиль.")
		}
		return nil
	}
	if result, _, _ := probePostMessage.Call(uintptr(dialog), 0x0010, 0, 0); result == 0 { // WM_CLOSE
		return model.E("native_picker", "Не удалось отменить нативный диалог.")
	}
	return nil
}
