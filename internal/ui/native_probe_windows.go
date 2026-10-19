package ui

import (
	"context"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/0FL01/WarpPocket/internal/model"
	"golang.org/x/sys/windows"
)

var (
	probeUser32      = windows.NewLazySystemDLL("user32.dll")
	probePostMessage = probeUser32.NewProc("PostMessageW")
	probeSendMessage = probeUser32.NewProc("SendMessageTimeoutW")
	probeIsWindow    = probeUser32.NewProc("IsWindow")
	probeIsVisible   = probeUser32.NewProc("IsWindowVisible")
	probeGetDlgItem  = probeUser32.NewProc("GetDlgItem")
)

// The pinned explorer's single-file dialog has no hook/template. Windows may
// therefore use cmb13 (a filename combo) instead of edt1. CDM_SETCONTROLTEXT
// sent to a nonexistent edt1 succeeds as a message but does not enter a path.
// Resolve the documented controls and verify the actual edit contents instead.
func nativeFilenameControl(dialog windows.HWND) windows.HWND {
	if visible, _, _ := probeIsVisible.Call(uintptr(dialog)); visible == 0 {
		return 0
	}
	for _, id := range []uintptr{0x0480, 0x047c} { // edt1, cmb13
		value, _, _ := probeGetDlgItem.Call(uintptr(dialog), id)
		control := windows.HWND(value)
		var pid uint32
		windows.GetWindowThreadProcessId(control, &pid)
		if control == 0 || pid != uint32(os.Getpid()) {
			continue
		}
		var name [64]uint16
		if n, _ := windows.GetClassName(control, &name[0], int32(len(name))); n <= 0 {
			continue
		}
		switch windows.UTF16ToString(name[:]) {
		case "Edit", "ComboBox":
			return control
		case "ComboBoxEx32":
			var edit uintptr
			ok, _, _ := probeSendMessage.Call(uintptr(control), 0x0407, 0, 0, 0x0002, 2000, uintptr(unsafe.Pointer(&edit))) // CBEM_GETEDITCONTROL
			if ok != 0 && edit != 0 {
				windows.GetWindowThreadProcessId(windows.HWND(edit), &pid)
				if pid == uint32(os.Getpid()) {
					return windows.HWND(edit)
				}
			}
		}
	}
	return 0
}

func enterNativeFilename(ctx context.Context, dialog windows.HWND, profilePath string) error {
	var control windows.HWND
	for control == 0 {
		control = nativeFilenameControl(dialog)
		if control != 0 {
			break
		}
		select {
		case <-ctx.Done():
			return model.E("native_filename_control", "Не найдено поле проверочного файла.")
		case <-time.After(20 * time.Millisecond):
		}
	}
	path, err := windows.UTF16FromString(profilePath)
	if err != nil {
		return model.E("native_import", "Не удалось проверить выбор профиля.")
	}
	var reply uintptr
	sent, _, _ := probeSendMessage.Call(uintptr(control), 0x000c, 0, uintptr(unsafe.Pointer(&path[0])), 0x0002, 2000, uintptr(unsafe.Pointer(&reply))) // WM_SETTEXT
	runtime.KeepAlive(path)
	if sent == 0 || reply == 0 {
		return model.E("native_filename_write", "Не удалось заполнить проверочный путь.")
	}
	buffer := make([]uint16, len(path)+1)
	sent, _, _ = probeSendMessage.Call(uintptr(control), 0x000d, uintptr(len(buffer)), uintptr(unsafe.Pointer(&buffer[0])), 0x0002, 2000, uintptr(unsafe.Pointer(&reply))) // WM_GETTEXT
	runtime.KeepAlive(buffer)
	if sent == 0 || windows.UTF16ToString(buffer) != profilePath {
		return model.E("native_filename_verify", "Проверочный путь не подтверждён.")
	}
	return nil
}

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
	cancelDialog := func() { probePostMessage.Call(uintptr(dialog), 0x0010, 0, 0) }
	select {
	case <-ctx.Done():
		cancelDialog()
		return model.E("native_picker", "Не выполнена проверка закрытия диалога.")
	case <-allow:
	}
	if profilePath != "" {
		if err := enterNativeFilename(ctx, dialog, profilePath); err != nil {
			cancelDialog()
			return err
		}
		if result, _, _ := probePostMessage.Call(uintptr(dialog), 0x0111, 1, 0); result == 0 { // WM_COMMAND, IDOK
			cancelDialog()
			return model.E("native_import", "Не удалось выбрать проверочный профиль.")
		}
		// Selection is not complete merely because IDOK was posted. Retain the
		// owned dialog until it actually closes, and cancel it on failure so a
		// diagnostic timeout cannot leave an uncancellable native modal open.
		for {
			if alive, _, _ := probeIsWindow.Call(uintptr(dialog)); alive == 0 {
				return nil
			}
			select {
			case <-ctx.Done():
				cancelDialog()
				return model.E("native_import", "Не завершён выбор проверочного профиля.")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if result, _, _ := probePostMessage.Call(uintptr(dialog), 0x0010, 0, 0); result == 0 { // WM_CLOSE
		return model.E("native_picker", "Не удалось отменить нативный диалог.")
	}
	return nil
}
