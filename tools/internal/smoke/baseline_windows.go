//go:build windows && amd64

package smoke

import (
	"syscall"
	"unsafe"
)

func closeBaselineWindow(pid int) error {
	user := syscall.NewLazyDLL("user32.dll")
	enum := user.NewProc("EnumWindows")
	owner := user.NewProc("GetWindowThreadProcessId")
	visible := user.NewProc("IsWindowVisible")
	post := user.NewProc("PostMessageW")
	posted := false
	callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var current uint32
		owner.Call(hwnd, uintptr(unsafe.Pointer(&current)))
		if int(current) == pid {
			if shown, _, _ := visible.Call(hwnd); shown != 0 {
				if ok, _, _ := post.Call(hwnd, 0x0010, 0, 0); ok != 0 {
					posted = true
				}
			}
		}
		return 1
	})
	enum.Call(callback, 0)
	if !posted {
		return failure("baseline_window")
	}
	return nil
}
