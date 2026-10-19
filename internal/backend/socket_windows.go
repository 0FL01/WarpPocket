package backend

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock defines SO_EXCLUSIVEADDRUSE as ~SO_REUSEADDR; x/sys v0.45.0 does
// not export the former name.
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

// Do not permit an unrelated SO_REUSEADDR listener to share a reserved port.
func reservationControl(_, _ string, connection syscall.RawConn) error {
	var socketErr error
	if err := connection.Control(func(socket uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(socket), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
	}); err != nil {
		return err
	}
	return socketErr
}
