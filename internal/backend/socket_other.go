//go:build !windows

package backend

import "syscall"

// net.ListenConfig already gives Linux listeners SO_REUSEADDR, allowing an
// owned SOCKS listener to reconnect after its closed sessions enter TIME_WAIT.
func reservationControl(_, _ string, _ syscall.RawConn) error { return nil }
