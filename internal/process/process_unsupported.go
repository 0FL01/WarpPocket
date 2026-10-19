//go:build !linux && !windows

package process

// There is no unmanaged fallback on unsupported operating systems.
type nativeProcess struct{}

func launchNative([]string, string) (*nativeProcess, error) { return nil, ErrUnsupported }
func (*nativeProcess) pid() int                             { return 0 }
func (*nativeProcess) exited() (bool, error)                { return false, ErrUnsupported }
func (*nativeProcess) stop() (int, error)                   { return 0, ErrUnsupported }
