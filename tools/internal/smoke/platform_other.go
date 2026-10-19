//go:build !windows

package smoke

func newNativePlatform() (Platform, error) { return nil, failure("windows_required") }
