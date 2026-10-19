//go:build windows && !amd64

package smoke

func newNativePlatform() (Platform, error) { return nil, failure("windows_amd64_required") }
