//go:build !windows || !amd64

package smoke

func closeBaselineWindow(int) error { return failure("windows_required") }
