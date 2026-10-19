// Package smoke checks a packaged Windows executable without consulting tasklist,
// the application's logs, private profiles, or an external network service.
package smoke

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxReportBytes = 64 * 1024

var commonChecks = []string{
	"gio_frame", "embedded_resources", "same_executable", "socks_started", "engine_alive",
	"native_clipboard", "native_import", "native_picker",
}

var gracefulChecks = []string{
	"gio_frame", "embedded_resources", "same_executable", "socks_started", "engine_alive",
	"native_clipboard", "native_import", "native_picker",
	"engine_stopped", "runtime_clean", "window_closed",
}

// Report is the strictly decoded application schema, not a summary payload.
// In particular, ErrorCode and Workspace must never be copied into the summary.
type Report struct {
	Mode      string
	OK        bool
	PID       int
	Checks    map[string]bool
	ChildPID  int
	Port      int
	Workspace string
	ErrorCode *string
}

type failure string

func (e failure) Error() string { return string(e) }

func requiredChecks(mode string) []string {
	if mode == "graceful" {
		return gracefulChecks
	}
	return commonChecks
}

// ParseReport rejects unknown fields, duplicate keys (including escaped keys),
// non-integer numbers, invalid UTF-8, wrong types, and trailing JSON values.
// Workspace containment is checked separately against an open output directory.
func ParseReport(encoded []byte, mode string) (Report, error) {
	var report Report
	if len(encoded) > MaxReportBytes {
		return report, failure("report_file_invalid")
	}
	if !utf8.Valid(encoded) || !json.Valid(encoded) {
		return report, failure("report_json_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	value, err := uniqueJSON(decoder, 0)
	if err != nil {
		return report, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return report, failure("report_json_invalid")
	}
	data, ok := value.(map[string]any)
	fields := []string{"schema_version", "mode", "ok", "pid", "checks", "child_pid", "port", "workspace", "error_code"}
	if !ok || len(data) != len(fields) || (mode != "graceful" && mode != "wait") {
		return report, failure("report_schema_invalid")
	}
	for _, name := range fields {
		if _, exists := data[name]; !exists {
			return report, failure("report_schema_invalid")
		}
	}
	_, validVersion := integer(data["schema_version"], 2, 2)
	report.Mode, ok = data["mode"].(string)
	if !validVersion || !ok || report.Mode != mode {
		return Report{}, failure("report_schema_invalid")
	}
	if report.OK, ok = data["ok"].(bool); !ok {
		return Report{}, failure("report_schema_invalid")
	}
	if report.PID, ok = integer(data["pid"], 1, 0xffffffff); !ok {
		return Report{}, failure("report_schema_invalid")
	}
	if report.ChildPID, ok = integer(data["child_pid"], 1, 0xffffffff); !ok {
		return Report{}, failure("report_schema_invalid")
	}
	if report.Port, ok = integer(data["port"], 1, 65535); !ok {
		return Report{}, failure("report_schema_invalid")
	}
	if report.Workspace, ok = data["workspace"].(string); !ok {
		return Report{}, failure("workspace_invalid")
	}
	checks, ok := data["checks"].(map[string]any)
	if !ok {
		return Report{}, failure("report_schema_invalid")
	}
	allowed := make(map[string]bool)
	for _, name := range requiredChecks(mode) {
		allowed[name] = true
	}
	report.Checks = make(map[string]bool, len(checks))
	for name, value := range checks {
		checked, boolean := value.(bool)
		if !allowed[name] || !boolean {
			return Report{}, failure("report_schema_invalid")
		}
		report.Checks[name] = checked
	}
	if data["error_code"] != nil {
		code, stringValue := data["error_code"].(string)
		if !stringValue {
			return Report{}, failure("report_schema_invalid")
		}
		report.ErrorCode = &code
	}
	return report, nil
}

func (r Report) requireSuccess() error {
	if !r.OK || r.ErrorCode != nil {
		return failure("smoke_not_ok")
	}
	for _, name := range requiredChecks(r.Mode) {
		if !r.Checks[name] {
			return failure("required_checks_failed")
		}
	}
	return nil
}

func integer(value any, minimum, maximum uint64) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil || parsed < minimum || parsed > maximum || uint64(int(parsed)) != parsed {
		return 0, false
	}
	return int(parsed), true
}

func uniqueJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, failure("report_schema_invalid")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, failure("report_json_invalid")
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	if delimiter != '{' {
		return nil, failure("report_schema_invalid")
	}
	object := make(map[string]any)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, failure("report_json_invalid")
		}
		name, ok := key.(string)
		if !ok {
			return nil, failure("report_schema_invalid")
		}
		if _, duplicate := object[name]; duplicate {
			return nil, failure("report_schema_invalid")
		}
		value, err := uniqueJSON(decoder, depth+1)
		if err != nil {
			return nil, err
		}
		object[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, failure("report_json_invalid")
	}
	return object, nil
}
