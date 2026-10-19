package smoke

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func reportData(mode, workspace string, gui, child int) map[string]any {
	checks := map[string]bool{}
	for _, check := range requiredChecks(mode) {
		checks[check] = true
	}
	return map[string]any{
		"schema_version": 2, "mode": mode, "ok": true, "pid": gui,
		"checks": checks, "child_pid": child, "port": 25344,
		"workspace": workspace, "error_code": nil,
	}
}

func encodeReport(t *testing.T, data map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || safeCode(err) != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestReportSchemaTwoAndRequiredChecks(t *testing.T) {
	for _, mode := range []string{"graceful", "wait"} {
		t.Run(mode, func(t *testing.T) {
			data := reportData(mode, "workspace", 123, 124)
			report, err := ParseReport(encodeReport(t, data), mode)
			if err != nil || report.requireSuccess() != nil || report.PID != 123 || report.ChildPID != 124 {
				t.Fatalf("valid report rejected: %+v, %v", report, err)
			}
			for _, checks := range []map[string]bool{{}, {"gio_frame": true}, {"gio_frame": false}} {
				data["checks"] = checks
				report, err := ParseReport(encodeReport(t, data), mode)
				if err != nil {
					t.Fatal(err)
				}
				assertCode(t, report.requireSuccess(), "required_checks_failed")
			}
		})
	}
}

func TestReportRejectsWrongTypesValuesAndUnknownFields(t *testing.T) {
	tests := []struct {
		field string
		value any
	}{
		{"schema_version", 1}, {"schema_version", true}, {"schema_version", 2.1},
		{"mode", "wait"}, {"mode", false}, {"ok", 1}, {"ok", nil},
		{"pid", true}, {"pid", "123"}, {"pid", 0}, {"pid", -1}, {"pid", uint64(1) << 32},
		{"child_pid", nil}, {"child_pid", false}, {"child_pid", 0}, {"child_pid", -1},
		{"child_pid", uint64(1) << 32}, {"port", true}, {"port", "25344"}, {"port", 0},
		{"port", 65536}, {"port", nil}, {"checks", nil}, {"checks", []bool{true}},
		{"checks", map[string]any{"gio_frame": 1}}, {"checks", map[string]any{"gio_frame": nil}},
		{"checks", map[string]bool{"secret-token": true}}, {"error_code", true},
		{"error_code", map[string]any{}}, {"frozen", true}, {"raw_log", "never echo me"},
	}
	for _, test := range tests {
		t.Run(test.field+"/"+strings.TrimSpace(string(encodeReport(t, map[string]any{"v": test.value}))), func(t *testing.T) {
			data := reportData("graceful", "workspace", 123, 124)
			data[test.field] = test.value
			_, err := ParseReport(encodeReport(t, data), "graceful")
			assertCode(t, err, "report_schema_invalid")
		})
	}
	for _, field := range []string{"schema_version", "mode", "ok", "pid", "checks", "child_pid", "port", "workspace", "error_code"} {
		data := reportData("graceful", "workspace", 123, 124)
		delete(data, field)
		_, err := ParseReport(encodeReport(t, data), "graceful")
		assertCode(t, err, "report_schema_invalid")
	}
	for _, raw := range []string{`{"pid":1,"pid":2}`, `{"pid":1,"\u0070id":2}`, `{"checks":{"gio_frame":true,"gio_frame":false}}`, `[]`, `null`, `42`, `"text"`, `{}`} {
		_, err := ParseReport([]byte(raw), "graceful")
		assertCode(t, err, "report_schema_invalid")
	}
}

func TestReportRejectsMalformedLargeAndNonIntegerNumbers(t *testing.T) {
	valid := encodeReport(t, reportData("wait", "workspace", 123, 124))
	for _, encoded := range [][]byte{nil, []byte("not json"), {0xff}, append(bytes.Clone(valid), []byte(` {}`)...)} {
		_, err := ParseReport(encoded, "wait")
		assertCode(t, err, "report_json_invalid")
	}
	_, err := ParseReport(bytes.Repeat([]byte(" "), MaxReportBytes+1), "wait")
	assertCode(t, err, "report_file_invalid")
	for _, value := range []string{"123.0", "1.23e2", "-0", "18446744073709551616000"} {
		encoded := bytes.Replace(valid, []byte(`"pid":123`), []byte(`"pid":`+value), 1)
		_, err := ParseReport(encoded, "wait")
		assertCode(t, err, "report_schema_invalid")
	}
}

func TestReportAppErrorsRemainUntrusted(t *testing.T) {
	data := reportData("wait", "workspace", 123, 124)
	for _, changes := range []map[string]any{{"ok": false}, {"error_code": "private-token=must-not-be-emitted"}} {
		for key, value := range changes {
			data[key] = value
		}
		report, err := ParseReport(encodeReport(t, data), "wait")
		if err != nil {
			t.Fatal(err)
		}
		assertCode(t, report.requireSuccess(), "smoke_not_ok")
	}
	data["workspace"] = nil
	_, err := ParseReport(encodeReport(t, data), "wait")
	assertCode(t, err, "workspace_invalid")
}
