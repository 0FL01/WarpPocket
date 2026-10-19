package smoke

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func TestPinnedBaselineArchive(t *testing.T) {
	archive := func(name string, contents []byte) []byte {
		var out bytes.Buffer
		writer := zip.NewWriter(&out)
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(contents)
		writer.Close()
		return out.Bytes()
	}
	executable := []byte("MZ synthetic pinned binary")
	expected := fmt.Sprintf("%x", sha256.Sum256(executable))
	for _, tc := range []struct {
		name string
		data []byte
		hash string
		ok   bool
	}{
		{"valid", archive("WarpPocket.exe", executable), expected, true},
		{"digest", archive("WarpPocket.exe", executable), "bad", false},
		{"path", archive("../WarpPocket.exe", executable), expected, false},
		{"not_exe", archive("WarpPocket.exe", []byte("not an EXE")), "", false},
		{"not_zip", []byte("not a ZIP"), expected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := baselineExecutable(tc.data, tc.hash)
			if (err == nil) != tc.ok || (tc.ok && !bytes.Equal(got, executable)) {
				t.Fatalf("baseline accepted=%v, expected=%v", err == nil, tc.ok)
			}
		})
	}
}

func TestBaselineIncludesEveryOwnedProcess(t *testing.T) {
	processes := []ProcessMemory{
		{PID: 10, WorkingSetBytes: 100}, {PID: 20, WorkingSetBytes: 200},
		{PID: 30, WorkingSetBytes: 300}, {PID: 40, WorkingSetBytes: 400},
	}
	measurement, err := baselineFootprint(processes, 10, 20, 30, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(measurement.Processes) != 4 || measurement.OwnedWorkingSetBytes != 1000 || measurement.StartToReadyMS != 2000 {
		t.Fatalf("incomplete owned-process measurement: %+v", measurement)
	}
	if measurement.Processes[3].Role != "runtime_auxiliary" || processes[3].Role != "" {
		t.Fatal("auxiliary must remain measured without mutating the original sample")
	}
}

func TestBaselineMeasurementRejectsIncompleteOrDuplicateSamples(t *testing.T) {
	for _, tc := range []struct {
		name      string
		processes []ProcessMemory
	}{
		{"empty", nil},
		{"missing_launcher", []ProcessMemory{{PID: 10, WorkingSetBytes: 100}, {PID: 20, WorkingSetBytes: 200}}},
		{"duplicate", []ProcessMemory{{PID: 10, WorkingSetBytes: 100}, {PID: 20, WorkingSetBytes: 200}, {PID: 30, WorkingSetBytes: 300}, {PID: 10, WorkingSetBytes: 400}}},
		{"zero_pid", []ProcessMemory{{PID: 10, WorkingSetBytes: 100}, {PID: 20, WorkingSetBytes: 200}, {PID: 30, WorkingSetBytes: 300}, {WorkingSetBytes: 400}}},
		{"zero_memory", []ProcessMemory{{PID: 10, WorkingSetBytes: 100}, {PID: 20}, {PID: 30, WorkingSetBytes: 300}}},
		{"overflow", []ProcessMemory{{PID: 10, WorkingSetBytes: ^uint64(0)}, {PID: 20, WorkingSetBytes: 200}, {PID: 30, WorkingSetBytes: 300}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := baselineFootprint(tc.processes, 10, 20, 30, time.Second)
			assertCode(t, err, "baseline_working_set")
		})
	}
	_, err := baselineFootprint([]ProcessMemory{{PID: 10, WorkingSetBytes: 100}}, 10, 10, 10, time.Second)
	assertCode(t, err, "baseline_working_set")
}
