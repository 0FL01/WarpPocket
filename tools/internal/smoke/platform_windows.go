//go:build windows && amd64

package smoke

import (
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// This independent tools module deliberately uses only the standard library.
// Typed syscall wrappers are used where present. For the remaining Win32 APIs,
// pointers are passed directly in Proc.Call expressions and pinned when Windows
// retains them across calls (not merely kept alive as converted uintptr values).
var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	createJob       = kernel32.NewProc("CreateJobObjectW")
	setJobInfo      = kernel32.NewProc("SetInformationJobObject")
	queryJobInfo    = kernel32.NewProc("QueryInformationJobObject")
	assignJob       = kernel32.NewProc("AssignProcessToJobObject")
	isProcessInJob  = kernel32.NewProc("IsProcessInJob")
	terminateJob    = kernel32.NewProc("TerminateJobObject")
	resumeThread    = kernel32.NewProc("ResumeThread")
	queryImage      = kernel32.NewProc("QueryFullProcessImageNameW")
	getProcessID    = kernel32.NewProc("GetProcessId")
	getMemoryInfo   = kernel32.NewProc("K32GetProcessMemoryInfo")
	initializeAttrs = kernel32.NewProc("InitializeProcThreadAttributeList")
	updateAttrs     = kernel32.NewProc("UpdateProcThreadAttribute")
	deleteAttrs     = kernel32.NewProc("DeleteProcThreadAttributeList")
)

const (
	processQueryLimited = 0x1000
	synchronize         = 0x00100000
	processQueryInfo    = 0x0400
	processVMRead       = 0x0010
	createSuspended     = 0x00000004
	createNoWindow      = 0x08000000
	extendedStartup     = 0x00080000
	handleListAttribute = 0x00020002
	killOnJobClose      = 0x00002000
)

type jobBasicLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	_                       uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	_                       uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimits struct {
	BasicLimitInformation jobBasicLimits
	IOCounters            [6]uint64
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList unsafe.Pointer
}

type windowsPlatform struct{}

type windowsProcess struct {
	handle syscall.Handle
	pid    int
}

type windowsLaunch struct {
	job syscall.Handle
	gui *windowsProcess
}

func newNativePlatform() (Platform, error) { return windowsPlatform{}, nil }

func (windowsPlatform) OpenProcess(pid int) (Process, error) {
	if pid <= 0 || uint64(pid) > 0xffffffff {
		return nil, failure("process_identity_invalid")
	}
	// No PROCESS_TERMINATE: the retained engine handle cannot kill the engine.
	handle, err := syscall.OpenProcess(synchronize|processQueryLimited, false, uint32(pid))
	if err != nil {
		return nil, failure("process_open_failed")
	}
	return &windowsProcess{handle: handle, pid: pid}, nil
}

func (windowsPlatform) Launch(argv []string, cwd string) (Launch, error) {
	if len(argv) == 0 {
		return nil, failure("process_create_failed")
	}
	executable, err := syscall.UTF16PtrFromString(argv[0])
	if err != nil {
		return nil, failure("process_create_failed")
	}
	escaped := make([]string, len(argv))
	for index, argument := range argv {
		escaped[index] = syscall.EscapeArg(argument)
	}
	command, err := syscall.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return nil, failure("process_create_failed")
	}
	directory, err := syscall.UTF16PtrFromString(cwd)
	if err != nil {
		return nil, failure("process_create_failed")
	}
	job, _, _ := createJob.Call(0, 0)
	if job == 0 {
		return nil, failure("job_create_failed")
	}
	launch := &windowsLaunch{job: syscall.Handle(job)}
	transferred := false
	var info syscall.ProcessInformation
	defer func() {
		if info.Thread != 0 {
			_ = syscall.CloseHandle(info.Thread)
		}
		if !transferred {
			// No application code has run if assignment/resume failed. The
			// process is suspended, so terminating it cannot miss descendants.
			if info.Process != 0 {
				_ = syscall.TerminateProcess(info.Process, 1)
				_, _ = syscall.WaitForSingleObject(info.Process, 10000)
				_ = syscall.CloseHandle(info.Process)
			}
			_ = syscall.CloseHandle(launch.job)
		}
	}()
	if syscall.SetHandleInformation(launch.job, syscall.HANDLE_FLAG_INHERIT, 0) != nil {
		return nil, failure("job_setup_failed")
	}
	limits := jobExtendedLimits{}
	limits.BasicLimitInformation.LimitFlags = killOnJobClose
	ok, _, _ := setJobInfo.Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		return nil, failure("job_setup_failed")
	}
	nulName, _ := syscall.UTF16PtrFromString("NUL")
	security := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	nul, err := syscall.CreateFile(nulName, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, &security, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, failure("stdio_setup_failed")
	}
	defer syscall.CloseHandle(nul)
	var attributeBytes uintptr
	_, _, _ = initializeAttrs.Call(0, 1, 0, uintptr(unsafe.Pointer(&attributeBytes)))
	if attributeBytes == 0 || attributeBytes > 1024*1024 {
		return nil, failure("process_attributes_failed")
	}
	attributes := make([]uintptr, (attributeBytes+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	handles := []syscall.Handle{nul}
	var pinned runtime.Pinner
	pinned.Pin(&attributes[0])
	pinned.Pin(&handles[0])
	defer pinned.Unpin()
	attributeList := unsafe.Pointer(&attributes[0])
	ok, _, _ = initializeAttrs.Call(uintptr(attributeList), 1, 0, uintptr(unsafe.Pointer(&attributeBytes)))
	if ok == 0 {
		return nil, failure("process_attributes_failed")
	}
	defer deleteAttrs.Call(uintptr(attributeList))
	ok, _, _ = updateAttrs.Call(uintptr(attributeList), 0, handleListAttribute,
		uintptr(unsafe.Pointer(&handles[0])), unsafe.Sizeof(handles[0]), 0, 0)
	if ok == 0 {
		return nil, failure("process_attributes_failed")
	}
	startup := startupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = nul, nul, nul
	startup.AttributeList = attributeList
	// Assignment happens while the primary thread is still suspended. Only NUL
	// can be inherited; in particular the safety-job handle never enters the GUI.
	err = syscall.CreateProcess(executable, command, nil, nil, true,
		createSuspended|createNoWindow|extendedStartup, nil, directory, &startup.StartupInfo, &info)
	if err != nil {
		return nil, failure("process_create_failed")
	}
	ok, _, _ = assignJob.Call(job, uintptr(info.Process))
	if ok == 0 {
		return nil, failure("job_assign_failed")
	}
	launch.gui = &windowsProcess{handle: info.Process, pid: int(info.ProcessId)}
	member, err := launch.Contains(launch.gui)
	if err != nil || !member {
		return nil, failure("process_not_owned")
	}
	previous, _, _ := resumeThread.Call(uintptr(info.Thread))
	if previous != 1 {
		return nil, failure("process_resume_failed")
	}
	transferred = true
	return launch, nil
}

func (p *windowsProcess) PID() int { return p.pid }

func (p *windowsProcess) Exited(timeout time.Duration) (bool, error) {
	milliseconds := uint32(0)
	if timeout > 0 {
		count := uint64((timeout-1)/time.Millisecond) + 1
		if count > 0xfffffffe {
			count = 0xfffffffe
		}
		milliseconds = uint32(count)
	}
	result, err := syscall.WaitForSingleObject(p.handle, milliseconds)
	if err != nil || result != syscall.WAIT_OBJECT_0 && result != syscall.WAIT_TIMEOUT {
		return false, failure("process_wait_failed")
	}
	return result == syscall.WAIT_OBJECT_0, nil
}

func (p *windowsProcess) ExitCode() (uint32, error) {
	exited, err := p.Exited(0)
	if err != nil || !exited {
		return 0, failure("process_not_exited")
	}
	var code uint32
	if syscall.GetExitCodeProcess(p.handle, &code) != nil {
		return 0, failure("process_exit_code_failed")
	}
	return code, nil
}

func (p *windowsProcess) Identity() (Identity, error) {
	pid, _, _ := getProcessID.Call(uintptr(p.handle))
	if pid == 0 || int(pid) != p.pid {
		return Identity{}, failure("process_identity_invalid")
	}
	var created, exited, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(p.handle, &created, &exited, &kernel, &user) != nil {
		return Identity{}, failure("process_identity_failed")
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, _ := queryImage.Call(uintptr(p.handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 || int(size) >= len(buffer) {
		return Identity{}, failure("process_identity_failed")
	}
	parent, err := parentPID(uint32(p.pid))
	if err != nil {
		return Identity{}, err
	}
	return Identity{PID: p.pid, ParentPID: parent, Image: syscall.UTF16ToString(buffer[:size]),
		Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

func parentPID(pid uint32) (int, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, failure("process_identity_failed")
	}
	defer syscall.CloseHandle(snapshot)
	entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		if entry.ProcessID == pid {
			return int(entry.ParentProcessID), nil
		}
	}
	return 0, failure("process_identity_failed")
}

func (p *windowsProcess) Terminate() error {
	if syscall.TerminateProcess(p.handle, 1) != nil {
		return failure("process_terminate_failed")
	}
	return nil
}

func (p *windowsProcess) Close() error {
	if p.handle == 0 {
		return nil
	}
	if syscall.CloseHandle(p.handle) != nil {
		return failure("handle_close_failed")
	}
	p.handle = 0
	return nil
}

func (l *windowsLaunch) GUI() Process { return l.gui }

func (l *windowsLaunch) Contains(process Process) (bool, error) {
	p, ok := process.(*windowsProcess)
	if !ok {
		return false, failure("process_identity_invalid")
	}
	var member int32 // BOOL is 32 bits, not Go bool or a pointer-sized integer.
	result, _, _ := isProcessInJob.Call(uintptr(p.handle), uintptr(l.job), uintptr(unsafe.Pointer(&member)))
	if result == 0 {
		return false, failure("job_query_failed")
	}
	return member != 0, nil
}

func (l *windowsLaunch) Empty() (bool, error) {
	var accounting jobAccounting
	ok, _, _ := queryJobInfo.Call(uintptr(l.job), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), 0)
	if ok == 0 {
		return false, failure("job_query_failed")
	}
	return accounting.ActiveProcesses == 0, nil
}

func (l *windowsLaunch) processIDs() ([]uint32, error) {
	// Bounded growth handles a changed job snapshot without silently omitting
	// processes. The job may contain only a few workers; 1024 is a hard ceiling.
	for capacity := 8; capacity <= 1024; capacity *= 2 {
		// JOBOBJECT_BASIC_PROCESS_ID_LIST has two DWORDs then ULONG_PTR PIDs.
		buffer := make([]uintptr, capacity+1)
		ok, _, callErr := queryJobInfo.Call(uintptr(l.job), 3, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))*unsafe.Sizeof(buffer[0]), 0)
		if ok == 0 {
			if callErr == syscall.ERROR_MORE_DATA {
				continue
			}
			return nil, failure("job_query_failed")
		}
		counts := (*[2]uint32)(unsafe.Pointer(&buffer[0]))
		if counts[0] != counts[1] || counts[1] > uint32(capacity) {
			continue
		}
		pids := make([]uint32, int(counts[1]))
		for index := range pids {
			pid := buffer[index+1]
			if pid == 0 || uint64(pid) > 0xffffffff {
				return nil, failure("process_identity_invalid")
			}
			pids[index] = uint32(pid)
		}
		return pids, nil
	}
	return nil, failure("job_query_failed")
}

func (l *windowsLaunch) WorkingSets() ([]ProcessMemory, error) {
	pids, err := l.processIDs()
	if err != nil {
		return nil, err
	}
	measurements := make([]ProcessMemory, 0, len(pids))
	for _, pid := range pids {
		memory, err := l.workingSet(pid)
		if err != nil {
			return nil, err
		}
		measurements = append(measurements, ProcessMemory{PID: int(pid), WorkingSetBytes: memory})
	}
	after, err := l.processIDs()
	if err != nil {
		return nil, err
	}
	slices.Sort(pids)
	slices.Sort(after)
	if !slices.Equal(pids, after) {
		return nil, failure("working_set_changed")
	}
	return measurements, nil
}

func (l *windowsLaunch) workingSet(pid uint32) (uint64, error) {
	handle, err := syscall.OpenProcess(processQueryInfo|processVMRead|synchronize, false, pid)
	if err != nil {
		return 0, failure("working_set_query_failed")
	}
	defer syscall.CloseHandle(handle)
	p := &windowsProcess{handle: handle, pid: int(pid)}
	member, err := l.Contains(p)
	if err != nil || !member {
		return 0, failure("process_not_owned")
	}
	exited, err := p.Exited(0)
	if err != nil || exited {
		return 0, failure("wait_process_not_live")
	}
	counters := processMemoryCounters{CB: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	ok, _, _ := getMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), unsafe.Sizeof(counters))
	if ok == 0 {
		return 0, failure("working_set_query_failed")
	}
	return uint64(counters.WorkingSetSize), nil
}

func (l *windowsLaunch) TerminateJob() error {
	ok, _, _ := terminateJob.Call(uintptr(l.job), 1)
	if ok == 0 {
		return failure("job_terminate_failed")
	}
	return nil
}

func (l *windowsLaunch) Close() error {
	if l.job == 0 && l.gui.handle == 0 {
		return nil
	}
	var first error
	if l.job != 0 {
		if syscall.CloseHandle(l.job) != nil {
			first = failure("handle_close_failed")
		} else {
			l.job = 0
		}
	}
	// On a failed emergency TerminateJob, kill-on-close is asynchronous. Retain
	// the original GUI handle until the close-triggered termination is observed.
	if l.gui.handle != 0 {
		if exited, err := l.gui.Exited(10 * time.Second); (err != nil || !exited) && first == nil {
			first = failure("process_cleanup_failed")
		}
	}
	if err := l.gui.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
