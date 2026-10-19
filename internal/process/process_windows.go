package process

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JOB_LIST is available on the supported Windows versions but is not named in
// x/sys v0.45.0. Assignment through this creation attribute is atomic: there is
// deliberately no AssignProcessToJobObject or suspended/unmanaged fallback.
const procThreadAttributeJobList = 0x0002000d

type nativeProcess struct {
	process   windows.Handle
	job       windows.Handle
	processID int
}

func launchNative(args []string, cwd string) (_ *nativeProcess, err error) {
	application, err := windows.UTF16PtrFromString(args[0])
	if err != nil {
		return nil, ErrStart
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, ErrStart
	}
	var directory *uint16
	if cwd != "" {
		directory, err = windows.UTF16PtrFromString(cwd)
		if err != nil {
			return nil, ErrStart
		}
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, ErrStart
	}
	transferred := false
	var info windows.ProcessInformation
	defer func() {
		if info.Thread != 0 {
			_ = windows.CloseHandle(info.Thread)
		}
		if !transferred {
			// Closing the noninherited kill-on-close job also covers failures
			// immediately after a successful CreateProcessW.
			_ = windows.TerminateJobObject(job, 1)
			_ = windows.CloseHandle(job)
			if info.Process != 0 {
				_, _ = windows.WaitForSingleObject(info.Process, 5000)
				_ = windows.CloseHandle(info.Process)
			}
		}
	}()
	if windows.SetHandleInformation(job, windows.HANDLE_FLAG_INHERIT, 0) != nil {
		return nil, ErrStart
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// This x/sys API takes uintptr rather than a typed pointer. Pinning also
	// forces heap allocation, so a Go stack growth inside its wrapper cannot
	// invalidate the converted address before the actual syscall.
	var pin runtime.Pinner
	pin.Pin(&limits)
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	runtime.KeepAlive(&limits)
	pin.Unpin()
	if err != nil {
		return nil, ErrStart
	}
	nulName, _ := windows.UTF16PtrFromString("NUL")
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &security, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, ErrStart
	}
	defer windows.CloseHandle(nul)
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, ErrStart
	}
	defer attributes.Delete()
	jobs := [1]windows.Handle{job}
	handles := [1]windows.Handle{nul}
	if attributes.Update(procThreadAttributeJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs)) != nil {
		return nil, ErrStart
	}
	if attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)) != nil {
		return nil, ErrStart
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES,
			StdInput: nul, StdOutput: nul, StdErr: nul,
		},
		ProcThreadAttributeList: attributes.List(),
	}
	// Do not allocate even a hidden console for console-subsystem fixtures or
	// descendants. Standard streams are the explicit NUL handle above; atomic
	// JOB_LIST assignment and kill-on-close ownership are unaffected.
	flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	err = windows.CreateProcess(application, command, nil, nil, true, flags, nil, directory, &startup.StartupInfo, &info)
	// Attribute values and UTF-16 buffers must outlive the actual native call.
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(application)
	runtime.KeepAlive(command)
	runtime.KeepAlive(directory)
	if err != nil {
		return nil, ErrStart
	}
	p := &nativeProcess{process: info.Process, job: job, processID: int(info.ProcessId)}
	transferred = true
	return p, nil
}

func (p *nativeProcess) pid() int { return p.processID }

func (p *nativeProcess) exited() (bool, error) {
	result, err := windows.WaitForSingleObject(p.process, 0)
	if err != nil {
		return false, ErrStop
	}
	switch result {
	case windows.WAIT_OBJECT_0:
		return true, nil
	case uint32(windows.WAIT_TIMEOUT):
		return false, nil
	default:
		return false, ErrStop
	}
}

func (p *nativeProcess) stop() (int, error) {
	if p.job != 0 {
		// Closing the job is the fail-closed backstop if explicit termination
		// fails. Never allow this handle into a child inheritance list.
		_ = windows.TerminateJobObject(p.job, 1)
		if windows.CloseHandle(p.job) != nil {
			return 0, ErrStop
		}
		p.job = 0
	}
	result, err := windows.WaitForSingleObject(p.process, 5000)
	if err != nil || result != windows.WAIT_OBJECT_0 {
		return 0, ErrStop
	}
	var code uint32
	if windows.GetExitCodeProcess(p.process, &code) != nil {
		return 0, ErrStop
	}
	if windows.CloseHandle(p.process) != nil {
		return 0, ErrStop
	}
	p.process = 0
	return int(code), nil
}
