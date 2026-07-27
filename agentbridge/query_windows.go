//go:build windows

package agentbridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PuTTY's public Pageant agent protocol: a request is placed in a named shared
// memory mapping, then a WM_COPYDATA message tagged agentCopyDataID tells the
// Pageant window (class/title "Pageant") to read it and write the reply back.
const (
	agentCopyDataID = 0x804e50ba
	wmCopyData      = 0x004A
	pageReadWrite   = 0x04
	fileMapWrite    = 0x02

	// openSSHAgentPipe is the named pipe served by the Windows OpenSSH agent,
	// the standard ssh-agent on Windows.
	openSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW  = user32.NewProc("FindWindowW")
	procSendMessageW = user32.NewProc("SendMessageW")
)

// platformDefaultUpstream prefers the standard Windows OpenSSH agent pipe; use
// --upstream pageant to target PuTTY Pageant instead.
func platformDefaultUpstream() (upstream, error) {
	return upstream{
		label: "pipe:" + openSSHAgentPipe,
		dial:  func() (io.ReadWriteCloser, error) { return dialPipe(openSSHAgentPipe) },
	}, nil
}

// dialPipe opens a Windows named pipe (e.g. the OpenSSH agent) as a stream.
func dialPipe(name string) (io.ReadWriteCloser, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("agent-bridge: open pipe %s: %w", name, err)
	}
	return os.NewFile(uintptr(h), name), nil
}

// copyDataStruct mirrors the Win32 COPYDATASTRUCT passed by WM_COPYDATA.
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

// Query sends one raw (length-prefixed) ssh-agent request to Pageant and
// returns its raw reply.
func Query(request []byte) ([]byte, error) {
	if len(request) > agentMaxMessageLength {
		return nil, errors.New("agent-bridge: request too long")
	}

	className, _ := syscall.UTF16PtrFromString("Pageant")
	windowName, _ := syscall.UTF16PtrFromString("Pageant")
	if err := procFindWindowW.Find(); err != nil {
		return nil, err
	}
	hwnd, _, _ := syscall.SyscallN(procFindWindowW.Addr(), uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(windowName)))
	if hwnd == 0 {
		return nil, errors.New("agent-bridge: Pageant window not found (is Pageant running with keys loaded?)")
	}

	// A per-process mapping name keeps parallel requests from colliding.
	mapName := "WSLPageantRequest" + strconv.Itoa(os.Getpid())
	mapNameUTF16, err := syscall.UTF16PtrFromString(mapName)
	if err != nil {
		return nil, err
	}
	fileMap, err := windows.CreateFileMapping(^windows.Handle(0), nil, pageReadWrite, 0, agentMaxMessageLength, mapNameUTF16)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(fileMap)

	addr, err := windows.MapViewOfFile(fileMap, fileMapWrite, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.UnmapViewOfFile(addr)

	// addr is the base of the mapped view; it stays valid until the deferred
	// UnmapViewOfFile above. (go vet's unsafeptr check flags every uintptr->Pointer
	// conversion; this one is the standard, safe way to address a mapped view.)
	shared := (*[agentMaxMessageLength]byte)(unsafe.Pointer(addr))
	copy(shared[:], request)

	// WM_COPYDATA carries the mapping name (NUL-terminated) so Pageant can open it.
	mapNameNul := append([]byte(mapName), 0)
	cds := copyDataStruct{
		dwData: agentCopyDataID,
		cbData: uint32(len(mapNameNul)),
		lpData: uintptr(unsafe.Pointer(&mapNameNul[0])),
	}
	if err := procSendMessageW.Find(); err != nil {
		return nil, err
	}
	ret, _, _ := syscall.SyscallN(procSendMessageW.Addr(), hwnd, wmCopyData, 0, uintptr(unsafe.Pointer(&cds)))
	runtime.KeepAlive(mapNameNul)
	runtime.KeepAlive(cds)
	if ret == 0 {
		return nil, errors.New("agent-bridge: Pageant WM_COPYDATA request refused")
	}

	total := binary.BigEndian.Uint32(shared[:4]) + 4
	if total > agentMaxMessageLength {
		return nil, errors.New("agent-bridge: Pageant reply too long")
	}
	reply := make([]byte, total)
	copy(reply, shared[:total])
	return reply, nil
}
