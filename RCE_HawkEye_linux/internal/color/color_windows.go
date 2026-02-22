//go:build windows

package color

import (
	"syscall"
	"unsafe"
)

func enableWindowsANSI() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	
	stdoutHandle, _, _ := getStdHandle.Call(uintptr(0xFFFFFFF5))
	if stdoutHandle != uintptr(0) && stdoutHandle != uintptr(0xFFFFFFFF) {
		var mode uint32
		getConsoleMode.Call(stdoutHandle, uintptr(unsafe.Pointer(&mode)))
		mode |= 0x0004
		setConsoleMode.Call(stdoutHandle, uintptr(mode))
	}
	
	stderrHandle, _, _ := getStdHandle.Call(uintptr(0xFFFFFFF4))
	if stderrHandle != uintptr(0) && stderrHandle != uintptr(0xFFFFFFFF) {
		var mode uint32
		getConsoleMode.Call(stderrHandle, uintptr(unsafe.Pointer(&mode)))
		mode |= 0x0004
		setConsoleMode.Call(stderrHandle, uintptr(mode))
	}
}
