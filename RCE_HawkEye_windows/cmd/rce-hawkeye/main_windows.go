//go:build windows

package main

import (
	"syscall"

	"github.com/hbzw/RCE_HawkEye_go/internal/color"
)

func initPlatform() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	setConsoleOutputCP.Call(uintptr(65001))
	setConsoleCP := kernel32.NewProc("SetConsoleCP")
	setConsoleCP.Call(uintptr(65001))
	
	color.SetWindowsColorSupport(true)
}
