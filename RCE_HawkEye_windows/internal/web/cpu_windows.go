//go:build windows

package web

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

type FILETIME struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
}

type PROCESS_MEMORY_COUNTERS struct {
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

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	getProcessTimes    = kernel32.NewProc("GetProcessTimes")
	getSystemTimes     = kernel32.NewProc("GetSystemTimes")
	getCurrentProcess  = kernel32.NewProc("GetCurrentProcess")
	psapi              = syscall.NewLazyDLL("psapi.dll")
	getProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

type cpuUsageData struct {
	lastKernelTime uint64
	lastUserTime   uint64
	lastIdleTime   uint64
	lastTime       time.Time
}

var cpuUsageCache cpuUsageData

func getProcessCPUUsage() float64 {
	handle, _, _ := getCurrentProcess.Call()
	
	var creationTime, exitTime, kernelTime, userTime FILETIME
	ret, _, _ := getProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	
	if ret == 0 {
		return estimateCPUUsage()
	}
	
	kernelTimeVal := (uint64(kernelTime.DwHighDateTime) << 32) | uint64(kernelTime.DwLowDateTime)
	userTimeVal := (uint64(userTime.DwHighDateTime) << 32) | uint64(userTime.DwLowDateTime)
	
	now := time.Now()
	
	if cpuUsageCache.lastTime.IsZero() {
		cpuUsageCache.lastKernelTime = kernelTimeVal
		cpuUsageCache.lastUserTime = userTimeVal
		cpuUsageCache.lastTime = now
		return estimateCPUUsage()
	}
	
	elapsed := now.Sub(cpuUsageCache.lastTime).Seconds()
	if elapsed < 0.5 {
		return cpuTracker.currentUsage
	}
	
	kernelDiff := kernelTimeVal - cpuUsageCache.lastKernelTime
	userDiff := userTimeVal - cpuUsageCache.lastUserTime
	
	totalProcessTime := kernelDiff + userDiff
	
	cpuUsage := float64(totalProcessTime) / (elapsed * 10000000.0 * float64(runtime.NumCPU())) * 100
	
	cpuUsageCache.lastKernelTime = kernelTimeVal
	cpuUsageCache.lastUserTime = userTimeVal
	cpuUsageCache.lastTime = now
	
	if cpuUsage < 0 {
		cpuUsage = 0
	} else if cpuUsage > 100 {
		cpuUsage = 100
	}
	
	return cpuUsage
}

func estimateCPUUsage() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	goroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()
	
	heapUsage := float64(m.HeapAlloc) / float64(m.Sys) * 100
	
	goroutineLoad := float64(goroutines) / float64(numCPU*100) * 50
	
	cpuUsage := (heapUsage * 0.3 + goroutineLoad * 0.7)
	
	if goroutines > 100 {
		cpuUsage += float64(goroutines-100) * 0.1
	}
	
	if cpuUsage < 0 {
		cpuUsage = 0
	} else if cpuUsage > 100 {
		cpuUsage = 100
	}
	
	return cpuUsage
}

func init() {
	cpuTracker.lastTime = time.Now()
}
