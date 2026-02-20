//go:build !windows

package web

import (
	"runtime"
	"time"
)

func getProcessCPUUsage() float64 {
	return estimateCPUUsage()
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
