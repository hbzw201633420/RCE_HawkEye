package utils

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type InterruptHandler struct {
	interrupted bool
	mu          sync.Mutex
	callbacks   []func()
	sigChan     chan os.Signal
}

var (
	globalInterruptHandler *InterruptHandler
	once                   sync.Once
)

func GetInterruptHandler() *InterruptHandler {
	once.Do(func() {
		globalInterruptHandler = &InterruptHandler{
			interrupted: false,
			callbacks:   make([]func(), 0),
			sigChan:     make(chan os.Signal, 1),
		}
		globalInterruptHandler.setup()
	})
	return globalInterruptHandler
}

func (h *InterruptHandler) setup() {
	signal.Notify(h.sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-h.sigChan
		h.mu.Lock()
		h.interrupted = true
		fmt.Println("\n\n[!] 收到中断信号，正在停止扫描...")
		for _, cb := range h.callbacks {
			cb()
		}
		h.mu.Unlock()
	}()
}

func (h *InterruptHandler) IsInterrupted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.interrupted
}

func (h *InterruptHandler) RegisterCallback(cb func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callbacks = append(h.callbacks, cb)
}

func (h *InterruptHandler) Stop() {
	h.mu.Lock()
	h.interrupted = true
	h.mu.Unlock()
}
