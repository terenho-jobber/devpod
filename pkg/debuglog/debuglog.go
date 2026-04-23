// Package debuglog writes timestamped debug lines to /tmp/devpod-debug.log so
// we can trace the credential-helper code path end-to-end without relying on
// the SSH/gRPC log-forwarding pipeline, which has been observed to drop lines.
//
// This package is intentionally a best-effort, fire-and-forget logger: any
// error opening or writing to the log file is silently swallowed. It is
// intended for temporary diagnostic use only.
package debuglog

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const logPath = "/tmp/devpod-debug.log"

var mu sync.Mutex

// Log appends a formatted line to /tmp/devpod-debug.log with a header
// containing a wall-clock timestamp, pid, ppid, and euid.
func Log(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()

	// #nosec G304 -- log path is a hardcoded constant.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	header := fmt.Sprintf("[%s pid=%d ppid=%d euid=%d] ",
		time.Now().Format("15:04:05.000000"),
		os.Getpid(), os.Getppid(), os.Geteuid())
	_, _ = fmt.Fprintf(f, header+format+"\n", args...)
}
