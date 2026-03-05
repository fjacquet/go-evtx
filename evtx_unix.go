//go:build !windows

package evtx

import "syscall"

// syncDir performs an fsync on the directory containing a rotated file.
// This ensures the directory entry (rename) is durable on Linux/macOS.
// Errors are best-effort; callers log but do not abort rotation on failure.
func syncDir(dirPath string) error {
	fd, err := syscall.Open(dirPath, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := syscall.Fsync(fd); err != nil {
		_ = syscall.Close(fd)
		return err
	}
	return syscall.Close(fd)
}
