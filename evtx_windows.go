//go:build windows

package evtx

import (
	"errors"
	"syscall"
)

// syncDir is a no-op on Windows. Directory entries are durable immediately
// after MoveFileEx (os.Rename) on NTFS without an explicit fsync.
func syncDir(_ string) error {
	return nil
}

// errorInvalidFunction is ERROR_INVALID_FUNCTION, Windows' raw Win32 error
// code 1. CreateHardLink returns it (surfaced by os.Link as this exact
// syscall.Errno) on filesystems that do not support hard links — FAT32,
// exFAT, and some SMB and container overlay mounts. It is unrelated to
// syscall.EPERM: on Windows, the package syscall E* constants are invented
// large values for POSIX-compatibility (see zerrors_windows.go), not real
// Win32 error codes, so EPERM never matches this failure.
//
// This classification is reasoned from the Windows API documentation and
// the Go standard library source, not reproduced: this repository has no
// Windows FAT32 (or similar) target to verify it against empirically.
const errorInvalidFunction = syscall.Errno(1)

// isLinkUnsupported reports whether err from os.Link indicates the
// filesystem does not support hard links, so rotate() should fall back to
// Stat+Rename instead of poisoning the writer.
func isLinkUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, errorInvalidFunction)
}
