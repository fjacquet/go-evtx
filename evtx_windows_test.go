// evtx_windows_test.go — unit tests for the Windows isLinkUnsupported
// classification used by rotate()'s archive-commit fallback (Fix 4).
//
// This file only builds and runs under GOOS=windows. This repository's
// verification gate runs `GOOS=windows go build ./...` (compile-only, no
// test files) and `go test ./...` on the host GOOS, so neither currently
// exercises this file. The ERROR_INVALID_FUNCTION classification it checks
// is reasoned from the Windows API and the Go standard library source (see
// the comment on errorInvalidFunction in evtx_windows.go), not reproduced
// against a real FAT32/exFAT/SMB target — this environment has none.
//
// White-box: package evtx. stdlib only.
//go:build windows

package evtx

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsLinkUnsupported_Windows(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrUnsupported", errors.ErrUnsupported, true},
		{"EPERM", syscall.EPERM, true},
		{"ERROR_INVALID_FUNCTION", errorInvalidFunction, true},
		{"wrapped ERROR_INVALID_FUNCTION", fmt.Errorf("link: %w", errorInvalidFunction), true},
		{"unrelated sentinel", errors.New("some other failure"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLinkUnsupported(c.err); got != c.want {
				t.Errorf("isLinkUnsupported(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
