// evtx_unix_test.go — unit tests for the Unix isLinkUnsupported
// classification used by rotate()'s archive-commit fallback (Fix 4).
//
// White-box: package evtx. stdlib only.
//go:build !windows

package evtx

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsLinkUnsupported_Unix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrUnsupported", errors.ErrUnsupported, true},
		{"EPERM", syscall.EPERM, true},
		{"wrapped EPERM", fmt.Errorf("link: %w", syscall.EPERM), true},
		{"unrelated sentinel", errors.New("some other failure"), false},
		{"ENOENT", syscall.ENOENT, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLinkUnsupported(c.err); got != c.want {
				t.Errorf("isLinkUnsupported(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
