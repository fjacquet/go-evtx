//go:build windows

package evtx

// syncDir is a no-op on Windows. Directory entries are durable immediately
// after MoveFileEx (os.Rename) on NTFS without an explicit fsync.
func syncDir(_ string) error {
	return nil
}
