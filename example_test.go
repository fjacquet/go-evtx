// example_test.go — runnable examples for pkg.go.dev.
package evtx_test

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fjacquet/go-evtx"
)

// ExampleWriter_WriteRecord demonstrates writing structured audit events to an
// .evtx file with periodic background flushing.
func ExampleWriter_WriteRecord() {
	path := filepath.Join(os.TempDir(), "audit.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{FlushIntervalSec: 30})
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(path)

	err = w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "myhost",
		"TimeCreated":  time.Now().Format(time.RFC3339Nano),
		"ObjectName":   "/mnt/share/file.txt",
		"AccessMask":   "0x2",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("ok")
	// Output: ok
}

// ExampleWriter_WriteRecord_noFlush demonstrates using RotationConfig{} (zero
// value) to disable the background goroutine — records are flushed only on Close.
func ExampleWriter_WriteRecord_noFlush() {
	path := filepath.Join(os.TempDir(), "audit_noflush.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(path)

	if err := w.WriteRecord(4660, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "myhost",
		"ObjectName":   "/tmp/deleted.txt",
	}); err != nil {
		log.Fatal(err)
	}

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("ok")
	// Output: ok
}

// ExampleReader demonstrates a round-trip: write one record then read it back.
func ExampleReader() {
	path := filepath.Join(os.TempDir(), "roundtrip.evtx")

	// Write
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(path)

	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "myhost",
		"ObjectName":   "/mnt/share/report.xlsx",
	}); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	// Read
	r, err := evtx.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	for {
		rec, err := r.ReadRecord()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(rec.EventID, rec.Provider, rec.Fields["ObjectName"])
	}
	// Output: 4663 Microsoft-Windows-Security-Auditing /mnt/share/report.xlsx
}
