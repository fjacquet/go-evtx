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
	defer func() { _ = os.Remove(path) }()

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
	defer func() { _ = os.Remove(path) }()

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
	defer func() { _ = os.Remove(path) }()

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
	defer func() { _ = r.Close() }()

	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ev.System.EventID, ev.System.Provider.Name, ev.EventData)
	}
	// Output: 4663 Microsoft-Windows-Security-Auditing [{SubjectUserSid } {SubjectUserName } {SubjectDomainName } {SubjectLogonId } {ObjectServer } {ObjectType } {ObjectName /mnt/share/report.xlsx} {HandleId } {AccessList } {AccessMask } {ProcessId } {ProcessName } {IpAddress }]
}

// ExampleReader_FileInfo shows how to tell a go-evtx file from a
// Windows-written one: the format version is in the file header, and Windows
// Server 2025 writes 3.2 where this library writes 3.1.
func ExampleReader_FileInfo() {
	dir, err := os.MkdirTemp("", "evtx-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "example.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "EXAMPLE-HOST",
	}); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := evtx.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	fi := r.FileInfo()
	fmt.Printf("format %d.%d, %d chunk(s), dirty=%t\n", fi.Major, fi.Minor, fi.Chunks, fi.Dirty)
	// Output: format 3.1, 1 chunk(s), dirty=false
}

// ExampleReader_ReadEvent_json shows the library's own JSON rendering, which
// is exactly what `evtx dump` emits: Event carries the tags and Value renders
// each type, so a consumer never has to reimplement either.
func ExampleReader_ReadEvent_json() {
	dir, err := os.MkdirTemp("", "evtx-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "example.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "EXAMPLE-HOST",
		"TimeCreated":  "2026-08-10T06:02:35Z",
	}); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := evtx.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d %s %s\n", ev.System.EventID, ev.System.Computer,
		ev.System.TimeCreated.UTC().Format(time.RFC3339))
	// Output: 4663 EXAMPLE-HOST 2026-08-10T06:02:35Z
}
