// bench_test.go — writer throughput benchmarks backing docs/perf-baseline.md.
//
// No build tag: benchmarks run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
//
// Run: go test -run XXX -bench . -benchtime 3s .
package evtx

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func benchFields() map[string]string {
	return map[string]string{
		"ProviderName":      "Audit-Event-Receiver",
		"Computer":          "nas-node-01",
		"Channel":           "Security",
		"Level":             "4",
		"TimeCreated":       "2026-08-22T12:00:00.000000000Z",
		"ObjectName":        "/export/data/share/finance/q3-report.xlsx",
		"AccessMask":        "0x120089",
		"SubjectUserName":   "jdoe",
		"SubjectDomainName": "CORP",
		"IpAddress":         "10.20.30.40",
	}
}

// quietLogs silences the per-chunk slog.Info so benchmark output is readable.
func quietLogs(b *testing.B) {
	b.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(prev) })
}

// BenchmarkEncodeShared measures the encoder alone with the chunk's template
// already written — the steady state for every record but the chunk's first.
func BenchmarkEncodeShared(b *testing.B) {
	f := benchFields()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := buildBinXML(4663, uint64(i), f, 4096, 512)
		_ = wrapEventRecord(uint64(i), toFILETIME(time.Now()), res.payload)
	}
}

// BenchmarkEncodeInline measures the encoder when it must also write the
// template definition — the first record of every chunk.
func BenchmarkEncodeInline(b *testing.B) {
	f := benchFields()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := buildBinXML(4663, uint64(i), f, 4096, 0)
		_ = wrapEventRecord(uint64(i), toFILETIME(time.Now()), res.payload)
	}
}

// BenchmarkWriteRecord measures the full write path to a real file and reports
// how many records each fsync covers.
func BenchmarkWriteRecord(b *testing.B) {
	quietLogs(b)
	var syncs int64
	w, err := New(filepath.Join(b.TempDir(), "bench.evtx"), RotationConfig{
		OnFsync: func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		b.Fatal(err)
	}
	f := benchFields()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.WriteRecord(4663, f); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = w.Close()
	n := atomic.LoadInt64(&syncs)
	if n == 0 {
		n = 1
	}
	b.ReportMetric(float64(b.N)/float64(n), "rec/fsync")
}

// BenchmarkWriteRecordParallel measures the same path with many goroutines on
// one Writer: it reports lock contention, not scaling.
func BenchmarkWriteRecordParallel(b *testing.B) {
	quietLogs(b)
	w, err := New(filepath.Join(b.TempDir(), "bench-par.evtx"), RotationConfig{})
	if err != nil {
		b.Fatal(err)
	}
	f := benchFields()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := w.WriteRecord(4663, f); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	_ = w.Close()
}

// BenchmarkTickFlushIdle measures one background tick with no new records —
// the case v0.10.0 turns into a no-op.
func BenchmarkTickFlushIdle(b *testing.B) {
	quietLogs(b)
	w, err := New(filepath.Join(b.TempDir(), "bench-idle.evtx"), RotationConfig{})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	if err := w.WriteRecord(4663, benchFields()); err != nil {
		b.Fatal(err)
	}
	// The priming tick does the real work. If it fails, every iteration below
	// measures the len(w.records) == 0 branch instead of the idle-skip branch,
	// and the recorded number describes the wrong code.
	w.mu.Lock()
	primeErr := w.tickFlushLocked()
	w.mu.Unlock()
	if primeErr != nil {
		b.Fatalf("priming tick: %v", primeErr)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.mu.Lock()
		if err := w.tickFlushLocked(); err != nil {
			w.mu.Unlock()
			b.Fatal(err)
		}
		w.mu.Unlock()
	}
}
