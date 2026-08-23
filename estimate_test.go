// estimate_test.go — the payload-size upper bound used by WriteRecords.
//
// No build tag: tests run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
package evtx

import (
	"strings"
	"testing"
)

// estimateCases exercises the shapes that change the encoded size: empty,
// typical, non-ASCII (2 UTF-16 units per rune is not the only case), non-BMP
// (surrogate pairs), and a value near the record ceiling.
func estimateCases() []map[string]string {
	return []map[string]string{
		{"ProviderName": "P"},
		{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "testhost",
			"Channel":      "Security",
			"ObjectName":   "/nas/share/file.txt",
		},
		{"ProviderName": "P", "Computer": "ünïcödé-höst-ÆØÅ"},
		{"ProviderName": "P", "ObjectName": "/nas/\U0001F600\U0001F601/file.txt"},
		{"ProviderName": "P", "ObjectName": strings.Repeat("x", 20000)},
		{"ProviderName": "P", "ObjectName": strings.Repeat("\U0001F600", 5000)},
	}
}

// TestEstimateMaxPayload_IsUpperBound verifies the estimate is never below the
// real encoded size. WriteRecords rejects a record on the estimate alone, so an
// under-estimate would let an oversized record reach the buffer mid-batch and
// break the all-or-nothing contract.
func TestEstimateMaxPayload_IsUpperBound(t *testing.T) {
	for i, fields := range estimateCases() {
		est := estimateMaxPayload(4663, 1, fields)

		// Both encodings: inline template (first record of a chunk) and
		// shared (every later record). The estimate must bound both.
		for _, shared := range []uint32{0, 512} {
			got := len(buildBinXML(4663, 1, fields, 4096, shared).payload)
			if est < got {
				t.Errorf("case %d shared=%d: estimate %d < actual %d", i, shared, est, got)
			}
		}
	}
}

// TestEstimateMaxPayload_IsNotAbsurdlyLoose guards the other direction. A bound
// that always returned math.MaxInt would satisfy the property above and reject
// every record. The inline encoding is the larger of the two, so the estimate
// should stay within a small constant of it.
func TestEstimateMaxPayload_IsNotAbsurdlyLoose(t *testing.T) {
	for i, fields := range estimateCases() {
		est := estimateMaxPayload(4663, 1, fields)
		actual := len(buildBinXML(4663, 1, fields, 4096, 0).payload)
		if slack := est - actual; slack > 64 {
			t.Errorf("case %d: estimate %d exceeds inline actual %d by %d bytes; "+
				"the bound should be tight enough to reject only real overflows",
				i, est, actual, slack)
		}
	}
}

// FuzzEstimateMaxPayload_IsUpperBound is the property that makes WriteRecords'
// all-or-nothing contract true. The seeds cover ASCII, non-BMP runes and
// oversize values; the fuzzer explores from there.
func FuzzEstimateMaxPayload_IsUpperBound(f *testing.F) {
	f.Add("Provider", "host", "/nas/file.txt", "0x2")
	f.Add("P", "ünïcödé", "\U0001F600", "1")
	f.Add("", "", "", "")
	f.Add(strings.Repeat("x", 1000), strings.Repeat("\U0001F600", 500), "c", "d")

	f.Fuzz(func(t *testing.T, provider, computer, object, mask string) {
		fields := map[string]string{
			"ProviderName": provider,
			"Computer":     computer,
			"ObjectName":   object,
			"AccessMask":   mask,
		}
		est := estimateMaxPayload(4663, 1, fields)
		for _, shared := range []uint32{0, 512} {
			got := len(buildBinXML(4663, 1, fields, 4096, shared).payload)
			if est < got {
				t.Fatalf("estimate %d < actual %d (shared=%d) for %q/%q/%q/%q",
					est, got, shared, provider, computer, object, mask)
			}
		}
	})
}
