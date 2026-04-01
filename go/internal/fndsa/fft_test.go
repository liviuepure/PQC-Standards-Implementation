package fndsa

import (
	"fmt"
	"math"
	"testing"
)

// TestNTTRoundtrip verifies that NTT followed by INTT recovers the original polynomial mod Q.
// NOTE: TestNTTRoundtrip passes in Task 2 because on-the-fly twiddle computation is used.
// Task 3 will replace on-the-fly computation with precomputed tables for speed.
func TestNTTRoundtrip(t *testing.T) {
	for _, n := range []int{512, 1024} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			a := make([]int32, n)
			for i := range a {
				a[i] = int32(i % Q)
			}
			b := make([]int32, n)
			copy(b, a)
			NTT(b, n)
			INTT(b, n)
			for i := range a {
				if a[i] != b[i] {
					t.Fatalf("mismatch at index %d: got %d want %d", i, b[i], a[i])
				}
			}
		})
	}
}

// TestFFTRoundtrip verifies that FFT followed by IFFT recovers original values within float64 precision.
func TestFFTRoundtrip(t *testing.T) {
	for _, n := range []int{4, 8, 512, 1024} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			f := make([]complex128, n)
			for i := range f {
				f[i] = complex(float64(i+1), 0)
			}
			orig := make([]complex128, n)
			copy(orig, f)
			FFT(f, n)
			IFFT(f, n)
			for i := range f {
				if math.Abs(real(f[i])-real(orig[i])) > 1e-8 ||
					math.Abs(imag(f[i])-imag(orig[i])) > 1e-8 {
					t.Fatalf("FFT roundtrip mismatch at index %d: got %v want %v", i, f[i], orig[i])
				}
			}
		})
	}
}

// TestSplitMergeFFT verifies that SplitFFT followed by MergeFFT recovers the original FFT domain values.
func TestSplitMergeFFT(t *testing.T) {
	n := 8
	f := make([]complex128, n)
	for i := range f {
		f[i] = complex(float64(i*3+1), float64(i))
	}
	FFT(f, n)
	f0, f1 := SplitFFT(f, n)
	recovered := MergeFFT(f0, f1, n)
	for i := range f {
		if math.Abs(real(recovered[i])-real(f[i])) > 1e-8 {
			t.Fatalf("SplitMerge mismatch at %d", i)
		}
	}
}
