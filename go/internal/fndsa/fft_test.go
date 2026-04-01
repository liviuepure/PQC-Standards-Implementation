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

// TestNTTPolyMul verifies that NTT-based multiplication is correct.
// (x+1)*(x-1) = x^2 - 1 in Z[x], so mod x^n+1 the result is x^2 - 1
// (coeff[0]=-1, coeff[2]=1, all others 0 mod Q)
func TestNTTPolyMul(t *testing.T) {
	for _, n := range []int{512, 1024} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			a := make([]int32, n) // x+1: a[0]=1, a[1]=1
			b := make([]int32, n) // x-1: b[0]=Q-1, b[1]=1
			a[0], a[1] = 1, 1
			b[0], b[1] = Q-1, 1

			NTT(a, n)
			NTT(b, n)
			for i := range a {
				a[i] = int32((int64(a[i]) * int64(b[i])) % int64(Q))
			}
			INTT(a, n)

			// Expected: a[0]=Q-1 (i.e. -1 mod Q), a[2]=1, rest 0
			if a[0] != Q-1 {
				t.Errorf("coeff[0]: got %d want %d", a[0], Q-1)
			}
			if a[2] != 1 {
				t.Errorf("coeff[2]: got %d want 1", a[2])
			}
			for i, v := range a {
				if i == 0 || i == 2 {
					continue
				}
				if v != 0 {
					t.Errorf("coeff[%d]: got %d want 0", i, v)
				}
			}
		})
	}
}

// BenchmarkNTT measures NTT+INTT throughput for n=512 and n=1024 using precomputed zeta tables.
func BenchmarkNTT(b *testing.B) {
	for _, n := range []int{512, 1024} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			f := make([]int32, n)
			for i := range f {
				f[i] = int32(i % Q)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				NTT(f, n)
				INTT(f, n)
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
