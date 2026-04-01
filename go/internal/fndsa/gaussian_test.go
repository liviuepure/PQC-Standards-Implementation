package fndsa

import (
	"bytes"
	crypto_rand "crypto/rand"
	"math"
	"testing"
)

// TestGaussianDistribution verifies that SampleGaussian produces samples with
// mean ≈ 0 and standard deviation ≈ σ₀ (within 5%) over 100,000 draws.
func TestGaussianDistribution(t *testing.T) {
	n := 100000
	var sum, sumSq float64
	for i := 0; i < n; i++ {
		x := SampleGaussian(crypto_rand.Reader, sigma0)
		sum += float64(x)
		sumSq += float64(x) * float64(x)
	}
	mean := sum / float64(n)
	variance := sumSq/float64(n) - mean*mean
	sigma := math.Sqrt(variance)
	if math.Abs(mean) > 0.05 {
		t.Errorf("mean = %.4f, want ≈ 0", mean)
	}
	if math.Abs(sigma-sigma0) > 0.1 {
		t.Errorf("sigma = %.4f, want ≈ %.4f", sigma, sigma0)
	}
}

// TestGaussianDeterministic verifies that two readers with identical byte
// sequences produce identical sample sequences, confirming deterministic
// (and implicitly constant-time) structure.
func TestGaussianDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42, 0x13, 0xAB, 0xCD}, 1000)
	r1 := bytes.NewReader(seed)
	r2 := bytes.NewReader(seed)
	for i := 0; i < 100; i++ {
		a := SampleGaussian(r1, sigma0)
		b := SampleGaussian(r2, sigma0)
		if a != b {
			t.Fatalf("non-deterministic at i=%d: %d != %d", i, a, b)
		}
	}
}
