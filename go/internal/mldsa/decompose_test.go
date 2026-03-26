package mldsa

import "testing"

func TestPower2Round(t *testing.T) {
	tests := []int{0, 1, 4096, 8191, 8192, Q - 1, 1234567}
	for _, r := range tests {
		r1, r0 := Power2Round(r)
		// Check reconstruction: r = r1 * 2^13 + r0 mod Q
		reconstructed := ModQ(int64(r1*(1<<13)) + int64(r0))
		rMod := ModQ(int64(r))
		if reconstructed != rMod {
			t.Errorf("Power2Round(%d): r1=%d, r0=%d, reconstruction=%d != %d",
				r, r1, r0, reconstructed, rMod)
		}
	}
}

func TestDecompose(t *testing.T) {
	alphas := []int{2 * 95232, 2 * 261888}
	for _, alpha := range alphas {
		for _, r := range []int{0, 1, alpha / 2, alpha - 1, alpha, Q - 1, 4190208} {
			r1, r0 := Decompose(r, alpha)
			rMod := ModQ(int64(r))
			// Check reconstruction: r = r1*alpha + r0 mod Q (with corner case)
			if rMod == Q-1 {
				// Corner case: r1=0, r0=r0-1
				continue
			}
			reconstructed := ModQ(int64(r1)*int64(alpha) + int64(r0))
			if reconstructed != rMod {
				t.Errorf("Decompose(%d, %d): r1=%d, r0=%d, reconstruction=%d != %d",
					r, alpha, r1, r0, reconstructed, rMod)
			}
		}
	}
}

func TestHighLowBits(t *testing.T) {
	alpha := 2 * 95232
	for _, r := range []int{0, 100, 50000, Q - 2, 4190208} {
		h := HighBits(r, alpha)
		l := LowBits(r, alpha)
		rMod := ModQ(int64(r))
		reconstructed := ModQ(int64(h)*int64(alpha) + int64(l))
		if reconstructed != rMod && rMod != Q-1 {
			t.Errorf("HighBits/LowBits(%d, %d): high=%d, low=%d, reconstruction=%d != %d",
				r, alpha, h, l, reconstructed, rMod)
		}
	}
}

func TestUseHintRoundtrip(t *testing.T) {
	alpha := 2 * 95232
	// UseHint(0, r) should return HighBits(r)
	for _, r := range []int{0, 100, 50000, Q - 2} {
		h := UseHint(0, r, alpha)
		expected := HighBits(r, alpha)
		if h != expected {
			t.Errorf("UseHint(0, %d, %d) = %d, want %d", r, alpha, h, expected)
		}
	}
}
