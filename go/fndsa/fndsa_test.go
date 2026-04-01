package fndsa

import "testing"

func TestParamSizes(t *testing.T) {
	cases := []struct {
		p        *Params
		n        int
		pkBytes  int
		skBytes  int
		sigBytes int
	}{
		{FNDSA512, 512, 897, 1281, 666},
		{FNDSA1024, 1024, 1793, 2305, 1280},
		{FNDSAPadded512, 512, 897, 1281, 809},
		{FNDSAPadded1024, 1024, 1793, 2305, 1473},
	}
	for _, tc := range cases {
		if tc.p.N != tc.n {
			t.Errorf("%s: N=%d want %d", tc.p.Name, tc.p.N, tc.n)
		}
		if tc.p.PKSize != tc.pkBytes {
			t.Errorf("%s: PKSize=%d want %d", tc.p.Name, tc.p.PKSize, tc.pkBytes)
		}
		if tc.p.SKSize != tc.skBytes {
			t.Errorf("%s: SKSize=%d want %d", tc.p.Name, tc.p.SKSize, tc.skBytes)
		}
		if tc.p.SigSize != tc.sigBytes {
			t.Errorf("%s: SigSize=%d want %d", tc.p.Name, tc.p.SigSize, tc.sigBytes)
		}
	}
}
