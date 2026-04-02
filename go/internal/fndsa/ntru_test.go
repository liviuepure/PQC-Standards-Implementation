package fndsa

import (
	crypto_rand "crypto/rand"
	"testing"
)

// TestNTRUEquation verifies that f*G - g*F = q over Z[x]/(x^n+1) for each parameter set.
func TestNTRUEquation(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p // capture loop variable
		t.Run(p.Name, func(t *testing.T) {
			f, g, F, G, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatalf("NTRUKeyGen: %v", err)
			}

			// f*G - g*F should equal the polynomial q (constant = Q, rest 0).
			fG := polyMulIntZ(f, G, p.N)
			gF := polyMulIntZ(g, F, p.N)
			diff := polySubIntZ(fG, gF, p.N)

			if diff[0] != int64(Q) {
				t.Errorf("constant term: got %d want %d", diff[0], Q)
			}
			for i := 1; i < p.N; i++ {
				if diff[i] != 0 {
					t.Errorf("coeff[%d]: got %d want 0", i, diff[i])
				}
			}
		})
	}
}

// TestNTRUPublicKey verifies that f*h = g mod (q, x^n+1) for each parameter set.
func TestNTRUPublicKey(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p // capture loop variable
		t.Run(p.Name, func(t *testing.T) {
			f, g, _, _, err := NTRUKeyGen(p, crypto_rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			h := NTRUPublicKey(f, g, p)
			fh := PolyMulNTT(reduceModQ(f, p.N), h, p.N)
			gModQ := make([]int32, p.N)
			for i, v := range g {
				gModQ[i] = ((v % Q) + Q) % Q
			}
			for i := range fh {
				if fh[i] != gModQ[i] {
					t.Fatalf("f*h != g at coeff %d: got %d want %d", i, fh[i], gModQ[i])
				}
			}
		})
	}
}

// TestPolyMulNTT verifies that (x+1)*(x-1) = x^2-1 mod (q, x^n+1).
func TestPolyMulNTT(t *testing.T) {
	n := 512
	a := make([]int32, n)
	b := make([]int32, n)
	a[0] = 1
	a[1] = 1
	b[0] = Q - 1
	b[1] = 1
	c := PolyMulNTT(a, b, n)
	if c[0] != Q-1 {
		t.Errorf("c[0]=%d want %d", c[0], Q-1)
	}
	if c[2] != 1 {
		t.Errorf("c[2]=%d want 1", c[2])
	}
	for i, v := range c {
		if i == 0 || i == 2 {
			continue
		}
		if v != 0 {
			t.Errorf("c[%d]=%d want 0", i, v)
		}
	}
}

// TestPolyAddSub verifies PolyAdd and PolySub.
func TestPolyAddSub(t *testing.T) {
	n := 16
	a := make([]int32, n)
	b := make([]int32, n)
	for i := range a {
		a[i] = int32(i)
		b[i] = int32(n - i - 1)
	}
	c := PolyAdd(a, b, n)
	// a[i] + b[i] = n-1 for all i
	for i, v := range c {
		expected := int32(n-1) % Q
		if v != expected {
			t.Errorf("PolyAdd[%d]=%d want %d", i, v, expected)
		}
	}

	d := PolySub(a, b, n)
	for i, v := range d {
		expected := ((int32(i) - int32(n-i-1)) % Q + Q) % Q
		if v != expected {
			t.Errorf("PolySub[%d]=%d want %d", i, v, expected)
		}
	}
}

// TestNTRUAdjoint verifies the adjoint operation: adj[0] = f[0], adj[i] = -f[n-i] for i >= 1.
func TestNTRUAdjoint(t *testing.T) {
	n := 8
	f := []int32{1, 2, 3, 4, 5, 6, 7, 8}
	adj := polyAdjoint(f, n)
	if adj[0] != f[0] {
		t.Errorf("adj[0]=%d want %d", adj[0], f[0])
	}
	for i := 1; i < n; i++ {
		if adj[i] != -f[n-i] {
			t.Errorf("adj[%d]=%d want %d", i, adj[i], -f[n-i])
		}
	}
}

// reduceModQ reduces polynomial coefficients to [0, Q).
func reduceModQ(a []int32, n int) []int32 {
	b := make([]int32, n)
	for i, v := range a {
		b[i] = ((v % Q) + Q) % Q
	}
	return b
}
