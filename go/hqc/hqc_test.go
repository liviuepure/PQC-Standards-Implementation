package hqc_test

import (
	"bytes"
	"testing"

	"github.com/liviuepure/PQC-Standards-Implementation/go/hqc"
)

func TestRoundtrip(t *testing.T) {
	for _, p := range hqc.AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk, err := hqc.KeyGen(p, nil)
			if err != nil {
				t.Fatalf("KeyGen error: %v", err)
			}

			ct, ss1, err := hqc.Encaps(pk, p, nil)
			if err != nil {
				t.Fatalf("Encaps error: %v", err)
			}

			ss2, err := hqc.Decaps(sk, ct, p)
			if err != nil {
				t.Fatalf("Decaps error: %v", err)
			}

			if !bytes.Equal(ss1, ss2) {
				t.Error("shared secrets do not match")
			}
		})
	}
}

func TestMultipleRoundtrips(t *testing.T) {
	p := hqc.HQC128
	for i := 0; i < 5; i++ {
		pk, sk, err := hqc.KeyGen(p, nil)
		if err != nil {
			t.Fatalf("iteration %d: KeyGen error: %v", i, err)
		}

		ct, ss1, err := hqc.Encaps(pk, p, nil)
		if err != nil {
			t.Fatalf("iteration %d: Encaps error: %v", i, err)
		}

		ss2, err := hqc.Decaps(sk, ct, p)
		if err != nil {
			t.Fatalf("iteration %d: Decaps error: %v", i, err)
		}

		if !bytes.Equal(ss1, ss2) {
			t.Errorf("iteration %d: shared secrets do not match", i)
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	_, _, err := hqc.KeyGen(nil, nil)
	if err == nil {
		t.Error("expected error for nil params in KeyGen")
	}

	_, _, err = hqc.Encaps(nil, nil, nil)
	if err == nil {
		t.Error("expected error for nil params in Encaps")
	}

	_, err = hqc.Decaps(nil, nil, nil)
	if err == nil {
		t.Error("expected error for nil params in Decaps")
	}

	p := hqc.HQC128
	_, _, err = hqc.Encaps([]byte{1, 2, 3}, p, nil)
	if err == nil {
		t.Error("expected error for invalid pk size in Encaps")
	}

	_, err = hqc.Decaps([]byte{1, 2, 3}, []byte{4, 5, 6}, p)
	if err == nil {
		t.Error("expected error for invalid sk/ct size in Decaps")
	}
}

func TestKeySizes(t *testing.T) {
	for _, p := range hqc.AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			pk, sk, err := hqc.KeyGen(p, nil)
			if err != nil {
				t.Fatalf("KeyGen: %v", err)
			}
			if len(pk) != p.PKSize {
				t.Errorf("pk size = %d, want %d", len(pk), p.PKSize)
			}
			if len(sk) != p.SKSize {
				t.Errorf("sk size = %d, want %d", len(sk), p.SKSize)
			}
		})
	}
}

func TestCiphertextSize(t *testing.T) {
	for _, p := range hqc.AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			pk, _, err := hqc.KeyGen(p, nil)
			if err != nil {
				t.Fatalf("KeyGen: %v", err)
			}
			ct, ss, err := hqc.Encaps(pk, p, nil)
			if err != nil {
				t.Fatalf("Encaps: %v", err)
			}
			if len(ct) != p.CTSize {
				t.Errorf("ct size = %d, want %d", len(ct), p.CTSize)
			}
			if len(ss) != p.SSSize {
				t.Errorf("ss size = %d, want %d", len(ss), p.SSSize)
			}
		})
	}
}

func TestDecapsBadCiphertext(t *testing.T) {
	p := hqc.HQC128
	pk, sk, err := hqc.KeyGen(p, nil)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	ct, ss1, err := hqc.Encaps(pk, p, nil)
	if err != nil {
		t.Fatalf("Encaps: %v", err)
	}

	// Corrupt ciphertext
	ct[0] ^= 0xFF

	ss2, err := hqc.Decaps(sk, ct, p)
	if err != nil {
		t.Fatalf("Decaps: %v", err)
	}

	if bytes.Equal(ss1, ss2) {
		t.Error("shared secrets should not match with corrupted ciphertext")
	}
}
