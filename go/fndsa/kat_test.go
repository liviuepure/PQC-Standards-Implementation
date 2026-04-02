package fndsa

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// katEntry matches the JSON format used for FN-DSA interop vectors.
type katEntry struct {
	Count int    `json:"count"`
	PK    string `json:"pk"`
	SK    string `json:"sk"`
	Msg   string `json:"msg"`
	Sig   string `json:"sig"`
}

// interopEntry is the top-level vector file format.
type interopFile struct {
	Algorithm   string     `json:"algorithm"`
	GeneratedBy string     `json:"generated_by"`
	Timestamp   string     `json:"timestamp"`
	Vectors     []katEntry `json:"vectors"`
}

// TestKAT512 runs the NIST FIPS 206 KAT for FN-DSA-512 if the vector file exists.
func TestKAT512(t *testing.T) {
	runKATFile(t, "../../test-vectors/fn-dsa/kat/fn-dsa-512.json", FNDSA512)
}

// TestKAT1024 runs the NIST FIPS 206 KAT for FN-DSA-1024 if the vector file exists.
func TestKAT1024(t *testing.T) {
	runKATFile(t, "../../test-vectors/fn-dsa/kat/fn-dsa-1024.json", FNDSA1024)
}

// TestInteropVectors verifies the generated cross-language interop vectors.
func TestInteropVectors(t *testing.T) {
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			path := "../../test-vectors/fn-dsa/" + p.Name + ".json"
			runKATFile(t, path, p)
		})
	}
}

func runKATFile(t *testing.T, path string, p *Params) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vector file not found (skip): %v", err)
		return
	}
	var f interopFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}
	for _, e := range f.Vectors {
		e := e
		t.Run("", func(t *testing.T) {
			pk, _ := hex.DecodeString(e.PK)
			msg, _ := hex.DecodeString(e.Msg)
			sig, _ := hex.DecodeString(e.Sig)

			// Every stored vector must verify successfully.
			if !Verify(pk, msg, sig, p) {
				t.Errorf("count=%d: Verify returned false for stored vector", e.Count)
			}

			// Tampered message must fail.
			if Verify(pk, append([]byte("x"), msg...), sig, p) {
				t.Errorf("count=%d: Verify accepted wrong message", e.Count)
			}

			// If sk is present, verify that signing with it produces a verifiable signature.
			if e.SK != "" {
				sk, _ := hex.DecodeString(e.SK)
				newSig, err := Sign(sk, msg, p, rand.Reader)
				if err != nil {
					t.Errorf("count=%d: Sign failed: %v", e.Count, err)
				} else if !Verify(pk, msg, newSig, p) {
					t.Errorf("count=%d: freshly-generated signature does not verify", e.Count)
				}
			}
		})
	}
}

// TestGenerateInteropVectors writes interop vectors to test-vectors/fn-dsa/.
// Run with:
//
//	go test -run TestGenerateInteropVectors ./fndsa/... -v
//
// This is not a regular test and is only used to regenerate vectors.
func TestGenerateInteropVectors(t *testing.T) {
	if os.Getenv("FNDSA_GENERATE_VECTORS") == "" {
		t.Skip("set FNDSA_GENERATE_VECTORS=1 to regenerate interop vectors")
	}
	for _, p := range []*Params{FNDSA512, FNDSA1024} {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			const n = 3
			vectors := make([]katEntry, n)
			msgs := []string{
				"",
				"hello fn-dsa",
				"the quick brown fox jumps over the lazy dog",
			}
			for i := 0; i < n; i++ {
				pk, sk, err := KeyGen(p, rand.Reader)
				if err != nil {
					t.Fatalf("KeyGen: %v", err)
				}
				msg := []byte(msgs[i])
				sig, err := Sign(sk, msg, p, rand.Reader)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if !Verify(pk, msg, sig, p) {
					t.Fatal("self-verification failed")
				}
				vectors[i] = katEntry{
					Count: i,
					PK:    hex.EncodeToString(pk),
					SK:    hex.EncodeToString(sk),
					Msg:   hex.EncodeToString(msg),
					Sig:   hex.EncodeToString(sig),
				}
			}

			out := interopFile{
				Algorithm:   p.Name,
				GeneratedBy: "Go reference (FIPS 206 / Babai nearest-plane)",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Vectors:     vectors,
			}
			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := "../../test-vectors/fn-dsa/" + p.Name + ".json"
			if err := os.WriteFile(path, append(b, '\n'), 0644); err != nil {
				t.Fatalf("write vector file: %v", err)
			}
			t.Logf("wrote %d vectors to %s", n, path)

			// Verify the written file round-trips.
			written, _ := os.ReadFile(path)
			if !bytes.Equal(written, append(b, '\n')) {
				t.Error("round-trip file content mismatch")
			}
		})
	}
}
