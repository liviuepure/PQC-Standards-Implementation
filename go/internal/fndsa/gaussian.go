package fndsa

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// sigma0 is the base Gaussian parameter for the RCDT sampler (FIPS 206 §3.12).
const sigma0 = 1.8205

// rcdt72 represents a 72-bit unsigned integer as (hi uint8, lo uint64).
// The full value is: uint64(hi)<<64 | lo.
type rcdt72 struct {
	hi uint8
	lo uint64
}

// rcdtTable is the RCDT (Rejection Cumulative Distribution Table).
// Each entry i satisfies:
//
//	table[i] = floor(2^72 * Pr[|Z| >= i+1])
//
// where Z ~ D_{Z,σ₀} (discrete Gaussian with σ₀ = 1.8205).
//
// The RCDT algorithm samples u ~ Uniform[0, 2^72) and sets
//
//	|z| = #{i : u < table[i]}
//
// Values are computed as:
//
//	table[i] = floor(2^72 * Σ_{k=i+1}^{∞} 2·exp(-k²/(2σ₀²)) / Z)
//
// where Z = Σ_{k=-∞}^{∞} exp(-k²/(2σ₀²)) is the normalisation constant.
// Cross-checked: Σ_{k=0}^{17} (table[k]/2^72 - table[k+1]/2^72) · k² = σ₀² = 3.314220.
var rcdtTable = [18]rcdt72{
	{hi: 199, lo: 16610441552002023424},
	{hi: 103, lo: 7624082642567692288},
	{hi: 42, lo: 919243735747002368},
	{hi: 13, lo: 3484267233246674944},
	{hi: 3, lo: 2772878652510347264},
	{hi: 0, lo: 10479598105528201216},
	{hi: 0, lo: 1418221736465465344},
	{hi: 0, lo: 143439473028577328},
	{hi: 0, lo: 10810581864167812},
	{hi: 0, lo: 605874652027744},
	{hi: 0, lo: 25212870589170},
	{hi: 0, lo: 778215157694},
	{hi: 0, lo: 17802250993},
	{hi: 0, lo: 301647562},
	{hi: 0, lo: 3784361},
	{hi: 0, lo: 35141},
	{hi: 0, lo: 241},
	{hi: 0, lo: 1},
}

// lt64 returns 1 if a < b (unsigned 64-bit), 0 otherwise.
// Branchless: uses the carry-out formula from Hacker's Delight §2-12.
// The carry out of a - b equals 1 iff a < b (unsigned).
func lt64(a, b uint64) uint64 {
	return ((^a & b) | (^(a ^ b) & (a - b))) >> 63
}

// eq8 returns 1 if a == b (uint8), 0 otherwise. Branchless.
// Uses unsigned wrap-around: (x - 1) >> 63 is 1 iff x == 0.
func eq8(a, b uint8) uint64 {
	x := uint64(a) ^ uint64(b) // 0 iff a == b, non-zero otherwise
	return (x - 1) >> 63       // (0 - 1) wraps to ^0, bit 63 = 1; else 0
}

// sampleBaseGaussian samples from D_{Z, σ₀} using the RCDT table and returns
// a signed integer in [-(len(rcdtTable)), len(rcdtTable)].
//
// Constant-time properties:
//   - All 18 table comparisons always execute (no early exit).
//   - The sign application is branchless.
func sampleBaseGaussian(rng io.Reader) (int, error) {
	// Step 1: read 9 bytes (72 bits) from the CSPRNG.
	var buf [9]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return 0, fmt.Errorf("gaussian: CSPRNG read failed: %w", err)
	}

	// Interpret as little-endian 72-bit integer:
	//   lo = buf[0..7] (64 bits, little-endian)
	//   hi = buf[8]    (8 bits, the top byte)
	sampleLo := binary.LittleEndian.Uint64(buf[0:8])
	sampleHi := buf[8] // uint8

	// Step 2: count how many table entries the sample falls strictly below.
	// Constant-time 72-bit comparison:
	//   sample < table[i]  iff
	//   (sampleHi < tHi) || (sampleHi == tHi && sampleLo < tLo)
	z := 0
	for i := 0; i < len(rcdtTable); i++ {
		tHi := rcdtTable[i].hi
		tLo := rcdtTable[i].lo

		// hiLT: 1 iff sampleHi < tHi
		hiLT := lt64(uint64(sampleHi), uint64(tHi))
		// hiEQ: 1 iff sampleHi == tHi
		hiEQ := eq8(sampleHi, tHi)
		// loLT: 1 iff sampleLo < tLo
		loLT := lt64(sampleLo, tLo)

		// lt72: 1 iff sample < table[i]
		lt72 := hiLT | (hiEQ & loLT)
		z += int(lt72)
	}

	// Step 3: read 1 byte; use the lowest bit as the sign (constant-time negate).
	var signBuf [1]byte
	if _, err := io.ReadFull(rng, signBuf[:]); err != nil {
		return 0, fmt.Errorf("gaussian: CSPRNG read failed for sign: %w", err)
	}
	signBit := int(signBuf[0] & 1)
	// Branchless conditional negate: result = z if sign==0, -z if sign==1.
	// mask = 0 (all-zeros) if signBit==0; -1 (all-ones) if signBit==1.
	mask := -signBit
	result := (z ^ mask) - mask // = z XOR 0 - 0 = z, or z XOR -1 - (-1) = -z

	return result, nil
}

// SampleGaussian samples an integer from D_{Z,σ} centered at 0,
// implementing FIPS 206 §3.12 (Algorithm 13 scalar variant).
//
// rng must be a CSPRNG (e.g. crypto/rand.Reader or a SHAKE-256 stream keyed
// with the signing key). The RCDT inner loop is constant-time with respect
// to the sampled value.
//
// For σ == σ₀ the exponent in the rejection test is 0 (always accept).
// For σ > σ₀ the rejection step resamples from D_{Z,σ₀} until the candidate
// is accepted with probability exp(-z²·(σ²-σ₀²)/(2σ²σ₀²)).
func SampleGaussian(rng io.Reader, sigma float64) int {
	sigma2 := sigma * sigma
	sigma02 := sigma0 * sigma0

	// c = (σ² - σ₀²) / (2σ²σ₀²).
	// When σ == σ₀, c == 0 and exp(-z²·c) == 1 → always accept.
	c := (sigma2 - sigma02) / (2 * sigma2 * sigma02)

	for {
		z, err := sampleBaseGaussian(rng)
		if err != nil {
			panic(err)
		}

		// Rejection step: accept with probability exp(-fz² · c).
		fz := float64(z)
		logProb := -fz * fz * c // ≤ 0; exp(logProb) ∈ (0, 1]

		// Sample u uniformly in [0, 1) using 53 random bits (float64 mantissa).
		var ubuf [8]byte
		if _, err := io.ReadFull(rng, ubuf[:]); err != nil {
			panic(fmt.Errorf("gaussian: CSPRNG read for rejection: %w", err))
		}
		u53 := binary.LittleEndian.Uint64(ubuf[:]) >> 11       // 53-bit integer
		u := float64(u53) / float64(uint64(1)<<53)             // ∈ [0, 1)

		if u < math.Exp(logProb) {
			return z
		}
	}
}
