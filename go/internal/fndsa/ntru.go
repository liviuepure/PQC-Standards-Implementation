package fndsa

import (
	"errors"
	"io"
	"math"
	"math/big"
)

// ErrNTRUFailed is returned when NTRU key generation cannot find a valid key.
var ErrNTRUFailed = errors.New("fndsa: NTRU key generation failed")

// ntruSigma returns σ = 1.17 * sqrt(Q / (2N)).
func ntruSigma(n int) float64 {
	return 1.17 * math.Sqrt(float64(Q)/float64(2*n))
}

// NTRUKeyGen generates (f, g, F, G) for FN-DSA key generation.
// Implements FIPS 206 Algorithm 5 (NTRUGen).
// Output satisfies f*G - g*F = q over Z[x]/(x^n+1).
func NTRUKeyGen(p *Params, rng io.Reader) (f, g, F, G []int32, err error) {
	n := p.N
	sigma := ntruSigma(n)

	for attempt := 0; attempt < 1000; attempt++ {
		// Sample f and g from D_{Z,sigma}.
		fCoeffs := make([]int32, n)
		gCoeffs := make([]int32, n)
		for i := 0; i < n; i++ {
			fCoeffs[i] = int32(SampleGaussian(rng, sigma))
			gCoeffs[i] = int32(SampleGaussian(rng, sigma))
		}

		// f must be invertible mod 2.
		xorSum := 0
		for _, v := range fCoeffs {
			xorSum ^= int(v & 1)
		}
		if xorSum == 0 {
			continue
		}

		// f must be invertible mod q.
		fNTT := make([]int32, n)
		for i, v := range fCoeffs {
			fNTT[i] = ((v % Q) + Q) % Q
		}
		NTT(fNTT, n)
		ok := true
		for _, v := range fNTT {
			if v == 0 {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}

		// Gram-Schmidt norm bound.
		normSq := 0.0
		for _, v := range fCoeffs {
			normSq += float64(v) * float64(v)
		}
		for _, v := range gCoeffs {
			normSq += float64(v) * float64(v)
		}
		if normSq > 1.17*1.17*float64(Q)*float64(n) {
			continue
		}

		// Solve the NTRU equation.
		FCoeffs, GCoeffs, solveErr := ntruSolve(n, fCoeffs, gCoeffs)
		if solveErr != nil {
			continue
		}

		// Verify exactness.
		if !verifyNTRU(fCoeffs, gCoeffs, FCoeffs, GCoeffs, n) {
			continue
		}

		return fCoeffs, gCoeffs, FCoeffs, GCoeffs, nil
	}

	return nil, nil, nil, nil, ErrNTRUFailed
}

// verifyNTRU checks f*G - g*F = q exactly over Z[x]/(x^n+1).
func verifyNTRU(f, g, F, G []int32, n int) bool {
	fG := polyMulIntZ(f, G, n)
	gF := polyMulIntZ(g, F, n)
	if fG[0]-gF[0] != int64(Q) {
		return false
	}
	for i := 1; i < n; i++ {
		if fG[i]-gF[i] != 0 {
			return false
		}
	}
	return true
}

// NTRUPublicKey computes h = g * f^{-1} mod (q, x^n+1).
func NTRUPublicKey(f, g []int32, p *Params) []int32 {
	n := p.N

	fNTT := make([]int32, n)
	gNTT := make([]int32, n)
	for i := range f {
		fNTT[i] = ((f[i] % Q) + Q) % Q
		gNTT[i] = ((g[i] % Q) + Q) % Q
	}
	NTT(fNTT, n)
	NTT(gNTT, n)

	fInvNTT := make([]int32, n)
	for i, v := range fNTT {
		fInvNTT[i] = nttPow(int64(v), int64(Q-2))
	}

	hNTT := make([]int32, n)
	for i := range hNTT {
		hNTT[i] = int32(int64(gNTT[i]) * int64(fInvNTT[i]) % int64(Q))
	}
	INTT(hNTT, n)
	return hNTT
}

// PolyMulNTT multiplies two polynomials mod (q, x^n+1) using NTT.
func PolyMulNTT(a, b []int32, n int) []int32 {
	aNTT := make([]int32, n)
	bNTT := make([]int32, n)
	copy(aNTT, a)
	copy(bNTT, b)
	NTT(aNTT, n)
	NTT(bNTT, n)
	cNTT := make([]int32, n)
	for i := range cNTT {
		cNTT[i] = int32(int64(aNTT[i]) * int64(bNTT[i]) % int64(Q))
	}
	INTT(cNTT, n)
	return cNTT
}

// PolyAdd adds two polynomials mod q.
func PolyAdd(a, b []int32, n int) []int32 {
	c := make([]int32, n)
	for i := range c {
		c[i] = nttAddModQ(((a[i]%Q)+Q)%Q, ((b[i]%Q)+Q)%Q)
	}
	return c
}

// PolySub subtracts two polynomials mod q.
func PolySub(a, b []int32, n int) []int32 {
	c := make([]int32, n)
	for i := range c {
		ai := ((a[i] % Q) + Q) % Q
		bi := ((b[i] % Q) + Q) % Q
		c[i] = nttSubModQ(ai, bi)
	}
	return c
}

// polyMulIntZ multiplies two polynomials over Z[x]/(x^n+1) exactly.
func polyMulIntZ(a, b []int32, n int) []int64 {
	c := make([]int64, n)
	for i, ai := range a {
		for j, bj := range b {
			idx := i + j
			val := int64(ai) * int64(bj)
			if idx < n {
				c[idx] += val
			} else {
				c[idx-n] -= val
			}
		}
	}
	return c
}

// polySubIntZ subtracts two int64 slices.
func polySubIntZ(a, b []int64, n int) []int64 {
	c := make([]int64, n)
	for i := range c {
		c[i] = a[i] - b[i]
	}
	return c
}

// polyAdjoint computes the ring adjoint: f*(x) = f[0] - f[n-1]*x - ... - f[1]*x^{n-1}.
func polyAdjoint(f []int32, n int) []int32 {
	adj := make([]int32, n)
	adj[0] = f[0]
	for i := 1; i < n; i++ {
		adj[i] = -f[n-i]
	}
	return adj
}

// ---- NTRU Solver ----

// ntruSolve solves f*G - g*F = q over Z[x]/(x^n+1).
// Uses exact big.Int arithmetic for the field norm recursion and lift,
// and float64/big.Float FFT for the Babai reduction depending on coefficient size.
func ntruSolve(n int, f, g []int32) (F, G []int32, err error) {
	fBig := int32ToBig(f)
	gBig := int32ToBig(g)

	FBig, GBig, solveErr := ntruSolveBig(n, fBig, gBig)
	if solveErr != nil {
		return nil, nil, solveErr
	}

	// Convert big.Int coefficients to int32.
	// After Babai reduction, the coefficients should be small enough to fit.
	Fout := make([]int32, n)
	Gout := make([]int32, n)
	for i := 0; i < n; i++ {
		v := FBig[i].Int64()
		if v > math.MaxInt32 || v < math.MinInt32 {
			return nil, nil, errors.New("fndsa: F coefficient out of int32 range after reduction")
		}
		Fout[i] = int32(v)
		v = GBig[i].Int64()
		if v > math.MaxInt32 || v < math.MinInt32 {
			return nil, nil, errors.New("fndsa: G coefficient out of int32 range after reduction")
		}
		Gout[i] = int32(v)
	}
	return Fout, Gout, nil
}

// ntruSolveBig solves the NTRU equation recursively using exact big.Int arithmetic.
// Algorithm follows FALCON spec §3.8 and Pornin & Prest (2019),
// "Simple, Fast, Constant-Time Gaussian Sampling over the Integers"
// (https://eprint.iacr.org/2019/015).
// At each level, the Babai reduction uses the current level's f,g polynomials (fBig, gBig).
// For levels where the coefficients fit in float64 (≤ 53 bits), float64 FFT is used.
// For deeper levels with large coefficients, big.Float FFT is used.
func ntruSolveBig(n int, fBig, gBig []*big.Int) (F, G []*big.Int, err error) {
	if n == 1 {
		// Base case: solve f[0]*G[0] - g[0]*F[0] = Q over Z.
		fVal := fBig[0]
		gVal := gBig[0]

		gcdVal := new(big.Int)
		uBig := new(big.Int)
		vBig := new(big.Int)
		gcdVal.GCD(uBig, vBig, new(big.Int).Set(fVal), new(big.Int).Set(gVal))

		qBig := big.NewInt(Q)
		rem := new(big.Int).Mod(new(big.Int).Set(qBig), new(big.Int).Abs(gcdVal))
		if rem.Sign() != 0 {
			return nil, nil, errors.New("fndsa: gcd does not divide q at base case")
		}

		scale := new(big.Int).Div(qBig, gcdVal)
		GVal := new(big.Int).Mul(uBig, scale)
		FVal := new(big.Int).Neg(new(big.Int).Mul(vBig, scale))

		return []*big.Int{FVal}, []*big.Int{GVal}, nil
	}

	// Compute field norms (exact big.Int arithmetic).
	fNorm := fieldNormBig(fBig, n)
	gNorm := fieldNormBig(gBig, n)

	// Recursively solve for the half-degree problem.
	Fp, Gp, err := ntruSolveBig(n/2, fNorm, gNorm)
	if err != nil {
		return nil, nil, err
	}

	// Lift from degree n/2 to degree n.
	FLifted, GLifted := liftBig(Fp, Gp, fBig, gBig, n)

	// Determine maximum coefficient bit length of current level's f,g
	// to decide whether float64 or big.Float Babai is needed.
	maxBits := 0
	for _, v := range fBig {
		if b := v.BitLen(); b > maxBits {
			maxBits = b
		}
	}
	for _, v := range gBig {
		if b := v.BitLen(); b > maxBits {
			maxBits = b
		}
	}

	// Babai reduction using the current level's f,g.
	// Run 2 rounds to ensure thorough reduction.
	for round := 0; round < 2; round++ {
		// Determine the maximum bit length across f, g, F, and G.
		// ALL of these contribute to the precision required for the Babai FFT.
		maxFGBits := maxBits // max bits in f,g
		for _, v := range FLifted {
			if b := v.BitLen(); b > maxFGBits {
				maxFGBits = b
			}
		}
		for _, v := range GLifted {
			if b := v.BitLen(); b > maxFGBits {
				maxFGBits = b
			}
		}

		var k []*big.Int
		if maxFGBits <= 53 {
			// All values fit in float64: use fast float64 FFT Babai.
			fSmall := make([]float64, n)
			gSmall := make([]float64, n)
			for i, v := range fBig {
				f64, _ := new(big.Float).SetInt(v).Float64()
				fSmall[i] = f64
			}
			for i, v := range gBig {
				f64, _ := new(big.Float).SetInt(v).Float64()
				gSmall[i] = f64
			}
			k = babaiFloat64BigF(FLifted, GLifted, fSmall, gSmall, n)
		} else {
			// float64 is insufficient here: intermediate F, G coefficients grow to
			// ~4000 bits during the recursive field-norm computation. At n=1024 the
			// recursion has ~10 levels; each level roughly doubles the coefficient
			// magnitude (the field norm squares the input polynomial), so top-level
			// coefficients far exceed float64's 53-bit mantissa. Using float64 at
			// this stage would lose all precision and produce +Inf, yielding an
			// incorrect (or non-terminating) Babai reduction. big.Float with
			// precision proportional to the actual bit length is required.
			prec := uint(maxFGBits*2 + fftLogN(n)*64 + 256)
			k = babaiBigFloat(FLifted, GLifted, fBig, gBig, n, prec)
		}
		kf := polyMulIntZBig(k, fBig, n)
		kg := polyMulIntZBig(k, gBig, n)
		for i := 0; i < n; i++ {
			FLifted[i].Sub(FLifted[i], kf[i])
			GLifted[i].Sub(GLifted[i], kg[i])
		}
	}

	return FLifted, GLifted, nil
}

// babaiFloat64BigF computes the Babai rounding k using float64 FFT.
// f and g are float64 slices (coefficients must fit in float64 without loss).
// F and G are the big.Int polynomials to reduce (their float64 representation is used for FFT).
func babaiFloat64BigF(F, G []*big.Int, f, g []float64, n int) []*big.Int {
	toComplex := func(a []*big.Int) []complex128 {
		c := make([]complex128, n)
		for i, v := range a {
			f64, _ := new(big.Float).SetInt(v).Float64()
			c[i] = complex(f64, 0)
		}
		return c
	}
	fC := make([]complex128, n)
	gC := make([]complex128, n)
	for i := range f {
		fC[i] = complex(f[i], 0)
		gC[i] = complex(g[i], 0)
	}
	FC := toComplex(F)
	GC := toComplex(G)

	FFT(fC, n)
	FFT(gC, n)
	FFT(FC, n)
	FFT(GC, n)

	kC := make([]complex128, n)
	for i := 0; i < n; i++ {
		fi := fC[i]
		gi := gC[i]
		Fi := FC[i]
		Gi := GC[i]
		fiConj := complex(real(fi), -imag(fi))
		giConj := complex(real(gi), -imag(gi))
		num := Fi*fiConj + Gi*giConj
		denom := fi*fiConj + gi*giConj
		if real(denom) != 0 {
			kC[i] = num / denom
		}
	}

	IFFT(kC, n)

	k := make([]*big.Int, n)
	for i, v := range kC {
		k[i] = big.NewInt(int64(math.Round(real(v))))
	}
	return k
}


// bigFloatPi computes π to precision prec using Machin's formula:
// π = 4 * (4*arctan(1/5) - arctan(1/239))
// arctan(1/x) = 1/x - 1/(3x³) + 1/(5x⁵) - ...
func bigFloatPi(prec uint) *big.Float {
	one := new(big.Float).SetPrec(prec).SetInt64(1)
	four := new(big.Float).SetPrec(prec).SetInt64(4)

	arctanRecip := func(x int64) *big.Float {
		// Compute arctan(1/x) using Taylor series
		xBig := new(big.Float).SetPrec(prec).SetInt64(x)
		x2 := new(big.Float).SetPrec(prec).Mul(xBig, xBig)
		term := new(big.Float).SetPrec(prec).Quo(one, xBig) // 1/x
		sum := new(big.Float).SetPrec(prec).Set(term)
		sign := int64(-1)
		for k := int64(3); ; k += 2 {
			term.Quo(term, x2) // term /= x²
			kBig := new(big.Float).SetPrec(prec).SetInt64(k)
			addend := new(big.Float).SetPrec(prec).Quo(term, kBig)
			if sign < 0 {
				addend.Neg(addend)
			}
			sign = -sign
			sum.Add(sum, addend)
			// Check convergence: |addend| < 2^(-prec)
			exp := addend.MantExp(nil)
			if exp < -int(prec) {
				break
			}
		}
		return sum
	}

	// π/4 = 4*arctan(1/5) - arctan(1/239)
	a5 := arctanRecip(5)
	a239 := arctanRecip(239)
	piOver4 := new(big.Float).SetPrec(prec).Sub(
		new(big.Float).SetPrec(prec).Mul(four, a5),
		a239,
	)
	return new(big.Float).SetPrec(prec).Mul(four, piOver4)
}

// bigFloatCosSin computes cos(π*num/den) and sin(π*num/den) to precision prec.
// Uses Taylor series for sin and cos with argument reduction.
func bigFloatCosSin(num, den int, prec uint) (cosVal, sinVal *big.Float) {
	// Compute the angle: x = π * num / den
	pi := bigFloatPi(prec)
	x := new(big.Float).SetPrec(prec).SetInt64(int64(num))
	x.Mul(x, pi)
	x.Quo(x, new(big.Float).SetPrec(prec).SetInt64(int64(den)))

	// Taylor series: sin(x) = x - x³/3! + x⁵/5! - ...
	//                cos(x) = 1 - x²/2! + x⁴/4! - ...
	// These converge well for |x| <= π/2

	one := new(big.Float).SetPrec(prec).SetInt64(1)
	x2 := new(big.Float).SetPrec(prec).Mul(x, x)

	sinSum := new(big.Float).SetPrec(prec).Set(x) // x
	cosSum := new(big.Float).SetPrec(prec).Set(one) // 1

	sinTerm := new(big.Float).SetPrec(prec).Set(x) // current term for sin
	cosTerm := new(big.Float).SetPrec(prec).Set(one) // current term for cos

	for k := int64(1); ; k++ {
		// Update terms: sinTerm_{k} = sinTerm_{k-1} * (-x²) / ((2k)(2k+1))
		//               cosTerm_{k} = cosTerm_{k-1} * (-x²) / ((2k-1)(2k))
		denom2k := new(big.Float).SetPrec(prec).SetInt64(2 * k)
		denom2kp1 := new(big.Float).SetPrec(prec).SetInt64(2*k + 1)
		denom2km1 := new(big.Float).SetPrec(prec).SetInt64(2*k - 1)

		// sinTerm *= -x² / (2k * (2k+1))
		sinTerm.Mul(sinTerm, x2)
		sinTerm.Quo(sinTerm, new(big.Float).SetPrec(prec).Mul(denom2k, denom2kp1))
		sinTerm.Neg(sinTerm)

		// cosTerm *= -x² / ((2k-1) * 2k)
		cosTerm.Mul(cosTerm, x2)
		cosTerm.Quo(cosTerm, new(big.Float).SetPrec(prec).Mul(denom2km1, denom2k))
		cosTerm.Neg(cosTerm)

		sinSum.Add(sinSum, sinTerm)
		cosSum.Add(cosSum, cosTerm)

		// Check convergence
		exp := sinTerm.MantExp(nil)
		if exp < -int(prec) {
			break
		}
	}

	return cosSum, sinSum
}

// babaiBigFloat computes the Babai rounding using big.Float FFT with high-precision trig.
func babaiBigFloat(F, G, f, g []*big.Int, n int, prec uint) []*big.Int {
	logn := fftLogN(n)

	type cplx struct{ re, im *big.Float }
	zero := func() cplx {
		return cplx{new(big.Float).SetPrec(prec), new(big.Float).SetPrec(prec)}
	}
	setInt := func(v *big.Int) cplx {
		return cplx{
			new(big.Float).SetPrec(prec).SetInt(v),
			new(big.Float).SetPrec(prec),
		}
	}
	add := func(a, b cplx) cplx {
		return cplx{
			new(big.Float).SetPrec(prec).Add(a.re, b.re),
			new(big.Float).SetPrec(prec).Add(a.im, b.im),
		}
	}
	sub := func(a, b cplx) cplx {
		return cplx{
			new(big.Float).SetPrec(prec).Sub(a.re, b.re),
			new(big.Float).SetPrec(prec).Sub(a.im, b.im),
		}
	}
	mul := func(a, b cplx) cplx {
		return cplx{
			new(big.Float).SetPrec(prec).Sub(
				new(big.Float).SetPrec(prec).Mul(a.re, b.re),
				new(big.Float).SetPrec(prec).Mul(a.im, b.im),
			),
			new(big.Float).SetPrec(prec).Add(
				new(big.Float).SetPrec(prec).Mul(a.re, b.im),
				new(big.Float).SetPrec(prec).Mul(a.im, b.re),
			),
		}
	}
	twiddle := func(brk, n int, inv bool) cplx {
		// Compute exp(i*π*brk/n) exactly with big.Float precision
		cosVal, sinVal := bigFloatCosSin(brk, n, prec)
		if inv {
			sinVal.Neg(sinVal)
		}
		return cplx{cosVal, sinVal}
	}

	doFFT := func(arr []cplx) {
		k := 0
		for length := n >> 1; length >= 1; length >>= 1 {
			for start := 0; start < n; start += 2 * length {
				k++
				brk := fftBitRev(k, logn)
				w := twiddle(brk, n, false)
				for j := start; j < start+length; j++ {
					t := mul(w, arr[j+length])
					arr[j+length] = sub(arr[j], t)
					arr[j] = add(arr[j], t)
				}
			}
		}
	}
	doIFFT := func(arr []cplx) {
		k := n
		for length := 1; length < n; length <<= 1 {
			for start := n - 2*length; start >= 0; start -= 2 * length {
				k--
				brk := fftBitRev(k, logn)
				wInv := twiddle(brk, n, true)
				for j := start; j < start+length; j++ {
					a := arr[j]
					b := arr[j+length]
					arr[j] = add(a, b)
					arr[j+length] = mul(wInv, sub(a, b))
				}
			}
		}
		invN := new(big.Float).SetPrec(prec).SetFloat64(1.0 / float64(n))
		for i := range arr {
			arr[i].re.Mul(arr[i].re, invN)
			arr[i].im.Mul(arr[i].im, invN)
		}
	}

	FA := make([]cplx, n)
	GA := make([]cplx, n)
	fA := make([]cplx, n)
	gA := make([]cplx, n)
	for i := 0; i < n; i++ {
		FA[i] = setInt(F[i])
		GA[i] = setInt(G[i])
		fA[i] = setInt(f[i])
		gA[i] = setInt(g[i])
	}
	doFFT(FA)
	doFFT(GA)
	doFFT(fA)
	doFFT(gA)

	kA := make([]cplx, n)
	for i := 0; i < n; i++ {
		fConj := cplx{fA[i].re, new(big.Float).SetPrec(prec).Neg(fA[i].im)}
		gConj := cplx{gA[i].re, new(big.Float).SetPrec(prec).Neg(gA[i].im)}
		num := add(mul(FA[i], fConj), mul(GA[i], gConj))
		fMag2 := new(big.Float).SetPrec(prec).Add(
			new(big.Float).SetPrec(prec).Mul(fA[i].re, fA[i].re),
			new(big.Float).SetPrec(prec).Mul(fA[i].im, fA[i].im),
		)
		gMag2 := new(big.Float).SetPrec(prec).Add(
			new(big.Float).SetPrec(prec).Mul(gA[i].re, gA[i].re),
			new(big.Float).SetPrec(prec).Mul(gA[i].im, gA[i].im),
		)
		denom := new(big.Float).SetPrec(prec).Add(fMag2, gMag2)
		if denom.Sign() != 0 {
			kA[i] = cplx{
				new(big.Float).SetPrec(prec).Quo(num.re, denom),
				new(big.Float).SetPrec(prec).Quo(num.im, denom),
			}
		} else {
			kA[i] = zero()
		}
	}

	doIFFT(kA)

	result := make([]*big.Int, n)
	half := new(big.Float).SetPrec(prec).SetFloat64(0.5)
	for i, v := range kA {
		val := v.re
		var rounded *big.Int
		if val.Sign() >= 0 {
			rounded, _ = new(big.Float).SetPrec(prec).Add(val, half).Int(nil)
		} else {
			tmp := new(big.Float).SetPrec(prec).Sub(val, half)
			tmp.Neg(tmp)
			rounded, _ = tmp.Int(nil)
			rounded.Neg(rounded)
		}
		result[i] = rounded
	}
	return result
}

// ---- Big.Int polynomial helpers ----

// polyMulIntZBig multiplies two polynomials over Z[x]/(x^n+1) using big.Int.
func polyMulIntZBig(a, b []*big.Int, n int) []*big.Int {
	c := make([]*big.Int, n)
	for i := range c {
		c[i] = new(big.Int)
	}
	tmp := new(big.Int)
	for i, ai := range a {
		for j, bj := range b {
			idx := i + j
			tmp.Mul(ai, bj)
			if idx < n {
				c[idx].Add(c[idx], tmp)
			} else {
				c[idx-n].Sub(c[idx-n], tmp)
			}
		}
	}
	return c
}

// fieldNormBig computes the field norm of f from Z[x]/(x^n+1) to Z[x]/(x^{n/2}+1).
// N(f)(y) = f_0(y)^2 - y*f_1(y)^2 where f(x) = f_0(x^2) + x*f_1(x^2).
func fieldNormBig(f []*big.Int, n int) []*big.Int {
	h := n / 2
	f0 := make([]*big.Int, h)
	f1 := make([]*big.Int, h)
	for i := 0; i < h; i++ {
		f0[i] = new(big.Int).Set(f[2*i])
		f1[i] = new(big.Int).Set(f[2*i+1])
	}
	f0sq := polyMulIntZBig(f0, f0, h)
	f1sq := polyMulIntZBig(f1, f1, h)

	// N(f)[0] = f0sq[0] + f1sq[h-1]  (wrap: y * f1sq has -f1sq[h-1] at 0, so -(-f1sq[h-1]) = +f1sq[h-1])
	// N(f)[i] = f0sq[i] - f1sq[i-1]  for i ≥ 1
	result := make([]*big.Int, h)
	result[0] = new(big.Int).Add(f0sq[0], f1sq[h-1])
	for i := 1; i < h; i++ {
		result[i] = new(big.Int).Sub(f0sq[i], f1sq[i-1])
	}
	return result
}

// towerConjugateBig computes f*(x) = f_0(x^2) - x*f_1(x^2) by negating odd coefficients.
func towerConjugateBig(f []*big.Int) []*big.Int {
	n := len(f)
	result := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			result[i] = new(big.Int).Set(f[i])
		} else {
			result[i] = new(big.Int).Neg(f[i])
		}
	}
	return result
}

// liftBig lifts (F', G') from degree n/2 to degree n.
// G = f*(x) * G'(x^2), F = g*(x) * F'(x^2) in Z[x]/(x^n+1).
func liftBig(Fp, Gp []*big.Int, f, g []*big.Int, n int) ([]*big.Int, []*big.Int) {
	h := n / 2
	FpLift := make([]*big.Int, n)
	GpLift := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		FpLift[i] = new(big.Int)
		GpLift[i] = new(big.Int)
	}
	for i := 0; i < h; i++ {
		FpLift[2*i].Set(Fp[i])
		GpLift[2*i].Set(Gp[i])
	}
	fConj := towerConjugateBig(f)
	gConj := towerConjugateBig(g)
	F := polyMulIntZBig(gConj, FpLift, n)
	G := polyMulIntZBig(fConj, GpLift, n)
	return F, G
}

// int32ToBig converts []int32 to []*big.Int.
func int32ToBig(a []int32) []*big.Int {
	res := make([]*big.Int, len(a))
	for i, v := range a {
		res[i] = big.NewInt(int64(v))
	}
	return res
}

