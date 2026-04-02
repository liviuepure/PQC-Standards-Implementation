<?php

declare(strict_types=1);

namespace PQC\FnDsa;

use PQC\MlKem\HashFuncs;

/**
 * FN-DSA signing (FIPS 206).
 *
 * Implements HashToPoint and the Babai nearest-plane signing pipeline.
 */
final class Sign
{
    private const Q = 12289;

    /**
     * Hash msg (salt||message) to a polynomial c in Z_q[x]/(x^n+1).
     * Uses SHAKE-256, rejection-sampling 16-bit values mod Q.
     *
     * @param string $msg Input bytes (typically salt || message).
     * @param Params $p Parameter set.
     * @return int[] Polynomial coefficients in [0, Q).
     */
    public static function hashToPoint(string $msg, Params $p): array
    {
        $n = $p->n;
        $out = [];
        // We need to produce n values; rejection sampling wastes some, over-request.
        $needed = $n;
        $bufSize = $needed * 4; // generous
        $hashOut = HashFuncs::shake256($msg, $bufSize);
        $count = 0;
        $pos = 0;
        while ($count < $n) {
            if ($pos + 2 > strlen($hashOut)) {
                // Need more bytes, extend.
                $bufSize *= 2;
                $hashOut = HashFuncs::shake256($msg, $bufSize);
                // Continue from start -- SHAKE is deterministic.
                // Actually we need to be streaming. Let's buffer enough up front.
            }
            $v = ord($hashOut[$pos]) | (ord($hashOut[$pos + 1]) << 8);
            $pos += 2;
            if ($v < 5 * self::Q) {
                $out[$count] = $v % self::Q;
                $count++;
            }
        }
        return $out;
    }

    /**
     * Center v mod Q into (-Q/2, Q/2].
     */
    public static function centerModQ(int $v): int
    {
        $v = (($v % self::Q) + self::Q) % self::Q;
        if ($v > (int)(self::Q / 2)) {
            $v -= self::Q;
        }
        return $v;
    }

    /**
     * Recover G from (f, g, F) via the NTRU equation fG - gF = Q.
     *
     * @return int[]|null G coefficients or null if f is not invertible.
     */
    public static function recoverG(array $f, array $g, array $F, int $n): ?array
    {
        $gModQ = [];
        $FModQ = [];
        for ($i = 0; $i < $n; $i++) {
            $gModQ[$i] = (($g[$i] % self::Q) + self::Q) % self::Q;
            $FModQ[$i] = (($F[$i] % self::Q) + self::Q) % self::Q;
        }
        $gF = NTT::polyMulNtt($gModQ, $FModQ, $n);

        // Compute f^{-1} mod q via NTT.
        $fModQ = [];
        for ($i = 0; $i < $n; $i++) {
            $fModQ[$i] = (($f[$i] % self::Q) + self::Q) % self::Q;
        }
        $fNtt = $fModQ;
        NTT::ntt($fNtt, $n);
        for ($i = 0; $i < $n; $i++) {
            if ($fNtt[$i] === 0) return null;
        }
        $fInvNtt = [];
        for ($i = 0; $i < $n; $i++) {
            $fInvNtt[$i] = NTT::powModQ($fNtt[$i], self::Q - 2);
        }
        NTT::intt($fInvNtt, $n);

        $G = NTT::polyMulNtt($gF, $fInvNtt, $n);

        $result = [];
        for ($i = 0; $i < $n; $i++) {
            $v = $G[$i];
            if ($v > (int)(self::Q / 2)) {
                $v -= self::Q;
            }
            $result[$i] = $v;
        }
        return $result;
    }

    /**
     * Babai nearest-plane signing.
     *
     * @param int[] $c Target polynomial (centered).
     * @param int[] $f, $g, $F, $G NTRU basis.
     * @param int $n Polynomial degree.
     * @return array [s1, s2] signed coefficient arrays.
     */
    public static function ffSamplingBabai(array $c, array $f, array $g, array $F, array $G, int $n): array
    {
        $cFFT = self::int32sToFFT($c, $n);
        $fFFT = self::int32sToFFT($f, $n);
        $gFFT = self::int32sToFFT($g, $n);
        $FFFT = self::int32sToFFT($F, $n);
        $GFFT = self::int32sToFFT($G, $n);

        // Gram-Schmidt: compute b1* and ||b1*||^2.
        $b1StarFFT = [];
        $b1StarNormSqFFT = [];
        for ($j = 0; $j < $n; $j++) {
            $gj = $gFFT[$j]; $fj = $fFFT[$j];
            $Gj = $GFFT[$j]; $Fj = $FFFT[$j];
            $b0NormSq = $gj[0] * $gj[0] + $gj[1] * $gj[1] + $fj[0] * $fj[0] + $fj[1] * $fj[1];

            $mu10Re = 0.0; $mu10Im = 0.0;
            if ($b0NormSq != 0.0) {
                // num = G*conj(g) + F*conj(f)
                $numRe = $Gj[0] * $gj[0] + $Gj[1] * $gj[1] + $Fj[0] * $fj[0] + $Fj[1] * $fj[1];
                $numIm = $Gj[1] * $gj[0] - $Gj[0] * $gj[1] + $Fj[1] * $fj[0] - $Fj[0] * $fj[1];
                $mu10Re = $numRe / $b0NormSq;
                $mu10Im = $numIm / $b0NormSq;
            }
            // b1* = (G - mu10*g, -F + mu10*f)
            $b1s0Re = $Gj[0] - ($mu10Re * $gj[0] - $mu10Im * $gj[1]);
            $b1s0Im = $Gj[1] - ($mu10Re * $gj[1] + $mu10Im * $gj[0]);
            $b1s1Re = -$Fj[0] + ($mu10Re * $fj[0] - $mu10Im * $fj[1]);
            $b1s1Im = -$Fj[1] + ($mu10Re * $fj[1] + $mu10Im * $fj[0]);

            $b1StarFFT[$j] = [[$b1s0Re, $b1s0Im], [$b1s1Re, $b1s1Im]];
            $b1StarNormSqFFT[$j] = $b1s0Re * $b1s0Re + $b1s0Im * $b1s0Im +
                                    $b1s1Re * $b1s1Re + $b1s1Im * $b1s1Im;
        }

        // Step 1: project (c, 0) along b1*.
        $tau1FFT = [];
        for ($j = 0; $j < $n; $j++) {
            $b1sNorm = $b1StarNormSqFFT[$j];
            if ($b1sNorm != 0.0) {
                $b1s0 = $b1StarFFT[$j][0];
                // num = c * conj(b1*[0])
                $numRe = $cFFT[$j][0] * $b1s0[0] + $cFFT[$j][1] * $b1s0[1];
                $numIm = $cFFT[$j][1] * $b1s0[0] - $cFFT[$j][0] * $b1s0[1];
                $tau1FFT[$j] = [$numRe / $b1sNorm, $numIm / $b1sNorm];
            } else {
                $tau1FFT[$j] = [0.0, 0.0];
            }
        }
        $z1 = self::roundFFTToInt32s($tau1FFT, $n);
        $z1FFT = self::int32sToFFT($z1, $n);

        // Update target.
        $cPrimeFFT = [];
        $xPrimeFFT = [];
        for ($j = 0; $j < $n; $j++) {
            $cPrimeFFT[$j] = [
                $cFFT[$j][0] - ($z1FFT[$j][0] * $GFFT[$j][0] - $z1FFT[$j][1] * $GFFT[$j][1]),
                $cFFT[$j][1] - ($z1FFT[$j][0] * $GFFT[$j][1] + $z1FFT[$j][1] * $GFFT[$j][0]),
            ];
            $xPrimeFFT[$j] = [
                $z1FFT[$j][0] * $FFFT[$j][0] - $z1FFT[$j][1] * $FFFT[$j][1],
                $z1FFT[$j][0] * $FFFT[$j][1] + $z1FFT[$j][1] * $FFFT[$j][0],
            ];
        }

        // Step 2: project t' along b0* = (g, -f).
        $tau0FFT = [];
        for ($j = 0; $j < $n; $j++) {
            $gj = $gFFT[$j]; $fj = $fFFT[$j];
            $b0NormSq = $gj[0] * $gj[0] + $gj[1] * $gj[1] + $fj[0] * $fj[0] + $fj[1] * $fj[1];
            if ($b0NormSq != 0.0) {
                // num = c'*conj(g) - x'*conj(f)
                $numRe = $cPrimeFFT[$j][0] * $gj[0] + $cPrimeFFT[$j][1] * $gj[1]
                        - $xPrimeFFT[$j][0] * $fj[0] - $xPrimeFFT[$j][1] * $fj[1];
                $numIm = $cPrimeFFT[$j][1] * $gj[0] - $cPrimeFFT[$j][0] * $gj[1]
                        - $xPrimeFFT[$j][1] * $fj[0] + $xPrimeFFT[$j][0] * $fj[1];
                $tau0FFT[$j] = [$numRe / $b0NormSq, $numIm / $b0NormSq];
            } else {
                $tau0FFT[$j] = [0.0, 0.0];
            }
        }
        $z0 = self::roundFFTToInt32s($tau0FFT, $n);
        $z0FFT = self::int32sToFFT($z0, $n);

        // Compute s1 = z0*f + z1*F, s2 = c - z0*g - z1*G.
        $s1FFT = [];
        $s2FFT = [];
        for ($j = 0; $j < $n; $j++) {
            $s1FFT[$j] = [
                $z0FFT[$j][0] * $fFFT[$j][0] - $z0FFT[$j][1] * $fFFT[$j][1]
                + $z1FFT[$j][0] * $FFFT[$j][0] - $z1FFT[$j][1] * $FFFT[$j][1],
                $z0FFT[$j][0] * $fFFT[$j][1] + $z0FFT[$j][1] * $fFFT[$j][0]
                + $z1FFT[$j][0] * $FFFT[$j][1] + $z1FFT[$j][1] * $FFFT[$j][0],
            ];
            $s2FFT[$j] = [
                $cFFT[$j][0]
                - ($z0FFT[$j][0] * $gFFT[$j][0] - $z0FFT[$j][1] * $gFFT[$j][1])
                - ($z1FFT[$j][0] * $GFFT[$j][0] - $z1FFT[$j][1] * $GFFT[$j][1]),
                $cFFT[$j][1]
                - ($z0FFT[$j][0] * $gFFT[$j][1] + $z0FFT[$j][1] * $gFFT[$j][0])
                - ($z1FFT[$j][0] * $GFFT[$j][1] + $z1FFT[$j][1] * $GFFT[$j][0]),
            ];
        }

        $s1Raw = self::roundFFTToInt32s($s1FFT, $n);
        $s2Raw = self::roundFFTToInt32s($s2FFT, $n);

        $s1 = [];
        $s2 = [];
        for ($i = 0; $i < $n; $i++) {
            $s1[$i] = self::centerModQ($s1Raw[$i]);
            $s2[$i] = self::centerModQ($s2Raw[$i]);
        }
        return [$s1, $s2];
    }

    /**
     * Compute squared Euclidean norm of (s1, s2).
     */
    public static function normSq(array $s1, array $s2): int
    {
        $n = 0;
        foreach ($s1 as $v) {
            $n += $v * $v;
        }
        foreach ($s2 as $v) {
            $n += $v * $v;
        }
        return $n;
    }

    /**
     * Sign a message with the secret key.
     *
     * @param string $sk Encoded secret key.
     * @param string $msg Message bytes.
     * @param Params $p Parameter set.
     * @return string|null Encoded signature, or null on failure.
     */
    public static function signInternal(string $sk, string $msg, Params $p): ?string
    {
        $decoded = Encode::decodeSk($sk, $p);
        if ($decoded === null) {
            return null;
        }
        [$f, $g, $F] = $decoded;
        $n = $p->n;

        $G = self::recoverG($f, $g, $F, $n);
        if ($G === null) {
            return null;
        }

        // Compute h for verification check.
        $h = NTRUKeygen::publicKey($f, $g, $p);

        $maxAttempts = 1000;
        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            $salt = random_bytes(40);

            $hashInput = $salt . $msg;
            $c = self::hashToPoint($hashInput, $p);

            $cCentered = [];
            for ($i = 0; $i < $n; $i++) {
                $cCentered[$i] = self::centerModQ($c[$i]);
            }

            [$s1, $s2] = self::ffSamplingBabai($cCentered, $f, $g, $F, $G, $n);

            // Verify s1*h + s2 = c (mod q).
            $s1ModQ = [];
            for ($i = 0; $i < $n; $i++) {
                $s1ModQ[$i] = (($s1[$i] % self::Q) + self::Q) % self::Q;
            }
            $s1h = NTT::polyMulNtt($s1ModQ, $h, $n);
            $valid = true;
            for ($i = 0; $i < $n; $i++) {
                $sum = (($s1h[$i] + $s2[$i]) % self::Q + self::Q) % self::Q;
                if ($sum !== $c[$i]) {
                    $valid = false;
                    break;
                }
            }
            if (!$valid) {
                continue;
            }

            // Check norm bound.
            $ns = self::normSq($s1, $s2);
            if ($ns > $p->betaSq) {
                continue;
            }

            $sig = Encode::encodeSig($salt, $s1, $p);
            if ($sig === null) {
                continue;
            }
            return $sig;
        }

        return null;
    }

    /**
     * Convert int array to FFT domain.
     *
     * @return array Array of [re, im] pairs.
     */
    private static function int32sToFFT(array $a, int $n): array
    {
        $f = [];
        for ($i = 0; $i < $n; $i++) {
            $f[$i] = [(float)$a[$i], 0.0];
        }
        FFT::fft($f, $n);
        return $f;
    }

    /**
     * Apply IFFT and round to nearest integers.
     */
    private static function roundFFTToInt32s(array $fft, int $n): array
    {
        $tmp = $fft;
        FFT::ifft($tmp, $n);
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[$i] = (int)round($tmp[$i][0]);
        }
        return $out;
    }
}
