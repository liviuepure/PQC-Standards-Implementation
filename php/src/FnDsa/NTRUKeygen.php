<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * NTRU key generation for FN-DSA (FIPS 206).
 */
final class NTRUKeygen
{
    private const Q = 12289;

    public static function keygen(Params $p, callable $rng): ?array
    {
        $n = $p->n;
        $sigma = 1.17 * sqrt(self::Q / (2.0 * $n));

        for ($attempt = 0; $attempt < 1000; $attempt++) {
            $f = []; $g = [];
            for ($i = 0; $i < $n; $i++) {
                $f[$i] = Gaussian::sampleGaussian($rng, $sigma);
                $g[$i] = Gaussian::sampleGaussian($rng, $sigma);
            }

            $xorSum = 0;
            for ($i = 0; $i < $n; $i++) $xorSum ^= ($f[$i] & 1);
            if ($xorSum === 0) continue;

            $fNtt = [];
            for ($i = 0; $i < $n; $i++) $fNtt[$i] = (($f[$i] % self::Q) + self::Q) % self::Q;
            NTT::ntt($fNtt, $n);
            $ok = true;
            for ($i = 0; $i < $n; $i++) { if ($fNtt[$i] === 0) { $ok = false; break; } }
            if (!$ok) continue;

            $normSq = 0.0;
            for ($i = 0; $i < $n; $i++) {
                $normSq += (float)$f[$i] * (float)$f[$i];
                $normSq += (float)$g[$i] * (float)$g[$i];
            }
            if ($normSq > 1.17 * 1.17 * self::Q * $n) continue;

            $result = self::ntruSolve($n, $f, $g);
            if ($result === null) continue;
            [$F, $G] = $result;

            $fitsInt8 = true;
            foreach ($F as $v) { if ($v < -128 || $v > 127) { $fitsInt8 = false; break; } }
            if (!$fitsInt8) continue;

            if (!self::verifyNTRU($f, $g, $F, $G, $n)) continue;

            return [$f, $g, $F, $G];
        }
        return null;
    }

    public static function publicKey(array $f, array $g, Params $p): array
    {
        $n = $p->n;
        $fNtt = []; $gNtt = [];
        for ($i = 0; $i < $n; $i++) {
            $fNtt[$i] = (($f[$i] % self::Q) + self::Q) % self::Q;
            $gNtt[$i] = (($g[$i] % self::Q) + self::Q) % self::Q;
        }
        NTT::ntt($fNtt, $n); NTT::ntt($gNtt, $n);
        $fInvNtt = [];
        for ($i = 0; $i < $n; $i++) $fInvNtt[$i] = NTT::powModQ($fNtt[$i], self::Q - 2);
        $hNtt = [];
        for ($i = 0; $i < $n; $i++) $hNtt[$i] = (int)($gNtt[$i] * $fInvNtt[$i] % self::Q);
        NTT::intt($hNtt, $n);
        return $hNtt;
    }

    private static function verifyNTRU(array $f, array $g, array $F, array $G, int $n): bool
    {
        $fG = self::polyMulIntZ($f, $G, $n);
        $gF = self::polyMulIntZ($g, $F, $n);
        if ($fG[0] - $gF[0] !== self::Q) return false;
        for ($i = 1; $i < $n; $i++) { if ($fG[$i] - $gF[$i] !== 0) return false; }
        return true;
    }

    private static function polyMulIntZ(array $a, array $b, int $n): array
    {
        $c = array_fill(0, $n, 0);
        for ($i = 0; $i < $n; $i++) for ($j = 0; $j < $n; $j++) {
            $idx = $i + $j; $val = $a[$i] * $b[$j];
            if ($idx < $n) $c[$idx] += $val; else $c[$idx - $n] -= $val;
        }
        return $c;
    }

    private static function ntruSolve(int $n, array $f, array $g): ?array
    {
        $fBig = array_map(fn($v) => gmp_init($v), $f);
        $gBig = array_map(fn($v) => gmp_init($v), $g);
        $result = self::ntruSolveBig($n, $fBig, $gBig);
        if ($result === null) return null;
        [$FB, $GB] = $result;
        $F = []; $G = [];
        for ($i = 0; $i < $n; $i++) { $F[$i] = gmp_intval($FB[$i]); $G[$i] = gmp_intval($GB[$i]); }
        return [$F, $G];
    }

    private static function ntruSolveBig(int $n, array $f, array $g): ?array
    {
        if ($n === 1) {
            $ext = gmp_gcdext($f[0], $g[0]);
            $gcd = $ext['g'];
            if (gmp_sign(gmp_mod(gmp_init(self::Q), gmp_abs($gcd))) !== 0) return null;
            $s = gmp_div_q(gmp_init(self::Q), $gcd);
            return [[gmp_neg(gmp_mul($ext['t'], $s))], [gmp_mul($ext['s'], $s)]];
        }

        $fN = self::fieldNorm($f, $n);
        $gN = self::fieldNorm($g, $n);
        $sub = self::ntruSolveBig((int)($n / 2), $fN, $gN);
        if ($sub === null) return null;
        [$Fp, $Gp] = $sub;

        [$FL, $GL] = self::lift($Fp, $Gp, $f, $g, $n);

        // Babai reduction (2 rounds).
        for ($round = 0; $round < 2; $round++) {
            $maxB = self::maxBits([$f, $g, $FL, $GL]);
            if ($maxB <= 50) {
                $k = self::babaiFloat64($FL, $GL, $f, $g, $n);
            } else {
                $k = self::babaiIterative($FL, $GL, $f, $g, $n);
            }
            $kf = self::polyMulBig($k, $f, $n);
            $kg = self::polyMulBig($k, $g, $n);
            for ($i = 0; $i < $n; $i++) {
                $FL[$i] = gmp_sub($FL[$i], $kf[$i]);
                $GL[$i] = gmp_sub($GL[$i], $kg[$i]);
            }
        }
        return [$FL, $GL];
    }

    /** Float64 Babai (all coefficients fit float64). */
    private static function babaiFloat64(array $F, array $G, array $f, array $g, int $n): array
    {
        $toC = function (array $a) use ($n) {
            $c = [];
            for ($i = 0; $i < $n; $i++) $c[$i] = [(float)gmp_strval($a[$i]), 0.0];
            return $c;
        };
        $fC = $toC($f); $gC = $toC($g); $FC = $toC($F); $GC = $toC($G);
        FFT::fft($fC, $n); FFT::fft($gC, $n); FFT::fft($FC, $n); FFT::fft($GC, $n);
        $kC = [];
        for ($i = 0; $i < $n; $i++) {
            $nr = $FC[$i][0]*$fC[$i][0]+$FC[$i][1]*$fC[$i][1]+$GC[$i][0]*$gC[$i][0]+$GC[$i][1]*$gC[$i][1];
            $ni = $FC[$i][1]*$fC[$i][0]-$FC[$i][0]*$fC[$i][1]+$GC[$i][1]*$gC[$i][0]-$GC[$i][0]*$gC[$i][1];
            $d = $fC[$i][0]*$fC[$i][0]+$fC[$i][1]*$fC[$i][1]+$gC[$i][0]*$gC[$i][0]+$gC[$i][1]*$gC[$i][1];
            $kC[$i] = $d != 0.0 ? [$nr/$d, $ni/$d] : [0.0, 0.0];
        }
        FFT::ifft($kC, $n);
        $k = [];
        for ($i = 0; $i < $n; $i++) $k[$i] = gmp_init((int)round($kC[$i][0]));
        return $k;
    }

    /**
     * Iterative Babai via adjoint method.
     *
     * Computes N = F*adj(f) + G*adj(g) and D = f*adj(f) + g*adj(g) exactly,
     * then iteratively extracts bits of k via float64 FFT division on scaled versions.
     */
    private static function babaiIterative(array $F, array $G, array $f, array $g, int $n): array
    {
        // Ring adjoint.
        $fAdj = [$f[0]]; $gAdj = [$g[0]];
        for ($i = 1; $i < $n; $i++) { $fAdj[$i] = gmp_neg($f[$n-$i]); $gAdj[$i] = gmp_neg($g[$n-$i]); }

        $Ff = self::polyMulBig($F, $fAdj, $n);
        $Gg = self::polyMulBig($G, $gAdj, $n);
        $Ncur = [];
        for ($i = 0; $i < $n; $i++) $Ncur[$i] = gmp_add($Ff[$i], $Gg[$i]);

        $ff = self::polyMulBig($f, $fAdj, $n);
        $gg = self::polyMulBig($g, $gAdj, $n);
        $D = [];
        for ($i = 0; $i < $n; $i++) $D[$i] = gmp_add($ff[$i], $gg[$i]);

        $logn = FFT::logN($n);
        $targetBits = max(5, (int)((50 - 2 * $logn) / 2));
        $maxD = self::maxBits([$D]);
        $dShift = max(0, $maxD - $targetBits);

        // Precompute shifted D FFT.
        $DC = [];
        for ($i = 0; $i < $n; $i++) {
            $sv = ($dShift === 0) ? $D[$i] : gmp_div_q($D[$i], gmp_pow(gmp_init(2), $dShift), GMP_ROUND_MINUSINF);
            $DC[$i] = [(float)gmp_strval($sv), 0.0];
        }
        FFT::fft($DC, $n);

        $kTotal = array_fill(0, $n, gmp_init(0));

        for ($iter = 0; $iter < 500; $iter++) {
            $curBits = self::maxBits([$Ncur]);
            if ($curBits <= 10) break;

            $nShift = max(0, $curBits - $targetBits);
            $kShiftCorr = $nShift - $dShift;

            $NC = [];
            $shiftPow = ($nShift > 0) ? gmp_pow(gmp_init(2), $nShift) : null;
            for ($i = 0; $i < $n; $i++) {
                $sv = ($nShift === 0) ? $Ncur[$i] : gmp_div_q($Ncur[$i], $shiftPow, GMP_ROUND_MINUSINF);
                $NC[$i] = [(float)gmp_strval($sv), 0.0];
            }
            FFT::fft($NC, $n);

            $kC = [];
            for ($j = 0; $j < $n; $j++) {
                $dr = $DC[$j][0]; $di = $DC[$j][1];
                $dm = $dr*$dr + $di*$di;
                if ($dm != 0.0 && is_finite($NC[$j][0]) && is_finite($NC[$j][1])) {
                    $nr = $NC[$j][0]; $ni = $NC[$j][1];
                    $kC[$j] = [($nr*$dr+$ni*$di)/$dm, ($ni*$dr-$nr*$di)/$dm];
                } else {
                    $kC[$j] = [0.0, 0.0];
                }
            }
            FFT::ifft($kC, $n);

            $kRound = [];
            $anyNonzero = false;
            for ($i = 0; $i < $n; $i++) {
                if (!is_finite($kC[$i][0])) { $kRound[$i] = gmp_init(0); continue; }
                $kv = gmp_init((int)round($kC[$i][0]));
                if (gmp_sign($kv) === 0) { $kRound[$i] = gmp_init(0); continue; }
                if ($kShiftCorr > 0) $kv = gmp_mul($kv, gmp_pow(gmp_init(2), $kShiftCorr));
                elseif ($kShiftCorr < 0) $kv = gmp_div_q($kv, gmp_pow(gmp_init(2), -$kShiftCorr), GMP_ROUND_MINUSINF);
                $kTotal[$i] = gmp_add($kTotal[$i], $kv);
                $kRound[$i] = $kv;
                $anyNonzero = true;
            }
            if (!$anyNonzero) break;

            $kD = self::polyMulBig($kRound, $D, $n);
            for ($i = 0; $i < $n; $i++) $Ncur[$i] = gmp_sub($Ncur[$i], $kD[$i]);
        }
        return $kTotal;
    }

    // ---- Polynomial arithmetic ----

    private static function fieldNorm(array $f, int $n): array
    {
        $h = (int)($n/2);
        $f0 = []; $f1 = [];
        for ($i = 0; $i < $h; $i++) { $f0[$i] = $f[2*$i]; $f1[$i] = $f[2*$i+1]; }
        $f0sq = self::polyMulBig($f0, $f0, $h);
        $f1sq = self::polyMulBig($f1, $f1, $h);
        $r = [];
        $r[0] = gmp_add($f0sq[0], $f1sq[$h-1]);
        for ($i = 1; $i < $h; $i++) $r[$i] = gmp_sub($f0sq[$i], $f1sq[$i-1]);
        return $r;
    }

    private static function lift(array $Fp, array $Gp, array $f, array $g, int $n): array
    {
        $h = (int)($n/2);
        $FL = array_fill(0, $n, gmp_init(0));
        $GL = array_fill(0, $n, gmp_init(0));
        for ($i = 0; $i < $h; $i++) { $FL[2*$i] = $Fp[$i]; $GL[2*$i] = $Gp[$i]; }
        $fC = $f; $gC = $g;
        for ($i = 1; $i < $n; $i += 2) { $fC[$i] = gmp_neg($f[$i]); $gC[$i] = gmp_neg($g[$i]); }
        return [self::polyMulBig($gC, $FL, $n), self::polyMulBig($fC, $GL, $n)];
    }

    private static function polyMulBig(array $a, array $b, int $n): array
    {
        if ($n <= 16) {
            $c = array_fill(0, $n, gmp_init(0));
            for ($i = 0; $i < $n; $i++) for ($j = 0; $j < $n; $j++) {
                $p = gmp_mul($a[$i], $b[$j]); $idx = $i+$j;
                if ($idx < $n) $c[$idx] = gmp_add($c[$idx], $p);
                else $c[$idx-$n] = gmp_sub($c[$idx-$n], $p);
            }
            return $c;
        }
        $prod = self::kara($a, $b, $n);
        $r = [];
        for ($i = 0; $i < $n; $i++) $r[$i] = $prod[$i];
        for ($i = $n; $i < 2*$n-1; $i++) $r[$i-$n] = gmp_sub($r[$i-$n], $prod[$i]);
        return $r;
    }

    private static function kara(array $a, array $b, int $n): array
    {
        if ($n <= 16) {
            $c = array_fill(0, max(1, 2*$n-1), gmp_init(0));
            for ($i = 0; $i < $n; $i++) for ($j = 0; $j < $n; $j++)
                $c[$i+$j] = gmp_add($c[$i+$j], gmp_mul($a[$i], $b[$j]));
            return $c;
        }
        $h = (int)($n/2);
        $a0 = array_slice($a, 0, $h); $a1 = array_slice($a, $h);
        $b0 = array_slice($b, 0, $h); $b1 = array_slice($b, $h);
        while (count($a1) < $h) $a1[] = gmp_init(0);
        while (count($b1) < $h) $b1[] = gmp_init(0);
        $z0 = self::kara($a0, $b0, $h);
        $z2 = self::kara($a1, $b1, $h);
        $as = []; $bs = [];
        for ($i = 0; $i < $h; $i++) { $as[$i] = gmp_add($a0[$i], $a1[$i]); $bs[$i] = gmp_add($b0[$i], $b1[$i]); }
        $z1f = self::kara($as, $bs, $h);
        $ml = max(count($z1f), count($z0), count($z2));
        $z1 = [];
        for ($i = 0; $i < $ml; $i++) {
            $v = $i < count($z1f) ? $z1f[$i] : gmp_init(0);
            if ($i < count($z0)) $v = gmp_sub($v, $z0[$i]);
            if ($i < count($z2)) $v = gmp_sub($v, $z2[$i]);
            $z1[$i] = $v;
        }
        $rl = 2*$n-1;
        $r = array_fill(0, $rl, gmp_init(0));
        for ($i = 0; $i < count($z0); $i++) $r[$i] = gmp_add($r[$i], $z0[$i]);
        for ($i = 0; $i < count($z1); $i++) if ($i+$h < $rl) $r[$i+$h] = gmp_add($r[$i+$h], $z1[$i]);
        for ($i = 0; $i < count($z2); $i++) if ($i+2*$h < $rl) $r[$i+2*$h] = gmp_add($r[$i+2*$h], $z2[$i]);
        return $r;
    }

    private static function maxBits(array $arrays): int
    {
        $m = 0;
        foreach ($arrays as $arr) foreach ($arr as $v) {
            $abs = gmp_abs($v);
            if (gmp_sign($abs) === 0) continue;
            $b = strlen(gmp_strval($abs, 2));
            if ($b > $m) $m = $b;
        }
        return $m;
    }
}
