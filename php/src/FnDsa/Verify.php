<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * FN-DSA verification (FIPS 206 Algorithm 4).
 */
final class Verify
{
    private const Q = 12289;

    /**
     * Verify a FN-DSA signature.
     *
     * @param string $pk Encoded public key.
     * @param string $msg Message bytes.
     * @param string $sig Encoded signature.
     * @param Params $p Parameter set.
     * @return bool True if valid.
     */
    public static function verify(string $pk, string $msg, string $sig, Params $p): bool
    {
        // 1. Decode and validate public key.
        $h = Encode::decodePk($pk, $p);
        if ($h === null) {
            return false;
        }

        // 2. Decode and validate signature.
        $decoded = Encode::decodeSig($sig, $p);
        if ($decoded === null) {
            return false;
        }
        [$salt, $s1] = $decoded;

        // 3. Recompute c = HashToPoint(salt || msg).
        $hashInput = $salt . $msg;
        $c = Sign::hashToPoint($hashInput, $p);

        // 4. Compute s2 = c - s1*h (mod q), centered.
        $n = $p->n;
        $s1ModQ = [];
        for ($i = 0; $i < $n; $i++) {
            $s1ModQ[$i] = (($s1[$i] % self::Q) + self::Q) % self::Q;
        }
        $s1h = NTT::polyMulNtt($s1ModQ, $h, $n);
        $s2 = [];
        for ($i = 0; $i < $n; $i++) {
            $s2[$i] = Sign::centerModQ($c[$i] - $s1h[$i]);
        }

        // 5. Norm check: ||(s1, s2)||^2 <= beta^2.
        return Sign::normSq($s1, $s2) <= $p->betaSq;
    }
}
