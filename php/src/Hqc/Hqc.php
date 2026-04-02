<?php

declare(strict_types=1);

namespace PQC\Hqc;

use PQC\MlKem\HashFuncs;

/**
 * HQC KEM (Hamming Quasi-Cyclic) Key Encapsulation Mechanism.
 *
 * Implements KeyGen, Encaps, and Decaps following the NIST HQC specification.
 */
final class Hqc
{
    /**
     * Generate an HQC key pair.
     *
     * @return array{0: string, 1: string} [publicKey, secretKey]
     */
    public static function keyGen(HqcParams $p, ?string $rng = null): array
    {
        // Generate random seeds
        $skSeed = $rng ?? random_bytes(HqcParams::SEED_BYTES);
        $pkSeed = random_bytes(HqcParams::SEED_BYTES);

        if ($rng !== null) {
            // Deterministic: derive pkSeed from skSeed expansion
            // This matches the Go implementation where both seeds come from RNG
            // but in the deterministic case we need separate seeds.
            // For the actual API, both are random.
        }

        // Re-derive from seeds if using the standard approach:
        // skSeed -> SHAKE256 -> pkSeed || x-positions || y-positions || sigma
        $skExpanded = self::seedExpand($skSeed, HqcParams::SEED_BYTES + $p->w * 4 * 2 + $p->vecKSizeBytes + 1024);
        $pkSeed = substr($skExpanded, 0, HqcParams::SEED_BYTES);
        $offset = HqcParams::SEED_BYTES;

        // Generate secret vectors x, y from expanded sk seed
        [$x, $offset] = self::generateFixedWeight($skExpanded, $offset, $p->n, $p->w);
        [$y, $offset] = self::generateFixedWeight($skExpanded, $offset, $p->n, $p->w);

        // Generate random vector h from pk_seed
        $h = self::expandH($pkSeed, $p->n);

        // Compute s = x + h * y mod (x^n - 1)
        $hy = GF2::mulMod($h, $y, $p->n);
        $s = GF2::add($hy, $x);
        $s = GF2::mask($s, $p->n);

        // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
        $pk = $pkSeed . GF2::toBytes($s, $p->vecNSizeBytes);

        // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
        $sk = $skSeed . $pk;

        return [$pk, $sk];
    }

    /**
     * Encapsulate: generate a shared secret and ciphertext.
     *
     * @return array{0: string, 1: string} [ciphertext, sharedSecret]
     */
    public static function encaps(string $pk, HqcParams $p): array
    {
        // Generate random message m and salt
        $m = random_bytes($p->vecKSizeBytes);
        $salt = random_bytes(HqcParams::HASH_BYTES);

        // Compute d = H(m) = SHAKE256(H_domain || m), 64 bytes
        $d = self::computeD($m);

        // Compute theta = SHAKE256(G_domain || m || pk || d)
        $theta = self::computeTheta($m, $pk, $d, $p);

        // PKE Encrypt
        [$u, $v] = self::pkeEncrypt($m, $theta, $pk, $p);

        // Compute shared secret: ss = SHAKE256(K_domain || m || u_bytes || v_bytes)
        $ss = self::computeSS($m, $u, $v, $p);

        // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
        $ct = GF2::toBytes($u, $p->vecNSizeBytes)
            . GF2::toBytes($v, $p->vecN1N2SizeBytes)
            . $d;

        return [$ct, $ss];
    }

    /**
     * Decapsulate: recover shared secret from secret key and ciphertext.
     */
    public static function decaps(string $sk, string $ct, HqcParams $p): string
    {
        // Parse secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
        $skSeed = substr($sk, 0, HqcParams::SEED_BYTES);
        $pk = substr($sk, HqcParams::SEED_BYTES);

        // Parse ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
        $u = GF2::fromBytes(substr($ct, 0, $p->vecNSizeBytes), $p->n);
        $v = GF2::fromBytes(substr($ct, $p->vecNSizeBytes, $p->vecN1N2SizeBytes), $p->n1n2);
        $d = substr($ct, $p->vecNSizeBytes + $p->vecN1N2SizeBytes);

        // Re-derive x, y, sigma from sk_seed
        $skExpanded = self::seedExpand($skSeed, HqcParams::SEED_BYTES + $p->w * 4 * 2 + $p->vecKSizeBytes + 1024);
        $offset = HqcParams::SEED_BYTES; // skip pkSeed
        [$x, $offset] = self::generateFixedWeight($skExpanded, $offset, $p->n, $p->w);
        [$y, $offset] = self::generateFixedWeight($skExpanded, $offset, $p->n, $p->w);

        // sigma (rejection secret)
        $sigma = substr($skExpanded, $offset, $p->vecKSizeBytes);

        // Compute v - u * y (= v XOR u*y in GF(2))
        $uy = GF2::mulMod($u, $y, $p->n);
        $uyTrunc = GF2::mask($uy, $p->n1n2);
        $vMinusUY = GF2::add($v, $uyTrunc);

        // Decode using tensor product code
        [$mPrime, $ok] = TensorCode::decode($vMinusUY, $p);

        if (!$ok) {
            // Decoding failed - use sigma as rejection value
            $mPrime = array_values(unpack('C*', $sigma));
        }

        // Re-encrypt to verify
        $thetaPrime = self::computeTheta(
            pack('C*', ...$mPrime),
            $pk,
            $d,
            $p
        );
        [$u2, $v2] = self::pkeEncrypt(pack('C*', ...$mPrime), $thetaPrime, $pk, $p);

        // Compare
        $u2Masked = GF2::mask($u2, $p->n);
        $uMasked = GF2::mask($u, $p->n);
        $uMatch = GF2::equal($u2Masked, $uMasked);

        $v2Masked = GF2::mask($v2, $p->n1n2);
        $vMasked = GF2::mask($v, $p->n1n2);
        $vMatch = GF2::equal($v2Masked, $vMasked);

        $match = $uMatch & $vMatch;

        // Constant-time selection of message or sigma
        $mc = [];
        $sigmaBytes = array_values(unpack('C*', $sigma));
        $maskOK = (0 - $match) & 0xFF;     // 0xFF if match, 0x00 otherwise
        $maskFail = (0 - (1 - $match)) & 0xFF; // 0x00 if match, 0xFF otherwise
        for ($i = 0; $i < $p->vecKSizeBytes; $i++) {
            $mc[] = ($mPrime[$i] & $maskOK) | ($sigmaBytes[$i] & $maskFail);
        }

        // Compute shared secret
        $ss = self::computeSS(pack('C*', ...$mc), $u, $v, $p);

        return $ss;
    }

    /**
     * PKE Encryption.
     *
     * @return array{0: \GMP, 1: \GMP} [u, v]
     */
    private static function pkeEncrypt(string $m, string $theta, string $pk, HqcParams $p): array
    {
        // Parse public key
        $pkSeed = substr($pk, 0, HqcParams::SEED_BYTES);
        $s = GF2::fromBytes(substr($pk, HqcParams::SEED_BYTES), $p->n);

        // Generate h from pk_seed
        $h = self::expandH($pkSeed, $p->n);

        // Generate r1, r2, e from theta
        $thetaExpanded = self::seedExpand($theta, $p->wr * 4 * 2 + $p->we * 4 + 1024);
        $offset = 0;
        [$r1, $offset] = self::generateFixedWeight($thetaExpanded, $offset, $p->n, $p->wr);
        [$r2, $offset] = self::generateFixedWeight($thetaExpanded, $offset, $p->n, $p->wr);
        [$e, $offset] = self::generateFixedWeight($thetaExpanded, $offset, $p->n, $p->we);

        // u = r1 + h * r2 mod (x^n - 1)
        $hr2 = GF2::mulMod($h, $r2, $p->n);
        $u = GF2::add($hr2, $r1);
        $u = GF2::mask($u, $p->n);

        // v = encode(m) + s * r2 + e
        $msgBytes = array_values(unpack('C*', $m));
        $encoded = TensorCode::encode($msgBytes, $p);

        // s * r2 in the ring, then truncate to n1*n2 bits
        $sr2 = GF2::mulMod($s, $r2, $p->n);
        $sr2Trunc = GF2::mask($sr2, $p->n1n2);

        // Resize e to n1*n2
        $eResized = GF2::mask($e, $p->n1n2);

        $v = GF2::add($encoded, $sr2Trunc);
        $v = GF2::add($v, $eResized);
        $v = GF2::mask($v, $p->n1n2);

        return [$u, $v];
    }

    /**
     * Compute d = SHAKE256(H_domain || m), 64 bytes.
     */
    private static function computeD(string $m): string
    {
        return HashFuncs::shake256(chr(HqcParams::H_FCT_DOMAIN) . $m, HqcParams::SHARED_SECRET_BYTES);
    }

    /**
     * Compute theta = SHAKE256(G_domain || m || pk || d), SEED_BYTES output.
     */
    private static function computeTheta(string $m, string $pk, string $d, HqcParams $p): string
    {
        return HashFuncs::shake256(
            chr(HqcParams::G_FCT_DOMAIN) . $m . $pk . $d,
            HqcParams::SEED_BYTES
        );
    }

    /**
     * Compute ss = SHAKE256(K_domain || m || u_bytes || v_bytes), 64 bytes.
     */
    private static function computeSS(string $m, \GMP $u, \GMP $v, HqcParams $p): string
    {
        return HashFuncs::shake256(
            chr(HqcParams::K_FCT_DOMAIN) . $m . GF2::toBytes($u, $p->vecNSizeBytes) . GF2::toBytes($v, $p->vecN1N2SizeBytes),
            HqcParams::SHARED_SECRET_BYTES
        );
    }

    /**
     * SHAKE256-based seed expansion.
     */
    private static function seedExpand(string $seed, int $length): string
    {
        return HashFuncs::shake256($seed, $length);
    }

    /**
     * Expand a seed into a random GF(2) polynomial of n bits.
     */
    private static function expandH(string $seed, int $n): \GMP
    {
        $nBytes = intdiv($n + 7, 8);
        // Use full 64-bit word granularity like the Go implementation
        $nWords = intdiv($n + 63, 64);
        $data = HashFuncs::shake256($seed, $nWords * 8);
        $v = GF2::fromBytes($data, $n);
        return GF2::mask($v, $n);
    }

    /**
     * Generate a random GF(2) polynomial with exactly $weight bits set.
     * Uses rejection sampling from sequential 4-byte chunks of expanded data.
     *
     * @return array{0: \GMP, 1: int} [polynomial, newOffset]
     */
    private static function generateFixedWeight(string $data, int $offset, int $n, int $weight): array
    {
        $v = GF2::zero();
        $positions = [];
        $seen = [];

        for ($i = 0; $i < $weight; /* increment inside */) {
            if ($offset + 4 > strlen($data)) {
                throw new \RuntimeException('Not enough expanded data for fixed-weight generation');
            }
            $val = unpack('V', substr($data, $offset, 4))[1]; // little-endian uint32
            $offset += 4;

            // Ensure unsigned interpretation
            $pos = self::unsignedMod($val, $n);

            if (!isset($seen[$pos])) {
                $seen[$pos] = true;
                $positions[] = $pos;
                $i++;
            }
        }

        foreach ($positions as $pos) {
            $v = GF2::setBit($v, $pos);
        }

        return [$v, $offset];
    }

    /**
     * Compute val % n treating val as unsigned 32-bit integer.
     */
    private static function unsignedMod(int $val, int $n): int
    {
        // PHP unpacks V as signed on 64-bit, but we need unsigned mod
        $unsigned = $val & 0xFFFFFFFF;
        return $unsigned % $n;
    }
}
