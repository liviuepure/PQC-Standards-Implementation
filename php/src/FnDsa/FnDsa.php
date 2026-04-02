<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * FN-DSA (FIPS 206) post-quantum digital signatures.
 *
 * Public API: keyGen, sign, verify.
 */
final class FnDsa
{
    /**
     * Generate a key pair.
     *
     * @param Params $p Parameter set.
     * @return array [pk, sk] as binary strings.
     * @throws \RuntimeException If key generation fails.
     */
    public static function keyGen(Params $p): array
    {
        $rng = function (int $n): string {
            return random_bytes($n);
        };

        $result = NTRUKeygen::keygen($p, $rng);
        if ($result === null) {
            throw new \RuntimeException('FN-DSA key generation failed');
        }
        [$f, $g, $F, $G] = $result;

        $h = NTRUKeygen::publicKey($f, $g, $p);
        $pk = Encode::encodePk($h, $p);
        $sk = Encode::encodeSk($f, $g, $F, $p);

        return [$pk, $sk];
    }

    /**
     * Sign a message.
     *
     * @param string $sk Encoded secret key.
     * @param string $msg Message bytes.
     * @param Params $p Parameter set.
     * @return string Encoded signature.
     * @throws \RuntimeException If signing fails.
     */
    public static function sign(string $sk, string $msg, Params $p): string
    {
        $sig = Sign::signInternal($sk, $msg, $p);
        if ($sig === null) {
            throw new \RuntimeException('FN-DSA signing failed');
        }
        return $sig;
    }

    /**
     * Verify a signature.
     *
     * @param string $pk Encoded public key.
     * @param string $msg Message bytes.
     * @param string $sig Encoded signature.
     * @param Params $p Parameter set.
     * @return bool True if valid.
     */
    public static function verify(string $pk, string $msg, string $sig, Params $p): bool
    {
        return Verify::verify($pk, $msg, $sig, $p);
    }
}
