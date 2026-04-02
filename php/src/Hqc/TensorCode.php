<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * Tensor product code: concatenated RS (outer) x RM (inner) code.
 *
 * Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
 * to n2 bits -> total n1*n2 bits.
 *
 * Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
 * RM-decode each block to get n1 bytes -> RS-decode to get k bytes.
 */
final class TensorCode
{
    /**
     * Encode a k-byte message into an n1*n2-bit codeword (GMP polynomial).
     *
     * @param int[] $msg Array of byte values (length k)
     */
    public static function encode(array $msg, HqcParams $p): \GMP
    {
        // Step 1: RS encode the message
        $rsCodeword = ReedSolomon::encode($msg, $p);

        // Step 2: RM encode each RS symbol
        $out = GF2::zero();

        for ($i = 0; $i < $p->n1; $i++) {
            ReedMuller::encodeInto($out, $rsCodeword[$i], $i * $p->n2, $p->multiplicity);
        }

        return $out;
    }

    /**
     * Decode a received n1*n2-bit GMP polynomial back to a k-byte message.
     *
     * @return array{0: int[], 1: bool}
     */
    public static function decode(\GMP $received, HqcParams $p): array
    {
        // Step 1: RM-decode each block of n2 bits
        $rsReceived = [];

        for ($i = 0; $i < $p->n1; $i++) {
            // Extract n2 bits starting at position i * n2
            $block = self::extractBits($received, $i * $p->n2, $p->n2);
            $rsReceived[] = ReedMuller::decode($block, $p->n2, $p->multiplicity);
        }

        // Step 2: RS-decode
        return ReedSolomon::decode($rsReceived, $p);
    }

    /**
     * Extract nBits bits from src starting at bitOffset.
     */
    private static function extractBits(\GMP $src, int $bitOffset, int $nBits): \GMP
    {
        $shifted = GF2::shiftRight($src, $bitOffset);
        return GF2::mask($shifted, $nBits);
    }
}
