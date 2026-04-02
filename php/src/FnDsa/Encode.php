<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * FIPS 206 key and signature encoding/decoding for FN-DSA.
 *
 * All bit-packing is LSB-first: bit 0 of coefficient 0 goes to bit 0 of byte 0.
 */
final class Encode
{
    /**
     * Encode public key polynomial h into FIPS 206 format.
     *
     * @param int[] $h NTT polynomial coefficients in [0, Q).
     * @param Params $p Parameter set.
     * @return string Encoded public key.
     */
    public static function encodePk(array $h, Params $p): string
    {
        $out = str_repeat("\x00", $p->pkSize);
        $out[0] = chr(0x00 | $p->logN);
        $packed = self::packBits14($h, $p->n);
        for ($i = 0; $i < strlen($packed); $i++) {
            $out[$i + 1] = $packed[$i];
        }
        return $out;
    }

    /**
     * Decode a FIPS 206 public key.
     *
     * @return int[]|null NTT coefficients, or null on error.
     */
    public static function decodePk(string $data, Params $p): ?array
    {
        if (strlen($data) !== $p->pkSize) {
            return null;
        }
        if (ord($data[0]) !== (0x00 | $p->logN)) {
            return null;
        }
        return self::unpackBits14(substr($data, 1), $p->n);
    }

    /**
     * Encode secret key (f, g, F) into FIPS 206 format.
     *
     * @param int[] $f
     * @param int[] $g
     * @param int[] $F
     * @param Params $p
     * @return string Encoded secret key.
     */
    public static function encodeSk(array $f, array $g, array $F, Params $p): string
    {
        $out = str_repeat("\x00", $p->skSize);
        $out[0] = chr(0x50 | $p->logN);
        $fgBits = $p->fgBits;
        $offset = 1;
        $packed = self::packSignedBits($f, $p->n, $fgBits);
        for ($i = 0; $i < strlen($packed); $i++) {
            $out[$offset + $i] = $packed[$i];
        }
        $offset += ($p->n * $fgBits) / 8;
        $packed = self::packSignedBits($g, $p->n, $fgBits);
        for ($i = 0; $i < strlen($packed); $i++) {
            $out[$offset + $i] = $packed[$i];
        }
        $offset += ($p->n * $fgBits) / 8;
        $packed = self::packSignedBits($F, $p->n, 8);
        for ($i = 0; $i < strlen($packed); $i++) {
            $out[$offset + $i] = $packed[$i];
        }
        return $out;
    }

    /**
     * Decode a FIPS 206 secret key.
     *
     * @return array|null [f, g, F] or null on error.
     */
    public static function decodeSk(string $data, Params $p): ?array
    {
        if (strlen($data) !== $p->skSize) {
            return null;
        }
        if (ord($data[0]) !== (0x50 | $p->logN)) {
            return null;
        }
        $fgBits = $p->fgBits;
        $offset = 1;
        $f = self::unpackSignedBits($data, $offset, $p->n, $fgBits);
        $offset += (int)(($p->n * $fgBits) / 8);
        $g = self::unpackSignedBits($data, $offset, $p->n, $fgBits);
        $offset += (int)(($p->n * $fgBits) / 8);
        $F = self::unpackSignedBits($data, $offset, $p->n, 8);
        return [$f, $g, $F];
    }

    /**
     * Encode a signature into FIPS 206 format.
     *
     * @param string $salt 40-byte salt.
     * @param int[] $s1 Signed coefficients.
     * @param Params $p Parameter set.
     * @return string|null Encoded signature, or null if too large.
     */
    public static function encodeSig(string $salt, array $s1, Params $p): ?string
    {
        $capacity = $p->sigMaxLen - 41;
        $compBuf = str_repeat("\x00", $capacity);
        $used = self::compressS1($compBuf, $s1, $p->n, self::loBitsFor($p));
        if ($used === null) {
            return null;
        }

        if ($p->padded) {
            $out = str_repeat("\x00", $p->sigSize);
        } else {
            $out = str_repeat("\x00", 1 + 40 + $used);
        }
        $out[0] = chr(0x30 | $p->logN);
        for ($i = 0; $i < 40; $i++) {
            $out[$i + 1] = $salt[$i];
        }
        for ($i = 0; $i < $used; $i++) {
            $out[41 + $i] = $compBuf[$i];
        }
        return $out;
    }

    /**
     * Decode a FIPS 206 signature.
     *
     * @return array|null [salt, s1] or null on error.
     */
    public static function decodeSig(string $data, Params $p): ?array
    {
        if (strlen($data) < 41) {
            return null;
        }
        if (ord($data[0]) !== (0x30 | $p->logN)) {
            return null;
        }
        if ($p->padded) {
            if (strlen($data) !== $p->sigSize) {
                return null;
            }
        } else {
            if (strlen($data) > $p->sigMaxLen) {
                return null;
            }
        }

        $salt = substr($data, 1, 40);
        $s1 = self::decompressS1(substr($data, 41), $p->n, self::loBitsFor($p));
        if ($s1 === null) {
            return null;
        }
        return [$salt, $s1];
    }

    /**
     * Get lo-bits parameter for s1 compression.
     */
    private static function loBitsFor(Params $p): int
    {
        return ($p->n === 1024) ? 7 : 6;
    }

    // ---- Bit packing helpers ----

    /**
     * Pack n coefficients at 14 bits each, LSB-first.
     */
    private static function packBits14(array $src, int $n): string
    {
        $dstLen = (int)ceil(14 * $n / 8);
        $dst = str_repeat("\x00", $dstLen);
        $cursor = 0;
        for ($i = 0; $i < $n; $i++) {
            $v = $src[$i] & 0x3FFF;
            $byteIdx = $cursor >> 3;
            $bitIdx = $cursor & 7;
            $dst[$byteIdx] = chr(ord($dst[$byteIdx]) | (($v << $bitIdx) & 0xFF));
            if ($bitIdx === 0) {
                $dst[$byteIdx + 1] = chr(ord($dst[$byteIdx + 1]) | (($v >> 8) & 0xFF));
            } else {
                $dst[$byteIdx + 1] = chr(ord($dst[$byteIdx + 1]) | (($v >> (8 - $bitIdx)) & 0xFF));
                if ($bitIdx > 2) {
                    $dst[$byteIdx + 2] = chr(ord($dst[$byteIdx + 2]) | (($v >> (16 - $bitIdx)) & 0xFF));
                }
            }
            $cursor += 14;
        }
        return $dst;
    }

    /**
     * Unpack n 14-bit coefficients, LSB-first.
     */
    private static function unpackBits14(string $src, int $n): array
    {
        $out = [];
        $cursor = 0;
        for ($i = 0; $i < $n; $i++) {
            $byteIdx = $cursor >> 3;
            $bitIdx = $cursor & 7;
            if ($bitIdx === 0) {
                $v = ord($src[$byteIdx]) | (ord($src[$byteIdx + 1]) << 8);
            } else {
                $v = ord($src[$byteIdx]) >> $bitIdx;
                $v |= ord($src[$byteIdx + 1]) << (8 - $bitIdx);
                if ($bitIdx > 2) {
                    $v |= ord($src[$byteIdx + 2]) << (16 - $bitIdx);
                }
            }
            $out[$i] = $v & 0x3FFF;
            $cursor += 14;
        }
        return $out;
    }

    /**
     * Pack n signed integers at `bits` bits each (two's complement), LSB-first.
     */
    private static function packSignedBits(array $src, int $n, int $bits): string
    {
        $dstLen = (int)ceil($bits * $n / 8);
        $dst = str_repeat("\x00", $dstLen);
        $mask = (1 << $bits) - 1;
        $cursor = 0;
        for ($i = 0; $i < $n; $i++) {
            $v = $src[$i] & $mask;
            $rem = $bits;
            $cur = $cursor;
            while ($rem > 0) {
                $byteIdx = $cur >> 3;
                $bitIdx = $cur & 7;
                $avail = 8 - $bitIdx;
                $chunk = min($rem, $avail);
                $dst[$byteIdx] = chr(ord($dst[$byteIdx]) | (($v & ((1 << $chunk) - 1)) << $bitIdx));
                $v >>= $chunk;
                $cur += $chunk;
                $rem -= $chunk;
            }
            $cursor += $bits;
        }
        return $dst;
    }

    /**
     * Unpack n signed integers of `bits` bits each (two's complement), LSB-first.
     */
    private static function unpackSignedBits(string $src, int $offset, int $n, int $bits): array
    {
        $out = [];
        $mask = (1 << $bits) - 1;
        $signBit = 1 << ($bits - 1);
        $cursor = $offset * 8;
        for ($i = 0; $i < $n; $i++) {
            $v = 0;
            $rem = $bits;
            $cur = $cursor;
            $shift = 0;
            while ($rem > 0) {
                $byteIdx = $cur >> 3;
                $bitIdx = $cur & 7;
                $avail = 8 - $bitIdx;
                $chunk = min($rem, $avail);
                $b = (ord($src[$byteIdx]) >> $bitIdx) & ((1 << $chunk) - 1);
                $v |= $b << $shift;
                $shift += $chunk;
                $cur += $chunk;
                $rem -= $chunk;
            }
            $v &= $mask;
            // Sign-extend.
            if ($v & $signBit) {
                $v |= ~$mask;
            }
            $out[$i] = $v;
            $cursor += $bits;
        }
        return $out;
    }

    /**
     * Compress s1 using FIPS 206 variable-length scheme.
     *
     * @param string &$dst Output buffer.
     * @param int[] $s1 Signed coefficients.
     * @param int $n Polynomial degree.
     * @param int $lo Lo-bits parameter.
     * @return int|null Bytes used, or null if too large.
     */
    private static function compressS1(string &$dst, array $s1, int $n, int $lo): ?int
    {
        $loMask = (1 << $lo) - 1;
        $cursor = 0;
        $capacity = strlen($dst) * 8;

        $writeBit = function (int $bit) use (&$dst, &$cursor, $capacity): bool {
            if ($cursor >= $capacity) {
                return false;
            }
            if ($bit) {
                $byteIdx = $cursor >> 3;
                $dst[$byteIdx] = chr(ord($dst[$byteIdx]) | (1 << ($cursor & 7)));
            }
            $cursor++;
            return true;
        };

        for ($i = 0; $i < $n; $i++) {
            $s = $s1[$i];
            $v = ($s < 0) ? -$s : $s;
            $low = $v & $loMask;
            $high = $v >> $lo;

            // Emit lo bits of low, LSB-first.
            for ($b = 0; $b < $lo; $b++) {
                if (!$writeBit(($low >> $b) & 1)) {
                    return null;
                }
            }
            // Emit high 1-bits.
            for ($h = 0; $h < $high; $h++) {
                if (!$writeBit(1)) {
                    return null;
                }
            }
            // Emit terminating 0-bit.
            if (!$writeBit(0)) {
                return null;
            }
            // Emit sign bit.
            if (!$writeBit($s < 0 ? 1 : 0)) {
                return null;
            }
        }
        return (int)(($cursor + 7) / 8);
    }

    /**
     * Decompress s1 from FIPS 206 variable-length format.
     *
     * @return int[]|null Coefficients, or null on format error.
     */
    private static function decompressS1(string $src, int $n, int $lo): ?array
    {
        $totalBits = strlen($src) * 8;
        $cursor = 0;

        $readBit = function () use ($src, &$cursor, $totalBits): ?int {
            if ($cursor >= $totalBits) {
                return null;
            }
            $bit = (ord($src[$cursor >> 3]) >> ($cursor & 7)) & 1;
            $cursor++;
            return $bit;
        };

        $out = [];
        for ($i = 0; $i < $n; $i++) {
            // Read lo bits of low, LSB-first.
            $low = 0;
            for ($b = 0; $b < $lo; $b++) {
                $bit = $readBit();
                if ($bit === null) return null;
                $low |= $bit << $b;
            }
            // Read unary-coded high.
            $high = 0;
            while (true) {
                $bit = $readBit();
                if ($bit === null) return null;
                if ($bit === 0) break;
                $high++;
            }
            // Read sign bit.
            $signBit = $readBit();
            if ($signBit === null) return null;

            $v = ($high << $lo) | $low;
            if ($signBit === 1) {
                if ($v === 0) {
                    // Non-canonical zero with sign bit 1 (FIPS 206 §3.11.5).
                    return null;
                }
                $v = -$v;
            }
            $out[$i] = $v;
        }
        return $out;
    }
}
