<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Encoding/decoding functions for ML-KEM polynomials.
 */
final class Encode
{
    /**
     * ByteEncode_d: encode polynomial with d-bit coefficients to bytes.
     * FIPS 203 Algorithm 4.
     *
     * @param array $f Polynomial (256 coefficients)
     * @param int $d Bits per coefficient
     * @return string Byte string of length 32*d
     */
    public static function byteEncode(array $f, int $d): string
    {
        if ($d === 12) {
            return self::byteEncode12($f);
        }

        $bits = [];
        for ($i = 0; $i < 256; $i++) {
            $val = $f[$i] % (1 << $d);
            for ($j = 0; $j < $d; $j++) {
                $bits[] = ($val >> $j) & 1;
            }
        }

        $numBytes = 32 * $d;
        $bytes = '';
        for ($i = 0; $i < $numBytes; $i++) {
            $byte = 0;
            for ($j = 0; $j < 8; $j++) {
                $idx = $i * 8 + $j;
                if ($idx < count($bits)) {
                    $byte |= ($bits[$idx] << $j);
                }
            }
            $bytes .= chr($byte);
        }

        return $bytes;
    }

    /**
     * Optimized 12-bit encoding.
     */
    private static function byteEncode12(array $f): string
    {
        $bytes = '';
        for ($i = 0; $i < 256; $i += 2) {
            $a = $f[$i] & 0xFFF;
            $b = $f[$i + 1] & 0xFFF;
            $bytes .= chr($a & 0xFF);
            $bytes .= chr((($a >> 8) | ($b << 4)) & 0xFF);
            $bytes .= chr(($b >> 4) & 0xFF);
        }
        return $bytes;
    }

    /**
     * ByteDecode_d: decode bytes to polynomial with d-bit coefficients.
     * FIPS 203 Algorithm 5.
     *
     * @param string $b Byte string of length 32*d
     * @param int $d Bits per coefficient
     * @return array Polynomial (256 coefficients)
     */
    public static function byteDecode(string $b, int $d): array
    {
        if ($d === 12) {
            return self::byteDecode12($b);
        }

        $bits = [];
        $len = strlen($b);
        for ($i = 0; $i < $len; $i++) {
            $byte = ord($b[$i]);
            for ($j = 0; $j < 8; $j++) {
                $bits[] = ($byte >> $j) & 1;
            }
        }

        $f = [];
        $m = (1 << $d);
        for ($i = 0; $i < 256; $i++) {
            $val = 0;
            for ($j = 0; $j < $d; $j++) {
                $val |= ($bits[$i * $d + $j] << $j);
            }
            $f[$i] = $val % $m;
        }

        return $f;
    }

    /**
     * Optimized 12-bit decoding.
     */
    private static function byteDecode12(string $b): array
    {
        $f = [];
        for ($i = 0; $i < 256; $i += 2) {
            $idx = intdiv($i, 2) * 3;
            $b0 = ord($b[$idx]);
            $b1 = ord($b[$idx + 1]);
            $b2 = ord($b[$idx + 2]);
            $f[$i] = $b0 | (($b1 & 0x0F) << 8);
            $f[$i + 1] = ($b1 >> 4) | ($b2 << 4);
        }
        return $f;
    }
}
