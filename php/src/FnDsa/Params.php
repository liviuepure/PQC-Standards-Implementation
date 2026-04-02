<?php

declare(strict_types=1);

namespace PQC\FnDsa;

/**
 * FN-DSA parameter sets (FIPS 206).
 */
class Params
{
    public function __construct(
        public readonly string $name,
        public readonly int $n,
        public readonly int $logN,
        public readonly bool $padded,
        public readonly int $pkSize,
        public readonly int $skSize,
        public readonly int $sigSize,
        public readonly int $sigMaxLen,
        public readonly int $betaSq,
        public readonly int $fgBits,
    ) {}

    public static function fnDsa512(): self
    {
        return new self('FN-DSA-512', 512, 9, false, 897, 1281, 666, 666, 34034726, 6);
    }

    public static function fnDsa1024(): self
    {
        return new self('FN-DSA-1024', 1024, 10, false, 1793, 2305, 1280, 1280, 70265242, 5);
    }

    public static function fnDsaPadded512(): self
    {
        return new self('FN-DSA-PADDED-512', 512, 9, true, 897, 1281, 809, 666, 34034726, 6);
    }

    public static function fnDsaPadded1024(): self
    {
        return new self('FN-DSA-PADDED-1024', 1024, 10, true, 1793, 2305, 1473, 1280, 70265242, 5);
    }
}
