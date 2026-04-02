<?php

declare(strict_types=1);

namespace PQC\Hqc;

/**
 * HQC parameter sets for security levels 128, 192, and 256.
 */
final class HqcParams
{
    // Seed and hash sizes
    public const SEED_BYTES = 40;
    public const HASH_BYTES = 64;
    public const SHARED_SECRET_BYTES = 64;

    // Domain separation bytes for SHAKE256
    public const G_FCT_DOMAIN = 3; // theta = G(m || pk || salt)
    public const H_FCT_DOMAIN = 4; // d = H(m)
    public const K_FCT_DOMAIN = 5; // ss = K(m || ct)

    public readonly string $name;
    public readonly int $n;          // ring dimension
    public readonly int $n1;         // RS codeword length
    public readonly int $n2;         // RM codeword length
    public readonly int $n1n2;       // concatenated code length
    public readonly int $k;          // message size in bytes
    public readonly int $delta;      // RS error correction capability
    public readonly int $g;          // RS generator polynomial degree
    public readonly int $w;          // weight of secret key vectors x, y
    public readonly int $wr;         // weight of encryption vectors r1, r2
    public readonly int $we;         // weight of ephemeral error vector e
    public readonly int $pkSize;     // public key size in bytes
    public readonly int $skSize;     // secret key size in bytes
    public readonly int $ctSize;     // ciphertext size in bytes
    public readonly int $ssSize;     // shared secret size in bytes

    // Derived sizes
    public readonly int $vecNSize64;
    public readonly int $vecNSizeBytes;
    public readonly int $vecN1N2Size64;
    public readonly int $vecN1N2SizeBytes;
    public readonly int $vecKSizeBytes;

    // GF(2^8) parameters
    public readonly int $gfPoly;
    public readonly int $gfMulOrder;

    // Reed-Muller parameters
    public readonly int $rmOrder;
    public readonly int $multiplicity;

    private function __construct(
        string $name,
        int $n, int $n1, int $n2, int $k, int $delta,
        int $w, int $wr, int $we,
        int $pkSize, int $skSize, int $ctSize,
        int $multiplicity
    ) {
        $this->name = $name;
        $this->n = $n;
        $this->n1 = $n1;
        $this->n2 = $n2;
        $this->n1n2 = $n1 * $n2;
        $this->k = $k;
        $this->delta = $delta;
        $this->g = 2 * $delta + 1;
        $this->w = $w;
        $this->wr = $wr;
        $this->we = $we;
        $this->pkSize = $pkSize;
        $this->skSize = $skSize;
        $this->ctSize = $ctSize;
        $this->ssSize = self::SHARED_SECRET_BYTES;

        $this->vecNSize64 = intdiv($n + 63, 64);
        $this->vecNSizeBytes = intdiv($n + 7, 8);
        $this->vecN1N2Size64 = intdiv($this->n1n2 + 63, 64);
        $this->vecN1N2SizeBytes = intdiv($this->n1n2 + 7, 8);
        $this->vecKSizeBytes = $k;

        $this->gfPoly = 0x11D;
        $this->gfMulOrder = 255;
        $this->rmOrder = 7;
        $this->multiplicity = $multiplicity;
    }

    public static function hqc128(): self
    {
        return new self('HQC-128', 17669, 46, 384, 16, 15, 66, 77, 77, 2249, 2289, 4481, 3);
    }

    public static function hqc192(): self
    {
        return new self('HQC-192', 35851, 56, 640, 24, 16, 100, 117, 117, 4522, 4562, 9026, 5);
    }

    public static function hqc256(): self
    {
        return new self('HQC-256', 57637, 90, 640, 32, 29, 131, 153, 153, 7245, 7285, 14469, 5);
    }

    /**
     * @return self[]
     */
    public static function all(): array
    {
        return [self::hqc128(), self::hqc192(), self::hqc256()];
    }
}
