<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\Hqc\GF256;
use PQC\Hqc\GF2;
use PQC\Hqc\ReedMuller;
use PQC\Hqc\ReedSolomon;
use PQC\Hqc\TensorCode;
use PQC\Hqc\HqcParams;
use PQC\Hqc\Hqc;

class HqcTest extends TestCase
{
    public function testGF256Tables(): void
    {
        GF256::init();
        for ($i = 1; $i < 256; $i++) {
            $this->assertSame($i, GF256::mul(1, $i), "1 * $i should be $i");
        }
        for ($i = 1; $i < 256; $i++) {
            $this->assertSame(1, GF256::mul($i, GF256::inv($i)), "$i * inv($i) should be 1");
        }
    }

    public function testGF2VectOps(): void
    {
        $a = gmp_init('AAAA', 16);
        $b = gmp_init('5555', 16);
        $c = GF2::add($a, $b);
        $this->assertSame('ffff', gmp_strval($c, 16));
    }

    public function testRMEncodeDecodeRoundtrip(): void
    {
        for ($msg = 0; $msg < 256; $msg++) {
            foreach ([3, 5] as $mult) {
                $n2 = $mult * 128;
                $cw = GF2::zero();
                ReedMuller::encodeInto($cw, $msg, 0, $mult);
                $decoded = ReedMuller::decode($cw, $n2, $mult);
                $this->assertSame($msg, $decoded, "RM mult=$mult msg=$msg: got $decoded");
            }
        }
    }

    /**
     * @dataProvider paramProvider
     */
    public function testRSEncodeDecodeRoundtrip(HqcParams $p): void
    {
        $msg = [];
        for ($i = 0; $i < $p->k; $i++) {
            $msg[] = ($i + 1) & 0xFF;
        }
        $cw = ReedSolomon::encode($msg, $p);
        [$decoded, $ok] = ReedSolomon::decode($cw, $p);
        $this->assertTrue($ok, 'decode failed on clean codeword');
        $this->assertSame($msg, $decoded, 'roundtrip mismatch');
    }

    /**
     * @dataProvider paramProvider
     */
    public function testRSDecodeWithErrors(HqcParams $p): void
    {
        $msg = [];
        for ($i = 0; $i < $p->k; $i++) {
            $msg[] = ($i * 3 + 7) & 0xFF;
        }
        $cw = ReedSolomon::encode($msg, $p);

        // Inject delta errors
        for ($i = 0; $i < $p->delta; $i++) {
            $cw[$i] ^= ($i + 1) & 0xFF;
        }

        [$decoded, $ok] = ReedSolomon::decode($cw, $p);
        $this->assertTrue($ok, 'decode failed with correctable errors');
        $this->assertSame($msg, $decoded, 'decode mismatch after error correction');
    }

    /**
     * @dataProvider paramProvider
     */
    public function testTensorEncodeDecodeRoundtrip(HqcParams $p): void
    {
        $msg = [];
        for ($i = 0; $i < $p->k; $i++) {
            $msg[] = ($i + 42) & 0xFF;
        }
        $encoded = TensorCode::encode($msg, $p);
        [$decoded, $ok] = TensorCode::decode($encoded, $p);
        $this->assertTrue($ok, 'tensor decode failed');
        $this->assertSame($msg, $decoded, 'tensor roundtrip mismatch');
    }

    /**
     * @dataProvider paramProvider
     */
    public function testKEMRoundtrip(HqcParams $p): void
    {
        [$pk, $sk] = Hqc::keyGen($p);
        $this->assertSame($p->pkSize, strlen($pk), 'pk size mismatch');
        $this->assertSame($p->skSize, strlen($sk), 'sk size mismatch');

        [$ct, $ss1] = Hqc::encaps($pk, $p);
        $this->assertSame($p->ctSize, strlen($ct), 'ct size mismatch');
        $this->assertSame($p->ssSize, strlen($ss1), 'ss size mismatch');

        $ss2 = Hqc::decaps($sk, $ct, $p);
        $this->assertSame($ss1, $ss2, 'shared secrets do not match');
    }

    public function testKEMDecapsBadCiphertext(): void
    {
        $p = HqcParams::hqc128();
        [$pk, $sk] = Hqc::keyGen($p);
        [$ct, $ss1] = Hqc::encaps($pk, $p);

        // Corrupt ciphertext
        $ct[0] = chr(ord($ct[0]) ^ 0xFF);
        $ct[1] = chr(ord($ct[1]) ^ 0xFF);

        $ss2 = Hqc::decaps($sk, $ct, $p);
        $this->assertNotSame($ss1, $ss2, 'shared secrets should not match with corrupted ciphertext');
    }

    /**
     * @dataProvider paramProvider
     */
    public function testKEMMultipleRoundtrips(HqcParams $p): void
    {
        $trials = 5;
        for ($i = 0; $i < $trials; $i++) {
            [$pk, $sk] = Hqc::keyGen($p);
            [$ct, $ss1] = Hqc::encaps($pk, $p);
            $ss2 = Hqc::decaps($sk, $ct, $p);
            $this->assertSame($ss1, $ss2, "trial $i: shared secrets do not match");
        }
    }

    /**
     * @return array<string, array{0: HqcParams}>
     */
    public static function paramProvider(): array
    {
        return [
            'HQC-128' => [HqcParams::hqc128()],
            'HQC-192' => [HqcParams::hqc192()],
            'HQC-256' => [HqcParams::hqc256()],
        ];
    }
}
