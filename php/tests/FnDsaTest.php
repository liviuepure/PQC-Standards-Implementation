<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\FnDsa\FnDsa;
use PQC\FnDsa\Params;

class FnDsaTest extends TestCase
{
    public static function allParams(): array
    {
        return [
            'FN-DSA-512' => [Params::fnDsa512()],
            'FN-DSA-1024' => [Params::fnDsa1024()],
            'FN-DSA-PADDED-512' => [Params::fnDsaPadded512()],
            'FN-DSA-PADDED-1024' => [Params::fnDsaPadded1024()],
        ];
    }

    public static function params512(): array
    {
        return [
            'FN-DSA-512' => [Params::fnDsa512()],
            'FN-DSA-PADDED-512' => [Params::fnDsaPadded512()],
        ];
    }

    public static function params1024(): array
    {
        return [
            'FN-DSA-1024' => [Params::fnDsa1024()],
            'FN-DSA-PADDED-1024' => [Params::fnDsaPadded1024()],
        ];
    }

    /**
     * @dataProvider allParams
     */
    public function testParamSizes(Params $p): void
    {
        $this->assertGreaterThan(0, $p->pkSize);
        $this->assertGreaterThan(0, $p->skSize);
        $this->assertGreaterThan(0, $p->sigSize);
        $this->assertGreaterThan(0, $p->betaSq);
    }

    /**
     * @dataProvider params512
     */
    public function testRoundtrip512(Params $p): void
    {
        $this->doRoundtrip($p);
    }

    /**
     * N=1024 keygen is slow in pure PHP (~minutes). Skipped in CI; run with:
     *   phpunit --filter testRoundtrip1024
     *
     * @dataProvider params1024
     * @group slow
     */
    public function testRoundtrip1024(Params $p): void
    {
        $this->doRoundtrip($p);
    }

    private function doRoundtrip(Params $p): void
    {
        [$pk, $sk] = FnDsa::keyGen($p);
        $this->assertEquals($p->pkSize, strlen($pk));
        $this->assertEquals($p->skSize, strlen($sk));

        $msg = 'test message FN-DSA';
        $sig = FnDsa::sign($sk, $msg, $p);

        if ($p->padded) {
            $this->assertEquals($p->sigSize, strlen($sig));
        } else {
            $this->assertLessThanOrEqual($p->sigSize, strlen($sig));
        }

        $this->assertTrue(FnDsa::verify($pk, $msg, $sig, $p));
        $this->assertFalse(FnDsa::verify($pk, 'wrong', $sig, $p));

        $tampered = $sig;
        $idx = min(42, strlen($tampered) - 1);
        $tampered[$idx] = chr(ord($tampered[$idx]) ^ 0x01);
        $this->assertFalse(FnDsa::verify($pk, $msg, $tampered, $p));
    }

    public function testInteropVectors(): void
    {
        $anyRan = false;
        foreach ([
            ['FN-DSA-512', Params::fnDsa512()],
            ['FN-DSA-1024', Params::fnDsa1024()],
        ] as [$name, $p]) {
            $path = __DIR__ . "/../../test-vectors/fn-dsa/{$name}.json";
            if (!file_exists($path)) {
                continue;
            }
            $data = json_decode(file_get_contents($path), true);
            foreach ($data['vectors'] as $v) {
                $pk = hex2bin($v['pk']);
                $msg = hex2bin($v['msg']);
                $sig = hex2bin($v['sig']);
                $this->assertTrue(
                    FnDsa::verify($pk, $msg, $sig, $p),
                    "count={$v['count']}: verify failed"
                );
            }
            $anyRan = true;
        }
        $this->assertTrue($anyRan, 'No FN-DSA test vector files found');
    }
}
