package com.pqc.fndsa;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.*;
import org.junit.jupiter.params.provider.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FnDsaTest {

    @ParameterizedTest
    @MethodSource("allParams")
    void testParamSizes(Params p) {
        assertTrue(p.pkSize > 0, "pkSize should be positive for " + p.name);
        assertTrue(p.skSize > 0, "skSize should be positive for " + p.name);
        assertTrue(p.sigSize > 0, "sigSize should be positive for " + p.name);
        assertTrue(p.betaSq > 0, "betaSq should be positive for " + p.name);
    }

    @ParameterizedTest
    @MethodSource("allParams")
    void testRoundtrip(Params p) {
        SecureRandom rng = new SecureRandom();
        byte[][] keys = FnDsa.keyGen(p, rng);
        byte[] pk = keys[0];
        byte[] sk = keys[1];

        assertEquals(p.pkSize, pk.length, "pk size mismatch for " + p.name);
        assertEquals(p.skSize, sk.length, "sk size mismatch for " + p.name);

        byte[] msg = "test message FN-DSA".getBytes();
        byte[] sig = FnDsa.sign(sk, msg, p, rng);

        assertNotNull(sig, "signature should not be null for " + p.name);
        if (p.padded) {
            assertEquals(p.sigSize, sig.length, "padded sig size mismatch for " + p.name);
        } else {
            assertTrue(sig.length <= p.sigSize, "sig exceeds max size for " + p.name);
        }

        assertTrue(FnDsa.verify(pk, msg, sig, p), "valid signature should verify for " + p.name);
        assertFalse(FnDsa.verify(pk, "wrong".getBytes(), sig, p),
            "wrong message should not verify for " + p.name);

        byte[] tampered = sig.clone();
        tampered[Math.min(42, tampered.length - 1)] ^= 0x01;
        assertFalse(FnDsa.verify(pk, msg, tampered, p),
            "tampered signature should not verify for " + p.name);
    }

    @Test
    void testInteropVectors() throws Exception {
        HexFormat hex = HexFormat.of();
        for (Object[] entry : new Object[][] {
            {"FN-DSA-512", Params.FNDSA512},
            {"FN-DSA-1024", Params.FNDSA1024}
        }) {
            String name = (String) entry[0];
            Params p = (Params) entry[1];

            // Try multiple paths (from different working directories)
            Path path = null;
            for (String candidate : new String[] {
                "../test-vectors/fn-dsa/" + name + ".json",
                "../../test-vectors/fn-dsa/" + name + ".json",
                "../../../test-vectors/fn-dsa/" + name + ".json",
                "test-vectors/fn-dsa/" + name + ".json"
            }) {
                Path cp = Path.of(candidate);
                if (Files.exists(cp)) {
                    path = cp;
                    break;
                }
            }

            if (path == null) {
                System.out.println("Skipping " + name + " -- vector file not found");
                continue;
            }

            String json = Files.readString(path);
            List<TestVector> vectors = parseVectors(json);
            System.out.println("Testing " + vectors.size() + " vectors for " + name);

            for (int i = 0; i < vectors.size(); i++) {
                TestVector v = vectors.get(i);
                byte[] pk = hex.parseHex(v.pk);
                byte[] msg = hex.parseHex(v.msg);
                byte[] sig = hex.parseHex(v.sig);

                assertTrue(FnDsa.verify(pk, msg, sig, p),
                    "Interop vector " + i + " for " + name + " should verify");
            }
        }
    }

    // Minimal JSON parser for test vectors (no Jackson dependency needed)
    private static List<TestVector> parseVectors(String json) {
        List<TestVector> result = new ArrayList<>();
        // Find "vectors" array
        int vectorsIdx = json.indexOf("\"vectors\"");
        if (vectorsIdx < 0) return result;
        int arrStart = json.indexOf('[', vectorsIdx);
        if (arrStart < 0) return result;

        int pos = arrStart + 1;
        while (pos < json.length()) {
            // Skip whitespace
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
            if (pos >= json.length() || json.charAt(pos) == ']') break;
            if (json.charAt(pos) != '{') { pos++; continue; }

            // Find matching }
            int depth = 0;
            int objStart = pos;
            int objEnd = pos;
            for (int i = pos; i < json.length(); i++) {
                char ch = json.charAt(i);
                if (ch == '{') depth++;
                else if (ch == '}') {
                    depth--;
                    if (depth == 0) { objEnd = i; break; }
                }
            }
            String obj = json.substring(objStart, objEnd + 1);
            TestVector tv = new TestVector();
            tv.pk = extractField(obj, "pk");
            tv.msg = extractField(obj, "msg");
            tv.sig = extractField(obj, "sig");
            if (tv.pk != null && tv.msg != null && tv.sig != null) {
                result.add(tv);
            }
            pos = objEnd + 1;
        }
        return result;
    }

    private static String extractField(String obj, String field) {
        String key = "\"" + field + "\"";
        int idx = obj.indexOf(key);
        if (idx < 0) return null;
        int colonIdx = obj.indexOf(':', idx + key.length());
        if (colonIdx < 0) return null;
        int quoteStart = obj.indexOf('"', colonIdx + 1);
        if (quoteStart < 0) return null;
        int quoteEnd = obj.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) return null;
        return obj.substring(quoteStart + 1, quoteEnd);
    }

    private static class TestVector {
        String pk, msg, sig;
    }

    static Stream<Params> allParams() {
        return Stream.of(
            Params.FNDSA512,
            Params.FNDSA1024,
            Params.FNDSA_PADDED_512,
            Params.FNDSA_PADDED_1024
        );
    }
}
