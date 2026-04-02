// TensorCode.swift -- Tensor product code: concatenated RS (outer) x RM (inner).
//
// Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
// to n2 bits -> total n1*n2 bits.
//
// Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
// RM-decode each block to get n1 bytes -> RS-decode to get k bytes.

import Foundation

/// Encode a k-byte message into an n1*n2-bit codeword.
func tensorEncode(_ msg: [UInt8], _ p: HqcParams) -> [UInt64] {
    // Step 1: RS encode
    let rsCodeword = rsEncode(msg, p)

    // Step 2: RM encode each RS symbol
    let n1n2Words = p.vecN1N2Size64
    var out = [UInt64](repeating: 0, count: n1n2Words)

    for i in 0..<p.n1 {
        rmEncodeInto(&out, rsCodeword[i], i * p.n2, p.multiplicity)
    }

    return out
}

/// Decode a received n1*n2-bit word back to a k-byte message.
func tensorDecode(_ received: [UInt64], _ p: HqcParams) -> ([UInt8]?, Bool) {
    // Step 1: RM-decode each block of n2 bits to get one byte
    var rsReceived = [UInt8](repeating: 0, count: p.n1)

    for i in 0..<p.n1 {
        let block = extractBits(received, i * p.n2, p.n2)
        rsReceived[i] = rmDecode(block, p.n2, p.multiplicity)
    }

    // Step 2: RS-decode
    return rsDecode(rsReceived, p)
}

/// Extract nBits bits from src starting at bitOffset.
func extractBits(_ src: [UInt64], _ bitOffset: Int, _ nBits: Int) -> [UInt64] {
    let nWords = (nBits + 63) / 64
    var out = [UInt64](repeating: 0, count: nWords)

    let srcWord = bitOffset / 64
    let srcBit = bitOffset % 64

    if srcBit == 0 {
        for i in 0..<nWords {
            if srcWord + i < src.count {
                out[i] = src[srcWord + i]
            }
        }
    } else {
        for i in 0..<nWords {
            let idx = srcWord + i
            if idx < src.count {
                out[i] = src[idx] >> srcBit
            }
            if idx + 1 < src.count {
                out[i] |= src[idx + 1] << (64 - srcBit)
            }
        }
    }

    // Mask last word
    let rem = nBits % 64
    if rem != 0 && nWords > 0 {
        out[nWords - 1] &= (1 << rem) - 1
    }

    return out
}
