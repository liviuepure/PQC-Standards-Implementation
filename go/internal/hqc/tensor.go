package hqc

// Tensor product code: concatenated RS (outer) x RM (inner) code.
//
// Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
// to n2 bits -> total n1*n2 bits.
//
// Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
// RM-decode each block to get n1 bytes -> RS-decode to get k bytes.

// tensorEncode encodes a k-byte message into an n1*n2-bit codeword.
func tensorEncode(msg []byte, p *Params) []uint64 {
	// Step 1: RS encode the message
	rsCodeword := rsEncode(msg, p)

	// Step 2: RM encode each RS symbol
	n1n2Words := p.VecN1N2Size64
	out := make([]uint64, n1n2Words)

	for i := 0; i < p.N1; i++ {
		// Encode byte i of RS codeword into n2 bits starting at position i*n2
		rmEncodeInto(out, rsCodeword[i], i*p.N2, p.Multiplicity)
	}

	return out
}

// rmEncodeInto encodes a byte into the dst vector starting at bitOffset.
func rmEncodeInto(dst []uint64, msg byte, bitOffset int, multiplicity int) {
	base := rmEncodeBase(msg)

	bitPos := bitOffset
	for rep := 0; rep < multiplicity; rep++ {
		for w := 0; w < 2; w++ {
			word := base[w]
			dstWord := bitPos / 64
			dstBit := uint(bitPos % 64)

			if dstBit == 0 && dstWord < len(dst) {
				// Aligned write
				dst[dstWord] ^= word
				bitPos += 64
			} else {
				// Unaligned write, bit by bit
				for bit := 0; bit < 64; bit++ {
					if word&(1<<uint(bit)) != 0 {
						idx := bitPos / 64
						off := uint(bitPos % 64)
						if idx < len(dst) {
							dst[idx] ^= 1 << off
						}
					}
					bitPos++
				}
			}
		}
	}
}

// tensorDecode decodes a received n1*n2-bit word back to a k-byte message.
func tensorDecode(received []uint64, p *Params) ([]byte, bool) {
	// Step 1: RM-decode each block of n2 bits to get one byte
	rsReceived := make([]byte, p.N1)

	for i := 0; i < p.N1; i++ {
		// Extract n2 bits starting at position i * n2
		block := extractBits(received, i*p.N2, p.N2)
		rsReceived[i] = rmDecode(block, p.N2, p.Multiplicity)
	}

	// Step 2: RS-decode the n1-byte received word to get k bytes
	return rsDecode(rsReceived, p)
}

// extractBits extracts nBits bits from src starting at bitOffset,
// returning them as a []uint64 vector.
func extractBits(src []uint64, bitOffset, nBits int) []uint64 {
	nWords := (nBits + 63) / 64
	out := make([]uint64, nWords)

	srcWord := bitOffset / 64
	srcBit := uint(bitOffset % 64)

	if srcBit == 0 {
		// Aligned extraction
		for i := 0; i < nWords && srcWord+i < len(src); i++ {
			out[i] = src[srcWord+i]
		}
	} else {
		// Unaligned extraction
		for i := 0; i < nWords; i++ {
			idx := srcWord + i
			if idx < len(src) {
				out[i] = src[idx] >> srcBit
			}
			if idx+1 < len(src) {
				out[i] |= src[idx+1] << (64 - srcBit)
			}
		}
	}

	// Mask last word
	rem := nBits % 64
	if rem != 0 && nWords > 0 {
		out[nWords-1] &= (1 << uint(rem)) - 1
	}

	return out
}
