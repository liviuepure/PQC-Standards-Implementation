package fndsa

// encode.go implements FIPS 206 key and signature encoding/decoding for FN-DSA.
//
// All bit-packing is LSB-first: bit 0 of coefficient 0 goes to bit 0 of byte 0.

// ─────────────────────────────────────────────────────────────────────────────
// Public-key encoding  (14 bits per NTT coefficient, LSB-first)
// ─────────────────────────────────────────────────────────────────────────────

// EncodePK encodes the NTT public-key polynomial h into the FIPS 206 format:
//
//	byte 0   : 0x00 | LogN
//	bytes 1… : h coefficients packed at 14 bits each, LSB-first
func EncodePK(h []int32, p *Params) []byte {
	out := make([]byte, p.PKSize)
	out[0] = byte(0x00 | p.LogN)
	packBits14(out[1:], h, p.N)
	return out
}

// DecodePK decodes a FIPS 206 public key and returns the NTT coefficients.
// The header byte is not validated; callers that need strict validation should
// check it themselves.
func DecodePK(data []byte, p *Params) []int32 {
	return unpackBits14(data[1:], p.N)
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret-key encoding  (f, g at fgBits bits; F at 8 bits — all two's complement)
// ─────────────────────────────────────────────────────────────────────────────

// fgBitsFor returns the signed bit-width used for f and g coefficients.
func fgBitsFor(p *Params) int {
	if p.N == 1024 {
		return 5
	}
	return 6
}

// EncodeSK encodes (f, g, F) into the FIPS 206 secret-key format:
//
//	byte 0        : 0x50 | LogN
//	next fgBits×N/8 bytes : f  (signed, two's complement)
//	next fgBits×N/8 bytes : g  (signed, two's complement)
//	next 8×N/8   bytes    : F  (signed, 8 bits)
//
// G is NOT stored.
func EncodeSK(f, g, F []int32, p *Params) []byte {
	out := make([]byte, p.SKSize)
	out[0] = byte(0x50 | p.LogN)
	fgBits := fgBitsFor(p)
	offset := 1
	packSignedBits(out[offset:], f, p.N, fgBits)
	offset += (p.N * fgBits) / 8
	packSignedBits(out[offset:], g, p.N, fgBits)
	offset += (p.N * fgBits) / 8
	packSignedBits(out[offset:], F, p.N, 8)
	return out
}

// DecodeSK decodes a FIPS 206 secret key.  Returns ok=false if the header byte
// does not match the expected value for p.
func DecodeSK(data []byte, p *Params) (f, g, F []int32, ok bool) {
	if len(data) != p.SKSize {
		return nil, nil, nil, false
	}
	if data[0] != byte(0x50|p.LogN) {
		return nil, nil, nil, false
	}
	fgBits := fgBitsFor(p)
	offset := 1
	f = unpackSignedBits(data[offset:], p.N, fgBits)
	offset += (p.N * fgBits) / 8
	g = unpackSignedBits(data[offset:], p.N, fgBits)
	offset += (p.N * fgBits) / 8
	F = unpackSignedBits(data[offset:], p.N, 8)
	return f, g, F, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature encoding  (variable-length compressed s1)
// ─────────────────────────────────────────────────────────────────────────────

// loBitsFor returns the lo parameter for s1 compression.
func loBitsFor(p *Params) int {
	if p.N == 1024 {
		return 7
	}
	return 6
}

// EncodeSig encodes a signature into FIPS 206 format:
//
//	byte 0       : 0x30 | LogN
//	bytes 1–40   : salt (40 bytes)
//	bytes 41…    : compressed s1
//
// For PADDED parameter sets the result is always exactly p.SigSize bytes
// (zero-padded after the compressed data).  For non-PADDED sets the result
// is exactly 1+40+actualCompressedBytes bytes (variable, ≤ SigMaxLen).
//
// Returns (nil, false) if the compressed s1 would exceed SigMaxLen-41 bytes.
func EncodeSig(salt []byte, s1 []int32, p *Params) ([]byte, bool) {
	capacity := p.SigMaxLen - 41 // bytes available for compressed s1
	compBuf := make([]byte, capacity)
	used, ok := compressS1(compBuf, s1, p.N, loBitsFor(p))
	if !ok {
		return nil, false
	}

	var out []byte
	if p.Padded {
		out = make([]byte, p.SigSize)
	} else {
		out = make([]byte, 1+40+used)
	}
	out[0] = byte(0x30 | p.LogN)
	copy(out[1:41], salt)
	copy(out[41:41+used], compBuf[:used])
	// Remaining bytes are already zero for PADDED (Go zero-initialises slices).
	return out, true
}

// DecodeSig decodes a FIPS 206 signature.  Returns ok=false on any format error.
func DecodeSig(data []byte, p *Params) (salt []byte, s1 []int32, ok bool) {
	if len(data) < 41 {
		return nil, nil, false
	}
	if data[0] != byte(0x30|p.LogN) {
		return nil, nil, false
	}
	if p.Padded {
		if len(data) != p.SigSize {
			return nil, nil, false
		}
	} else {
		if len(data) > p.SigMaxLen {
			return nil, nil, false
		}
	}
	salt = make([]byte, 40)
	copy(salt, data[1:41])

	s1, ok = decompressS1(data[41:], p.N, loBitsFor(p))
	if !ok {
		return nil, nil, false
	}
	return salt, s1, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// packBits14 packs n coefficients (each exactly 14 bits) LSB-first into dst.
// dst must have at least ceil(14*n/8) bytes.
//
// 14 bits starting at bit offset b span bytes [b/8 .. (b+13)/8], which is
// always 2 bytes when b%8 == 0, and 3 bytes when b%8 >= 3.
func packBits14(dst []byte, src []int32, n int) {
	cursor := 0
	for i := 0; i < n; i++ {
		v := uint32(src[i]) & 0x3FFF // 14 bits
		byteIdx := cursor >> 3
		bitIdx := uint(cursor & 7)
		// Byte 0 of the window always gets the low bits.
		dst[byteIdx] |= byte(v << bitIdx)
		// Byte 1: middle bits (always needed because 14 > 8).
		if bitIdx == 0 {
			dst[byteIdx+1] |= byte(v >> 8)
		} else {
			dst[byteIdx+1] |= byte(v >> (8 - bitIdx))
			// Byte 2: only when the 14 bits overflow into a third byte.
			if bitIdx > 2 { // (8-bitIdx) + 8 < 14  →  bitIdx > 2
				dst[byteIdx+2] |= byte(v >> (16 - bitIdx))
			}
		}
		cursor += 14
	}
}

// unpackBits14 unpacks n 14-bit coefficients LSB-first from src.
func unpackBits14(src []byte, n int) []int32 {
	out := make([]int32, n)
	cursor := 0
	for i := 0; i < n; i++ {
		byteIdx := cursor >> 3
		bitIdx := uint(cursor & 7)
		var v uint32
		if bitIdx == 0 {
			v = uint32(src[byteIdx]) | uint32(src[byteIdx+1])<<8
		} else {
			v = uint32(src[byteIdx]) >> bitIdx
			v |= uint32(src[byteIdx+1]) << (8 - bitIdx)
			if bitIdx > 2 {
				v |= uint32(src[byteIdx+2]) << (16 - bitIdx)
			}
		}
		out[i] = int32(v & 0x3FFF)
		cursor += 14
	}
	return out
}

// packSignedBits packs n signed integers, each stored as `bits` bits of
// two's complement, LSB-first, into dst.
// dst must have at least ceil(bits*n/8) bytes.
func packSignedBits(dst []byte, src []int32, n, bits int) {
	mask := uint32((1 << bits) - 1)
	cursor := 0
	for i := 0; i < n; i++ {
		v := uint32(src[i]) & mask
		rem := bits
		cur := cursor
		for rem > 0 {
			byteIdx := cur >> 3
			bitIdx := uint(cur & 7)
			avail := 8 - int(bitIdx)
			chunk := rem
			if chunk > avail {
				chunk = avail
			}
			dst[byteIdx] |= byte((v & uint32((1<<chunk)-1)) << bitIdx)
			v >>= uint(chunk)
			cur += chunk
			rem -= chunk
		}
		cursor += bits
	}
}

// unpackSignedBits reads n signed integers of `bits` bits each (two's
// complement, LSB-first) from src and sign-extends them to int32.
func unpackSignedBits(src []byte, n, bits int) []int32 {
	out := make([]int32, n)
	mask := uint32((1 << bits) - 1)
	signBit := uint32(1 << (bits - 1))
	cursor := 0
	for i := 0; i < n; i++ {
		var v uint32
		rem := bits
		cur := cursor
		shift := 0
		for rem > 0 {
			byteIdx := cur >> 3
			bitIdx := uint(cur & 7)
			avail := 8 - int(bitIdx)
			chunk := rem
			if chunk > avail {
				chunk = avail
			}
			b := uint32(src[byteIdx] >> bitIdx)
			b &= uint32((1 << chunk) - 1)
			v |= b << uint(shift)
			shift += chunk
			cur += chunk
			rem -= chunk
		}
		v &= mask
		// Sign-extend.
		if v&signBit != 0 {
			v |= ^mask
		}
		out[i] = int32(v)
		cursor += bits
	}
	return out
}

// compressS1 encodes s1 into dst using the FIPS 206 variable-length scheme
// with parameter lo.  Returns (bytesUsed, true) on success, or (0, false) if
// the encoding would exceed len(dst) bytes.
//
// Encoding per coefficient s:
//
//	v    = |s|
//	low  = v & ((1<<lo)-1)          // lo LSBs
//	high = v >> lo                   // unary count
//	emit lo bits of low  (LSB-first)
//	emit high 1-bits
//	emit one 0-bit       (unary terminator)
//	emit 1 sign bit      (0=non-negative, 1=negative; 0 for s==0)
func compressS1(dst []byte, s1 []int32, n, lo int) (bytesUsed int, ok bool) {
	loMask := int32((1 << lo) - 1)
	cursor := 0
	capacity := len(dst) * 8

	writeBit := func(bit uint8) bool {
		if cursor >= capacity {
			return false
		}
		if bit != 0 {
			dst[cursor>>3] |= 1 << uint(cursor&7)
		}
		cursor++
		return true
	}

	for i := 0; i < n; i++ {
		s := s1[i]
		v := s
		if v < 0 {
			v = -v
		}
		low := v & loMask
		high := v >> lo

		// Emit lo bits of low, LSB-first.
		for b := 0; b < lo; b++ {
			if !writeBit(uint8((low >> uint(b)) & 1)) {
				return 0, false
			}
		}
		// Emit high 1-bits.
		for h := int32(0); h < high; h++ {
			if !writeBit(1) {
				return 0, false
			}
		}
		// Emit terminating 0-bit.
		if !writeBit(0) {
			return 0, false
		}
		// Emit sign bit (1 if negative, 0 otherwise; 0 for s==0).
		var signBit uint8
		if s < 0 {
			signBit = 1
		}
		if !writeBit(signBit) {
			return 0, false
		}
	}
	// Round up to whole bytes.
	bytesUsed = (cursor + 7) / 8
	return bytesUsed, true
}

// decompressS1 reads n coefficients from src using the FIPS 206
// variable-length scheme with parameter lo.  Returns (s1, true) on success.
// Returns (nil, false) if the input is malformed.
func decompressS1(src []byte, n, lo int) ([]int32, bool) {
	loMask := int32((1 << lo) - 1)
	_ = loMask
	totalBits := len(src) * 8
	cursor := 0

	readBit := func() (uint8, bool) {
		if cursor >= totalBits {
			return 0, false
		}
		bit := (src[cursor>>3] >> uint(cursor&7)) & 1
		cursor++
		return bit, true
	}

	out := make([]int32, n)
	for i := 0; i < n; i++ {
		// Read lo bits of low, LSB-first.
		var low int32
		for b := 0; b < lo; b++ {
			bit, ok := readBit()
			if !ok {
				return nil, false
			}
			low |= int32(bit) << uint(b)
		}
		// Read unary-coded high (count 1-bits until 0-bit).
		var high int32
		for {
			bit, ok := readBit()
			if !ok {
				return nil, false
			}
			if bit == 0 {
				break
			}
			high++
		}
		// Read sign bit.
		signBit, ok := readBit()
		if !ok {
			return nil, false
		}

		v := (high << lo) | low
		if signBit == 1 {
			v = -v
		}
		out[i] = v
	}
	return out, true
}
