package kwp

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// Wrap implements RFC 5649 AES Key Wrap with Padding (AES-KWP).
//
// It wraps arbitrary-length plaintext using a KEK (key-encryption-key) of
// length 16/24/32 bytes (AES-128/192/256).
//
// This is used to produce the "wrapped target key" portion for Vault Transit
// BYOK import.
func Wrap(kek, plaintext []byte) ([]byte, error) {
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, errors.New("kwp: kek must be 16, 24, or 32 bytes")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("kwp: plaintext must be non-empty")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	mlen := len(plaintext)
	n := (mlen + 7) / 8 // number of 64-bit blocks after padding
	padded := make([]byte, n*8)
	copy(padded, plaintext)

	// RFC5649 AIV: 0xA65959A6 + 32-bit big-endian mlen
	A := make([]byte, 8)
	binary.BigEndian.PutUint32(A[0:4], 0xA65959A6)
	binary.BigEndian.PutUint32(A[4:8], uint32(mlen))

	if n == 1 {
		// For a single 64-bit block, RFC5649 uses a single AES invocation over
		// AIV|P1 (16 bytes).
		buf := make([]byte, 16)
		copy(buf[0:8], A)
		copy(buf[8:16], padded[0:8])
		block.Encrypt(buf, buf)
		return buf, nil
	}

	// General case: identical to RFC3394 with initial A=AIV and R[1..n]=P.
	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], padded[i*8:(i+1)*8])
	}

	// 6 rounds, j=0..5; i=1..n
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[0:8], A)
			copy(buf[8:16], R[i])
			block.Encrypt(buf, buf)

			t := uint64((j * n) + i + 1) // (j*n)+i, but i is 1-based in spec
			for k := 0; k < 8; k++ {
				A[k] = buf[k] ^ byte(t>>(56-8*k))
			}
			copy(R[i], buf[8:16])
		}
	}

	out := make([]byte, 8+n*8)
	copy(out[0:8], A)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:], R[i])
	}
	return out, nil
}
