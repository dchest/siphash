package siphash

type byteseq interface {
	string | []byte
}

// Hash returns the 64-bit SipHash-2-4 of the given byte slice with two 64-bit
// parts of 128-bit key: k0 and k1.
func Hash(k0, k1 uint64, p []byte) uint64 {
	return HashG(k0, k1, p)
}

// Hash128 returns the 128-bit SipHash-2-4 of the given byte slice with two 64-bit
// parts of 128-bit key: k0 and k1.
//
// Note that 128-bit SipHash is considered experimental by SipHash authors at this time.
func Hash128(k0, k1 uint64, p []byte) (uint64, uint64) {
	return Hash128G(k0, k1, p)
}
