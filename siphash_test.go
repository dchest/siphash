package siphash

import "testing"

func TestNew(t *testing.T) {
	k := []byte{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	m := []byte{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e}
	result := uint64(0xa129ca6149be45e5)
	h := New(k)
	h.Write(m)
	if sum := h.Sum64(); sum != result {
		t.Errorf("expected %x, got %x", result, sum)
	}
}

var key = []byte{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
var bench = New(key)
var buf = make([]byte, 8<<10)

func BenchmarkHash8(b *testing.B) {
	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:8])
		bench.Sum64()
	}
}

func BenchmarkHash16(b *testing.B) {
	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:16])
		bench.Sum64()
	}
}

func BenchmarkHash40(b *testing.B) {
	b.SetBytes(24)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:16])
		bench.Sum64()
	}
}

func BenchmarkHash64(b *testing.B) {
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:64])
		bench.Sum64()
	}
}

func BenchmarkHash128(b *testing.B) {
	b.SetBytes(128)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:64])
		bench.Sum64()
	}
}

func BenchmarkHash1K(b *testing.B) {
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:1024])
		bench.Sum64()
	}
}

func BenchmarkHash8K(b *testing.B) {
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf)
		bench.Sum64()
	}
}
