// Written in 2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// Package siphash implements SipHash-2-4, a fast short-input PRF
// created by Jean-Philippe Aumasson and Daniel J. Bernstein.
package siphash

import (
	"encoding/binary"
	"hash"
)

const (
	// The block size of hash algorithm in bytes.
	BlockSize = 8
	// The size of hash output in bytes.
	Size = 8
	// Number of c iterations.
	CRounds = 2
	// Number of d iterations.
	DRounds = 4
)

type digest struct {
	v0, v1, v2, v3 uint64  // state
	k0, k1         uint64  // two parts of key
	t              uint8   // message bytes counter (mod 256)
	nx             int     // number of bytes in buffer x
	x              [8]byte // buffer for unprocessed bytes
}

// New returns a new hash.Hash64 computing SipHash-2-4 with 16-byte key.
func New(key []byte) hash.Hash64 {
	d := new(digest)
	d.k0 = binary.LittleEndian.Uint64(key[0:8])
	d.k1 = binary.LittleEndian.Uint64(key[8:16])
	d.Reset()
	return d
}

func (d *digest) Reset() {
	d.v0 = d.k0 ^ 0x736f6d6570736575
	d.v1 = d.k1 ^ 0x646f72616e646f6d
	d.v2 = d.k0 ^ 0x6c7967656e657261
	d.v3 = d.k1 ^ 0x7465646279746573
	d.t = 0
	d.nx = 0
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func block(d *digest, p []uint8) {
	v0, v1, v2, v3 := d.v0, d.v1, d.v2, d.v3

	for len(p) >= BlockSize {
		m := binary.LittleEndian.Uint64(p)

		v3 ^= m
		for i := 0; i < CRounds; i++ {
			v0 += v1
			v2 += v3
			v1 = v1<<13 | v1>>(64-13)
			v3 = v3<<16 | v3>>(64-16)
			v1 ^= v0
			v3 ^= v2
			v0 = v0<<32 | v0>>(64-32)

			v2 += v1
			v0 += v3
			v1 = v1<<17 | v1>>(64-17)
			v3 = v3<<21 | v3>>(64-21)

			v1 ^= v2
			v3 ^= v0
			v2 = v2<<32 | v2>>(64-32)
		}
		v0 ^= m

		p = p[BlockSize:]
		d.t += BlockSize
	}

	d.v0, d.v1, d.v2, d.v3 = v0, v1, v2, v3
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := len(p)
		if n > BlockSize-d.nx {
			n = BlockSize - d.nx
		}
		d.nx += copy(d.x[d.nx:], p)
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum64() uint64 {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	var zeros [8]byte
	d.Write(zeros[:7-d.nx])
	d.t += uint8(d.nx)
	d.Write([]byte{d.t})

	v0, v1, v2, v3 := d.v0, d.v1, d.v2, d.v3
	v2 ^= 0xff
	for i := 0; i < DRounds; i++ {
		v0 += v1
		v2 += v3
		v1 = v1<<13 | v1>>(64-13)
		v3 = v3<<16 | v3>>(64-16)
		v1 ^= v0
		v3 ^= v2
		v0 = v0<<32 | v0>>(64-32)

		v2 += v1
		v0 += v3
		v1 = v1<<17 | v1>>(64-17)
		v3 = v3<<21 | v3>>(64-21)

		v1 ^= v2
		v3 ^= v0
		v2 = v2<<32 | v2>>(64-32)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func (d *digest) Sum(in []byte) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], d.Sum64())
	return append(in, tmp[:]...)
}
