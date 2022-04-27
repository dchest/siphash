//go:build amd64 && !appengine && !gccgo

// Written in 2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// This file contains a function definition for use with assembly implementations of Hash()

package siphash

import "unsafe"

//go:noescape
func _hash(k0, k1 uint64, b string) uint64

// HashG returns the 64-bit SipHash-2-4 of the given byte slice or string with two 64-bit
// parts of 128-bit key: k0 and k1.
func HashG[T byteseq](k0, k1 uint64, b T) uint64 {
	// T is string or []byte which can be safely cast to string
	return _hash(k0, k1, *(*string)(unsafe.Pointer(&b)))
}

//go:noescape
func _hash128(k0, k1 uint64, b string) (uint64, uint64)

// Hash128G returns the 128-bit SipHash-2-4 of the given byte slice or string with two
// 64-bit parts of 128-bit key: k0 and k1.
func Hash128G[T byteseq](k0, k1 uint64, b T) (uint64, uint64) {
	// T is string or []byte which can be safely cast to string
	return _hash128(k0, k1, *(*string)(unsafe.Pointer(&b)))
}
