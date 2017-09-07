// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package salsa20 implements the Salsa20 stream cipher as specified in https://cr.yp.to/snuffle/spec.pdf.

Salsa20 differs from many other stream ciphers in that it is message orientated
rather than byte orientated. Keystream blocks are not preserved between calls,
therefore each side must encrypt/decrypt data with the same segmentation.

Another aspect of this difference is that part of the counter is exposed as
a nonce in each call. Encrypting two different messages with the same (key,
nonce) pair leads to trivial plaintext recovery. This is analogous to
encrypting two different messages with the same key with a traditional stream
cipher.

This package also implements XSalsa20: a version of Salsa20 with a 24-byte
nonce as specified in https://cr.yp.to/snuffle/xsalsa-20081128.pdf. Simply
passing a 24-byte slice as the nonce triggers XSalsa20.
*/
package salsa20 // import_ "golang.org/x/crypto/salsa20"

// TODO(agl): implement XORKeyStream12 and XORKeyStream8 - the reduced round variants of Salsa20.

import (
	"crypto/salsa20/salsa"
)

// XORKeyStream crypts bytes from in to out using the given key and nonce. In
// and out may be the same slice but otherwise should not overlap. Nonce must
// be either 8 or 24 bytes long.
func XORKeyStream(out, in []byte, nonce []byte, key *[32]byte) {
	xorKeyStream(out, in, nonce, key, &salsa.Sigma32, 20)
}

func XORKeyStreamWithRounds(out, in []byte, nonce []byte, key *[]byte, rounds int) {
	keyArr, sigma := preKey(key)
	xorKeyStream(out, in, nonce, keyArr, sigma, rounds)

}

func xorKeyStream(out, in []byte, nonce []byte, key *[32]byte, sigma *[16]byte, rounds int) {
	if rounds <= 0 {
		rounds = 20
	} else if rounds != 8 && rounds != 12 && rounds != 20 {
		panic("salsa20: rounds must be 8, 12, 20")
	}
	if len(out) < len(in) {
		in = in[:len(out)]
	}
	var subNonce [16]byte

	if len(nonce) == 24 {
		var subKey [32]byte
		var hNonce [16]byte
		copy(hNonce[:], nonce[:16])
		salsa.HSalsa20(&subKey, &hNonce, key, sigma, rounds)
		copy(subNonce[:], nonce[16:])
		key = &subKey
	} else if len(nonce) == 8 {
		copy(subNonce[:], nonce[:])
	} else {
		panic("salsa20: nonce must be 8 or 24 bytes")
	}

	salsa.XORKeyStream(out, in, &subNonce, key, sigma, rounds)
}

func preKey(keySlice *[]byte) (*[32]byte, *[16]byte) {
	var array [32]byte
	var sigma [16]byte

	if len(*keySlice) == 32 {
		sigma = salsa.Sigma32
		copy(array[:], *keySlice)
	} else if len(*keySlice) == 16 {
		sigma = salsa.Sigma16
		copy(array[0:16], *keySlice)
		copy(array[16:32], *keySlice)
	} else {
		panic("salsa20: key must be 32 or 16 bytes.")
	}

	return &array, &sigma
}
