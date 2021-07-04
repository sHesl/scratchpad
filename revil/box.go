package revil

import (
	"crypto/rand"
	"io"
)

type BoxECCKey *[32]byte
type BoxDecryptorKey *[32]byte // Salsa20 key
type BoxNonce *[24]byte

// Decryptor contains all the information required to perform a box.OpenAfterPrecomputation,
// where the 'Key' is the XSalsa20 shared encryption key that actually encrypts the data.
// This key is obtained via box.Precompute where public and private keys are known.
type Decryptor struct {
	Nonce BoxNonce
	Key   BoxDecryptorKey
}

func nonce() BoxNonce {
	var n []byte
	io.ReadFull(rand.Reader, n)

	var nonce [24]byte
	copy(nonce[:], n)

	return &nonce
}
