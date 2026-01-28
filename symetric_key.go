package libcrypto

import (
	"io"
)

type EncryptionScheme interface {
	Encrypt(key Key, message []byte) ([]byte, error)
	Decrypt(key Key, ciphertext []byte) ([]byte, error)
}

type Key interface {
	Bytes() []byte
	FromBytes(bytes []byte) error
	Size() int
	Random(rng io.Reader) error
}
