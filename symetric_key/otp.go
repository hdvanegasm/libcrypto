package symetric_key

import (
	"errors"
	"io"
)

type Otp struct {
	keySize uint32
}

func NewOtp(keySize uint32) (*Otp, error) {
	if keySize == 0 {
		return nil, errors.New("key size must be a positive number")
	}
	return &Otp{keySize: keySize}, nil
}

func (s Otp) Encrypt(key Key, message []byte) ([]byte, error) {
	if s.keySize != uint32(key.Size()) {
		return nil, errors.New("invalid key size")
	}
	if s.keySize != uint32(len(message)) {
		return nil, errors.New("invalid message size ")
	}

	ciphertext := make([]byte, s.keySize)
	for i := 0; i < len(message); i++ {
		ciphertext[i] = key.Bytes()[i] ^ message[i]
	}
	return ciphertext, nil
}

func (s Otp) Decrypt(key Key, ciphertext []byte) ([]byte, error) {
	if s.keySize != uint32(key.Size()) {
		return nil, errors.New("invalid key size")
	}
	if s.keySize != uint32(len(ciphertext)) {
		return nil, errors.New("invalid message size ")
	}

	message := make([]byte, key.Size())
	for i := 0; i < len(message); i++ {
		message[i] = key.Bytes()[i] ^ ciphertext[i]
	}
	return message, nil
}

type OtpKey []byte

func (k OtpKey) Bytes() []byte {
	return []byte(k)
}

func (k OtpKey) Size() int {
	return len(k)
}

func NewOtpKey(keySize int) OtpKey {
	key := make([]byte, keySize)
	return OtpKey(key)
}

func (k OtpKey) FromBytes(bytes []byte) error {
	if len(bytes) != len(k) {
		return errors.New("invalid key size. The provided bytes must have the same length as the key size")
	}
	copy(k, bytes)
	return nil
}

func (k OtpKey) Random(rng io.Reader) error {
	_, err := rng.Read(k)
	return err
}
