package symetric_key

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDifferentLengthsKey(t *testing.T) {
	otp, err := NewOtp(10)
	if err != nil {
		t.Fatal(err)
	}

	key := NewOtpKey(32)
	if err := key.Random(rand.Reader); err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 10)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	_, err = otp.Encrypt(key, message)
	assert.NotNil(t, err)
}

func TestDifferentLengthsMessage(t *testing.T) {
	otp, err := NewOtp(10)
	if err != nil {
		t.Fatal(err)
	}

	key := NewOtpKey(10)
	if err := key.Random(rand.Reader); err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 32)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	_, err = otp.Encrypt(key, message)
	assert.NotNil(t, err)
}

func TestOtpCorrectness(t *testing.T) {
	otp, err := NewOtp(32)
	if err != nil {
		t.Fatal(err)
	}

	key := NewOtpKey(32)
	if err := key.Random(rand.Reader); err != nil {
		t.Fatal(err)
	}

	message := make([]byte, 32)
	_, err = rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := otp.Encrypt(key, message)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := otp.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, message, plaintext)
}
