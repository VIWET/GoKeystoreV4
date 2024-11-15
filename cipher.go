package gokeystorev4

import (
	"crypto/aes"
	"crypto/cipher"
)

// Cipher function interface
type CipherFunction interface {
	Function() string
	Encrypt(secret, key []byte) ([]byte, error)
	Decrypt(key, message []byte) ([]byte, error)
}

// AES128 params
const AES128KeyLen = 16

// AES-128 params
type AES128 struct {
	InitialValue IV `json:"iv"`
}

// NewAES128 with new initial value
func NewAES128() *AES128 {
	return &AES128{
		InitialValue: RandomBytes(AES128KeyLen),
	}
}

// Encrypt data using key
func (c *AES128) Encrypt(data, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key[:AES128KeyLen])
	if err != nil {
		return nil, err
	}

	var (
		message = make([]byte, len(data))
		stream  = cipher.NewCTR(aes, c.InitialValue)
	)

	stream.XORKeyStream(message, data)
	return message, nil
}

// Decrypt data using key
func (c *AES128) Decrypt(key, data []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key[:AES128KeyLen])
	if err != nil {
		return nil, err
	}

	var (
		secret = make([]byte, len(data))
		stream = cipher.NewCTR(aes, c.InitialValue)
	)

	stream.XORKeyStream(secret, data)
	return secret, nil
}

// Function name
func (c *AES128) Function() string { return "aes-128-ctr" }
