package gokeystorev4

import (
	"bytes"
	"fmt"
)

type ModuleFunction struct {
	Function string `json:"function"`
}

// Generic crypto module
type Module[T any] struct {
	ModuleFunction
	Params  T   `json:"params"`
	Message Hex `json:"message"`
}

// Crypto modules of keystore
type Crypto struct {
	KDF      *Module[KDFunction]       `json:"kdf"`
	Cipher   *Module[CipherFunction]   `json:"cipher"`
	Checksum *Module[ChecksumFunction] `json:"checksum"`
}

// Encrypt secret key using password
func (crypto *Crypto) Encrypt(secret, password []byte) error {
	var (
		kdf      = crypto.KDF.Params
		cipher   = crypto.Cipher.Params
		checksum = crypto.Checksum.Params
	)

	key, err := kdf.DeriveKey(password)
	if err != nil {
		return fmt.Errorf("failed to derive key from password: %w", err)
	}

	cip, err := cipher.Encrypt(secret, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	crypto.Cipher.Message = cip
	crypto.Checksum.Message = checksum.Checksum(key, cip)

	return nil
}

// Decrypt secret key using password
func (crypto *Crypto) Decrypt(password []byte) ([]byte, error) {
	var (
		kdf      = crypto.KDF.Params
		cipher   = crypto.Cipher.Params
		checksum = crypto.Checksum.Params
	)

	key, err := kdf.DeriveKey(password)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from password: %w", err)
	}

	cip := crypto.Cipher.Message
	if !bytes.Equal(crypto.Checksum.Message, checksum.Checksum(key, cip)) {
		return nil, fmt.Errorf("failed to validate key: invalid checksum")
	}

	secret, err := cipher.Decrypt(key, cip)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return secret, nil
}
