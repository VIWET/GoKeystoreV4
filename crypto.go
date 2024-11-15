package gokeystorev4

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Crypto modules of keystore
type Crypto struct {
	KDF      *Module[KDFunction]       `json:"kdf"`
	Cipher   *Module[CipherFunction]   `json:"cipher"`
	Checksum *Module[ChecksumFunction] `json:"checksum"`
}

// Default Crypto with Scrypt, AES128 and Sha256
func DefaultCrypto() *Crypto {
	var (
		kdf      = NewScrypt()
		cipher   = NewAES128()
		checksum = NewSha256()
	)

	return &Crypto{
		KDF: &Module[KDFunction]{
			Function: kdf.Function(),
			Params:   kdf,
		},
		Cipher: &Module[CipherFunction]{
			Function: cipher.Function(),
			Params:   cipher,
		},
		Checksum: &Module[ChecksumFunction]{
			Function: checksum.Function(),
			Params:   checksum,
		},
	}
}

// NewCrypto with options or default
func NewCrypto(options ...CryptoOption) (*Crypto, error) {
	crypto := DefaultCrypto()
	if err := CryptoOptions(options).Apply(crypto); err != nil {
		return nil, err
	}

	return crypto, nil
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

// Generic crypto module
type Module[T any] struct {
	Function string `json:"function"`
	Params   T      `json:"params"`
	Message  Hex    `json:"message"`
}

// ModuleJSON representation
type ModuleJSON struct {
	Function string          `json:"function"`
	Params   json.RawMessage `json:"params"`
	Message  Hex             `json:"message"`
}

// CryptoJSON representation
type CryptoJSON struct {
	KDF      *ModuleJSON `json:"kdf"`
	Cipher   *ModuleJSON `json:"cipher"`
	Checksum *ModuleJSON `json:"checksum"`
}

// impl json.Unmarshaler for Crypto
func (c *Crypto) UnmarshalJSON(data []byte) error {
	var crypto CryptoJSON
	if err := json.Unmarshal(data, &crypto); err != nil {
		return err
	}

	var err error
	switch crypto.KDF.Function {
	case ScryptName:
		c.KDF, err = unmarshalModule[KDFunction](new(Scrypt), crypto.KDF)
	case PBKDF2Name:
		c.KDF, err = unmarshalModule[KDFunction](new(PBKDF2), crypto.KDF)
	default:
		return fmt.Errorf("unknown key derivation function: %s", crypto.KDF.Function)
	}
	if err != nil {
		return fmt.Errorf("failed to unmarshal KDF module: %w", err)
	}

	switch crypto.Cipher.Function {
	case AES128Name:
		c.Cipher, err = unmarshalModule[CipherFunction](new(AES128), crypto.Cipher)
	default:
		return fmt.Errorf("unknown cipher function: %s", crypto.Cipher.Function)
	}
	if err != nil {
		return fmt.Errorf("failed to unmarshal Cipher module: %w", err)
	}

	switch crypto.Checksum.Function {
	case Sha256Name:
		c.Checksum, err = unmarshalModule[ChecksumFunction](new(Sha256), crypto.Checksum)
	default:
		return fmt.Errorf("unknown checksum function: %s", crypto.Checksum.Function)
	}
	if err != nil {
		return fmt.Errorf("failed to unmarshal Checksum module: %w", err)
	}

	return nil
}

func unmarshalModule[T any](params T, module *ModuleJSON) (*Module[T], error) {
	if err := json.Unmarshal(module.Params, params); err != nil {
		return nil, err
	}

	return &Module[T]{
		Function: module.Function,
		Params:   params,
		Message:  module.Message,
	}, nil
}
