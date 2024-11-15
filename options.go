package gokeystorev4

import "fmt"

// Generic option
type Option[T any] func(T) error

// Type alias
type CryptoOption = Option[*Crypto]

// WithKDF sets KDFunction
func WithKDF(kdf KDFunction) CryptoOption {
	return func(crypto *Crypto) error {
		switch kdf.Function() {
		case ScryptName, PBKDF2Name:
		default:
			return fmt.Errorf("unknown key derivation function: %s", kdf.Function())
		}

		crypto.KDF.Function = kdf.Function()
		crypto.KDF.Params = kdf
		return nil
	}
}

// WithCipher sets CipherFunction
func WithCipher(cipher CipherFunction) CryptoOption {
	return func(crypto *Crypto) error {
		switch cipher.Function() {
		case AES128Name:
		default:
			return fmt.Errorf("unknown cipher function: %s", cipher.Function())
		}

		crypto.Cipher.Function = cipher.Function()
		crypto.Cipher.Params = cipher
		return nil
	}
}

// WithChecksum sets ChecksumFunction
func WithChecksum(checksum ChecksumFunction) CryptoOption {
	return func(crypto *Crypto) error {
		switch checksum.Function() {
		case Sha256Name:
		default:
			return fmt.Errorf("unknown checksum function: %s", checksum.Function())
		}

		crypto.Checksum.Function = checksum.Function()
		crypto.Checksum.Params = checksum
		return nil
	}
}

// Generic option slice
type Options[T any] []Option[T]

// Type aliase
type CryptoOptions = Options[*Crypto]

// Apply all the options
func (opts Options[T]) Apply(obj T) error {
	for _, opt := range opts {
		if err := opt(obj); err != nil {
			return err
		}
	}

	return nil
}
