package gokeystorev4

import "github.com/google/uuid"

// KeystoreVersion
const KeystoreVersion = 4

// KeystoreV4
type Keystore struct {
	Crypto      *Crypto   `json:"crypto"`
	Description string    `json:"description,omitempty"`
	PublicKey   PublicKey `json:"pubkey,omitempty"`
	Path        string    `json:"path"`
	UUID        uuid.UUID `json:"uuid"`
	Version     uint64    `json:"version"`
}

func newKeystore(path string) *Keystore {
	return &Keystore{
		Crypto:  DefaultCrypto(),
		Path:    path,
		UUID:    uuid.New(),
		Version: KeystoreVersion,
	}
}

// Encrypt secret key at path using password and options
func Encrypt(secret []byte, password, path string, opts ...KeystoreOption) (*Keystore, error) {
	keystore := newKeystore(path)
	if err := KeystoreOptions(opts).Apply(keystore); err != nil {
		return nil, err
	}

	if err := keystore.Crypto.Encrypt(secret, ProcessPassword(password)); err != nil {
		return nil, err
	}

	return keystore, nil
}

// Decrypt secret key from keystore using password
func Decrypt(keystore *Keystore, password string) ([]byte, error) {
	return keystore.Crypto.Decrypt(ProcessPassword(password))
}
