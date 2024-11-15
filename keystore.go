package gokeystorev4

import "github.com/google/uuid"

const KeystoreVersion = 4

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

func Decrypt(keystore *Keystore, password string) ([]byte, error) {
	return keystore.Crypto.Decrypt(ProcessPassword(password))
}
