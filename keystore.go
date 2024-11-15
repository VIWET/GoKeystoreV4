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
