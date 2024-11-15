package gokeystorev4

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	_ KDFunction = (&Scrypt{})
	_ KDFunction = (&PBKDF2{})
)

// Default Scrypt params
const (
	ScryptDKLen = 32
	ScryptN     = 1 << 18
	ScryptR     = 8
	ScryptP     = 1

	ScryptName = "scrypt"
)

// Default Scrypt params
const (
	PBKDF2DKLen = 32
	PBKDF2C     = 1 << 18
	PBKDF2PRF   = "hmac-sha256"

	PBKDF2Name = "pbkdf2"
)

// Key derivation function interface
type KDFunction interface {
	Function() string
	DeriveKey(password []byte) ([]byte, error)
}

// Scrypt params
type Scrypt struct {
	DKLen int  `json:"dklen"`
	N     int  `json:"n"`
	R     int  `json:"r"`
	P     int  `json:"p"`
	Salt  Salt `json:"salt"`
}

// NewScrypt with default params and new salt
func NewScrypt() *Scrypt {
	return &Scrypt{
		DKLen: ScryptDKLen,
		N:     ScryptN,
		R:     ScryptR,
		P:     ScryptP,
		Salt:  RandomBytes(32),
	}
}

// DeriveKey from password using provided params
func (kdf *Scrypt) DeriveKey(password []byte) ([]byte, error) {
	return scrypt.Key(password, kdf.Salt, kdf.N, kdf.R, kdf.P, kdf.DKLen)
}

// Function name
func (kdf *Scrypt) Function() string { return ScryptName }

// PBKDF2 params
type PBKDF2 struct {
	DKLen int    `json:"dklen"`
	C     int    `json:"c"`
	PRF   string `json:"prf"`
	Salt  Salt   `json:"salt"`
}

// NewPBKDF2 with default params and new salt
func NewPBKDF2() *PBKDF2 {
	return &PBKDF2{
		DKLen: PBKDF2DKLen,
		C:     PBKDF2C,
		PRF:   PBKDF2PRF,
		Salt:  RandomBytes(32),
	}
}

// DeriveKey from password using provided params
func (kdf *PBKDF2) DeriveKey(password []byte) ([]byte, error) {
	return pbkdf2.Key(password, kdf.Salt, kdf.C, kdf.DKLen, sha256.New), nil
}

// Function name
func (kdf *PBKDF2) Function() string { return PBKDF2Name }
