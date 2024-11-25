package gokeystorev4

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// RandomBytse generates random bytes sequence of given length
func RandomBytes(length int) []byte {
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		panic(err)
	}
	return random
}

// Hex string
type Hex []byte

// Type aliases
type (
	Salt      = Hex
	IV        = Hex
	PublicKey = Hex
)

// imlp json.Marshaler for Hex
func (h Hex) MarshalJSON() ([]byte, error) {
	hexstr := hex.EncodeToString(h)
	return json.Marshal(&hexstr)
}

// imlp json.Unmarshaler for Hex
func (h *Hex) UnmarshalJSON(data []byte) error {
	var (
		hexstr string
		err    error
	)

	err = json.Unmarshal(data, &hexstr)
	if err != nil {
		return err
	}

	*h, err = hex.DecodeString(hexstr)
	if err != nil {
		return err
	}

	return nil
}
