# Go KeystoreV4

Golang implementation of EIP-2335 BLS12-381 KeystoreV4

# Example

```Go
package main

import (
	"encoding/hex"
	"log"
	"strings"

	keystore "github.com/viwet/GoKeystoreV4"
)

const (
	SecretKey     = "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	PublicKey     = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
	SecretKeyPath = "m/12381/60/0/0"
	Description   = "Keystore description"
	Password      = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
)

func main() {
	secret, err := hex.DecodeString(strings.TrimPrefix(SecretKey, "0x"))
	if err != nil {
		log.Fatal(err)
	}
	pubkey, err := hex.DecodeString(strings.TrimPrefix(PublicKey, "0x"))
	if err != nil {
		log.Fatal(err)
	}

	keystore, err := keystore.Encrypt(
		secret,
		Password,
		SecretKeyPath,
		// Optional params
		keystore.WithPublicKey(pubkey),
		keystore.WithDescription(Description),
		keystore.WithCrypto(
			keystore.WithKDF(keystore.NewScrypt()), // or keystore.WithKDF(keystore.NewPBKDF2())
			keystore.WithCipher(keystore.NewAES128()),
			keystore.WithChecksum(keystore.NewSha256()),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	...
}
```
