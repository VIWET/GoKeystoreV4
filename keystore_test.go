package gokeystorev4_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	v4 "github.com/viwet/GoKeystoreV4"
)

func Test_EncryptDecrypt(t *testing.T) {
	f := func(t *testing.T, filePath string) {
		keystore, key, password := LoadTestVector(t, filePath)
		decrypted, err := v4.Decrypt(keystore, password)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(key, decrypted) {
			t.Fatal("invalid key decrypted")
		}

		encrypted, err := v4.Encrypt(
			key,
			password,
			keystore.Path,
			v4.WithCrypto(
				v4.WithKDF(keystore.Crypto.KDF.Params),
				v4.WithCipher(keystore.Crypto.Cipher.Params),
				v4.WithChecksum(keystore.Crypto.Checksum.Params),
			),
			v4.WithPublicKey(keystore.PublicKey),
			v4.WithDescription(keystore.Description),
		)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encrypted.Crypto.Cipher.Message, keystore.Crypto.Cipher.Message) {
			t.Fatal("invalid ecryption: cipher")
		}
		if !bytes.Equal(encrypted.Crypto.Checksum.Message, keystore.Crypto.Checksum.Message) {
			t.Fatal("invalid ecryption: checkusm")
		}
		if !bytes.Equal(encrypted.PublicKey, keystore.PublicKey) {
			t.Fatal("invalid ecryption: public key")
		}
		if encrypted.Description != keystore.Description {
			t.Fatal("invalid ecryption: description")
		}
	}

	f(t, "tests/pbkdf2_keystore.json")
	f(t, "tests/scrypt_keystore.json")
}

func LoadTestVector(t *testing.T, filePath string) (*v4.Keystore, []byte, string) {
	t.Helper()

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var keystore v4.Keystore
	if err := json.NewDecoder(file).Decode(&keystore); err != nil {
		t.Fatal(err)
	}

	key, err := hex.DecodeString("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	if err != nil {
		t.Fatal(err)
	}

	password := "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"

	return &keystore, key, password
}
