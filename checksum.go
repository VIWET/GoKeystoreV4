package gokeystorev4

import "crypto/sha256"

// Checksum function interface
type ChecksumFunction interface {
	Function() string
	Checksum(key, cipher []byte) []byte
}

// Sha256 function
type Sha256 struct{}

// NewSha256
func NewSha256() *Sha256 {
	return &Sha256{}
}

// Checksum key and cipher
func (c *Sha256) Checksum(key, cipher []byte) []byte {
	data := append(key[16:32], cipher...)
	hash := sha256.Sum256(data)
	return hash[:]
}

// Function name
func (c *Sha256) Function() string { return "sha256" }
