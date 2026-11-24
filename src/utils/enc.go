package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Byte length of 0s prepended for key commitment
const sentinelSize = 2 * aes.BlockSize

// Key commitment error when expected 0 blocks don't appear after decrytpion
var ErrMissingSentinel = errors.New("utils: decrypted message is missing the expected all-zero sentinel block")

// Wrapper for AES-GCM Encryption, sampling nonce and prepending 0s for key commitment.
func Encrypt(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("utils: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("utils: creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("utils: generating nonce: %w", err)
	}

	sentinel := make([]byte, sentinelSize)
	padded := append(sentinel, msg...)

	// Prepend the nonce to the output so Decrypt can recover it.
	return gcm.Seal(nonce, nonce, padded, nil), nil
}

// Wrapper for AES-GCM Decryption checking with extra check for 0 blocks to get key commitment.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("utils: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("utils: creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("utils: ciphertext shorter than the nonce (%d bytes)", nonceSize)
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]

	padded, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("utils: decrypting: %w", err)
	}

	if len(padded) < sentinelSize {
		return nil, ErrMissingSentinel
	}
	sentinel, msg := padded[:sentinelSize], padded[sentinelSize:]
	if subtle.ConstantTimeCompare(sentinel, make([]byte, sentinelSize)) != 1 {
		return nil, ErrMissingSentinel
	}

	return msg, nil
}
