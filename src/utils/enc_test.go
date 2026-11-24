package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32) // AES-256
	for i := range key {
		key[i] = byte(i)
	}
	msg := []byte("threshold ML-DSA opening of z_j")

	ciphertext, err := Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestEncryptDecryptEmptyMessage(t *testing.T) {
	key := make([]byte, 16) // AES-128
	ciphertext, err := Encrypt(key, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestEncryptUsesAFreshNonceEachCall(t *testing.T) {
	key := make([]byte, 16)
	msg := []byte("same message twice")

	c1, err := Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	c2, err := Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatalf("two Encrypt calls on the same message produced identical ciphertexts - nonce is not being randomized")
	}
}

func TestDecryptDetectsTamperedCiphertext(t *testing.T) {
	key := make([]byte, 16)
	ciphertext, err := Encrypt(key, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xFF // corrupt the last byte (inside GCM's tag)

	if _, err := Decrypt(key, ciphertext); err == nil {
		t.Fatalf("expected Decrypt to reject a tampered ciphertext, got no error")
	}
}

// TestDecryptDetectsMissingSentinel checks the sentinel-block check itself,
// independent of GCM's own authentication: re-encrypt a message that was
// never prefixed with the all-zero block (bypassing Encrypt to do so) and
// confirm Decrypt still rejects it, with ErrMissingSentinel specifically.
func TestDecryptDetectsMissingSentinel(t *testing.T) {
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())

	// Encrypt "hello" directly, without Encrypt's all-zero sentinel prefix.
	ciphertext := gcm.Seal(nonce, nonce, []byte("hello, no sentinel here"), nil)

	_, err = Decrypt(key, ciphertext)
	if !errors.Is(err, ErrMissingSentinel) {
		t.Fatalf("Decrypt error = %v, want ErrMissingSentinel", err)
	}
}
