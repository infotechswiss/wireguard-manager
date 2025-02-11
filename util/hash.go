package util

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const BcryptCost = 14 // Bcrypt cost factor (adjust as needed)

// HashPassword hashes the provided plaintext password using bcrypt and returns
// a base64-encoded hash. Returns an error if hashing fails or if the password is empty.
func HashPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("cannot hash password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hashed), nil
}

// VerifyHash compares a plaintext password with a base64-encoded bcrypt hash.
// It returns true if the password matches the hash. If the password does not match,
// it returns false with no error.
func VerifyHash(base64Hash, plaintext string) (bool, error) {
	hash, err := base64.StdEncoding.DecodeString(base64Hash)
	if err != nil {
		return false, fmt.Errorf("cannot decode base64 hash: %w", err)
	}
	err = bcrypt.CompareHashAndPassword(hash, []byte(plaintext))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot verify password: %w", err)
	}
	return true, nil
}
