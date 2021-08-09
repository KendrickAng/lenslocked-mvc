package rand

import (
	"crypto/rand"
	"encoding/base64"
)

// this package will be a wrapper around the crypto/rand package.

const RememberTokenBytes = 32

func RememberToken() (string, error) {
	return String(RememberTokenBytes)
}

// generates a byte slice of size nBytes, returns a base64 encoded version of it as a string
func String(nBytes int) (string, error) {
	b, err := Bytes(nBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generate n random bytes, returns error if any
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
