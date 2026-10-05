package fuzz

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func randomString(n int) (string, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func md5Hash(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}
