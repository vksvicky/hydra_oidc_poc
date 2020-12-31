package services

import (
	"crypto/rand"

	log "github.com/sirupsen/logrus"
)

func GenerateKey(length int) []byte {
	key := make([]byte, length)
	read, err := rand.Read(key)
	if err != nil {
		log.Fatalf("could not generate key: %s", err)
	}
	if read != length {
		log.Fatalf("read %d bytes, expected %d bytes", read, length)
	}
	return key
}
