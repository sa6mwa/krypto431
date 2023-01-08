package kenc

import (
	"bytes"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

type Encrypter interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	GetNextKey() (keystore.Key, error)
	OpenKey(name string) (keystore.Key, error)
	Close() error
}

func NewEncrypter(store keystore.KeyStore) Encrypter {
	e := encDec{
		store:   store,
		buf:     bytes.NewBuffer(nil),
		encrypt: true,
	}
	return &e
}
