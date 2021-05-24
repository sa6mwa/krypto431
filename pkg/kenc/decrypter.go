package kenc

import (
	"bytes"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

type Decrypter interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	OpenKey(name string) (keystore.Key, error)
	Close() error
}

func NewDectypter(store keystore.KeyStore) Decrypter {
	d := encDec{
		store:   store,
		buf:     bytes.NewBuffer(nil),
		encrypt: false,
	}
	return &d
}
