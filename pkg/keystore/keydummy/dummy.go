package keydummy

import (
	"io"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

type KeyDummy struct {
	io.Reader
}

func New() *KeyDummy {
	return &KeyDummy{}
}

func (d *KeyDummy) Open() error {
	return nil
}

func (d *KeyDummy) Close() error {
	return nil
}

func (d *KeyDummy) NextKey() (keystore.Key, error) {
	return newKey(), nil
}

func (d *KeyDummy) OpenKey(name string) (keystore.Key, error) {
	return newKey(), nil
}

func (d *KeyDummy) Generate(name string, size int64, rng io.Reader) error {
	return nil
}
