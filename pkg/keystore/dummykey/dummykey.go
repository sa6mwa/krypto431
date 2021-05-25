package dummykey

import (
	"io"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

type DummyKey struct {
	keyChar byte
}

func New() *DummyKey {
	return &DummyKey{
		keyChar: 'A',
	}
}

func (d *DummyKey) SetKeyChar(keyChar byte) {
	d.keyChar = keyChar
}

func (d *DummyKey) Open() error {
	return nil
}

func (d *DummyKey) Close() error {
	return nil
}

func (d *DummyKey) NextKey() (keystore.Key, error) {
	return newKey(d.keyChar), nil
}

func (d *DummyKey) OpenKey(name string) (keystore.Key, error) {
	return newKey(d.keyChar), nil
}

func (d *DummyKey) Generate(name string, size int64, rng io.Reader) error {
	return nil
}
