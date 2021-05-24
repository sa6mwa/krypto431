package keystore

import (
	"fmt"
	"io"
)

var (
	ErrNotOpen        = fmt.Errorf("not open")
	ErrNoMoreKeys     = fmt.Errorf("no more keys available")
	ErrKeyNotFound    = fmt.Errorf("key not found")
	ErrInvalidKeyData = fmt.Errorf("invalid key data, only A-Z allowed")
)

type Key interface {
	Name() string
	Read(p []byte) (int, error)
	BytesLeft() int
}

type KeyStore interface {
	Open() error
	Close() error
	OpenKey(name string) (Key, error)
	NextKey() (Key, error)
	Generate(name string, size int64, rndGen io.Reader) error
}
