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
	// Name returns the name of the key
	Name() string
	// Read reads key data
	Read(p []byte) (int, error)
	// BytesLeft returns the bytes left of this key
	BytesLeft() int
}

type KeyStore interface {
	// Open opens the key store
	Open() error
	// Close closes the key store
	Close() error
	// OpenKey opens the key and applies it for use on the next write
	OpenKey(name string) (Key, error)
	// NextKey returns the next key, but doesn't apply it for use
	// Run OpenKey to apply the key returned by NextKey
	NextKey() (Key, error)
	// Generate allows a new key to be generated and saved
	Generate(name string, size int64, rndGen io.Reader) error
}
