package kenc

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

const moduloMr = 26

type encDec struct {
	store   keystore.KeyStore
	buf     *bytes.Buffer
	bufM    sync.Mutex
	curKey  keystore.Key
	encrypt bool
	closed  bool
}

func (e *encDec) Read(p []byte) (int, error) {
	e.bufM.Lock()
	defer e.bufM.Unlock()
	if e.closed {
		return 0, io.EOF
	}
	return e.buf.Read(p)
}

// Write writes data to be encrypted
func (e *encDec) Write(p []byte) (int, error) {
	pLen := len(p)
	keyBuf := make([]byte, pLen)
	outBuf := make([]byte, pLen)
	_, err := io.ReadAtLeast(e.curKey, keyBuf, pLen)
	if err != nil {
		return 0, fmt.Errorf("error reading key: %w", err)
	}
	for i := 0; i < pLen; i++ {
		if e.encrypt {
			outBuf[i] = byte(mod(int(p[i]-'A')+int(keyBuf[i]-'A'), moduloMr)) + 'A'
		} else {
			outBuf[i] = byte(mod(int(p[i]-'A')-int(keyBuf[i]-'A'), moduloMr)) + 'A'
		}
	}
	e.bufM.Lock()
	defer e.bufM.Unlock()
	if e.closed {
		return 0, fmt.Errorf("closed")
	}
	return e.buf.Write(outBuf)
}

// GetNextKey assigns and returns the key to be used on the next write(s)
func (e *encDec) GetNextKey() (keystore.Key, error) {
	var err error
	e.curKey, err = e.store.NextKey()
	if err != nil {
		return nil, fmt.Errorf("key error: %w", err)
	}
	return e.curKey, nil
}

// OpenKey assigns and returns the specified key to be used on the next write(s)
func (e *encDec) OpenKey(name string) (keystore.Key, error) {
	var err error
	e.curKey, err = e.store.OpenKey(name)
	if err != nil {
		return nil, fmt.Errorf("key error: %w", err)
	}
	return e.curKey, nil
}

func (e *encDec) Close() error {
	e.bufM.Lock()
	defer e.bufM.Unlock()
	e.closed = true
	return e.store.Close()
}

func mod(a, b int) int {
	return (a%b + b) % b
}
