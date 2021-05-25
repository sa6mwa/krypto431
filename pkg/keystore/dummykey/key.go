package dummykey

import "io"

type Key struct {
	buf []byte
}

const keySize = 256

func newKey(keyChar byte) *Key {
	buf := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		buf[i] = keyChar
	}
	return &Key{
		buf: buf,
	}
}

func (k *Key) Name() string {
	return "DUMMY"
}

func (k *Key) BytesLeft() int {
	return len(k.buf)
}

func (k *Key) Read(p []byte) (int, error) {
	if len(k.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, k.buf)
	k.buf = k.buf[n:]
	return n, nil
}
