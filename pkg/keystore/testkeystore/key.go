package testkeystore

import "io"

type Key struct {
	buf  []byte
	name string
}

const keySize = 256

func newKey(name string, buf []byte) (*Key, error) {
	return &Key{
		buf:  buf,
		name: name,
	}, nil
}

func (k *Key) Name() string {
	return k.name
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
