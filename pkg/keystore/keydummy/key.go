package keydummy

type Key struct {
	buf []byte
}

const keySize = 256

func newKey() *Key {
	buf := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		buf[i] = 'A'
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
	n := copy(p, k.buf)
	k.buf = k.buf[n:]
	return n, nil
}
