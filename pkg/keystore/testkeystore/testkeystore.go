package testkeystore

import (
	"io"
	"math/rand"
	"strconv"

	"github.com/sa6mwa/krypto431/pkg/keystore"
)

type TestKeyStore struct {
	rng      io.Reader
	rndBytes []byte
	nextKey  int
}

func New() *TestKeyStore {
	// Insecure predictable random source for testing only
	rng := rand.New(rand.NewSource(0))
	return &TestKeyStore{
		rng: rng,
	}
}

func (d *TestKeyStore) Open() error {
	return nil
}

func (d *TestKeyStore) Close() error {
	return nil
}

func (d *TestKeyStore) NextKey() (keystore.Key, error) {
	defer func() {
		d.nextKey++
	}()
	keyId := d.nextKey
	offset := keyId * keySize
	err := d.ensureRndBuf(offset)
	if err != nil {
		return nil, err
	}
	name := strconv.Itoa(keyId)
	return newKey(name, d.rndBytes[offset:offset+keySize])
}

func (d *TestKeyStore) OpenKey(name string) (keystore.Key, error) {
	keyId, err := strconv.Atoi(name)
	if err != nil {
		return nil, err
	}
	offset := keyId * keySize
	d.nextKey = keyId + 1
	err = d.ensureRndBuf(offset)
	if err != nil {
		return nil, err
	}
	return newKey(name, d.rndBytes[offset:offset+keySize])
}

func (d *TestKeyStore) Generate(name string, size int64, rng io.Reader) error {
	return nil
}

func (d *TestKeyStore) ensureRndBuf(offset int) error {
	missingBytes := len(d.rndBytes) - offset + keySize
	if missingBytes > 0 {
		buf := make([]byte, missingBytes)
		n, err := io.ReadAtLeast(d.rng, buf, missingBytes)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			buf[i] = byte(int(buf[i])%26) + byte('A')
		}
		d.rndBytes = append(d.rndBytes, buf...)
	}
	return nil
}
