package krypto

import (
	"testing"
)

var (
	shortTestKey = &Key{
		Id:    []byte("UGXLV"),
		Bytes: []byte("IKWZHPUXQXDNYWTCPKIVLVGWBKGRJYTWQDDPKLYIMSSHYQXOLLIBAOXTZGBCQLYEXCLZKRVTLXEZULTEJKUAERIOXVHIGXJEFIWF"),
	}
)

func TestGenerateOneKey(t *testing.T) {
	keySize := 1000
	k := New(WithKeyLength(keySize))
	t.Log("Generating...")
	key := k.GenerateOneKey()
	if len(key.Bytes) != keySize {
		t.Errorf("Key is %d bytes long, wanted %d", len(key.Bytes), keySize)
	}
	if len(key.Id) != k.GroupSize {
		t.Errorf("KeyId is not the group size (wanted %d, got %d)", k.GroupSize, len(key.Id))
	}
	for _, b := range key.Bytes {
		if !(b >= 'A' && b <= 'Z') {
			t.Error("Key letters are not between A and Z")
		}
	}
	t.Logf("OK, here is key id %s: %s", string(key.Id), string(key.Bytes))
}
