package krypto431

import (
	"testing"
)

var (
/*
	shortTestKey = &Key{
		Id:    []rune("UGXLV"),
		Runes: []rune("IKWZHPUXQXDNYWTCPKIVLVGWBKGRJYTWQDDPKLYIMSSHYQXOLLIBAOXTZGBCQLYEXCLZKRVTLXEZULTEJKUAERIOXVHIGXJEFIWF"),
	}
*/
)

func TestGenerateOneKey(t *testing.T) {
	keySize := 1000
	k := New(WithKeyLength(keySize))
	t.Log("Generating...")
	key, err := k.GenerateOneKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Runes) != keySize {
		t.Errorf("Key is %d runes long, wanted %d", len(key.Runes), keySize)
	}
	if len(key.Id) != k.GroupSize {
		t.Errorf("KeyId is not the group size (wanted %d, got %d)", k.GroupSize, len(key.Id))
	}
	for _, b := range key.Runes {
		if !(b >= 'A' && b <= 'Z') {
			t.Error("Key letters are not between A and Z")
		}
	}
	t.Logf("OK, here is key id %s: %s", string(key.Id), string(key.Runes))
}
