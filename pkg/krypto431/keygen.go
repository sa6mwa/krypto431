package krypto431

import (
	"bytes"
	"fmt"
	"math"

	"github.com/sa6mwa/krypto431/pkg/crand"
)

// Krypto431.ContainsKeyId(keyId []byte) checks if the Krypto431.Keys slice
// already contains keyId and return true if it does, false if it does not.
func (k *Krypto431) ContainsKeyId(keyId []byte) bool {
	for i := range k.Keys {
		if bytes.Compare(k.Keys[i].KeyId, keyId) == 0 {
			return true
		}
	}
	return false
}

// Krypto431.GenerateKeyId(key *Key) generates a KeyId. The current
// implementation simply generates a random group not in the Krypto431
// construct.
func (k *Krypto431) GenerateKeyId(key *Key) error {
	key.KeyId = make([]byte, k.GroupSize)
	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.KeyId {
			key.KeyId[i] = byte(crand.Intn(26)) + byte('A')
		}
		if k.ContainsKeyId(key.KeyId) == false {
			break
		}
		fmt.Println("WARNING!")
	}
	return nil
}

// Krypto431.GenerateOneKey() generates a single key and appends it to the
// Krypto431.Keys slice
func (k *Krypto431) GenerateOneKey() error {
	var key Key
	key.instance = k
	groupsToGenerate := int(math.Ceil(float64(k.KeyLength) / float64(k.GroupSize)))
	k.GenerateKeyId(&key)
	key.Bytes = make([]byte, int(groupsToGenerate*k.GroupSize))
	for i := range key.Bytes {
		key.Bytes[i] = byte(crand.Intn(26)) + byte('A')
	}
	k.Keys = append(k.Keys, key)
	return nil
}

func (k *Krypto431) GenerateKeys(n int) error {
	for i := 0; i < n; i++ {
		k.GenerateOneKey()
	}
	return nil
}
