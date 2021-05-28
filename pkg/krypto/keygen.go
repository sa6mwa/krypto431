package krypto

import (
	"bytes"
	"fmt"
	"math"

	"github.com/sa6mwa/krypto431/pkg/crand"
)

// Instance.ContainsKeyId(keyId []byte) checks if the Instance.Keys slice
// already contains Id and return true if it does, false if it does not.
func (r *Instance) ContainsKeyId(keyId []byte) bool {
	for i := range r.Keys {
		if bytes.Compare(r.Keys[i].Id, keyId) == 0 {
			return true
		}
	}
	return false
}

// Instance.GenerateKeyId(key *Key) generates an Id. The current
// implementation simply generates a random group not in the Instance
// construct.
func (r *Instance) GenerateKeyId(key *Key) error {
	key.Id = make([]byte, r.GroupSize)
	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.Id {
			key.Id[i] = byte(crand.Intn(26)) + byte('A')
		}
		if r.ContainsKeyId(key.Id) == false {
			break
		}
		fmt.Println("WARNING!")
	}
	return nil
}

// Instance.GenerateOneKey() generates a single key and appends it to the
// Instance.Keys slice returning a pointer to the Key object
func (r *Instance) GenerateOneKey() *Key {
	var key Key
	key.instance = r
	groupsToGenerate := int(math.Ceil(float64(r.KeyLength) / float64(r.GroupSize)))
	r.GenerateKeyId(&key)
	key.Bytes = make([]byte, int(groupsToGenerate*r.GroupSize))
	for i := range key.Bytes {
		key.Bytes[i] = byte(crand.Intn(26)) + byte('A')
	}
	r.Keys = append(r.Keys, key)
	return &key
}

func (r *Instance) GenerateKeys(n int) error {
	for i := 0; i < n; i++ {
		r.GenerateOneKey()
	}
	return nil
}
