package krypto

import (
	"fmt"
	"math"

	"github.com/sa6mwa/krypto431/pkg/crand"
)

// ContainsKeyID checks if the Instance.Keys slice already contains ID and
// return true if it does, false if it does not.
func (r *Instance) ContainsKeyID(keyID []rune) bool {
	for i := range r.Keys {
		if string(r.Keys[i].ID) == string(keyID) {
			return true
		}
	}
	return false
}

// GenerateKeyID generates an ID. The current implementation simply generates a
// random group not in the Instance construct.
func (r *Instance) GenerateKeyID(key *Key) error {
	key.ID = make([]rune, r.GroupSize)
	for { // if we already have 26*26*26*26*26 keys, this is an infinite loop :)
		for i := range key.ID {
			key.ID[i] = rune(crand.Intn(26)) + rune('A')
		}
		if !r.ContainsKeyID(key.ID) {
			break
		}
		fmt.Println("WARNING!")
	}
	return nil
}

// GenerateOneKey generates a single key and appends it to the Instance.Keys
// slice returning a pointer to the Key object
func (r *Instance) GenerateOneKey() (*Key, error) {
	var key Key
	key.instance = r
	groupsToGenerate := int(math.Ceil(float64(r.KeyLength) / float64(r.GroupSize)))
	err := r.GenerateKeyID(&key)
	if err != nil {
		return nil, err
	}
	key.Runes = make([]rune, int(groupsToGenerate*r.GroupSize))
	for i := range key.Runes {
		key.Runes[i] = rune(crand.Intn(26)) + rune('A')
	}
	r.Keys = append(r.Keys, key)
	return &key, nil
}

// GenerateKeys creates n amount of keys
func (r *Instance) GenerateKeys(n int) error {
	for i := 0; i < n; i++ {
		_, err := r.GenerateOneKey()
		if err != nil {
			return err
		}
	}
	return nil
}
