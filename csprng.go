package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
)

// credit for user-friendly access to crypto/rand goes to prof. Stefan Nilsson:
// https://yourbasic.org/golang/crypto-rand-int/
type cryptoSource struct{}

func (s cryptoSource) Seed(seed int64) {}
func (s cryptoSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}
func (s cryptoSource) Uint64() (v uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	var src cryptoSource
	rnd := rand.New(src)

	slice := []string{
		"alpha", "bravo", "charlie", "delta",
	}

	fmt.Println(slice[rnd.Intn(len(slice))])
}
