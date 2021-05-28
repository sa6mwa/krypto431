package main

import (
	"fmt"

	"github.com/sa6mwa/krypto431/pkg/krypto"
)

func main() {
	k := krypto.New()

	for i := 0; i < 3; i++ {
		k.GenerateOneKey()
	}

	for i := range k.Keys {
		groups := k.Keys[i].Groups()
		fmt.Printf("%d:\n'%s'\n\n", len(k.Keys[i].Bytes), string(groups))
		//krypto.Wipe(groups)
	}

	k.Wipe()

	//fmt.Printf("%v\n", k.Keys)

}
