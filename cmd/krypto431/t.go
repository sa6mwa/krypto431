package main

import (
	"fmt"

	"github.com/sa6mwa/krypto431"
)

func main() {
	k := krypto431.New()
	k.Load()

	/* 	for i := 0; i < 3; i++ {
	   		fmt.Printf("Generated key with id: %s\n", string(*k.NewKey()))
	   	}
	*/
	for i := range k.Keys {
		groups, err := k.Keys[i].Groups()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%d:\n'%s'\n\n", len(k.Keys[i].Runes), string(*groups))
		//krypto.Wipe(groups)
	}

	//k.NewTextMessage("Hello world", "VQ, KA", "HELLO")
	k.NewTextMessage("Hello world")

	//k.Save()

}
