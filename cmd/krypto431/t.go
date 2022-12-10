package main

import (
	"fmt"
	"log"
	"strings"

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
		fmt.Printf("%d (id: %s, used: %t, keepers: %s):\n'%s'\n\n", len(k.Keys[i].Runes), string(k.Keys[i].Id), k.Keys[i].Used, strings.Join(krypto431.RunesToStrings(&k.Keys[i].Keepers), ","), string(*groups))
		//krypto.Wipe(groups)
	}

	//k.NewTextMessage("Hello world", "VQ, KA", "HELLO")
	err := k.NewTextMessage("Hello world")
	if err != nil {
		log.Fatal(err)
	}

	//k.Save()

}
