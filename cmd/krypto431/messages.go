package main

import (
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func tranceiveMessage(c *cli.Context) error {
	o := getOptions(c)
	k := krypto431.New(krypto431.WithPersistence(o.persistence), krypto431.WithInteractive(true))
	defer k.Wipe()
	err := setSaltAndPFK(c, &k)
	if err != nil {
		return err
	}
	return nil
}

func receiveMessage(c *cli.Context) error {
	o := getOptions(c)
	k := krypto431.New(krypto431.WithPersistence(o.persistence), krypto431.WithInteractive(true))
	defer k.Wipe()
	err := setSaltAndPFK(c, &k)
	if err != nil {
		return err
	}
	return nil
}

func dev(c *cli.Context) error {
	persistence := c.String("file")
	k := krypto431.New(krypto431.WithPersistence(persistence))
	err := k.Load()
	if err != nil {
		return err
	}

	/* 	for i := range k.Keys {
	   		groups, err := k.Keys[i].Groups()
	   		if err != nil {
	   			return err
	   		}
	   		fmt.Printf("%d (id: %s, used: %t, keepers: %s):\n'%s'\n\n", len(k.Keys[i].Runes), string(k.Keys[i].Id), k.Keys[i].Used, strings.Join(krypto431.RunesToStrings(&k.Keys[i].Keepers), ", "), string(*groups))
	   		krypto431.Wipe(groups)
	   	}
	*/
	//k.NewTextMessage("Hello world", "VQ, KA", "HELLO")
	err = k.NewTextMessage("Hej, how is it? Hello world")
	if err != nil {
		return err
	}

	for i := range k.Messages {
		err := k.Messages[i].Decipher()
		if err != nil {
			return err
		}
	}

	if c.Bool("save") {
		err := k.Save()
		if err != nil {
			return err
		}
	}

	return nil
}
