package main

import (
	"fmt"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func dev(c *cli.Context) error {
	o := getOptions(c)
	k := krypto431.New(krypto431.WithPersistence(o.persistence), krypto431.WithInteractive(true))
	defer k.Wipe()
	err := setSaltAndPFK(c, &k)
	if err != nil {
		return err
	}
	err = k.Load()
	if err != nil {
		return err
	}
	defer k.Wipe()

	_, err = k.PromptNewTextMessage()
	if err != nil {
		return err
	}

	for i := range k.Messages {
		fmt.Printf("%#v"+LineBreak, k.Messages[i])
	}

	err = k.Save()
	if err != nil {
		return err
	}

	return nil
}
