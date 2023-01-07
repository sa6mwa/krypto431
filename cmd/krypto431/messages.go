package main

import (
	"fmt"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func messages(c *cli.Context) error {
	atLeastOneOfThem := []string{oList, oNew, oDelete}
	opCount := 0
	for _, op := range atLeastOneOfThem {
		if c.IsSet(op) {
			opCount++
		}
	}
	if opCount == 0 {
		cli.ShowSubcommandHelp(c)
		return nil
	}
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
	//vettedRecipients := krypto431.VettedRecipients(recipients...)

	return nil
}

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
		fmt.Printf("%+v\n"+LineBreak, k.Messages[i])
	}

	err = k.Save()
	if err != nil {
		return err
	}

	return nil
}
