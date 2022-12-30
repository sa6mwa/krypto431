package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
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
	o := getOptions(c)
	k := krypto431.New(krypto431.WithPersistence(o.persistence), krypto431.WithInteractive(true))
	err := k.Load()
	if err != nil {
		return err
	}
	defer k.Wipe()

	fmt.Print(krypto431.HelpTextRadiogram)
	var radiogram string
	prompt := &survey.Multiline{
		Message: "Enter new message as radiogram",
	}
	err = survey.AskOne(prompt, &radiogram)
	if err != nil {
		return err
	}

	err = k.NewTextMessage(radiogram)
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
