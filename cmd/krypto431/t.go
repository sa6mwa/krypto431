package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func fatalf(format string, a ...any) {
	format += LineBreak
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func main() {
	app := &cli.App{
		Name:      "krypto431",
		Usage:     "CADCRYS: the Computer-Aided Diana Cryptosystem",
		Copyright: "(C) SA6MWA 2021-2023 sa6mwa@gmail.com, https://github.com/sa6mwa/krypto431",
		Commands: []*cli.Command{
			{
				Name:    "dev",
				Aliases: []string{"test"},
				Usage:   "Development code",
				Action:  dev,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "save",
						Aliases: []string{"s"},
						Value:   false,
						Usage:   "Persist changes to save-file",
					},
				},
			},
			{
				Name:   "reinit",
				Usage:  "Re-initialize the storage file",
				Action: reinit,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "keys",
						Aliases: []string{"n"},
						Value:   10,
						Usage:   "Number of keys to generate",
					},
					&cli.StringFlag{
						Name:    "callsign",
						Aliases: []string{"c"},
						Value:   "KA",
						Usage:   "My call-sign",
					},
					&cli.IntFlag{
						Name:    "keyLength",
						Aliases: []string{"l"},
						Value:   krypto431.DefaultKeyLength,
						Usage:   "Length of each key",
					},
				},
			},
			{
				Name:   "genkey",
				Usage:  "Generate key(s)",
				Action: generateKeys,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "keys",
						Aliases: []string{"n"},
						Value:   1,
						Usage:   "Number of keys to generate",
					},
					&cli.StringSliceFlag{
						Name:    "keepers",
						Aliases: []string{"k"},
						Usage:   "Call-signs to distribute these keys to (keepers of the keys)",
					},
					&cli.BoolFlag{
						Name:    "save",
						Aliases: []string{"s"},
						Value:   true,
						Usage:   "Persist key(s) to save-file",
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Value:   krypto431.DefaultSaveFile,
				Usage:   "Storage file for persisting keys and messages",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fatalf("ERROR: %v", err)
	}
}

func dev(c *cli.Context) error {
	saveFile := c.String("file")
	k := krypto431.New(krypto431.WithSaveFile(saveFile))
	err := k.Load()
	if err != nil {
		return err
	}

	for i := range k.Keys {
		groups, err := k.Keys[i].Groups()
		if err != nil {
			return err
		}
		fmt.Printf("%d (id: %s, used: %t, keepers: %s):\n'%s'\n\n", len(k.Keys[i].Runes), string(k.Keys[i].Id), k.Keys[i].Used, strings.Join(krypto431.RunesToStrings(&k.Keys[i].Keepers), ","), string(*groups))
		krypto431.Wipe(groups)
	}

	//k.NewTextMessage("Hello world", "VQ, KA", "HELLO")
	err = k.NewTextMessage("Hej, how is it? Hello world")
	if err != nil {
		return err
	}

	for i := range k.Messages {
		err := k.Messages[i].Encipher()
		if err != nil {
			return err
		}
	}

	if c.Bool("save") {
		k.Save()
	}

	return nil
}

func reinit(c *cli.Context) error {
	saveFile := c.String("file")
	numberOfKeys := c.Int("keys")
	keyLength := c.Int("keyLength")
	k := krypto431.New(krypto431.WithSaveFile(saveFile), krypto431.WithKeyLength(keyLength))

	for i := 0; i < numberOfKeys; i++ {
		fmt.Printf("Generated key with id: %s\n", string(*k.NewKey()))
	}

	err := k.Save()
	if err != nil {
		return err
	}
	return nil
}

func generateKeys(c *cli.Context) error {
	saveFile := c.String("file")
	numberOfKeys := c.Int("keys")
	keepers := c.StringSlice("keepers")
	k := krypto431.New(krypto431.WithSaveFile(saveFile))
	err := k.Load()
	if err != nil {
		return err
	}
	err = k.GenerateKeys(numberOfKeys, keepers...)
	if err != nil {
		return err
	}
	err = k.Save()
	if err != nil {
		return err
	}
	fmt.Printf("Generated %d keys\n", numberOfKeys)
	return nil
}

func newMessage(c *cli.Context) error {
	return nil
}

func receiveMessage(c *cli.Context) error {
	return nil
}
