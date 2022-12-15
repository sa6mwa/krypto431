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
		Name: "krypto431",
		Authors: []*cli.Author{
			{
				Name:  "SA6MWA Michel",
				Email: "sa6mwa@gmail.com",
			},
			{
				Name:  "SA4LGZ Patrik",
				Email: "patrik@ramnet.se",
			},
		},
		Usage:     "CADCRYS (The Computer-Aided DIANA Cryptosystem)",
		Copyright: "(C) 2021-2023 Michel Blomgren, https://github.com/sa6mwa/krypto431",
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
			{
				Name:   "listkeys",
				Usage:  "List keys",
				Action: listKeys,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:    "keepers",
						Aliases: []string{"k"},
						Usage:   "Filter on keeper of keys (if empty, only anonymous keys are listed). OR is default logic for multiple keepers",
					},
					&cli.BoolFlag{
						Name:    "and",
						Aliases: []string{"a"},
						Usage:   "Change keepers filter logic to AND, e.g keeper X and Y instead of X or Y",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "all",
						Usage: "List all keys",
						Value: false,
					},
					&cli.BoolFlag{
						Name:    "unused",
						Aliases: []string{"U"},
						Usage:   "List un-used keys only",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "used",
						Aliases: []string{"u"},
						Usage:   "List used keys only",
						Value:   false,
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

func listKeys(c *cli.Context) error {
	saveFile := c.String("file")
	keepers := krypto431.VettedKeepers(c.StringSlice("keepers")...)
	and := c.Bool("and")
	all := c.Bool("all")
	unusedOnly := c.Bool("unused")
	usedOnly := c.Bool("used")

	k := krypto431.New(krypto431.WithSaveFile(saveFile))
	err := k.Load()
	if err != nil {
		return err
	}

	sv := fmt.Sprintf("%%-%ds", k.GroupSize+1)
	headerFormat := sv + "%s" + LineBreak + sv + "%s" + LineBreak
	anonKeyStr := "Unknown (anonymous key)"

listKeysMainLoop:
	for i := range k.Keys {
		if unusedOnly && !usedOnly && k.Keys[i].Used {
			continue
		} else if !unusedOnly && usedOnly && !k.Keys[i].Used {
			continue
		}
		if all {
			kprs := anonKeyStr
			if len(k.Keys[i].Keepers) > 0 {
				kprs = strings.Join(krypto431.RunesToStrings(&k.Keys[i].Keepers), ", ")
			}
			fmt.Printf(headerFormat, "ID:", "Keepers:", string(k.Keys[i].Id), kprs)
			groups, err := k.Keys[i].GroupsBlock()
			if err != nil {
				return err
			}
			fmt.Print(string(*groups) + LineBreak + LineBreak)
			err = krypto431.Wipe(groups)
			if err != nil {
				return err
			}
		} else {
			if len(keepers) > 0 {
				// List keys with keepers (not anonymous).
				if len(k.Keys[i].Keepers) > 0 {
					if and {
						for x := range keepers {
							foundKey := false
							for y := range k.Keys[i].Keepers {
								if krypto431.EqualRunes(&keepers[x], &k.Keys[i].Keepers[y]) {
									foundKey = true
								}
							}
							if !foundKey {
								continue listKeysMainLoop
							}
						}
					} else {
						foundOneKey := false
					listKeysOrOuterLoop:
						for x := range keepers {
							for y := range k.Keys[i].Keepers {
								if krypto431.EqualRunes(&keepers[x], &k.Keys[i].Keepers[y]) {
									foundOneKey = true
									break listKeysOrOuterLoop
								}
							}
						}
						if !foundOneKey {
							continue
						}
					}
					fmt.Printf(headerFormat, "ID:", "Keepers:", string(k.Keys[i].Id), strings.Join(krypto431.RunesToStrings(&k.Keys[i].Keepers), ", "))
					groups, err := k.Keys[i].GroupsBlock()
					if err != nil {
						return err
					}
					fmt.Print(string(*groups) + LineBreak + LineBreak)
					err = krypto431.Wipe(groups)
					if err != nil {
						return err
					}
				}
			} else {
				// List anonymous keys only.
				if len(k.Keys[i].Keepers) == 0 {
					fmt.Printf(headerFormat, "ID:", "Keepers:", string(k.Keys[i].Id), anonKeyStr)
					groups, err := k.Keys[i].GroupsBlock()
					if err != nil {
						return err
					}
					fmt.Print(string(*groups) + LineBreak + LineBreak)
					err = krypto431.Wipe(groups)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func newMessage(c *cli.Context) error {
	return nil
}

func receiveMessage(c *cli.Context) error {
	return nil
}

func dev(c *cli.Context) error {
	saveFile := c.String("file")
	k := krypto431.New(krypto431.WithSaveFile(saveFile))
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
		k.Save()
	}

	return nil
}
