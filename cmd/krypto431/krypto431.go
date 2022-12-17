package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

var (
	ErrAssertion = errors.New("assertion error")
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
		Usage:                  "CADCRYS (The Computer-Aided DIANA Cryptosystem)",
		Copyright:              "(C) 2021-2023 Michel Blomgren, https://github.com/sa6mwa/krypto431",
		UseShortOptionHandling: true,
		EnableBashCompletion:   true,
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
				Name:   "initialize",
				Usage:  "Initialize or reset storage file (keys, messages and settings)",
				Action: initialize,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "yes",
						Aliases: []string{"y"},
						Value:   false,
						Usage:   "If storage file exists, overwrite without asking",
					},
					&cli.StringFlag{
						Name:    "call",
						Aliases: []string{"c"},
						Usage:   "My call-sign",
					},
					&cli.IntFlag{
						Name:    "keys",
						Aliases: []string{"n"},
						Value:   0,
						Usage:   "Initial keys to generate",
					},
					&cli.StringSliceFlag{
						Name:    "keepers",
						Aliases: []string{"k"},
						Usage:   "Call-sign(s) that keep these keys (omit for anonymous keys)",
					},
					&cli.IntFlag{
						Name:    "keylength",
						Aliases: []string{"l"},
						Value:   krypto431.DefaultKeyLength,
						Usage:   "Length of each key",
					},
					&cli.IntFlag{
						Name:    "groupsize",
						Aliases: []string{"g"},
						Value:   krypto431.DefaultGroupSize,
						Usage:   "Number of characters per group",
					},
					&cli.IntFlag{
						Name:  "keycolumns",
						Usage: "Width of key in print-out",
						Value: krypto431.DefaultKeyColumns,
					},
					&cli.IntFlag{
						Name:  "columns",
						Usage: "Total width of print-out",
						Value: krypto431.DefaultColumns,
						Action: func(ctx *cli.Context, v int) error {
							if v < krypto431.MinimumColumnWidth {
								return errors.New("total width too narrow (trigraph table alone is 80 characters wide)")
							}
							return nil
						},
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

func initialize(c *cli.Context) error {
	saveFile := c.String("file")
	yesOption := c.Bool("yes")
	call := c.String("call")
	numberOfKeys := c.Int("keys")
	keepers := c.StringSlice("keepers")
	keyLength := c.Int("keylength")
	groupSize := c.Int("groupsize")
	keyColumns := c.Int("keycolumns")
	columns := c.Int("columns")

	if !c.IsSet("call") {
		// Required option, ask for call-sign using go-survey if -y is not set...
		if yesOption {
			return krypto431.ErrNoCallSign
		}
		prompt := &survey.Input{
			Message: "Enter your call-sign:",
		}
		survey.AskOne(prompt, &call, survey.WithValidator(survey.Required))
		call = strings.ToUpper(strings.TrimSpace(call))
		if len(call) == 0 {
			return krypto431.ErrNoCallSign
		}
	} else {
		call = strings.ToUpper(strings.TrimSpace(call))
	}

	flags := []string{"yes", "call", "keys", "keepers", "keylength", "groupsize"}
	goInteractive := true
	for i := range flags {
		if c.IsSet(flags[i]) {
			goInteractive = false
		}
	}

	if goInteractive {
		// Too few flags used, go interactive with go-survey...
		answers := struct {
			NumberOfKeys int    `survey:"keys"`
			Keepers      string `survey:"keepers"`
			KeyLength    int    `survey:"keylength"`
			GroupSize    int    `survey:"groupsize"`
		}{}
		questions := []*survey.Question{
			{
				Name: "keys",
				Prompt: &survey.Input{
					Message: "Enter number of initial keys to generate:",
					Default: fmt.Sprintf("%d", numberOfKeys),
				},
				Validate: func(val interface{}) error {
					str, ok := val.(string)
					if !ok {
						return ErrAssertion
					}
					i, err := strconv.Atoi(str)
					if err != nil {
						return err
					}
					if i < 0 {
						return errors.New("keys to generate must be 0 or more")
					}
					return nil
				},
			},
			{
				Name: "keepers",
				Prompt: &survey.Input{
					Message: "Enter keepers of the initial keys (leave empty for anonymous):",
					Help:    "Enter a single call-sign or multiple separated with comma or space",
				},
			},
			{
				Name: "keylength",
				Prompt: &survey.Input{
					Message: "Choose length of key:",
					Help:    fmt.Sprintf("Default key length of %d is recommended", krypto431.DefaultKeyLength),
					Default: fmt.Sprintf("%d", keyLength),
				},
				Validate: func(val interface{}) error {
					str, ok := val.(string)
					if !ok {
						return ErrAssertion
					}
					i, err := strconv.Atoi(str)
					if err != nil {
						return err
					}
					if i < krypto431.MinimumSupportedKeyLength {
						return fmt.Errorf("key length must be at least %d", krypto431.MinimumSupportedKeyLength)
					}
					return nil
				},
			},
			{
				Name: "groupsize",
				Prompt: &survey.Input{
					Message: "Choose group size:",
					Help:    fmt.Sprintf("Keys and messages are separated into groups, %d is the default", krypto431.DefaultGroupSize),
					Default: fmt.Sprintf("%d", groupSize),
				},
				Validate: func(val interface{}) error {
					str, ok := val.(string)
					if !ok {
						return ErrAssertion
					}
					i, err := strconv.Atoi(str)
					if err != nil {
						return err
					}
					if i < 1 {
						return errors.New("group size must be 1 or more")
					}
					return nil
				},
			},
		}
		err := survey.Ask(questions, &answers)
		if err != nil {
			return err
		}
		numberOfKeys = answers.NumberOfKeys
		ik := strings.Split(answers.Keepers, ",")
		for i := range ik {
			tk := strings.Split(strings.TrimSpace(ik[i]), " ")
			for t := range tk {
				fk := strings.ToUpper(strings.TrimSpace(tk[t]))
				if len(fk) > 0 {
					keepers = append(keepers, fk)
				}
			}
		}
		ik = nil
		keyLength = answers.KeyLength
		groupSize = answers.GroupSize
	}

	k := krypto431.New(krypto431.WithSaveFile(saveFile),
		krypto431.WithInteractive(true),
		krypto431.WithKeyLength(keyLength),
		krypto431.WithGroupSize(groupSize),
		krypto431.WithKeyColumns(keyColumns),
		krypto431.WithColumns(columns),
		krypto431.WithCallSign(call),
		krypto431.WithOverwriteSaveFileIfExists(yesOption),
	)

	err := k.Assert()
	if err != nil {
		return err
	}

	if numberOfKeys > 0 {
		err := k.GenerateKeys(numberOfKeys, keepers...)
		if err != nil {
			return err
		}
	}
	err = k.Save()
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
		err := k.Save()
		if err != nil {
			return err
		}
	}

	return nil
}
