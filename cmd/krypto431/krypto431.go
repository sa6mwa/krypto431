package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

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

type options struct {
	saveFile     string
	save         bool
	call         string
	numberOfKeys int
	keepers      []string
	keyLength    int
	groupSize    int
	keyColumns   int
	columns      int
	listItems    bool
	exportItems  string
	importItems  string
	deleteItems  bool
	all          bool
	used         bool
	unused       bool
	yes          bool
}

const (
	osFile         string = "file"
	osSave         string = "save"
	osCall         string = "call"
	osNumberOfKeys string = "keys"
	osKeepers      string = "keepers"
	osKeyLength    string = "keylength"
	osGroupSize    string = "groupsize"
	osKeyColumns   string = "keycolumns"
	osColumns      string = "columns"
	osList         string = "list"
	osExport       string = "export"
	osImport       string = "import"
	osDelete       string = "delete"
	osAll          string = "all"
	osUsed         string = "used"
	osUnused       string = "unused"
	osYes          string = "yes"
)

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
						Name:    osSave,
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
						Name:    osYes,
						Aliases: []string{"y"},
						Value:   false,
						Usage:   "If storage file exists, overwrite without asking",
					},
					&cli.StringFlag{
						Name:    osCall,
						Aliases: []string{"c"},
						Usage:   "My call-sign",
					},
					&cli.IntFlag{
						Name:    osNumberOfKeys,
						Aliases: []string{"n"},
						Value:   0,
						Usage:   "Initial keys to generate",
					},
					&cli.StringSliceFlag{
						Name:    osKeepers,
						Aliases: []string{"k"},
						Usage:   "Call-sign(s) that keep these keys (omit for anonymous keys)",
					},
					&cli.IntFlag{
						Name:    osKeyLength,
						Aliases: []string{"l"},
						Value:   krypto431.DefaultKeyLength,
						Usage:   "Length of each key",
					},
					&cli.IntFlag{
						Name:    osGroupSize,
						Aliases: []string{"g"},
						Value:   krypto431.DefaultGroupSize,
						Usage:   "Number of characters per group",
					},
					&cli.IntFlag{
						Name:  osKeyColumns,
						Usage: "Width of key in print-out",
						Value: krypto431.DefaultKeyColumns,
					},
					&cli.IntFlag{
						Name:  osColumns,
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
				Name:   "keys",
				Usage:  "List, generate, export, import or delete key(s)",
				Action: generateKeys,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    osList,
						Aliases: []string{"l"},
						Value:   false,
						Usage:   "List keys (filter on keepers and used/unused)",
					},
					&cli.BoolFlag{
						Name:    osDelete,
						Aliases: []string{"d"},
						Value:   false,
						Usage:   "Delete keys (interactive)",
					},
					&cli.StringFlag{
						Name:    osImport,
						Aliases: []string{"i"},
						Usage:   "Import keys from file",
					},
					&cli.StringFlag{
						Name:    osExport,
						Aliases: []string{"e"},
						Usage:   "Export keys from main file to new file",
					},

					&cli.IntFlag{
						Name:    osNumberOfKeys,
						Aliases: []string{"n"},
						Value:   1,
						Usage:   "Number of keys to generate",
					},
					&cli.StringSliceFlag{
						Name:    osKeepers,
						Aliases: []string{"k"},
						Usage:   "Call-signs to distribute these keys to (keepers of the keys)",
					},
					&cli.BoolFlag{
						Name:    osSave,
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
	o := &options{
		saveFile:     c.String(osFile),
		yes:          c.Bool(osYes),
		call:         c.String(osCall),
		numberOfKeys: c.Int(osNumberOfKeys),
		keepers:      c.StringSlice(osKeepers),
		keyLength:    c.Int(osKeyLength),
		groupSize:    c.Int(osGroupSize),
		keyColumns:   c.Int(osKeyColumns),
		columns:      c.Int(osColumns),
	}

	if !c.IsSet(osCall) {
		// Required option, ask for call-sign using go-survey if -y is not set...
		if o.yes {
			return krypto431.ErrNoCallSign
		}
		prompt := &survey.Input{
			Message: "Enter your call-sign:",
		}
		survey.AskOne(prompt, &o.call, survey.WithValidator(survey.Required))
		o.call = strings.ToUpper(strings.TrimSpace(o.call))
		if utf8.RuneCountInString(o.call) == 0 {
			return krypto431.ErrNoCallSign
		}
	} else {
		o.call = strings.ToUpper(strings.TrimSpace(o.call))
	}

	flags := []string{osYes, osCall, osNumberOfKeys, osKeepers, osKeyLength, osGroupSize}
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
					Default: fmt.Sprintf("%d", o.numberOfKeys),
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
					Default: fmt.Sprintf("%d", o.keyLength),
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
					Default: fmt.Sprintf("%d", o.groupSize),
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
		o.numberOfKeys = answers.NumberOfKeys
		ik := strings.Split(answers.Keepers, ",")
		for i := range ik {
			tk := strings.Split(strings.TrimSpace(ik[i]), " ")
			for t := range tk {
				fk := strings.ToUpper(strings.TrimSpace(tk[t]))
				if len(fk) > 0 {
					o.keepers = append(o.keepers, fk)
				}
			}
		}
		ik = nil
		o.keyLength = answers.KeyLength
		o.groupSize = answers.GroupSize
	}

	k := krypto431.New(krypto431.WithSaveFile(o.saveFile),
		krypto431.WithInteractive(true),
		krypto431.WithKeyLength(o.keyLength),
		krypto431.WithGroupSize(o.groupSize),
		krypto431.WithKeyColumns(o.keyColumns),
		krypto431.WithColumns(o.columns),
		krypto431.WithCallSign(o.call),
		krypto431.WithOverwriteSaveFileIfExists(o.yes),
	)

	err := k.Assert()
	if err != nil {
		return err
	}

	if o.numberOfKeys > 0 {
		if o.numberOfKeys > 5000 {
			fmt.Printf("Generating %d keys", o.numberOfKeys)
		}
		err := k.GenerateKeys(o.numberOfKeys, o.keepers...)
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

func keys(c *cli.Context) error {
	o := &options{
		saveFile:     c.String(osFile),
		listItems:    c.Bool(osList),
		exportItems:  c.String(osExport),
		importItems:  c.String(osImport),
		deleteItems:  c.Bool(osDelete),
		numberOfKeys: c.Int(osNumberOfKeys),
		keepers:      c.StringSlice(osKeepers),
		all:          c.Bool(osAll),
		used:         c.Bool(osUsed),
		unused:       c.Bool(osUnused),
		yes:          c.Bool(osYes),
	}

	k := krypto431.New(krypto431.WithSaveFile(o.saveFile))
	err := k.Load()
	if err != nil {
		return err
	}

	// list keys is a singleton, exit after listing

	// delete keys

	// import keys

	// export keys

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

	k := krypto431.New(krypto431.WithSaveFile(saveFile), krypto431.WithInteractive(true))
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
