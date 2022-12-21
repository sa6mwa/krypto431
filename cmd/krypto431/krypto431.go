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
	salt         string
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
	and          bool
	all          bool
	used         bool
	unused       bool
	yes          bool
}

const (
	oFile         string = "file"
	oSalt         string = "salt"
	oSave         string = "save"
	oCall         string = "call"
	oNumberOfKeys string = "keys"
	oKeepers      string = "keepers"
	oKeyLength    string = "keylength"
	oGroupSize    string = "groupsize"
	oKeyColumns   string = "keycolumns"
	oColumns      string = "columns"
	oList         string = "list"
	oExport       string = "export"
	oImport       string = "import"
	oDelete       string = "delete"
	oAnd          string = "and"
	oAll          string = "all"
	oUsed         string = "used"
	oUnused       string = "unused"
	oYes          string = "yes"
)

func main() {
	cli.AppHelpTemplate = fmt.Sprintf(`%s
Dedicated to the memory of Maximilian Kolbe (SP3RN) 08JAN1894-14AUG1941.

`, cli.AppHelpTemplate)

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
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    oFile,
				Aliases: []string{"f"},
				EnvVars: []string{"KRYPTO431_FILE"},
				Value:   krypto431.DefaultSaveFile,
				Usage:   "Storage file for persisting keys and messages",
			},
			&cli.StringFlag{
				Name:    oSalt,
				EnvVars: []string{"KRYPTO431_SALT"},
				Value:   krypto431.DefaultSalt,
				Usage:   "Custom salt. Must be a hex encoded string decoded to at least 32 bytes\nBeware! If you misplace this salt you will not be able to decrypt\nthe save-file even if you have the passphrase",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "dev",
				Aliases: []string{"test"},
				Usage:   "Development code",
				Action:  dev,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    oSave,
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
						Name:    oYes,
						Aliases: []string{"y"},
						Value:   false,
						Usage:   "If storage file exists, overwrite without asking",
					},
					&cli.StringFlag{
						Name:    oCall,
						Aliases: []string{"c"},
						Usage:   "My call-sign",
					},
					&cli.IntFlag{
						Name:    oNumberOfKeys,
						Aliases: []string{"n"},
						Value:   0,
						Usage:   "Initial keys to generate",
					},
					&cli.StringSliceFlag{
						Name:    oKeepers,
						Aliases: []string{"k"},
						Usage:   "Call-sign(s) that keep these keys (omit for anonymous keys)",
					},
					&cli.IntFlag{
						Name:    oKeyLength,
						Aliases: []string{"l"},
						Value:   krypto431.DefaultKeyLength,
						Usage:   "Length of each key",
					},
					&cli.IntFlag{
						Name:    oGroupSize,
						Aliases: []string{"g"},
						Value:   krypto431.DefaultGroupSize,
						Usage:   "Number of characters per group",
					},
					&cli.IntFlag{
						Name:  oKeyColumns,
						Usage: "Width of key in print-out",
						Value: krypto431.DefaultKeyColumns,
					},
					&cli.IntFlag{
						Name:  oColumns,
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
						Name:    oList,
						Aliases: []string{"l"},
						Value:   false,
						Usage:   "List keys",
					},
					&cli.IntFlag{
						Name:    oNumberOfKeys,
						Aliases: []string{"n"},
						Usage:   "Number of new keys to generate",
						Value:   0,
					},
					&cli.BoolFlag{
						Name:    oDelete,
						Aliases: []string{"d"},
						Value:   false,
						Usage:   "Delete keys (interactive)",
					},
					&cli.StringFlag{
						Name:    oImport,
						Aliases: []string{"i"},
						Usage:   "Import keys from file",
					},
					&cli.StringFlag{
						Name:    oExport,
						Aliases: []string{"e"},
						Usage:   "Export keys from main file to new file",
					},
					&cli.StringSliceFlag{
						Name:    oKeepers,
						Aliases: []string{"k"},
						Usage:   "Call-signs to keepers of keys (new and as filter, empty on new will make anonymous keys)",
					},
					&cli.BoolFlag{
						Name:  oAnd,
						Usage: "All keepers, not just one (AND instead of OR)",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  oAll,
						Usage: "Select all keys - list, import, export, delete (after confirmation)",
						Value: false,
					},
					&cli.BoolFlag{
						Name:    oUsed,
						Aliases: []string{"u"},
						Usage:   "Select keys marked used only (list, import, export, delete)",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    oUnused,
						Aliases: []string{"U"},
						Usage:   "Select unused keys only (list, import, export, delete)",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    oYes,
						Aliases: []string{"y"},
						Usage:   "Force option, answer yes on questions (non-interactive)",
						Value:   false,
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
	}

	err := app.Run(os.Args)
	if err != nil {
		fatalf("ERROR: %v", err)
	}
}

func initialize(c *cli.Context) error {
	o := &options{
		saveFile:     c.String(oFile),
		yes:          c.Bool(oYes),
		call:         c.String(oCall),
		numberOfKeys: c.Int(oNumberOfKeys),
		keepers:      c.StringSlice(oKeepers),
		keyLength:    c.Int(oKeyLength),
		groupSize:    c.Int(oGroupSize),
		keyColumns:   c.Int(oKeyColumns),
		columns:      c.Int(oColumns),
	}

	if !c.IsSet(oCall) {
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

	flags := []string{oYes, oCall, oNumberOfKeys, oKeepers, oKeyLength, oGroupSize}
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
		saveFile:     c.String(oFile),
		listItems:    c.Bool(oList),
		exportItems:  c.String(oExport),
		importItems:  c.String(oImport),
		deleteItems:  c.Bool(oDelete),
		numberOfKeys: c.Int(oNumberOfKeys),
		keepers:      c.StringSlice(oKeepers),

		all:    c.Bool(oAll),
		used:   c.Bool(oUsed),
		unused: c.Bool(oUnused),
		yes:    c.Bool(oYes),
	}

	k := krypto431.New(krypto431.WithSaveFile(o.saveFile))
	err := k.Load()
	if err != nil {
		return err
	}

	// list keys is a singleton, exit after listing

	// generate new keys is also a singleton

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
		return fmt.Errorf("unable to load %s: %w", saveFile, err)
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
