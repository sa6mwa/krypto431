package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

var (
	version      string
	ErrAssertion error = errors.New("assertion error")
)

func fatalf(format string, a ...any) {
	format += LineBreak
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func main() {
	cli.AppHelpTemplate = fmt.Sprintf(`%s
Salt (--salt or KRYPTO_SALT environment variable) must be a hex encoded string
of at least 32 bytes after decoding. Beware! If you misplace the salt you will
not be able to decrypt the persistence file even if you have the passphrase.

Persistence file key (--pfk or KRYPTO_PFK environment variable) must be a hex
encoded string of exactly 32 bytes after decoding. Please note, this is a string
type that can not be wiped before exiting the program and may remain in memory.
The default password-based interactive method is the recommended method.

The --password option (or KRYPTO_PASSWORD environment variable) should be
avoided as it is inherently insecure.

KRYPTO431 is dedicated to the memory of Maximilian Kolbe (SP3RN).

`, cli.AppHelpTemplate)

	app := &cli.App{
		Name:      "krypto431",
		Version:   version,
		Usage:     "CADCRYS (The Computer-Aided DIANA Cryptosystem)",
		Copyright: "(C) 2021-2023 Michel Blomgren, https://github.com/sa6mwa/krypto431",
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
		UseShortOptionHandling: true,
		EnableBashCompletion:   true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      oFile,
				Aliases:   []string{"f"},
				EnvVars:   []string{"KRYPTO_FILE"},
				Value:     krypto431.DefaultPersistence,
				Usage:     "Storage `file` for persisting keys and messages",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:    oSalt,
				Aliases: []string{"S"},
				EnvVars: []string{"KRYPTO_SALT"},
				Value:   krypto431.DefaultSalt,
				Usage:   "Custom hex-encoded `salt`",
			},
			&cli.StringFlag{
				Name:    oPFK,
				Aliases: []string{"K"},
				EnvVars: []string{"KRYPTO_PFK"},
				Usage:   "Supply your own persistence file key `PFK`",
			},
			&cli.StringFlag{
				Name:    oPassword,
				Aliases: []string{"P"},
				EnvVars: []string{"KRYPTO_PASSWORD"},
				Usage:   "Insecurely supply clear-text `password` to derive persistence key (avoid)",
			},
		},
		Commands: []*cli.Command{
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
				Name:   "pfk",
				Usage:  "Generate or change persistence file key (PFK)",
				Action: managePFK,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    oGenerate,
						Aliases: []string{"g"},
						Usage:   "Generate PFK for use with the --pfk global option or KRYPTO_PFK environment variable",
					},
					&cli.BoolFlag{
						Name:    oGenerateSalt,
						Aliases: []string{"G"},
						Usage:   "Generate salt for use with the --salt global option or KRYPTO_SALT environment variable",
					},
					&cli.BoolFlag{
						Name:    oRandom,
						Aliases: []string{"r"},
						Usage:   "Generate a random key when generating PFK",
						Value:   false,
					},
					&cli.StringFlag{
						Name:    oChange,
						Aliases: []string{"c", "p"},
						Usage:   "Change key of persistence `file`",
					},
					&cli.StringFlag{
						Name:    oNewSalt,
						Aliases: []string{"s"},
						Usage:   "Provide salt for new password (hex-encoded, not persisted), use \"default\" to reset",
					},
					&cli.StringFlag{
						Name:    oNewPFK,
						Aliases: []string{"k"},
						Usage:   "Provide new key (a 64 characters hex-encoded string)",
					},
					&cli.StringFlag{
						Name:    oOld,
						Aliases: []string{"P"},
						Usage:   "Provide old `password` (insecure)",
						EnvVars: []string{"KRYPTO_OLD_PASSWORD"},
					},
					&cli.StringFlag{
						Name:    oNew,
						Aliases: []string{"N"},
						Usage:   "Provide new `password` (insecure, default interactive method is recommended)",
						EnvVars: []string{"KRYPTO_NEW_PASSWORD"},
					},
					&cli.BoolFlag{
						Name:    oYes,
						Aliases: []string{"y"},
						Usage:   "Force option, answer yes on all questions",
						Value:   false,
					},
				},
			},
			{
				Name:   "keys",
				Usage:  "List, generate, export, import or delete key(s)",
				Action: keys,
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
						Usage:   "Call-signs to keepers of keys (new and as filter), omit on new will assign key(s) to you",
					},
					&cli.BoolFlag{
						Name:  oOr,
						Usage: "Any of the keepers can keep the key(s)",
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
						Usage:   "Force option, answer yes on questions",
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
						Usage:   "Save changes to persistence file",
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fatalf("Error: %v", err)
	}
}
