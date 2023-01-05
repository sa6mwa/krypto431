package main

import (
	"fmt"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

// pfk command
func managePFK(c *cli.Context) error {
	o := getOptions(c)
	if c.IsSet(oGeneratePFK) && o.generatePFK && c.IsSet(oGenerateSalt) && o.generateSalt {
		return fmt.Errorf("can not use both --%s and --%s, suggestion: first salt, use as input to --%s global option when running pfk --%s", oGeneratePFK, oGenerateSalt, oSalt, oGeneratePFK)
	}

	if c.IsSet(oGeneratePFK) && o.generatePFK {
		err := generatePFK(c)
		if err != nil {
			return err
		}
		return nil
	} else if c.IsSet(oGenerateSalt) && o.generateSalt {
		generateSalt()
		return nil
	} else if c.IsSet(oChange) {
		// Change PFK of file o.change
		k := krypto431.New(krypto431.WithPersistence(o.change), krypto431.WithInteractive(true))
		defer k.Wipe()
		err := setSaltAndPFK(c, &k)
		if err != nil {
			return err
		}
		if c.IsSet(oOld) {
			err := k.SetPFKFromPassword(o.old)
			if err != nil {
				return err
			}
		}
		err = k.Load()
		if err != nil {
			return err
		}

		if c.IsSet(oNewSalt) {
			if o.newsalt == "default" {
				o.newsalt = krypto431.DefaultSalt
			}
			err := k.SetSaltFromString(o.newsalt)
			if err != nil {
				return err
			}
		}

		if c.IsSet(oRandom) && o.random && c.IsSet(oNew) {
			return fmt.Errorf("can not use both --%s and --%s, choose one", oRandom, oNew)
		} else if c.IsSet(oNewPFK) && c.IsSet(oNew) {
			return fmt.Errorf("can not use both --%s and --%s, choose one", oNewPFK, oNew)
		} else if c.IsSet(oRandom) && o.random {
			if !o.yes {
				doit, err := askYesNo(fmt.Sprintf("Change encryption key for %s to a random key?", o.change))
				if err != nil {
					return err
				}
				if !doit {
					return nil
				}
			}
			newPFK := krypto431.GeneratePFK()
			err := k.SetPFKFromString(newPFK)
			if err != nil {
				return err
			}
			fmt.Printf("New random PFK for %s: %s"+LineBreak, o.change, newPFK)
			err = k.Save()
			if err != nil {
				return err
			}
		} else if c.IsSet(oNew) {
			// Use -N password
			err := k.SetPFKFromPassword(o.new)
			if err != nil {
				return err
			}
			if !o.yes {
				doit, err := askYesNo(fmt.Sprintf("Change encryption key for %s?", o.change))
				if err != nil {
					return err
				}
				if !doit {
					return nil
				}
			}
			err = k.Save()
			if err != nil {
				return err
			}
		} else if c.IsSet(oNewPFK) {
			// Use supplied hex-encoded PFK from the -k option.
			err := k.SetPFKFromString(o.newpfk)
			if err != nil {
				return err
			}
			if !o.yes {
				doit, err := askYesNo(fmt.Sprintf("Change encryption key for %s?", o.change))
				if err != nil {
					return err
				}
				if !doit {
					return nil
				}
			}
			err = k.Save()
			if err != nil {
				return err
			}
		} else {
			// Use default interactive method and ask for a new passphrase.
			pwd, err := krypto431.AskAndConfirmPassword(krypto431.NewEncryptionPrompt, krypto431.MinimumPasswordLength)
			if err != nil {
				return err
			}
			err = k.DerivePFKFromPassword(pwd)
			if err != nil {
				return err
			}
			err = k.Save()
			if err != nil {
				return err
			}
		}
		return nil
	}
	cli.ShowSubcommandHelp(c)
	return nil
}

// generatePFK() produces a random persistence file key (PFK) for use as perhaps
// the KRYPTO_PFK environment variable.
func generatePFK(c *cli.Context) error {
	o := options{
		salt:     c.String(oSalt),
		password: c.String(oPassword),
		random:   c.Bool(oRandom),
		newsalt:  c.String(oNewSalt),
	}
	k := krypto431.New()
	defer k.Wipe()
	err := setSaltAndPFK(c, &k)
	if err != nil {
		return err
	}

	if c.IsSet(oNewSalt) {
		if o.newsalt == "default" {
			o.newsalt = krypto431.DefaultSalt
		}
		err := k.SetSaltFromString(o.newsalt)
		if err != nil {
			return err
		}
	}

	if o.random {
		// Generate a random PFK...
		fmt.Println(krypto431.GeneratePFK())
	} else {
		// Derive key from a password/passphrase...
		if c.IsSet(oPassword) {
			// A password has been supplied in clear-text, warning has already been
			// issued in the help text so just use it...
			pwd := []byte(o.password)
			err := k.DerivePFKFromPassword(&pwd)
			if err != nil {
				return err
			}
			fmt.Println(k.GetPFKString())
		} else {
			// Neither the random option or password has been supplied, ask for a
			// password/passphrase...
			pwd, err := krypto431.AskAndConfirmPassword(krypto431.EncryptionPrompt, krypto431.MinimumPasswordLength)
			if err != nil {
				return err
			}
			err = k.DerivePFKFromPassword(pwd)
			if err != nil {
				return err
			}
			fmt.Println(k.GetPFKString())
		}
	}
	return nil
}
