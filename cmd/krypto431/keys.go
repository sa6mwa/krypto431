package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func keys(c *cli.Context) error {
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

	vettedKeepers := krypto431.VettedKeepers(o.keepers...)

	// list keys is a singleton, exit after listing
	if c.IsSet(oList) && o.listItems {
		// First, ensure there are keys in this instance.
		keys := len(k.Keys)
		if keys == 0 {
			fmt.Fprintf(os.Stderr, "There are no keys in %s."+LineBreak, k.GetPersistence())
			return nil
		}

		header, lines := k.SummaryOfKeys(func(key *krypto431.Key) bool {
			// Next is almost redundant as function selects all keys if no filters av been applied.
			if o.all {
				return true
			}
			if len(vettedKeepers) > 0 {
				// List keys with keepers AND anonymous if --anonymous is given...
				if o.or {
					if !krypto431.AnyNeedleInHaystack(&vettedKeepers, &key.Keepers) {
						return false
					}
				} else {
					if !krypto431.AllNeedlesInHaystack(&vettedKeepers, &key.Keepers) {
						return false
					}
				}
			}
			if o.invalid {
				if key.Compromised || key.IsExpired() {
					return false
				}
			}
			if o.compromised && !key.Compromised {
				return false
			}
			if o.used && !key.Used {
				return false
			}
			if o.unused && key.Used {
				return false
			}
			if c.IsSet(oValid) {
				if key.Compromised {
					return false
				}
				if !key.IsValid(time.Duration(o.valid) * 24 * time.Hour) {
					return false
				}
			}
			return true
		})

		if len(lines) == 0 {
			plural := ""
			if keys > 1 {
				plural = "s"
			}
			fmt.Fprintf(os.Stderr, "No key out of %d key"+plural+" in %s matched select criteria."+LineBreak, keys, k.GetPersistence())
			return nil
		}

		// Print lines of keys...
		fmt.Println(strings.TrimRight(string(header), " "))
		for i := range lines {
			fmt.Println(strings.TrimRight(string(lines[i]), " "))
		}

		return nil
	}

	// generate new keys function is also a singleton
	if c.IsSet(oNumberOfKeys) && o.numberOfKeys > 0 {
		return nil
	}

	// delete keys

	// import keys

	// export keys

	return nil
}

func generateKeys(c *cli.Context) error {
	persistence := c.String("file")
	numberOfKeys := c.Int("keys")
	keepers := c.StringSlice("keepers")
	k := krypto431.New(krypto431.WithPersistence(persistence))
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
	persistence := c.String("file")
	keepers := krypto431.VettedKeepers(c.StringSlice("keepers")...)
	and := c.Bool("and")
	all := c.Bool("all")
	unusedOnly := c.Bool("unused")
	usedOnly := c.Bool("used")

	k := krypto431.New(krypto431.WithPersistence(persistence), krypto431.WithInteractive(true))
	err := k.Load()
	if err != nil {
		return fmt.Errorf("unable to load %s: %w", persistence, err)
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
