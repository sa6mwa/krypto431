package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func keys(c *cli.Context) error {
	atLeastOneOfThem := []string{oList, oEdit, oNew, oDelete, oImport, oExport}
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
	vettedKeepers := krypto431.VettedKeepers(o.keepers...)
	vettedKeys := krypto431.VettedKeys(o.keySlice...)
	filterFunction := func(key *krypto431.Key) bool {
		// Next is almost redundant as function selects all keys if no filters av been applied.
		if o.all {
			return true
		}
		if len(vettedKeys) > 0 {
			for x := range vettedKeys {
				if krypto431.EqualRunesFold(&key.Id, &vettedKeys[x]) {
					return true
				}
			}
			return false
		}
		if len(vettedKeepers) > 0 {
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
		if o.expired && !key.IsExpired() {
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
	}

	// delete keys
	if c.IsSet(oDelete) && o.deleteItems {
		keys := len(k.Keys)
		if keys == 0 {
			eprintf("There are no keys in %s."+LineBreak, k.GetPersistence())
			return nil
		}
		deleted := 0
		if !o.yes {
			_, lines := k.SummaryOfKeys(filterFunction)
			if len(lines) == 0 {
				plural := ""
				if keys > 1 {
					plural = "s"
				}
				eprintf("No key out of %d key"+plural+" in %s matched criteria."+LineBreak, keys, k.GetPersistence())
				return nil
			}
			var keyStrings []string
			for i := range lines {
				keyStrings = append(keyStrings, string(lines[i]))
			}
			var response []string
			prompt := &survey.MultiSelect{
				Message:  "Select key(s) to delete",
				Help:     "Columns are ID, KEEPERS, CREATED, EXPIRES, USED, COMPROMISED and COMMENT",
				Options:  keyStrings,
				PageSize: 20,
			}
			err := survey.AskOne(prompt, &response, survey.WithKeepFilter(true))
			if err != nil {
				return err
			}
			if len(response) > 0 {
				deleted, err = k.DeleteKeysBySummaryString(response...)
				if err != nil {
					return err
				}
			}
		} else {
			// Do it, don't ask.
			deleted, err = k.DeleteKey(vettedKeys...)
			if err != nil {
				return err
			}
		}
		if deleted > 0 {
			err = k.Save()
			if err != nil {
				return err
			}
			eprintf("Deleted %d keys."+LineBreak, deleted)
		} else {
			eprintln("No keys were deleted.")
		}
	}

	// generate new keys
	if c.IsSet(oNew) && o.newInt > 0 {
		var expiryDTG *string = nil
		if c.IsSet(oExpire) {
			expiryDTG = &o.expire
		}
		err := k.GenerateKeys(o.newInt, expiryDTG, o.keepers...)
		if err != nil {
			return err
		}
		err = k.Save()
		if err != nil {
			return err
		}
		eprintf("Generated %d keys"+LineBreak, o.newInt)
	}

	// import keys
	if c.IsSet(oImport) {
		if utf8.RuneCountInString(o.importItems) == 0 {
			return ErrMissingImportFilename
		}
		numberOfKeysImported, err := k.ImportKeys(filterFunction, krypto431.WithPersistence(o.importItems), krypto431.WithInteractive(true))
		if err != nil {
			return err
		}
		err = k.Save()
		if err != nil {
			return err
		}
		plural := ""
		if numberOfKeysImported == 0 || numberOfKeysImported > 1 {
			plural = "s"
		}
		eprintf("Imported %d key%s from %s to %s."+LineBreak, numberOfKeysImported, plural, o.importItems, k.GetPersistence())
	}

	// export keys
	if c.IsSet(oExport) {
		if utf8.RuneCountInString(o.exportItems) == 0 {
			return ErrMissingExportFilename
		}
		k2 := k.ExportKeys(filterFunction, krypto431.WithPersistence(o.exportItems), krypto431.WithOverwritePersistenceIfExists(o.yes))
		defer k2.Wipe()
		err := k2.Save()
		if err != nil {
			return err
		}
		keysExported := len(k2.Keys)
		plural := ""
		if keysExported == 0 || keysExported > 1 {
			plural = "s"
		}
		eprintf("Exported %d key%s from %s to %s (change PFK/salt with the pfk command)."+LineBreak, keysExported, plural, k.GetPersistence(), k2.GetPersistence())
	}

	// list keys
	if c.IsSet(oList) && o.listItems {
		// First, ensure there are keys in this instance.
		keys := len(k.Keys)
		if keys == 0 {
			eprintf("There are no keys in %s."+LineBreak, k.GetPersistence())
			return nil
		}
		header, lines := k.SummaryOfKeys(filterFunction)
		if len(lines) == 0 {
			plural := ""
			if keys > 1 {
				plural = "s"
			}
			eprintf("No key out of %d key"+plural+" in %s matched criteria."+LineBreak, keys, k.GetPersistence())
			return nil
		}
		fmt.Printf("FILE=%s"+LineBreak+"KEEPER=%s TOTALKEYS=%d MESSAGES=%d"+LineBreak,
			k.GetPersistence(), k.CallSignString(),
			len(k.Keys), len(k.Messages))
		// Print lines of keys...
		fmt.Println(strings.TrimRightFunc(string(header), unicode.IsSpace))
		for i := range lines {
			fmt.Println(strings.TrimRightFunc(string(lines[i]), unicode.IsSpace))
		}
	}

	// output key(s)
	if c.IsSet(oOutput) {
		if utf8.RuneCountInString(o.output) == 0 {
			return ErrMissingOutputFilename
		}
		switch o.outputType {
		case "pdf", "PDF":
			err := k.KeysPDF(filterFunction, o.output)
			if err != nil {
				return err
			}
		case "txt", "text", "TXT":
			err := k.KeysTextFile(filterFunction, o.output)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("un-supported output-type \"%s\"", o.outputType)
		}
	}
	return nil
}
