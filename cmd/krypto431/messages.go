package main

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func messages(c *cli.Context) error {
	atLeastOneOfThem := []string{oList, oNew, oDelete}
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
	vettedAddressees := krypto431.VettedCallSigns(o.to...)
	vettedSenders := krypto431.VettedCallSigns(o.from...)

	filterFunction := func(msg *krypto431.Message) bool {
		if o.all {
			return true
		}
		if len(vettedAddressees) > 0 {
			if o.or {
				if !krypto431.AnyNeedleInHaystack(&vettedAddressees, &msg.Recipients) {
					return false
				}
			} else {
				if !krypto431.AllNeedlesInHaystack(&vettedAddressees, &msg.Recipients) {
					return false
				}
			}
		}
		if len(vettedSenders) > 0 {
			if !krypto431.AnyOfThem(&vettedSenders, &msg.From) {
				return false
			}
		}
		return true
	}

	// delete messages

	// new message

	// list messages

	if c.IsSet(oList) && o.listItems {
		// First, ensure there are messages in this instance.
		messages := len(k.Messages)
		if messages == 0 {
			eprintf("There are no messages in %s."+LineBreak, k.GetPersistence())
			return nil
		}
		header, lines := k.SummaryOfMessages(filterFunction)
		if len(lines) == 0 {
			plural := ""
			if messages > 1 {
				plural = "s"
			}
			eprintf("No message out of %d message"+plural+"in %s matched criteria."+LineBreak, messages, k.GetPersistence())
			return nil
		}
		fmt.Printf("FILE=%s"+LineBreak+"KEEPER=%s TOTALKEYS=%d MESSAGES=%d"+LineBreak,
			k.GetPersistence(), k.CallSignString(), len(k.Keys), len(k.Messages))
		// Print lines of messages...
		fmt.Println(strings.TrimRightFunc(string(header), unicode.IsSpace))
		for i := range lines {
			fmt.Println(strings.TrimRightFunc(string(lines[i]), unicode.IsSpace))
		}
	}
	return nil
}

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
