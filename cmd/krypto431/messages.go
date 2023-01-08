package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
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
	vettedMessageIds := krypto431.VettedMessageIds(o.idSlice...)
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
	if c.IsSet(oDelete) && o.deleteItems {
		messages := len(k.Messages)
		if messages == 0 {
			eprintf("There are no messages in %s."+LineBreak, k.GetPersistence())
			return nil
		}
		deleted := 0
		if !o.yes {
			_, lines := k.SummaryOfMessages(filterFunction)
			if len(lines) == 0 {
				plural := ""
				if messages > 1 {
					plural = "s"
				}
				eprintf("No message out of %d message"+plural+" in %s matched criteria."+LineBreak, messages, k.GetPersistence())
				return nil
			}
			var messageStrings []string
			for i := range lines {
				messageStrings = append(messageStrings, string(lines[i]))
			}
			var response []string
			prompt := &survey.MultiSelect{
				Message:  "Select message(s) to delete",
				Help:     "Columns are ID, DTG, TO, FROM (DE) and DIGEST",
				Options:  messageStrings,
				PageSize: 20,
			}
			err := survey.AskOne(prompt, &response, survey.WithKeepFilter(true))
			if err != nil {
				return err
			}
			if len(response) > 0 {
				deleted, err = k.DeleteMessagesBySummaryString(response...)
				if err != nil {
					return err
				}
			}
		} else {
			// Do it, don't ask.
			deleted, err = k.DeleteMessage(vettedMessageIds...)
			if err != nil {
				return err
			}
		}
		if deleted > 0 {
			err = k.Save()
			if err != nil {
				return err
			}
			eprintf("Deleted %d messages."+LineBreak, deleted)
		} else {
			eprintln("No messages were deleted.")
		}
	}

	// new message
	if c.IsSet(oNew) && o.newBool {
		msg, err := k.PromptNewTextMessage()
		if err != nil {
			return err
		}
		err = k.Save()
		if err != nil {
			return err
		}
		eprintf("Saved message %s in %s."+LineBreak, msg.IdString(), k.GetPersistence())
	}

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

	// output message(s)
	if c.IsSet(oOutput) {
		if utf8.RuneCountInString(o.output) == 0 {
			return ErrMissingOutputFilename
		}
		switch o.outputType {
		case "pdf", "PDF":
			err := k.MessagesPDF(filterFunction, o.output)
			if err != nil {
				return err
			}
		case "txt", "text", "TXT":
			err := k.MessagesTextFile(filterFunction, o.output)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("un-supported output-type \"%s\"", o.outputType)
		}
	}
	return nil
}
