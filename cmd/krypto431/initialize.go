package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

func initialize(c *cli.Context) error {
	o := getOptions(c)

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

	k := krypto431.New(krypto431.WithPersistence(o.persistence),
		krypto431.WithInteractive(true),
		krypto431.WithKeyLength(o.keyLength),
		krypto431.WithGroupSize(o.groupSize),
		krypto431.WithKeyColumns(o.keyColumns),
		krypto431.WithColumns(o.columns),
		krypto431.WithCallSign(o.call),
		krypto431.WithOverwritePersistenceIfExists(o.yes),
	)
	defer k.Wipe()

	err := setSaltAndPFK(c, &k)
	if err != nil {
		return err
	}

	err = k.Assert()
	if err != nil {
		return err
	}

	if o.numberOfKeys > 0 {
		if o.numberOfKeys > 5000 {
			fmt.Printf("Generating %d keys"+LineBreak, o.numberOfKeys)
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
