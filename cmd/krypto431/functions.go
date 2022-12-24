package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

type options struct {
	persistence  string
	salt         string
	pfk          string
	password     string
	random       bool
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
	or           bool
	all          bool
	used         bool
	unused       bool
	yes          bool
	change       string
	generate     bool
	generatesalt bool
	old          string
	new          string
	newsalt      string
	newpfk       string
}

const (
	oFile         string = "file"
	oSalt         string = "salt"
	oPFK          string = "pfk"
	oPassword     string = "password"
	oRandom       string = "random"
	oSave         string = "save"
	oCall         string = "call"
	oNumberOfKeys string = "keys"
	oKeepers      string = "keepers"
	oKeyLength    string = "key-length"
	oGroupSize    string = "groupsize"
	oKeyColumns   string = "key-columns"
	oColumns      string = "columns"
	oList         string = "list"
	oExport       string = "export"
	oImport       string = "import"
	oDelete       string = "delete"
	oOr           string = "or"
	oAll          string = "all"
	oUsed         string = "used"
	oUnused       string = "unused"
	oYes          string = "yes"
	oGenerate     string = "gen-key"
	oGenerateSalt string = "gen-salt"
	oChange       string = "change"
	oOld          string = "old"
	oNew          string = "new"
	oNewSalt      string = "new-salt"
	oNewPFK       string = "new-pfk"
)

// For simplicity, collect all values and return a populated options object.
func getOptions(c *cli.Context) options {
	return options{
		persistence:  c.String(oFile),
		salt:         c.String(oSalt),
		pfk:          c.String(oPFK),
		password:     c.String(oPassword),
		random:       c.Bool(oRandom),
		call:         c.String(oCall),
		numberOfKeys: c.Int(oNumberOfKeys),
		keepers:      c.StringSlice(oKeepers),
		keyLength:    c.Int(oKeyLength),
		groupSize:    c.Int(oGroupSize),
		keyColumns:   c.Int(oKeyColumns),
		columns:      c.Int(oColumns),
		listItems:    c.Bool(oList),
		exportItems:  c.String(oExport),
		importItems:  c.String(oImport),
		deleteItems:  c.Bool(oDelete),
		or:           c.Bool(oOr),
		all:          c.Bool(oAll),
		used:         c.Bool(oUsed),
		unused:       c.Bool(oUnused),
		yes:          c.Bool(oYes),
		change:       c.String(oChange),
		generate:     c.Bool(oGenerate),
		generatesalt: c.Bool(oGenerateSalt),
		old:          c.String(oOld),
		new:          c.String(oNew),
		newsalt:      c.String(oNewSalt),
		newpfk:       c.String(oNewPFK),
	}
}

// Keep it simple...
func generateSalt() {
	fmt.Println(krypto431.GenerateSalt())
}

// Simplify configuring salt and PFK...
func setSaltAndPFK(c *cli.Context, k *krypto431.Krypto431) error {
	o := getOptions(c)
	if c.IsSet(oPFK) && c.IsSet(oPassword) {
		return fmt.Errorf("can not use both options --%s and --%s, choose one", oPFK, oPassword)
	}
	if c.IsSet(oSalt) {
		err := k.SetSaltFromString(o.salt)
		if err != nil {
			return err
		}
	}
	if c.IsSet(oPFK) {
		err := k.SetKeyFromString(o.pfk)
		if err != nil {
			return err
		}
	} else if c.IsSet(oPassword) {
		err := k.SetKeyFromPassword(o.password)
		if err != nil {
			return err
		}
	}
	return nil
}

func askYesNo(msg string) (doit bool, err error) {
	prompt := &survey.Confirm{
		Message: msg,
	}
	err = survey.AskOne(prompt, &doit)
	return
}
