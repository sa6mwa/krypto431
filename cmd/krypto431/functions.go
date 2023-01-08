package main

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/krypto431"
	"github.com/urfave/cli/v2"
)

type options struct {
	persistence    string
	salt           string
	pfk            string
	password       string
	minimumEntropy float64
	random         bool
	call           string
	keys           int
	keySlice       []string
	newInt         int
	keepers        []string
	keyLength      int
	groupSize      int
	expire         string
	keyColumns     int
	columns        int
	listItems      bool
	editItems      bool
	exportItems    string
	importItems    string
	deleteItems    bool
	output         string
	outputType     string
	or             bool
	all            bool
	valid          int
	invalid        bool
	expired        bool
	compromised    bool
	used           bool
	unused         bool
	yes            bool
	change         string
	generatePFK    bool
	generateSalt   bool
	old            string
	new            string
	newsalt        string
	newpfk         string
	to             []string
	from           []string
	idSlice        []string
}

const (
	oFile           string = "file"
	oSalt           string = "salt"
	oPFK            string = "pfk"
	oPassword       string = "password"
	oMinimumEntropy string = "minimum-entropy"
	oRandom         string = "random"
	oSave           string = "save"
	oCall           string = "call"
	oKeys           string = "keys"
	oKeepers        string = "keepers"
	oKeyLength      string = "key-length"
	oGroupSize      string = "groupsize"
	oExpire         string = "expire"
	oKeyColumns     string = "key-columns"
	oColumns        string = "columns"
	oList           string = "list"
	oEdit           string = "edit"
	oExport         string = "export"
	oImport         string = "import"
	oDelete         string = "delete"
	oOutput         string = "output"
	oType           string = "type"
	oOr             string = "or"
	oAll            string = "all"
	oValid          string = "valid"
	oInvalid        string = "invalid"
	oExpired        string = "expired"
	oCompromised    string = "compromised"
	oUsed           string = "used"
	oUnused         string = "unused"
	oYes            string = "yes"
	oGeneratePFK    string = "gen-pfk"
	oGenerateSalt   string = "gen-salt"
	oChange         string = "change"
	oOld            string = "old"
	oNew            string = "new"
	oNewSalt        string = "new-salt"
	oNewPFK         string = "new-pfk"
	oTo             string = "to"
	oFrom           string = "from"
	oId             string = "id"
)

// For simplicity, collect all values and return a populated options object.
func getOptions(c *cli.Context) options {
	return options{
		persistence:    c.String(oFile),
		salt:           c.String(oSalt),
		pfk:            c.String(oPFK),
		password:       c.String(oPassword),
		minimumEntropy: c.Float64(oMinimumEntropy),
		random:         c.Bool(oRandom),
		call:           c.String(oCall),
		keys:           c.Int(oKeys),
		keySlice:       c.StringSlice(oKeys),
		newInt:         c.Int(oNew),
		keepers:        c.StringSlice(oKeepers),
		keyLength:      c.Int(oKeyLength),
		groupSize:      c.Int(oGroupSize),
		expire:         c.String(oExpire),
		keyColumns:     c.Int(oKeyColumns),
		columns:        c.Int(oColumns),
		listItems:      c.Bool(oList),
		editItems:      c.Bool(oEdit),
		exportItems:    c.String(oExport),
		importItems:    c.String(oImport),
		deleteItems:    c.Bool(oDelete),
		output:         c.String(oOutput),
		outputType:     c.String(oType),
		or:             c.Bool(oOr),
		all:            c.Bool(oAll),
		valid:          c.Int(oValid),
		invalid:        c.Bool(oInvalid),
		expired:        c.Bool(oExpired),
		compromised:    c.Bool(oCompromised),
		used:           c.Bool(oUsed),
		unused:         c.Bool(oUnused),
		yes:            c.Bool(oYes),
		change:         c.String(oChange),
		generatePFK:    c.Bool(oGeneratePFK),
		generateSalt:   c.Bool(oGenerateSalt),
		old:            c.String(oOld),
		new:            c.String(oNew),
		newsalt:        c.String(oNewSalt),
		newpfk:         c.String(oNewPFK),
		to:             c.StringSlice(oTo),
		from:           c.StringSlice(oFrom),
		idSlice:        c.StringSlice(oId),
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
		err := k.SetPFKFromString(o.pfk)
		if err != nil {
			return err
		}
	} else if c.IsSet(oPassword) {
		err := k.SetPFKFromPassword(o.password)
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

func eprintf(format string, a ...any) (int, error) {
	return fmt.Fprintf(os.Stderr, format, a...)
}

func eprintln(a ...any) (int, error) {
	return fmt.Fprintln(os.Stderr, a...)
}
