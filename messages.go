package krypto431

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sa6mwa/blox"
	"github.com/sa6mwa/dtg"
)

var (
	ErrNoRadiogramProvided = errors.New("no radiogram provided")
	ErrParsingRadiogram    = errors.New("unable to parse radiogram")
)

var (
	NilRunes          []rune = []rune("NIL")
	HelpTextRadiogram string = `Message header as well as text body is entered as a radiogram according to the
following simplified ACP 124 radiotelegraph message format:
TO1 TO2 TO3 DE FROM 012345 = Hello, this is the body of the message = K
DE FROM This is the shortest form.
TO DE FROM 012345ZDEC22 COL 3 = ABCDE FGHIJ KLMNO = K
TO DE FROM 012345 == TO2 TO3 == COL 2 = Hello world K
TO DE FROM 012345 C = This is a broadcast message. +
DE FROM 012345 4 = ABCDE FGHIJ KLMNO QRSTU = K
*) TO is(/are) the call-sign(s) of the recipient(s).
   FROM is your call-sign.
   012345 is a Date-Time Group (day hour minute, full format DDHHMMZmmmYY).
`

	// Full message format (012345 = Date-Time Group, abbreviated or full e.g
	// 012345AJAN23). Action addressees (adressmening), precedence or message
	// instructions (tjänsteanmärkning) are all non-capturing groups.
	//  AA BB CC DE DD 012345 == XY ZZ/P == COL 3 = ABCDE FGHIJ KLMNO = K
	//  DE VP 012345 == BA == COL 3 = ABCDE FGHIJ KLMNO = K
	//  Group 1 = TO (can be empty),
	//  Group 2 = FROM,
	//  Group 3 = DTG (optional, can be empty!),
	//  Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpFull *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*==\s*(?:[A-Z0-9/,\s]*)\s*==\s*(?:[A-Z\s]*\s*[\d]*)\s*=\s*(.*)`)

	// Semi-full message format, without message instructions (tjänsteanmärkning),
	// optional group count (both are non-capturing groups).
	//  AA DE BB 012345 == VJ QJ 3 = ABCDE FGHIJ KLMNO = K
	//  AA DE BB 012345 == VJ QJ = HELLO WORLD = K
	//  Group 1 = TO (can be empty),
	//  Group 2 = FROM,
	//  Group 3 = DTG (optional, can be empty!),
	//  Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpSemi *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*==\s*(?:[A-Z0-9/,\s]*\s*[\d]*)\s*=\s*(.*)`)

	// Short message format.
	//  AA BB CC DE VJ 012345 COL = HELLO WORLD = SECTION 2 GOES HERE, INCLUDED IN TXT = K
	//  AA BB CC DE VJ 012345 = HELLO WORLD
	//  AA DE VJ = HELLO WORLD
	//  DE VJ = HELLO WORLD = K
	//  Group 1 = TO (can be empty),
	//  Group 2 = FROM,
	//  Group 3 = DTG (optional, can be empty!),
	//  Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpShort *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*(?:[A-Z]{0,4}\s*[\d]{0,4})\s*=\s*(.*)`)

	// Even shorter format.
	//  DE SA6MWA HELLO WORLD
	//  AB DE ZY 012345 WELL, HELLO THERE = K
	//  Group 1 = TO (can be empty),
	//  Group 2 = FROM,
	//  Group 3 = DTG (optional, can be empty!),
	//  Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpMini *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*=*\s*(.*)`)

	// Regexp to match trailing = K, K, +, [AR], AR, etc in a string (e.g to clean
	// up the message text).
	//  MessageTrailRegexp.ReplaceAllString(messageText, "")
	MessageTrailRegexp *regexp.Regexp = regexp.MustCompile(`(?i)(\s*=\s*[K+]|\s[K+]|\s*\[AR\]|\s*=\s*AR)\s*$`)
)

var (
	CustomMultilineQuestionTemplate string = `
{{- if not .ShowAnswer}}
{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
{{- color "default+hb"}}{{ .Message }} {{color "reset"}}
{{- if .Default}}{{color "white"}}({{.Default}}) {{color "reset"}}{{end}}
{{- color "cyan"}}[Enter 2 empty lines to finish]{{color "reset"}}
{{ end}}`
)

func (m Message) GoString() string {
	return fmt.Sprintf("Message{Recipients:[%s] From:%s DTG:%s KeyId:%s PlainText:\"%s\" Binary:%q CipherText:\"%s\" Radiogram:\"%s\" instance:%p}",
		m.JoinRecipients(","), string(m.From), m.DTG, string(m.KeyId), string(m.PlainText), m.Binary, string(m.CipherText), string(m.Radiogram), m.instance)
}

// NewTextMessage creates a new message from a radiogram (Swedish Armed Forces telegraphy
// radiogram which can be thought of as simplified ACP 124). First argument is the
// radiogram, optional second argument is a key ID which - if specified - will
// override the key finder function if message is an outgoing message (a used or
// compromised key will not be allowed). If the From field (after DE in the
// radiogram) has the same call-sign as the instance's CallSign the message is
// considered an outgoing message. If From (DE) field is not your call-sign the
// message is considered an incoming message.
//
// Outgoing messages (DE yourCallSign) will be enciphered with a key found
// automatically or with key specified as an optional second argument.
//
// Incoming messages (DE notYourCallSign) will be attempted to be deciphered. If
// deciphering fails and it is still a valid incoming enciphered message, the
// cipher-text will stay in the PlainText field. The message function
// TryDecipherPlainText can safely be run prior to future presentation of the
// message, perhaps when the key - if initially missing in your store - has been
// obtained, deciphering may succeed (for example).
func (k *Krypto431) NewTextMessage(msg ...string) (*Message, error) {
	if len(msg) == 0 {
		return nil, ErrNoRadiogramProvided
	}
	// Prepare new message object from radiogram.
	message, err := k.ParseRadiogram(msg[0])
	if err != nil {
		return nil, err
	}
	reset := true
	defer func() {
		if reset {
			message.Wipe()
		}
	}()
	// Incoming or outgoing message?
	if message.IsMyCall() {
		// Outgoing message...
		//fmt.Fprintln(os.Stderr, "outgoing")
		if len(msg) >= 2 {
			message.KeyId = []rune(strings.ToUpper(strings.TrimSpace(msg[2])))
			if len(message.KeyId) != k.GroupSize {
				return nil, fmt.Errorf("key id \"%s\" must be %d characters long (the configured group size)", string(message.KeyId), k.GroupSize)
			}
		}
		err := message.Encipher()
		if err != nil {
			return nil, err
		}
	} else {
		// Incoming message...
		//fmt.Fprintln(os.Stderr, "incoming")
		// Add yourself if there are no recipients (this is a shortcut for the shortest radiogram)
		if len(message.Recipients) == 0 {
			message.AddRecipient(k.GetCallSign())
		}
		err := message.TryDecipherPlainText()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v"+LineBreak, err)
		}
	}
	k.Messages = append(k.Messages, *message)
	reset = false
	return message, nil
}

// PromptNewTextMessage prompts the user to enter a a new text message as a
// radiogram. If os.Stdin is not a terminal, radiogram is read from stdin
// without prompt. Returns a pointer to the new message or error on failure.
func (k *Krypto431) PromptNewTextMessage() (*Message, error) {
	if IsTerminal() {
		fmt.Print(HelpTextRadiogram)
		var radiogram string
		survey.MultilineQuestionTemplate = CustomMultilineQuestionTemplate
		prompt := &survey.Multiline{
			Message: fmt.Sprintf("Enter message as radiogram (your call is %s)", k.CallSignString()),
		}
		err := survey.AskOne(prompt, &radiogram)
		if err != nil {
			return nil, err
		}
		return k.NewTextMessage(radiogram)
	}
	return k.NewTextMessageFromReader(os.Stdin)
}

// NewTextMessageFromReader is similar to PromptNewTextMessage except radiogram
// is read from an io.Reader (until EOF). There is no output except
// warnings/errors.
// BUG(sa6mwa): NewTextMessage and ParseRadiogram need to implement io.Reader
// instead.
func (k *Krypto431) NewTextMessageFromReader(r io.Reader) (*Message, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return k.NewTextMessage(string(b))
}

// ParseRadiogram attempts to break out the Recipients, From (DE), Date-Time
// Group and PlainText from a Swedish Armed Forces radiotelegraphy message
// formatted as transmitted/received. Function returns a pointer to a new
// Message object. If DTG is empty, Message time will be set to current local
// system time. ParseRadiogram will always put the radiogram text in the
// PlainText field and leave KeyId empty. TryDecipherPlainText can be safely
// called on the return message object (especially with dryrun==true) to
// automatically attempt to identify the PlainText as CipherText with prepended
// KeyId. By default, TryDecipherPlainText will attempt to decipher the
// PlainText which will result in a populated KeyId and CipherText field as well
// as the actual (deciphered) PlainText.
func (k *Krypto431) ParseRadiogram(radiogram string) (*Message, error) {
	radiogram = blox.ReplaceLineBreaks(radiogram, " ")
	m := &Message{
		instance: k,
		Id:       k.NewUniqueMessageId(),
	}
	var matches [][]string
	regexps := []*regexp.Regexp{MessageRegexpFull, MessageRegexpSemi, MessageRegexpShort, MessageRegexpMini}
	for _, r := range regexps {
		matches = r.FindAllStringSubmatch(radiogram, 1)
		// if len(matches) > 0 {
		// 	for _, match := range matches[0] {
		// 		fmt.Fprintf(os.Stderr, "\"%s\""+LineBreak, match)
		// 	}
		// }
		if len(matches) == 1 && len(matches[0]) == 5 {
			// 1=Recipients, 2=From, 3=DTG, 4=Text
			m.Recipients = VettedRecipients(matches[0][1])
			m.From = []rune(strings.ToUpper(strings.TrimSpace(matches[0][2])))
			dtgString := strings.ToUpper(strings.TrimSpace(matches[0][3]))
			if utf8.RuneCountInString(dtgString) == 0 {
				//fmt.Fprintln(os.Stderr, "using time.Now() as message time")
				m.DTG.Time = time.Now()
			} else {
				var err error
				m.DTG, err = dtg.Parse(dtgString)
				if err != nil {
					return nil, err
				}
			}
			m.PlainText = []rune(strings.TrimSpace(MessageTrailRegexp.ReplaceAllString(matches[0][4], "")))
			m.PlainText = TrimRightRuneFunc(m.PlainText, func(r rune) bool {
				return unicode.IsSpace(r) || r == '+' || r == '='
			})
			m.Radiogram = []rune(radiogram)
			return m, nil
		}
	}
	return nil, ErrParsingRadiogram
}

// ContainsMessageId checks if the Krypto431.Messages slice already contains Id
// and return true if it does, false if it does not.
func (k *Krypto431) ContainsMessageId(msgId *[]rune) bool {
	if msgId == nil {
		return false
	}
	for i := range k.Messages {
		if EqualRunes(&k.Messages[i].Id, msgId) {
			return true
		}
	}
	return false
}

// ContainsRecipient returns true if all recipients are recipients of this
// message.
func (m *Message) ContainsRecipient(recipients ...[]rune) bool {
	if len(recipients) == 0 {
		return len(m.Recipients) == 0
	}
	if AllNeedlesInHaystack(&recipients, &m.Recipients, true) {
		return true
	}
	return false
}

// NewUniqueMessageId generates an alpha-numeric ID that is unique among the
// instance's messages. Returns a rune slice of length 4.
func (k *Krypto431) NewUniqueMessageId() []rune {
	idLen := 4
	id := make([]rune, idLen)
	for { // If you already have 62*62*62*62 (14776336) messages, this is an infinite loop :)
		id = RandomAlnumRunes(idLen)
		if !k.ContainsMessageId(&id) {
			break
		}
	}
	return id
}

// AddRecipient adds recipient(s) to the Recipients slice if not already there. Can be
// chained.
func (m *Message) AddRecipient(recipients ...[]rune) *Message {
	for _, recipient := range recipients {
		if !m.ContainsRecipient(recipient) {
			m.Recipients = append(m.Recipients, recipient)
		}
	}
	return m
}

// RemoveRecipient removes recipient(s) from the Recipients slice if found. Can be
// chained.
func (m *Message) RemoveRecipient(recipients ...[]rune) *Message {
	for _, recipient := range recipients {
		for i := range m.Recipients {
			if EqualRunesFold(&recipient, &m.Recipients[i]) {
				m.Recipients[i] = m.Recipients[len(m.Recipients)-1]
				m.Recipients = m.Recipients[:len(m.Recipients)-1]
				break
			}
		}
	}
	return m
}

// DeleteMessage removes one or more messages from the instance's Messages slice
// wiping the message before deleting it. Returns number of messages deleted or
// error on failure.
func (k *Krypto431) DeleteMessage(messageIds ...[]rune) (int, error) {
	// TODO: error-handling is a future improvement.
	deleted := 0
	if len(messageIds) == 0 {
		return 0, nil
	}
	for x := range messageIds {
		for i := range k.Messages {
			if EqualRunes(&k.Messages[i].Id, &messageIds[x]) {
				k.Messages[i].Wipe()
				k.Messages[i] = k.Messages[len(k.Messages)-1]
				k.Messages = k.Messages[:len(k.Messages)-1]
				deleted++
				break
			}
		}
	}
	return deleted, nil
}

// DeleteMessageByString is an alias for DeleteMessage where message IDs are
// issued as strings instead of rune slices.
func (k *Krypto431) DeleteMessageByString(messageIds ...string) (int, error) {
	return k.DeleteMessage(VettedMessageIds(messageIds...)...)
}

func (k *Krypto431) DeleteMessagesBySummaryString(summaryStrings ...string) (int, error) {
	deleted := 0
	for i := range summaryStrings {
		id, _, _ := strings.Cut(summaryStrings[i], " ")
		n, err := k.DeleteMessageByString(id)
		if err != nil {
			return deleted, err
		}
		deleted += n
	}
	return deleted, nil
}

func (m *Message) IdString() string {
	return string(m.Id)
}

// Groups for messages return a rune slice where each group (GroupSize) is
// separated by space. Don't forget to Wipe() this slice when you are done!
func (m *Message) Groups() (*[]rune, error) {
	// There is no need to group the Message (non-encoded) field.
	return groups(&m.CipherText, m.instance.GroupSize, 0)
}

// GroupsBlock returns a string-as-rune-slice representation of the message
// cipher text where each group is separated by a space or new line if a line
// becomes longer than Krypto431.Columns (or DefaultColumns). Don't forget to
// Wipe() this slice when you are done!
func (m *Message) GroupsBlock() (*[]rune, error) {
	return groups(&m.CipherText, m.instance.GroupSize, m.instance.Columns)
}

func (m *Message) JoinRecipients(separator string) string {
	return JoinRunesToString(&m.Recipients, separator)
}

// Return the Krypto431 instance (non-exported field) of a message.
func (m *Message) GetInstance() *Krypto431 {
	return m.instance
}

// Set instance of Krypto431 (non-exported field) for a message.
func (m *Message) SetInstance(instance *Krypto431) {
	m.instance = instance
}

// IsMyCall returns true if From field is the same as the instance's call-sign,
// false if not.
func (m *Message) IsMyCall() bool {
	return EqualRunesFold(&m.From, &m.instance.CallSign)
}

func (m *Message) QRZ() []rune {
	return m.instance.CallSign
}

func (m *Message) QRZString() string {
	return string(m.instance.CallSign)
}

func (k *Krypto431) SummaryOfMessages(filter func(msg *Message) bool) (header []rune, lines [][]rune) {
	var mp []*Message
	for i := range k.Messages {
		if filter(&k.Messages[i]) {
			err := k.Messages[i].TryDecipherPlainText(true)
			if err == nil {
				k.Messages[i].TryDecipherPlainText(false)
			}
			mp = append(mp, &k.Messages[i])
		}
	}

	predictedColumnSizes := predictColumnSizesOfMessages(mp)

	columnHeader := []string{"ID", "DTG", "TO", "DE", "DIGEST"}
	// Guard rail...
	if len(predictedColumnSizes) != len(columnHeader) {
		panic("wrong number of columns")
	}
	addSpace := 1
	for i := range predictedColumnSizes {
		if len(columnHeader) <= i {
			continue
		}
		// Add column header and padding.
		header = append(header, []rune(columnHeader[i])...)
		if i < len(predictedColumnSizes)-1 {
			padding := predictedColumnSizes[i] - len(columnHeader[i]) + addSpace
			for x := 0; x < padding; x++ {
				header = append(header, rune(' '))
			}
		}
	}
	// Populate lines rune slice with messages
	for i := range mp {
		var columns [][]rune
		columns = append(columns,
			withPadding(mp[i].Id, predictedColumnSizes[0]+addSpace),
			withPadding([]rune(mp[i].DTG.String()), predictedColumnSizes[1]+addSpace))
		if len(mp[i].Recipients) > 0 {
			columns = append(columns, withPadding([]rune(mp[i].JoinRecipients(",")), predictedColumnSizes[2]+addSpace))
		} else {
			columns = append(columns, withPadding(NilRunes, predictedColumnSizes[2]+addSpace))
		}
		if len(mp[i].From) > 0 {
			columns = append(columns, withPadding(mp[i].From, predictedColumnSizes[3]+addSpace))
		} else {
			columns = append(columns, withPadding(NilRunes, predictedColumnSizes[3]+addSpace))
		}
		digest := blox.CutLineShort(blox.WithoutLineBreaks(string(mp[i].PlainText)+string(mp[i].CipherText)), 35, true)
		columns = append(columns, []rune(digest))
		var totalLineLength int
		for x := range columns {
			totalLineLength += len(columns[x])
		}
		line := make([]rune, totalLineLength)
		var y int
		for z := range columns {
			y += copy(line[y:], columns[z])
		}
		lines = append(lines, line)
	}
	return
}

// TODO: Implement! :)

//func (k *Krypto431) NewBinaryMessage() {}
