package krypto431

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sa6mwa/dtg"
)

var (
	// Full message format (012345 = Date-Time Group, abbreviated or full e.g
	// 012345AJAN23). Action addressees (adressmening), precedence or message
	// instructions (tjänsteanmärkning) are all non-capturing groups.
	//
	// AA BB CC DE DD 012345 == XY ZZ/P == COL 3 = ABCDE FGHIJ KLMNO = K
	//
	// DE VP 012345 == BA == COL 3 = ABCDE FGHIJ KLMNO = K
	//
	// Group 1 = TO (can be empty),
	// Group 2 = FROM,
	// Group 3 = DTG (optional, can be empty!),
	// Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpFull *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*==\s*(?:[A-Z0-9/,\s]*)\s*==\s*(?:[A-Z\s]*\s*[\d]*)\s*=\s*(.*)`)

	// Semi-full message format, without message instructions (tjänsteanmärkning),
	// optional group count (both are non-capturing groups).
	//
	// AA DE BB 012345 == VJ QJ 3 = ABCDE FGHIJ KLMNO = K
	//
	// AA DE BB 012345 == VJ QJ = HELLO WORLD = K
	//
	// Group 1 = TO (can be empty),
	// Group 2 = FROM,
	// Group 3 = DTG (optional, can be empty!),
	// Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpSemi *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*==\s*(?:[A-Z0-9/,\s]*\s*[\d]*)\s*=\s*(.*)`)

	// Short message format.
	//
	// AA BB CC DE VJ 012345 COL = HELLO WORLD = SECTION 2 GOES HERE, INCLUDED IN TXT = K
	//
	// AA BB CC DE VJ 012345 = HELLO WORLD
	//
	// AA DE VJ = HELLO WORLD
	//
	// DE VJ = HELLO WORLD = K
	//
	// Group 1 = TO (can be empty),
	// Group 2 = FROM,
	// Group 3 = DTG (optional, can be empty!),
	// Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpShort *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*(?:[A-Z]{0,4}\s*[\d]{0,4})\s*=\s*(.*)`)

	// Even shorter format.
	//
	// DE SA6MWA HELLO WORLD
	//
	// AB DE ZY 012345 WELL, HELLO THERE = K
	//
	// Group 1 = TO (can be empty),
	// Group 2 = FROM,
	// Group 3 = DTG (optional, can be empty!),
	// Group 4 = Message text (will include trailing = K, K, +, etc)
	MessageRegexpMini *regexp.Regexp = regexp.MustCompile(`(?i)([A-Z0-9/,\s]*)(?:\s+|^)DE\s+([A-Z0-9/]+)\s*([0-9]{6}[A-Z]{0,1}(?:JAN|FEB|MAR|APR|MAY|MAJ|JUN|JUL|AUG|SEP|OCT|OKT|NOV|DEC){0,1}(?:[0-9]{2}){0,1}){0,1}\s*=*\s*(.*)`)

	// Regexp to match trailing = K, K, +, [AR], AR, etc in a string (e.g to clean
	// up the message text).
	//
	// MessageTrailRegexp.ReplaceAllString(messageText, "")
	MessageTrailRegexp *regexp.Regexp = regexp.MustCompile(`(\s*=\s*[K+]|\s[K+]|\s*\[AR\]|\s*=\s*AR)\s*$`)
)

// Creates a new message from a radiogram (Swedish Armed Forces telegraphy
// radiogram which can be thought of as a simplified ACP 124). First argument is
// a radiogram, optional second argument is a key ID which - if specified - will
// override the key finder function (a used or compromised key will not be
// allowed).
func (k *Krypto431) NewTextMessage(msg ...string) error {
	k.mx.Lock()
	defer k.mx.Unlock()
	if len(msg) == 0 {
		return errors.New("no radiogram provided")
	}
	// Prepare new message object from radiogram.
	message, err := k.ParseRadiogram(msg[0])
	if err != nil {
		return err
	}
	if len(msg) >= 2 {
		message.KeyId = []rune(strings.ToUpper(strings.TrimSpace(msg[2])))
		if len(message.KeyId) != k.GroupSize {
			return fmt.Errorf("key id \"%s\" must be %d characters long (the configured group size)", string(message.KeyId), k.GroupSize)
		}
	}
	err = message.Encipher()
	if err != nil {
		return err
	}
	k.Messages = append(k.Messages, *message)
	return nil
}

// Krypto431.ParseRadiogram() attempts to break out the Recipients, From (DE),
// Date-Time Group and PlainText from a Swedish Armed Forces radiotelegraphy
// message formatted as transmitted. Function returns a pointer to a new Message
// object. If DTG is empty, Message time will be set to current local system
// time.
func (k *Krypto431) ParseRadiogram(radiogram string) (*Message, error) {
	m := &Message{
		instance: k,
	}
	var matches [][]string
	regexps := []*regexp.Regexp{MessageRegexpFull, MessageRegexpSemi, MessageRegexpShort, MessageRegexpMini}
	for _, r := range regexps {
		matches = r.FindAllStringSubmatch(radiogram, 1)
		/* 		if len(matches) > 0 {
		   			for _, match := range matches[0] {
		   				fmt.Fprintf(os.Stderr, "\"%s\""+LineBreak, match)
		   			}
		   		}
		*/
		if len(matches) == 1 && len(matches[0]) == 5 {
			// 1=Recipients, 2=From, 3=DTG, 4=Text
			m.Recipients = VettedRecipients(matches[0][1])
			m.From = []rune(strings.ToUpper(strings.TrimSpace(matches[0][2])))
			if !EqualRunes(&m.From, &k.CallSign) {
				fmt.Fprintf(os.Stderr, "%s!=%s"+LineBreak, string(m.From), string(k.CallSign))
			}
			dtgString := strings.ToUpper(strings.TrimSpace(matches[0][3]))
			if utf8.RuneCountInString(dtgString) == 0 {
				fmt.Fprintln(os.Stderr, "using time.Now() as message time")
				m.DTG.Time = time.Now()
			} else {
				var err error
				m.DTG, err = dtg.Parse(dtgString)
				if err != nil {
					return nil, err
				}
			}
			m.PlainText = []rune(strings.TrimSpace(MessageTrailRegexp.ReplaceAllString(matches[0][4], "")))
			fmt.Printf("%+v\n", m)
			return m, nil
		}
	}
	return nil, errors.New("unable to parse radiogram")
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

// TODO: Implement! :)

//func (k *Krypto431) NewBinaryMessage() {}
