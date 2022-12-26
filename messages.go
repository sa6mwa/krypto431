package krypto431

import (
	"errors"
	"fmt"
	"strings"
)

// Groups for messages return a rune slice where each group (GroupSize) is
// separated by space. Don't forget to Wipe() this slice when you are done!
func (t *Message) Groups() (*[]rune, error) {
	// There is no need to group the Message (non-encoded) field.
	return groups(&t.CipherText, t.instance.GroupSize, 0)
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

// NewTextMessage() is a variadic function where first argument is the message,
// second is a comma-separated list with recipients, third a key id to override
// the key finder function and use a specific key (not marked "used"). First
// argument is mandatory, rest are optional.
func (k *Krypto431) NewTextMessage(msg ...string) (err error) {
	// 1st arg = message as a utf8 string (mandatory)
	// 2nd arg = recipients as a comma-separated list (optional)
	// 3rd arg = key id, overrides the key finder function (optional)

	if len(msg) == 0 {
		return errors.New("must at least provide the message text (first argument)")
	}

	message := Message{
		PlainText: []rune(strings.TrimSpace(msg[0])),
		instance:  k,
	}

	if len(message.PlainText) < 1 {
		return errors.New("message is empty")
	}

	if len(msg) >= 2 {
		recipients := strings.Split(msg[1], ",")
		for i := range recipients {
			message.Recipients = append(message.Recipients, []rune(strings.TrimSpace(strings.ToUpper(recipients[i]))))
		}
	}

	if len(msg) >= 3 {
		message.KeyId = []rune(strings.ToUpper(strings.TrimSpace(msg[2])))
		if len(message.KeyId) != k.GroupSize {
			return fmt.Errorf("key id \"%s\" must be %d characters long (the configured group size)", string(message.KeyId), k.GroupSize)
		}
	}

	/* EnrichWithKey() need to be changed:
	no err when key already present, and marked not used
	no err when ciphertext is already present, just return
	if there are no Recipients, find key that also has no Keepers (empty Keepers) / or my CS by default?
	*/

	err = message.Encipher()
	if err != nil {
		return err
	}
	k.Messages = append(k.Messages, message)
	return nil
}

// TODO: Implement! :)

//func (k *Krypto431) NewBinaryMessage() {}
