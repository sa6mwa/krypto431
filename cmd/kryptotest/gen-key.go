package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/sa6mwa/krypto431/pkg/keystore/keydir"
	"github.com/seehuhn/mt19937"
	"github.com/urfave/cli/v2"
)

func runGenKey(c *cli.Context) error {
	var rng io.Reader
	source := c.String("source")
	switch source {
	case "default", "system":
		rng = rand.Reader
	case "mt":
		mtRng := mt19937.New()
		mtRng.Seed(time.Now().UnixNano())
		rng = mtRng
	default:
		return fmt.Errorf("unknown source name: %s", source)
	}

	var err error
	dir := c.String("key-dir")
	kd := keydir.New(dir)
	err = kd.Open()
	if err != nil {
		return fmt.Errorf("error opening key dir '%s': %w", dir, err)
	}
	defer kd.Close()

	name := c.String("name")
	size := c.Int64("size")
	count := c.Int("count")
	for i := 0; i < count; i++ {
		keyName := name
		if count > 1 {
			keyName += strconv.Itoa(i + 1)
		}
		err = kd.Generate(keyName, size, rng)
		if err != nil {
			return fmt.Errorf("error generating key: %w", err)
		}
	}
	err = kd.Close()
	if err != nil {
		return fmt.Errorf("error closing key dir: %w", err)
	}
	return nil
}
