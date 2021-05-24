package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                 "kryptotest",
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "key-dir",
				Usage: "Key dir",
				Value: ".",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "encrypt",
				Action: runEncrypt,
			},
			{
				Name:   "decrypt",
				Action: runDecrypt,
			},
			{
				Name:  "gen-keys",
				Usage: "Generate keys",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "Key name",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "source",
						Usage: "Random source",
						Value: "default",
					},
					&cli.Int64Flag{
						Name:  "size",
						Usage: "Data size",
						Value: 256,
					},
					&cli.IntFlag{
						Name:  "count",
						Usage: "Create many keys",
						Value: 1,
					},
				},
				Action: runGenKey,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
