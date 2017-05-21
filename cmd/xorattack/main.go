package main

import (
	"fmt"
	"os"

	"github.com/jamesjb/cryptopals"
	"github.com/jawher/mow.cli"
)

func dieErr(err error) {
	fmt.Fprintf(os.Stderr, "xorattack: %s\n", err)
	os.Exit(1)
}

func main() {
	app := cli.App("xorattack", "guess key for repeating XOR")
	filename := app.StringArg("FILENAME", "", "base64 encrypted file to attack")

	app.Action = func() {
		ct, err := cryptopals.ReadFileBase64(*filename)
		if err != nil {
			dieErr(err)
		}

		k := cryptopals.AttackRepeatingXor(ct)
		fmt.Println(string(k))
	}

	app.Run(os.Args)
}
