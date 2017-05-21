package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jamesjb/cryptopals"
	"github.com/jawher/mow.cli"
)

func dieErr(err error) {
	fmt.Fprintf(os.Stderr, "xorenc: %s\n", err)
	os.Exit(1)
}

// usage: xorenc FILENAME KEY_STRING
func main() {
	app := cli.App("xorenc", "encrypt with repeating-key xor")

	filename := app.StringArg("FILENAME", "", "input file to encrypt/decrypt")
	flagDecrypt := app.BoolOpt("d decrypt", false, "decrypt and write plaintext")
	key := app.StringArg("KEY", "", "repeating xor key")

	app.Action = func() {
		bytes, err := ioutil.ReadFile(*filename)
		if err != nil {
			dieErr(err)
		}

		if *flagDecrypt {
			ct, err := base64.StdEncoding.DecodeString(string(bytes))
			if err != nil {
				dieErr(err)
			}

			fmt.Println(string(cryptopals.RepeatingXor(ct, []byte(*key))))
		} else {
			ct := cryptopals.RepeatingXor(bytes, []byte(*key))
			fmt.Println(base64.StdEncoding.EncodeToString(ct))
		}
	}

	app.Run(os.Args)
}
