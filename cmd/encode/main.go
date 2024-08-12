package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SymbolNotFound/gorng/sha1"
)

func main() {
	filename := flag.String("file", "", "path to a file that should be hashed")
	empty := flag.Bool("empty", false, "prints the empty-string digest")
	base64output := flag.Bool("base64", false, "prints the digest in base-64")

	flag.Parse()

	var input []byte
	if *empty {
		input = []byte{}
	} else if len(*filename) > 0 {
		var err error
		input, err = os.ReadFile(*filename)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		args := flag.Args()
		if len(args) > 0 {
			input = []byte(args[0])
		} else {
			fmt.Println("Expected a --file flag or a string argument.  Quitting.")
			flag.Usage()
			return
		}
	}

	digest, err := sha1.HashBytes(input)
	if err != nil {
		log.Fatal(err)
	}
	if *base64output {
		fmt.Println(base64.StdEncoding.EncodeToString(digest.Bytes()))
	} else {
		fmt.Printf("0x%X\n", digest.Bytes())
	}
}
