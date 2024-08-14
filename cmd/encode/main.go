// Copyright (c) 2024 Symbol Not Found LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// github.com:SymbolNotFound/gorng/cmd/encode/main.go

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
			fmt.Println()
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
