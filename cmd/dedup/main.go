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
// github.com:SymbolNotFound/gorng/cmd/dedup/main.go

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/SymbolNotFound/gorng/sha1"
)

// Represents the path and its content's signature (based on SHA-1).
type Signature struct {
	Content  hash64 `json:"signature"`
	Filepath string `json:"file_path"`
}

// An object that keeps track of all signatures seen so far and their paths.
// Also tracks whether duplicates should be deleted or not, and where the digest
// metadata and saved unique files should be stored.
type ContentIndex struct {
	index  map[hash64]Signature
	output chan<- Signature
	delete bool
}

// Inspect each file under the input path (indicated by --in-path -- by default,
// the current directory) and record the paths which containe the same content.
// Each duplicate is logged in a file named "<signature>.dup" where signature is
// the base64 representation of the SHA-1 hash of the bytes (so, very unlikely
// to have collisions as long as the files are less than 2^64 bytes).  This
// "duplicates" metadata is stored in the path indicated by --out-path.
//
// Example usage:
//   dedup --delete --in-path . --out-file ../duplicates.jsonl
//
// It is recommended not to use the --delete flag the first time running this
// binary, so that you can more readily see the effect that it would have after
// running, before impacting the source directory.
// This is why the default is --delete=false instead of --delete=true.

func main() {
	inpath := flag.String("in-path", ".", "prints the empty-string digest")
	outpath := flag.String("out-file", "duplicates.jsonl",
		"path to store duplication info and (when deleting) any saved unique files")
	delete := flag.Bool("delete", false,
		"also delete the contents from inpath, saving a unique copy to outpath")

	flag.Parse()
	fmt.Println("inspecting files under " + *inpath)

	// Some examples of ignored file names, add to this if desired,
	// Sometimes files should not be deleted from source even if they're copies.
	ignored := []string{
		".gitignore",
	}

	cas := newContentIndex(*outpath, *delete)
	err := filepath.WalkDir(*inpath,
		func(path string, entry fs.DirEntry, err error) error {
			if entry.IsDir() {
				return nil
			}
			if err != nil {
				log.Fatal(err)
			}
			for _, ignoreName := range ignored {
				if entry.Name() == ignoreName {
					return nil
				}
			}
			err = cas.addToIndex(path)
			return err
		})
	if err != nil {
		fmt.Println(err)
	}
}

type hash64 string

func BytesToBase64(bytes []byte) hash64 {
	return hash64(base64.StdEncoding.EncodeToString(bytes))
}

func newContentIndex(outpath string, deleteDuplicates bool) *ContentIndex {
	index := ContentIndex{
		make(map[hash64]Signature),
		newWriter(outpath),
		deleteDuplicates}
	return &index
}

// Compute the signature of the contents found at `filepath` and store/append to
// the entry in `cas` as well as the corresponding file for tracking duplicates.
func (index *ContentIndex) addToIndex(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest, err := sha1.HashBytes(data)
	if err != nil {
		return err
	}

	sig64 := BytesToBase64(digest.Bytes())
	signature, exists := index.index[sig64]
	if !exists {
		// First time this signature was found; record it and move on.
		signature = Signature{sig64, path}
		index.index[sig64] = signature
		return nil
	}

	// Otherwise, this signature was found already -- record the duplicate.
	basepath := filepath.Base(signature.Filepath)

	if signature.Filepath != basepath {
		if index.delete {
			savedpath := filepath.Join(".", "saved", basepath)
			os.Rename(signature.Filepath, savedpath)
			index.output <- Signature{sig64, basepath}
		}
		index.output <- signature
		signature.Filepath = basepath
	} else if index.delete {
		os.Remove(path)
	}

	index.output <- Signature{sig64, path}
	return nil
}

// Creates a signature writer in json-lines format (thread-safe/goroutine-safe).
func newWriter(outpath string) chan<- Signature {
	file, err := os.Create(outpath)
	if err != nil {
		log.Fatal(err)
	}
	channel := make(chan Signature)
	go func() {
		defer file.Close()
		writer := bufio.NewWriter(file)

		for sig := range channel {
			bytes, err := json.Marshal(sig)
			if err != nil {
				fmt.Printf("%s error:\n   %s\n", sig.Filepath, err)
				continue
			}
			writer.Write(bytes)
			writer.WriteByte('\n')
			writer.Flush()
		}
		writer.Flush()
	}()

	return channel
}
