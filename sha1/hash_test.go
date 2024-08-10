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
// github.com:SymbolNotFound/gorng/sha1/hash_test.go

package sha1_test

import (
	"bytes"
	"testing"

	"github.com/SymbolNotFound/gorng/sha1"
)

func Test_Random(t *testing.T) {
}

func Test_Hashing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected [sha1.DIGEST_BYTES]byte
	}{
		{"empty", "", [sha1.DIGEST_BYTES]byte{
			0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
			0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}},
		{"lazy dog", "The quick brown fox jumps over the lazy dog",
			[sha1.DIGEST_BYTES]byte{
				0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
				0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12}},
		{"lazy cog", "The quick brown fox jumps over the lazy cog",
			[sha1.DIGEST_BYTES]byte{
				0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3,
				0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := sha1.SHA1([]byte(tt.input))
			if err != nil {
				t.Errorf("error when attempting to hash input '%s':\n%s", tt.input, err)
			}
			if !bytes.Equal(digest.Bytes(), tt.expected[:]) {
				t.Errorf("hashing of test '%s' resulted in unexpected hash\ngot:  %v\nwant: %v",
					tt.name, digest, tt.expected)
			}
		})
	}
}
