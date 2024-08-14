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
// github.com:SymbolNotFound/gorng/random.go

package gorng

import (
	"encoding/binary"

	"github.com/SymbolNotFound/gorng/sha1"
)

type Source interface {
	Uint64() uint64
}

type ShaRing struct {
	rng    sha1.Hasher
	offset int
	digest sha1.Digest
}

// Creates a new random number generator using the provided Hasher source.
// If a nil value is passed for the source then the default hasher will be used.
func New(source sha1.Hasher) *ShaRing {
	if source == nil {
		source = sha1.New()
	}
	return &ShaRing{source, 0, nil}
}

func NewSourceSeeded(seed uint64, more ...uint64) *ShaRing {
	source := sha1.New()
	size := 2 + (2 * len(more))
	bytes := make([]byte, size)
	binary.BigEndian.PutUint64(bytes[0:], seed)
	for i := range more {
		binary.BigEndian.PutUint64(bytes[8*(i+1):], more[i])
	}
	source.Write(bytes)
	return &ShaRing{source, 0, nil}
}

func NewSourceDigest(digest sha1.Digest) *ShaRing {
	source := sha1.NewFromDigest(digest)
	return &ShaRing{source, 0, nil}
}

func (rng *ShaRing) Uint64() uint64 {
	var next uint64
	switch rng.offset {
	case 0:
		rng.digest = rng.rng.Hash()
		next = binary.BigEndian.Uint64(rng.digest.Bytes())
	case 4, 8:
		next = binary.BigEndian.Uint64(rng.digest.Bytes())
		rng.offset += 8
	case 12:
		next = binary.BigEndian.Uint64(rng.digest.Bytes())
		rng.offset = 0
	case 16:
		next = uint64(binary.BigEndian.Uint32(rng.digest.Bytes()[16:])) << 32
		rng.digest = rng.rng.Hash()
		next += uint64(binary.BigEndian.Uint32(rng.digest.Bytes()))
		rng.offset = 4
	}
	return next
}
