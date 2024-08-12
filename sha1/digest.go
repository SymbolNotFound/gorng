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
// github.com:SymbolNotFound/gorng/sha1/digest.go

package sha1

import "encoding/binary"

const DIGEST_BYTES = 20
const DIGEST_INTS = 5

func newDigest(ints [DIGEST_INTS]uint32) Digest {
	digest := digest{}
	binary.BigEndian.PutUint32(digest.bytes[0:4], ints[0])
	binary.BigEndian.PutUint32(digest.bytes[4:8], ints[1])
	binary.BigEndian.PutUint32(digest.bytes[8:12], ints[2])
	binary.BigEndian.PutUint32(digest.bytes[12:16], ints[3])
	binary.BigEndian.PutUint32(digest.bytes[16:20], ints[4])
	return digest
}

type Digest interface {
	Bytes() []byte
}

type digest struct {
	bytes [DIGEST_BYTES]byte
}

func (d digest) Bytes() []byte {
	return d.bytes[:]
}
