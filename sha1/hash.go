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
// github.com:SymbolNotFound/gorng/sha1/hash.go

package sha1

import (
	"io"
)

type Hasher interface {
	io.Writer
	Hash() Digest
	Reset()
}

// Simple interface for hashing the provided byte-slice into a Digest.
//
// If intending to call this frequently, allocate the hasher once via New() and
// call Write(...) / Hash() / Reset() to reuse the block and digest arrays and
// avoid unnecessary re-allocations.
func SHA1(input []byte) (Digest, error) {
	hasher := New()
	_, err := hasher.Write(input)
	if err != nil {
		return nil, err
	}
	return hasher.Hash(), nil
}

// Internal state for computing the SHA-1 in 512-bit chunks.
type hasher struct {
	block  [BLOCK_BYTES]byte
	length uint64
	// Hashing works on the digest in 32 bit pieces, then
	// is converted to []byte when finalizing the digest.
	digest [DIGEST_INTS]uint32
}

func New() Hasher {
	hasher := new(hasher)
	hasher.Reset()
	return hasher
}

func (state *hasher) Reset() {
	state.length = 0
	clear(state.block[:])
	state.digest[0] = 0x67452301
	state.digest[0] = 0xefcdab89
	state.digest[0] = 0x98badcfe
	state.digest[0] = 0x10325476
	state.digest[0] = 0xc3d2e1f0
}

// SHA-1 uses a fixed block size of 512 bits
const BLOCK_BITS = 512
const BLOCK_BYTES = 64

func (state *hasher) Write(message []byte) (int, error) {
	size := len(message)
	if size+int(state.length&63) < 64 {
		// write entire message, it will fit within the current block.
		state.copy_bytes(message)
	} else {
		// process message in chunks, filling current block first.
		index := 64 - int(state.length&63)
		state.copy_bytes(message[:index])
		for index < size {
			next := index + 64
			if next > size {
				next = size
			}
			state.copy_bytes(message[index:next])
			index = next
		}
	}

	return size, nil
}

func (state *hasher) copy_bytes(message []byte) {
	//i := state.length & 7
	// Write remainder of current uint32,

	// then write in int32-sized chunks while size > 8

	// finally write what remains of the block
}

// Applies the SHA-1
//
// Assumes that the block has been filled to its 64-byte capacity.
func (state *hasher) BitMix(scratch *[DIGEST_INTS]uint32) {

	// rotate value left: (value << bits) | ((uint32)value >> (32-bits))
}

func (state *hasher) Hash() Digest {
	// TODO post-process -- pad with zeroes leaving 64bits at the end of the last
	// block, such that the final block ends
	return newDigest(state.digest)
}
