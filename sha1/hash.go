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

// Simple interface for hashing the provided string into a Digest.
//
// If intending to call this frequently, allocate the hasher once via New() and
// call Write(...) / Hash() / Reset() to reuse the block and digest arrays and
// avoid unnecessary re-allocations.
func HashString(input string) (Digest, error) {
	return HashBytes([]byte(input))
}

// Simple interface for hashing the provided byte-slice into a Digest.
func HashBytes(input []byte) (Digest, error) {
	hasher := New()
	_, err := hasher.Write(input)
	if err != nil {
		return nil, err
	}
	return hasher.Hash(), nil
}

// SHA-1 uses a fixed block size of 512 bits.
// The blocks may be broken up into byte-sized words or uint32-sized words.
const BLOCK_BITS = 512
const BLOCK_BYTES = 64
const BLOCK_INTS = 16

// Reading and writing happens in uint32-sized pieces (aligning |bytes| at 4).
const BLOCKITEM_MASK = 0b11

// Size of the temporary scratch buffer used when processing each block.
const SCRATCH_INTS = 80

// Internal state for computing the SHA-1 in 512-bit chunks.
type hasher struct {
	block  [BLOCK_INTS]uint32
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
	// Zero out the length and block contents
	state.length = 0
	clear(state.block[:])
	state.digest[0] = 0x67452301
	state.digest[1] = 0xefcdab89
	state.digest[2] = 0x98badcfe
	state.digest[3] = 0x10325476
	state.digest[4] = 0xc3d2e1f0
}

func (state *hasher) Write(message []byte) (int, error) {
	msglen := len(message)
	if msglen == 0 {
		return 0, nil
	}

	offset := int(state.length & (BLOCK_BYTES - 1))
	if msglen+offset < BLOCK_BYTES {
		// Write entire message, it will fit within the current block.
		state.copyBytes(message)
	} else { // More bytes in `message` than can fit within the block's capacity,
		// process enough to fill the current buffer and then process the rest.
		scratch := new([SCRATCH_INTS]uint32)
		index := 64 - offset
		state.copyBytes(message[:index])
		state.mixBits(scratch)
		index += offset

		// Repeatedly process while there are more message bytes to write.
		for index < msglen {
			next := index + BLOCK_BYTES
			if next > msglen {
				next = msglen
			}
			state.copyBytes(message[index:next])
			if next-index == BLOCK_BYTES {
				state.mixBits(scratch)
			}
			index = next
		}
	}

	return msglen, nil
}

// Copies the bytes in `message` into a sequence of integers (big-endian). The
// message slice should have no more bytes than can fit in the current block.
func (state *hasher) copyBytes(message []byte) {
	msgi := uint32(0)
	msglen := uint32(len(message))
	length := state.length
	blocki := uint32(state.length&63) >> 2
	value := state.block[blocki]

	// Copy bytes in uint32 chunks, using big-endian order.
	for msgi < msglen {
		value = (value << 8) + uint32(message[msgi])
		msgi, length = msgi+1, length+1
		if length&BLOCKITEM_MASK == 0 {
			state.block[blocki] = value
			value, blocki = 0, blocki+1
		}
	}
	state.length = length
}

// Applies the SHA-1 hashing algorithm to the contents of the current block.
// Before calling this function, an initial hash value is populated into the
// digest and the message bytes are stored as an array of unsigned 32-bit ints.
//
// (prepare the message schedule, a scratch space of 80 uint32)
// W_t = M_t                                                      0 ≤ t ≤ 15
// W_t = ROTL[1]( W_(t-3) (+) W_(t-8) (+) W(t-14) (+) W(t-16) )  16 ≤ t ≤ 79
//
// (initialize working variables {a, b, c, d, e} from the latest hash value)
// a = H_0
// b = H_1
// c = H_2
// d = H_3
// e = H_4
//
// (for t from 0 to 79, mix the bits, let T be a temporary uint32)
// T = ROTL[5]( a ) + f_t(b, c, d) + e + K_t + W_t
// e = d
// d = c
// c = ROTL[30]( b )
// b = a
// a = T
//
// where f_t is a function that is selected from one of five possibilties,
// depending on which of four equal partitions the value t is in,
// likewise for the K_t values).
//
// ________________________________________________________________
// :          f_t(x, y, z)                         |      when    :
// :-----------------------------------------------|--------------:
// Ch(x, y, z) = (x & y) (+) (~x & z)              |    0 ≤ t ≤ 19
// Parity(x, y, z) = x (+) y (+) z                 |   20 ≤ t ≤ 39
// Maj(x, y, z) = (x & y) (+) (x & z) (+) (y & z)  |   40 ≤ t ≤ 59
// Parity(x, y, z) = x (+) y (+) z                 |   60 ≤ t ≤ 79
//
// Before the function returns it will clear the contents of the block and
// scratch memory passed to it.  The digest value will be updated in-place.
//
// Panics if the block hasn't been filled to 64-bytes (16 ints) before calling.
func (state *hasher) mixBits(scratch *[SCRATCH_INTS]uint32) {
	if state.length&63 > 0 {
		panic("block must be completely filled before processing")
	}
	var tmp uint32
	for i := 0; i < 16; i++ {
		scratch[i] = state.block[i]
	}
	for i := 16; i < SCRATCH_INTS; i++ {
		tmp = scratch[i-3] ^ scratch[i-8] ^ scratch[i-14] ^ scratch[i-16]
		scratch[i] = rotateLeft(tmp, 1)
	}

	a := state.digest[0]
	b := state.digest[1]
	c := state.digest[2]
	d := state.digest[3]
	e := state.digest[4]

	for i := 0; i < 20; i++ { // Choice(x, y, z) = x ? y : z, K_0
		tmp = rotateLeft(a, 5) + ((b & c) ^ (^b & d)) + e + K_0 + scratch[i]
		e = d
		d = c
		c = rotateLeft(b, 30)
		b = a
		a = tmp
	}
	for i := 20; i < 40; i++ { // Parity(x, y, z), K_1
		tmp = rotateLeft(a, 5) + (b ^ c ^ d) + e + K_1 + scratch[i]
		e = d
		d = c
		c = rotateLeft(b, 30)
		b = a
		a = tmp
	}
	for i := 40; i < 60; i++ { // Majority(x, y, z) => max{0, 1}, K_2
		tmp = rotateLeft(a, 5) + majority(b, c, d) + e + K_2 + scratch[i]
		e = d
		d = c
		c = rotateLeft(b, 30)
		b = a
		a = tmp
	}
	for i := 60; i < 80; i++ { // Parity(x, y, z), K_1
		tmp = rotateLeft(a, 5) + (b ^ c ^ d) + e + K_3 + scratch[i]
		e = d
		d = c
		c = rotateLeft(b, 30)
		b = a
		a = tmp
	}

	state.digest[0] += a
	state.digest[1] += b
	state.digest[2] += c
	state.digest[3] += d
	state.digest[4] += e

	// Clear the block and scratch space after processing.
	clear(state.block[:]) // With the bits zeroed, padding can be automatic.
	clear(scratch[:])     // Not strictly necessary but leaves less evidence.
}

const (
	K_0 uint32 = 0x5a827999
	K_1 uint32 = 0x6ed9eba1
	K_2 uint32 = 0x8f1bbcdc
	K_3 uint32 = 0xca62c1d6
)

func rotateLeft(value uint32, bits int) uint32 {
	return uint32(value<<bits) | uint32(value>>(32-bits))
}

func majority(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// Performs the final post-processing and returns the message hash as a Digest.
func (state *hasher) Hash() Digest {
	length := state.length
	scratch := new([SCRATCH_INTS]uint32)

	// write a single `1` bit before the rest of the padding.
	write1bit(&state.block, byte(length&63))

	if length&63 >= 56 {
		// current block is too full for length value, mix bits and use next block.
		state.length += 64 - (length & 63)
		state.mixBits(scratch)
	}

	state.block[BLOCK_INTS-2] = uint32(length >> 29)
	state.block[BLOCK_INTS-1] = uint32(length&0x1FFF) << 3
	state.length += 64 - (state.length & 63)
	state.mixBits(scratch)

	digest := newDigest(state.digest)
	state.Reset()
	return digest
}

func write1bit(block *[BLOCK_INTS]uint32, pos byte) {
	blocki := pos >> 2
	switch pos & BLOCKITEM_MASK {
	case 0:
		block[blocki] = 0x80_00_00_00
	case 1:
		block[blocki] = (block[blocki] << 24) | 0x00_80_00_00
	case 2:
		block[blocki] = (block[blocki] << 16) | 0x00_00_80_00
	case 3:
		block[blocki] = (block[blocki] << 8) | 0x00_00_00_80
	}
}
