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
	"encoding/binary"
	"io"
)

type Hasher interface {
	io.Writer
	Hash() Digest
	Reset()
}

type Digest interface {
	Bytes() []byte
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

// The digest is always 20 bytes, grouped into 5 32-bit words when computing.
const DIGEST_BYTES = 20
const DIGEST_INTS = 5

// Size of the temporary scratch buffer used when processing each block.
const SCRATCH_INTS = 80

// Internal state for computing the SHA-1 in 512-bit chunks.
type hasher struct {
	block  [BLOCK_INTS]uint32
	length uint64
	// Hashing works on the digest in 32 bit pieces, then
	// is converted to []byte when finalizing the digest.
	chainValue [DIGEST_INTS]uint32
}

// Constructor for a new Hasher instance.
func New() Hasher {
	hasher := new(hasher)
	hasher.Reset()
	return hasher
}

// Reset the length, the contents of the block and the initial digest value.
//
// This method is called automatically when Hash() is called, callers only need
// to use it if a message digest is being abandoned before being fully computed.
func (state *hasher) Reset() {
	// Zero out the length and block contents
	state.length = 0
	clear(state.block[:])
	state.chainValue[0] = 0x67452301
	state.chainValue[1] = 0xefcdab89
	state.chainValue[2] = 0x98badcfe
	state.chainValue[3] = 0x10325476
	state.chainValue[4] = 0xc3d2e1f0
}

// Hash the contents of message but leave the buffer ready for additional bytes.
// That is, it does not add the `1` bit, padding, and message length yet.
//
// Satisfies the io.Writer interface similar to other hashing algorithms in Go.
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
	// Write partial value if the loop above didn't end at a uint32 boundary.
	if length&BLOCKITEM_MASK != 0 {
		state.block[blocki] = value
	}
	state.length = length
}

// Applies the SHA-1 hashing algorithm to the contents of the current block.
// Before calling this function, an initial hash value is populated into the
// digest and the message bytes are stored as an array of unsigned 32-bit ints.
// This inner loop is processed for each 64-byte (512-bit) chunk of the message,
// as defined by the Secure Hash Standard published by NIST in
// [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//
// (prepare the message schedule W, a scratch space of 80 uint32)
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
// where f_t is a function that is selected from one of four possibilties,
// depending on which of four equal (80-byte) partitions the value t is in,
// likewise for the K_t values).
//
// .___________________________________________________________________________.
// |                 f_t(x, y, z)                   |    K(t)    |    when     |
// |------------------------------------------------|------------|-------------|
// | Ch(x, y, z) = (x & y) (+) (~x & z)             | 0x5A827999 |  0 ≤ t ≤ 19 |
// | Parity(x, y, z) = x (+) y (+) z                | 0x6ED9EBA1 | 20 ≤ t ≤ 39 |
// | Maj(x, y, z) = (x & y) (+) (x & z) (+) (y & z) | 0x8F1BBCDC | 40 ≤ t ≤ 59 |
// | Parity(x, y, z) = x (+) y (+) z                | 0xCA62C1D6 | 60 ≤ t ≤ 79 |
// '==========================================================================='
//
// Before the function returns it will clear the contents of the block and
// scratch memory passed to it.  The digest value will be updated in-place.
func (state *hasher) mixBits(scratch *[SCRATCH_INTS]uint32) {
	// Prepare the message schedule, expanded from the words of the current block.
	var tmp uint32
	for i := 0; i < 16; i++ {
		scratch[i] = state.block[i]
	}
	for i := 16; i < 32; i++ {
		tmp = scratch[i-3] ^ scratch[i-8] ^ scratch[i-14] ^ scratch[i-16]
		scratch[i] = rotateL(tmp, 1)
	}
	// From 32nd index onwards we can use this alternative that is 64-bit aligned.
	for i := 32; i < SCRATCH_INTS; i++ {
		tmp = scratch[i-6] ^ scratch[i-16] ^ scratch[i-28] ^ scratch[i-32]
		scratch[i] = rotateL(tmp, 2)
	}

	// Initial values of working memory are based on the chaining value thus far.
	a := state.chainValue[0]
	b := state.chainValue[1]
	c := state.chainValue[2]
	d := state.chainValue[3]
	e := state.chainValue[4]

	// The 80-integer buffer is traversed in four passes instead of one large
	// for loop with conditional evaluation.  This may result in a larger code
	// segment but avoids branches and the possibility of branch mis-prediction.

	// constant K_0, Choice(x, y, z) => bitwise{x ? y : z}
	for i := 0; i < 20; i++ {
		tmp = rotateL(a, 5) + (d ^ (b & (c ^ d))) + e + K_0 + scratch[i]
		e = d
		d = c
		c = rotateL(b, 30)
		b = a
		a = tmp
	}
	// constant K_1, Parity(x, y, z) => bitwise odd/even `1` bits
	for i := 20; i < 40; i++ {
		tmp = rotateL(a, 5) + (b ^ c ^ d) + e + K_1 + scratch[i]
		e = d
		d = c
		c = rotateL(b, 30)
		b = a
		a = tmp
	}
	// constant K_2, Majority(x, y, z) => bitwise majority 0s or 1s
	for i := 40; i < 60; i++ {
		tmp = rotateL(a, 5) + ((b & c) | (d & (b | c))) + e + K_2 + scratch[i]
		e = d
		d = c
		c = rotateL(b, 30)
		b = a
		a = tmp
	}
	// constant K_3, Parity(x, y, z) => bitwise odd/even `1` bits
	for i := 60; i < 80; i++ {
		tmp = rotateL(a, 5) + (b ^ c ^ d) + e + K_3 + scratch[i]
		e = d
		d = c
		c = rotateL(b, 30)
		b = a
		a = tmp
	}

	// Add the resulting values back to the digest (truncated to 2^32)
	state.chainValue[0] += a
	state.chainValue[1] += b
	state.chainValue[2] += c
	state.chainValue[3] += d
	state.chainValue[4] += e

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

// Convenience function, rotates the bits of an unsigned 32-bit integer.
func rotateL(value uint32, bits int) uint32 {
	return uint32(value<<bits) | uint32(value>>(32-bits))
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
	state.block[BLOCK_INTS-1] = uint32(length&0x1FFFFFFF) << 3
	state.length += 64 - (state.length & 63)
	state.mixBits(scratch)

	digest := newDigest(state.chainValue)
	state.Reset()
	return digest
}

// Writes a single `1` bit after the message contents.  The blockpos is the
// length of the written contents of block, 0 <= blockpos < BLOCK_INTS.
// This is only ever called when finishing
func write1bit(block *[BLOCK_INTS]uint32, blockpos byte) {
	blocki := blockpos >> 2
	switch blockpos & BLOCKITEM_MASK {
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

// Constructs a Digest result as byte array, from the five integers of the hash.
func newDigest(ints [DIGEST_INTS]uint32) Digest {
	digest := digest{}
	binary.BigEndian.PutUint32(digest.bytes[0:], ints[0])
	binary.BigEndian.PutUint32(digest.bytes[4:], ints[1])
	binary.BigEndian.PutUint32(digest.bytes[8:], ints[2])
	binary.BigEndian.PutUint32(digest.bytes[12:], ints[3])
	binary.BigEndian.PutUint32(digest.bytes[16:], ints[4])
	return digest
}

type digest struct {
	bytes [DIGEST_BYTES]byte
}

func (d digest) Bytes() []byte {
	return d.bytes[:]
}
