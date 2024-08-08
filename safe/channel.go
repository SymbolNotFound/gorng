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

package safe

type SafeRandom interface {
	Channel() <-chan []byte
	Close()
}

func New(source Source, bits uint8) SafeRandom {
	channel := make(chan []byte)
	saferandom := randchan{source, bits, channel}
	saferandom.start()
	return saferandom
}

// Provides a channel-based wrapper around a rand.Rand generator, allowing
// multiple callers to retrieve the next random value concurrently (without
// shearing or repetition).  This is very useful where simulations need many
// random values drawn in separate goroutines, without the overhead of making
// many RNG instances or performing the calls within a mutex.  You can also
// select {...} from multiple of these channels, i.e., many generators for
// each simulator, to obtain higher throughput on a multiprocessor system.
type randchan struct {
	source  Source
	bits    uint8
	channel chan []byte
}

func (rng randchan) start() {
}

func (rng randchan) Channel() <-chan []byte {
	return rng.channel
}

func (rng randchan) Close() {
}

// A source of random numbers, modeled after math/rand.Source.
type RandSource interface {
	Uint64() uint64
}

// An extension of math/rand.Source that also generates byte slices.
type Source interface {
	RandSource
	Bytes(size uint8) []byte
}

// Convenience method for extending a math/rand.Source for compatibility.
func ExtendSource(source RandSource) Source {
	return extendedSource{source}
}

type extendedSource struct {
	RandSource
}

func (source extendedSource) Bytes(bits uint8) []byte {
	if bits == 0 {
		return []byte{}
	}
	countBytes := bits / 8
	if bits&0x07 > 0 {
		countBytes += 1
	}
	bytes := make([]byte, 0, countBytes)
	offset := 0

	for bits > 0 {
		next := source.RandSource.Uint64()
		for i := 0; i < 8; i++ {
			if bits < 8 {
				mask := uint64(1<<bits) - 1
				bytes[offset+i] = byte(next & mask)
				bits = 0
				break
			}
			bytes[offset+i] = byte(next & 0xFF)
			next >>= 8
			bits >>= 3
		}
	}

	return bytes
}
