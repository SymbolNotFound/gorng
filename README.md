# gorng (rhymes with "orange")

Golang library of an unbiased, repeatable pseudo-random number generator (PRNG).

Implemented with the bit-mixing phase of SHA1, provides a convenient interface
for generating unbiased samples for a specified number of bits.  Because it is
based on SHA1 it is both simple and portable, and can be seeded to consistently
generate the same sequence.  However, this is not a cryptographically secure
random number generator -- the SHA-1 algorithm has known attacks and the custom
implementation here has not been hardened against collisions or timing attacks.

This library is best suited to the generation of random bits/bytes for puzzle
and casual game implementations, card or dice games with large domains, contexts
where an RNG can be kept in sync and/or reset to the beginning of the sequence.

It also provides a channel-based API for multi-threaded contexts where one RNG
is being shared among many goroutines, which can be very useful for simulating
playouts or random walks in a state graph, if predictable ordering is not
important but thread-safety is.  Callers can simply read from the provided
channel without needing to coordinate via an explicit synchronization primitive.

## Using the RNG

Include the module in your source code:

```go
include (
  "github.com/SymbolNotFound/gorng"
)
```

Call the simple interface (the library will allocate memory for you).  This
uses the default random number generator seeded with the system's current time
at startup, then generates enough bits to provide a value of the requested size.

```go
value := gorng.RandomInt32()
```

Or, call the direct interface, optionally providing a seed as well.  Allocations
are shared across calls to the generator's Next*() methods.

```go
rng := gorng.NewGenerator(seedBytes)
intValue := rng.NextInt32()

// Caller can specify an arbitrary number of bits, bytes are ordered big-endian,
// the zero'th element having the MSB.
var bigValue []byte = rng.NextBits(289)
```

If multiple concurrent threads or goroutines all need access to the random
number generator, use the channel-based API for thread-safe access.  The above
interface also usees an underlying channel, but using the channel directly
allows for involving it in other concurrency patterns such as `select {...}`.

```go
rng := gorng.NewGenerator(seedBytes)
var size int = 1337 // any number of bits can be specified
source := rng.Channel(size) // the channel will generate only for that size
var byteslice []byte = <-source // the channel type is (chan []byte)

source2 := rng.Channel(32) // multiple channels can coexist with different sizes
```

### Sample programs

<dt>[`cmd/encode`](cmd/encode/main.go)</dt>
<dd>
Example of using the SHA-1 hashing to encode the contents of a file or a string
passed as the first command-line argument.  May be useful by itself as a CLI
binary, or for adding a Content-Addressable Storage (CAS) layer to your app.
</dd>

## Why use this instead of math/rand or crypto/rand?

The main reason to use this library is if you want the consistency and
repeatability provided by it, and if you want the ease of concurrent use
from the channel-based API provided by it.  I wrote this out of a need to
have a random function that I could use in both Go and TypeScript/JavaScript
and be confident that it would produce the same numbers given the same seed.

I also wanted a random function that I could call from multiple goroutines
acting as service API handlers, where I wasn't as concerned about repeatability
but was in need of thread-safety.  There is an example service implementation
in this repo under /cmd/service that demonstrates using this to get a seed value
for initializing another generator that can then be used repeatedly.


### Alternatives

[SHA-2](https://pkg.go.dev/crypto/sha256) for a golang-native cryptographically
secure hashing function.  Or an [AES](https://pkg.go.dev/crypto/aes) cipher,
the algorithm group recommended by NIST -- however it has not been hardened
against timing attacks whereas the **SHA-\*** implementations have been.

For a basic pseudo-random number generator that doesn't need to be shared
between threads or goroutines, 
[math/rand](https://pkg.go.dev/math/rand),
or when adding your own synchronization constructs around it.  If you want the
speed of golang's provided RNG it can also be combined with the SafeRandom
wrapper defined here.


## Developing

The library is currently under development, but no new features are planned.
If you find bugs or have suggestions, reach out to the developer through the
Discussion Forum of the github repo.  For example, maybe I can be convinced
to add a good, unbiased floating-point representation but that's a non-trivial
request so I don't plan on adding it without significant demand for it.


## References

> <a href="https://go.dev/blog/randv2">
  Golang notes on math/rand/v2 and a retrospective on math/rand
  </a>

> <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">
  SHA-1 (Secure Hash Algorithm 1) specification FIPS PUB 180-4
  </a>

> <a href="https://en.wikipedia.org/wiki/SHA-1">
  SHA-1 Wikipedia page
  </a>

> <a href="https://git.tartarus.org/?p=simon/puzzles.git;a=blob_plain;f=random.c">
  Simon Tatham's random.c (the inspiration for using SHA-1)
  </a>

> <a href="https://shattered.io/static/shattered.pdf">
  SHAttered - The First Collision for Full SHA-1<br />
  (Marc Stevens, Elie Bursztein, Pierre Karpman, Ange Albertini, and Yarik Markov)
  </a>
