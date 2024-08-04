# gorng (rhymes with "orange")

Golang library of a consistent pseudo-random number generator (PRNG).

Implemented with the bit-mixing phase of SHA1, provides a convenient interface
for generating unbiased samples for a specified number of bits.  Because it is
based on SHA1 it is both simple and portable, and can be seeded to consistently
generate the same sequence.  However, this is not a cryptographically secure
random number generator -- the SHA-1 algorithm has known attacks and the custom
implementation here has not been hardened against collisions or timing attacks.

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


## Developing

The library is currently under development, but no new features are planned.
If you find bugs or have suggestions, reach out to the developer through the
Discussion Forum of the github repo.  For example, maybe I can be convinced
to add a good, unbiased floating-point representation but that's a non-trivial
request so I don't plan on adding it without significant demand for it.


## Alternatives

[SHA-2](https://pkg.go.dev/crypto/sha256) for a golang-native cryptographically
secure hashing function.  Or [math/rand](https://pkg.go.dev/math/rand) for a
basic pseudo-random number generator that doesn't need to be shared between
threads or goroutines, or using appropriate synchronization when doing so.

The main reason to use this library is if you want the consistency and
repeatability provided by it, and if you want the ease of concurrent use
from the channel-based API provided by it.

## References

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
  SHAttered - The First Collision for Full SHA-1
  (Marc Stevens, Elie Bursztein, Pierre Karpman, Ange Albertini, and Yarik Markov)
  </a>
