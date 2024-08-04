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

Or, call the direct interface, optionally providing a seed as well.

```go
rng := gorng.NewGenerator(seedBytes)
intValue := rng.NextInt32()

// Caller can specify an arbitrary number of bits.
var bigValue []byte = rng.Next(289)
```


## Developing

// TODO clone, build, test .. and agree to the Contributor License Agreement.

... no new features are planned but if you find bugs or have suggestions,
reach out to the developers through the Discussion Forum of the github repo

## Alternatives


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
