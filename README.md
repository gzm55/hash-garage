Collect interesting hashes
===

`NMHASH32`/`NMHASH32X`
---

32bit hash, the core loop is constructed of invertible operations, and the multiplications are limited to `16x16->16`. For better speed on short keys, the limitation is loosened to `32x32->32` multiplication in the `NMHASH32X` variant when hashing the short keys or avalanching the final result of the core loop.

### integer bijections in `NMHASH32`/`NMHASH32X`


except common [operations](https://marc-b-reynolds.github.io/math/2017/10/13/IntegerBijections.html), some compound ones are used:

```c
x ^= x << a | x << b; // a != b
x ^= x >> a | x >> b; // a != b
x ^= x << a | x >> b; // a != b && a + b != 32 && a % b != 0 && b % a != 0

// dot_prod_16
x = ((x >> 16) * M1) << 16 | (x * M2 & 0xFFFF); // M1, M2 are odd
```

### Quality

Both hashes are the same high quality, and pass the checking:

- [rurban/smhasher](https://github.com/rurban/smhasher), including LongNeighbors and BadSeeds
- [demerphq/smhasher](https://github.com/demerphq/smhasher/)
- [massive collision tester](https://github.com/Cyan4973/xxHash/tree/dev/tests/collisions), 1G, len=8,16,256


### Speed

For large keys, the hash is optimized for SSE2/AVX2/AVX512, and achieves about 60% speed of `XXH3` in `Gb/s`. For short keys, `NMHASH32X` is a little faster than `xxhash32`.


`fifty2hash64`/`fifty2hash128`
---

Non-cryptographic hash built on AVX-512 IFMA (52-bit integer fused multiply-add): "data x data" multiplies plus additive seed/len mixing. Header-only, single include, C99/C++11, no dependencies. For hash tables, dedup, checksums — not collision-resistant.

### API

```c
#include "52hash.h"

uint64_t fifty2hash64(const void * key, size_t len, uint64_t seed);
void     fifty2hash128(const void * key, size_t len, uint64_t seed, uint64_t out[2]);
```

`fifty2hash128` writes two 64-bit halves: `out[0]` (low, `fifty2hash128l`) and `out[1]` (high, `fifty2hash128h`), each finalized separately. There is no dedicated API for the halves — obtain them through `fifty2hash128`'s `out`. The 64- and 128-bit outputs are not interchangeable: the low half of `fifty2hash128` is not `fifty2hash64`.

Length tiers: `<=16` short, `17-96` medium, `97-895` medium loop, `>=896` long. The AVX-512 IFMA (512-bit), AVX-IFMA (256-bit) and scalar fallback paths are bit-identical; the 512-bit SIMD core needs only AVX-512F + AVX-512IFMA, the 256-bit one only AVX2 + AVX-IFMA.

### integer bijections

For a fixed seed the short path is injective over the union of lengths 0-7 (64-bit) / 0-15 (128-bit), and lengths 8 (64-bit) / 16 (128-bit) are full-width bijections — so the full-width case must collide with some shorter length (pigeonhole, not a defect).

### design notes

- The whole function stays on simple arithmetic (shift/rotate, add/xor, multiply).
- A bijective Lai-Massey avalanche is used by the 64-bit short path and the 128-bit finalizer. The finalizer and short-key paths are minimized to two multiplications (independent multiplies on the high/low halves run concurrently and count as one); the 128-bit short key ends up with three on one half.
- Short inputs use a length-encoding placement so inputs shorter than the hash width map to distinct equal-width inputs across lengths. The 128-bit halves do not have this bijection property but still pass all quality checks; use them when the injective short-hash behaviour is unwanted.
- The AVX-512 IFMA multiplier is used directly, and the seed-mix / data-mix / data-load dependency chains are reordered with a software-pipelined long loop (each round's loads are consumed a round later to hide memory latency), exploiting CPU pipeline concurrency and depth for higher throughput.

### Quality

All four variants — `fifty2hash64`, `fifty2hash128`, `fifty2hash128l`, `fifty2hash128h` — are the same high quality, and pass the checking:

- [rurban/smhasher](https://github.com/rurban/smhasher), including LongNeighbors
- [demerphq/smhasher](https://github.com/demerphq/smhasher/)
- [smhasher3](https://gitlab.com/fwojcik/smhasher3)
- [massive collision tester](https://github.com/Cyan4973/xxHash/tree/dev/tests/collisions), 100G samples per length

Here `G` = `2^30`, so 100G ≈ 1.07 × 10^11 keys.

#### 64-bit

Per length: 100G keys. For a uniform 64-bit hash the expected same-length collision
count is n² / 2^65 ≈ 312.5; the observed counts (271-341) match.

| length | samples | `fifty2hash64` | `fifty2hash128l` | `fifty2hash128h` |
|---|---|---|---|---|
| 6 | 100G | 0 | 329 | 317 |
| 7 | 100G | 0 | 298 | 341 |
| 8 | 100G | 0 | 302 | 329 |
| 9 | 100G | 325 | 316 | 311 |
| 16 | 100G | 296 | 311 | 299 |
| 32 | 100G | 298 | 305 | 323 |
| 64 | 100G | 283 | 306 | 286 |
| 256 | 100G | 324 | 304 | 316 |
| 512 | 100G | 330 | 324 | 331 |
| 1024 | 100G | 271 | 296 | 308 |
| 4096 | 100G | 281 | 284 | 305 |

`fifty2hash64` cannot collide at lengths 6/7/8 — see "integer bijections" above
(lengths 0-7 injective, length 8 a full-width bijection) — so its first collisions
appear at length 9. The 128-bit halves have no such property and collide at every length.

Cross-length among lengths 6/7/8 (`fifty2hash64`):

| pair | samples | expected | collisions |
|---|---|---|---|
| 6↔7 | 100G each | 0 | 0 |
| 6↔8 | 100G each | 625 | 723 |
| 7↔8 | 100G each | 625 | 526 |
| 6/7/8 merged | 100G each | 1250 | 1249 |

6↔7 is structurally 0 (both lengths injective over their union — see "integer
bijections"); length 8 is a full-width bijection covering the whole output space, so
it must collide with shorter lengths (n²/2^64 = 625 per pair). The merged row sorts
all three lengths into one set: 1249 = 723 + 526.

#### 128-bit

Per length: 100G keys.

| variant | lengths | samples | **cross-length collisions** |
|---|---|---|---|
| `fifty2hash128` | 6/7/8/9/16/32/64/256/512/1024/4096 | 100G each | 0 |

All 11 lengths are merged into one set and jointly sorted, covering both same-length
and cross-length collisions (expected and observed: 0).

For a uniform 128-bit hash with n = 100G samples, the natural expected collision
count per length is n²/2^129 ≈ 1.7e-17 — zero for every length > 16. Lengths <= 16
are injective by construction (see "integer bijections"), so exactly 0 there; length
16 is a full-width bijection that can only collide with a shorter length, and even
that is ~0 at 100G samples. Hence the cross-length expectation is 0.

### Speed

Long-key bulk throughput (262144-byte keys, Ice Lake):

| path | alignment | B/cycle | GB/s |
|---|---|---|---|
| SIMD (`fifty2hash64` / `fifty2hash128`, 512-bit AVX-512 IFMA) | aligned | 41.7 / 41.6 | ~83.5 |
| SIMD (`fifty2hash64` / `fifty2hash128`, 512-bit AVX-512 IFMA) | misaligned | 30.7 / 30.6 | ~61.5 |
| SIMD (256-bit AVX-IFMA, 16 reg) | aligned | 22.6 | ~47 |
| SIMD (256-bit AVX-IFMA, 16 reg) | misaligned | 19.1 | ~40 |
| scalar fallback (no IFMA) | — | ~4.3 | ~9.1 |

Misaligned = 1-7 byte offset; the 512-bit path swaps one 64B load for two 32B loads plus a lane shuffle. True 64-byte-aligned input reads ~109 GB/s (512-bit) / ~47 GB/s (256-bit) — the "aligned" rows above are 8-byte-aligned. The 256-bit numbers are the 16-reg AVX-IFMA path (EVEX.256 + `-ffixed-ymm16..31`, bit-identical to real VEX.256).

Short keys (0-16 B), throughput / latency in cycles:

| width | len | throughput (cycles) | latency (cycles) |
|---|---|---|---|
| 64-bit | 0 | 8.1 | 15.6 |
| 64-bit | 8 | 6.7 | 16.8 |
| 64-bit | 16 | 6.2 | 12.7 |
| 128-bit | 0 | 12.1 | 38.4 |
| 128-bit | 16 | 9.8 | 38.8 |

Short-key speed is mid-range by design: the bijection requirement and the quality of the seed mixing take priority over raw throughput.
