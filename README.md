Collect interesting hashes
===

`NMHASH32`/`NMHASH32X`
---

32bit hash, the core loop is constructed of invertible operations, and the multiplications are limited to `16x16->16`. The limitation is loosen to `32x32->32` multiplication in the `NMHASH32X` variant when hashing the short keys or avalanching the final result of the core loop.

### integer bijections in `NMHASH32`/`NMHASH32X`


except common [operations](https://marc-b-reynolds.github.io/math/2017/10/13/IntegerBijections.html), some compound ones are used:

```c
x ^= x << a | x << b; // a != b
x ^= x >> a | x >> b; // a != b
x ^= x << a | x >> b; // a != b && a + b != 32 && a % b != 0 && b % a != 0

// dot_prod_16
x = ((x >> 16) * M1) << 16 | (x * M2 & 0xFFFF); // M1, M2 are odd
```
