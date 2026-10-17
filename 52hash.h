/*
 * 52hash.h — IFMA-based hash: data x data multiply + additive seed/len mixing.
 *
 * Non-cryptographic: designed for hash tables, dedup, etc.  Not collision-resistant;
 * do not use for security purposes.
 *
 * Uses SIMD when AVX-512 IFMA (F52_HAVE_AVX512IFMA) is available; otherwise the
 * medium-loop/long paths fall back to a scalar layer (f52_v8), bit-identical to SIMD.
 * Portable across GNU/Clang/MSVC: the 64x64->128 multiply picks __int128 / _umul128 /
 * 32x32 decomposition by compiler; bswap/rotate, attributes, endianness and static
 * asserts all have F52_* portable wrappers.
 *
 * The 64-bit and 128-bit variants share the mixing core but use different finalizers,
 * so the low 64 bits of fifty2hash128(x) != fifty2hash64(x); they must not be truncated
 * from one another.
 *
 * Length-tiered: <=16B short / 17-96B medium / 97-895B medium loop / >=896B long.
 *
 * For a fixed seed the short path is injective over the union of lengths 0-7 (64b) /
 * 0-15 (128b), and lengths 8 (64b) / 16 (128b) are full-width bijections.  Because the
 * full-width bijection covers the entire output space, no cross-length collision-freedom
 * is guaranteed between shorter lengths and the full-width length.
 */
#ifndef FIFTY2HASH_H
#define FIFTY2HASH_H

/* Version.  "1" for the first release; the "-dev" suffix marks a not-yet-released
 * development state (currently: collision testing in progress). */
#define F52_VERSION "1-dev"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#if defined(_MSC_VER)
#  include <intrin.h>   /* _byteswap_*, _rotl64/_rotr64, _umul128 */
#endif

/* C89 (pre-C99 C) has no `inline` keyword: map it away so `static inline` degrades to
 * plain `static`.  Undone at the end of this header (see F52_UNDEF_INLINE). */
#if !defined(__cplusplus) && !(defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L))
#  define inline
#  define F52_UNDEF_INLINE 1
#endif

/* ---- AVX-512 IFMA detection ----
 * GCC/Clang define __AVX512IFMA__ under -mavx512ifma / -march=native; MSVC cl.exe does
 * not, so CMake detects IFMA and defines F52_FORCE_AVX512IFMA (together with /arch:AVX512). */
#if defined(__AVX512IFMA__) || defined(F52_FORCE_AVX512IFMA)
#  define F52_HAVE_AVX512IFMA 1
#else
#  define F52_HAVE_AVX512IFMA 0
#endif

/* The SIMD section (immintrin.h + medium-loop/long paths) is compiled only under
 * F52_HAVE_AVX512IFMA; otherwise the scalar fallback is used. */
#if F52_HAVE_AVX512IFMA
#  include <immintrin.h>
#endif

/* ---- compiler optimization / attribute macros ----
 * F52_AINLINE:  force-inline leaf helpers.
 * F52_CONST:    pure-function attribute (result depends only on arguments).
 * F52_NOINLINE: inhibit inlining (keep large functions standalone).
 * F52_LIKELY/UNLIKELY: branch probability hints.
 * F52_RESTRICT: restrict pointer qualifier.
 * F52_ALIGN64:  64-byte alignment (for _mm512_load_si512).
 * Note: const is a strong promise; functions that read/write pointed-to memory must not
 * be marked (or CSE can miscompile them). */
#if defined(_MSC_VER)
#  define F52_AINLINE __forceinline
#  define F52_CONST
#  define F52_LIKELY(x)   (x)
#  define F52_UNLIKELY(x) (x)
#  define F52_RESTRICT __restrict
#  define F52_ALIGN64 __declspec(align(64))
#  define F52_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
#  define F52_AINLINE __attribute__((always_inline))
#  define F52_CONST   __attribute__((const))
#  define F52_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define F52_UNLIKELY(x) __builtin_expect(!!(x), 0)
#  define F52_RESTRICT __restrict__
#  define F52_ALIGN64 __attribute__((aligned(64)))
#  define F52_NOINLINE __attribute__((noinline))
#else
#  define F52_AINLINE
#  define F52_CONST
#  define F52_LIKELY(x)   (x)
#  define F52_UNLIKELY(x) (x)
#  define F52_RESTRICT
#  define F52_ALIGN64
#  define F52_NOINLINE
#endif

/* GCC<10 ICEs on the __attribute__((target)) + inline-asm combination; disable both there
 * (the TU is compiled globally with -mavx512ifma, so dropping them is harmless). */
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 10
#  define F52_GCC_LEGACY 1
#endif

/* Static assert: expands to a declaration (file scope).  The negative-array fallback builds a
 * unique name from __COUNTER__ via two-level CONCAT (a single-level name##__COUNTER__ does NOT
 * expand __COUNTER__).  __COUNTER__ is supported by all targeted compilers (GCC/Clang/MSVC). */
#if defined(__cplusplus) && (__cplusplus >= 201103L)
#  define F52_STATIC_ASSERT(c, m) static_assert((c), m)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#  define F52_STATIC_ASSERT(c, m) _Static_assert((c), m)
#else
#  define F52_SA_CAT_I(a, b) a##b
#  define F52_SA_CAT(a, b)  F52_SA_CAT_I(a, b)
#  define F52_STATIC_ASSERT(c, m) typedef char F52_SA_CAT(f52_static_assert_failed_, __COUNTER__)[(c) ? 1 : -1]
#endif

/* SIMD function attribute: GNU/Clang use function-level target(avx512f,avx512ifma)
 * + noinline; MSVC has no function-level target (relies on TU-level /arch:AVX512) so only
 * noinline; legacy GCC (F52_GCC_LEGACY) also drops the target. */
#if F52_HAVE_AVX512IFMA
#  if defined(_MSC_VER)
#    define F52_AVX512_FN __declspec(noinline)
#  elif defined(F52_GCC_LEGACY)
#    define F52_AVX512_FN __attribute__((noinline))
#  else
#    define F52_AVX512_FN __attribute__((target("avx512f,avx512ifma"), noinline))
#  endif
/* MSVC lacks _mm512_rol/ror_epi64; fall back to shift+or (bit-identical per lane).
 * n must satisfy 0 < n < 64. */
#  if defined(_MSC_VER)
#    define F52_ROL512(x, n) _mm512_or_si512(_mm512_slli_epi64((x), (n)), _mm512_srli_epi64((x), 64 - (n)))
#    define F52_ROR512(x, n) _mm512_or_si512(_mm512_srli_epi64((x), (n)), _mm512_slli_epi64((x), 64 - (n)))
#  else
#    define F52_ROL512(x, n) _mm512_rol_epi64((x), (n))
#    define F52_ROR512(x, n) _mm512_ror_epi64((x), (n))
#  endif
#endif

#define F52_P1 0x9E3779B97F4A7C15ULL
#define F52_P2 0xC2B2AE3D27D4EB4FULL
#define F52_P3 0xCE516090AD952CC7ULL   /* odd multiplier (bijective) */

/* Non-multiplier magics (additive seed/len mixing and final-block cross-multiply):
 * need not be odd/bijective.  The multipliers P1/P2/P3 must be odd (to stay bijective). */
#define F52_M1 0x165667B19E3779F9ULL
#define F52_M2 0xC6A4A7935BD1E994ULL
#define F52_M3 0xFF51AFD7ED558CCDULL
#define F52_M4 0xD6E8FEB86659FD92ULL
#define F52_M52 0xFFFFFFFFFFFFFULL   /* 52-bit mask (IFMA madd52lo/hi 52-bit truncation) */

#ifdef __cplusplus
extern "C" {
#endif

#if F52_HAVE_AVX512IFMA
static inline F52_AINLINE __m512i f52_ld(const uint8_t * const p) {
    return _mm512_loadu_si512((const void *)p);
}

/* Misaligned-friendly 64B load: two separate 32B loads + combine; reads the same bytes
 * as f52_ld. */
static inline F52_AINLINE __m512i f52_ld32(const uint8_t * const p) {
    __m256i lo = _mm256_loadu_si256((const __m256i *)p);
    __m256i hi = _mm256_loadu_si256((const __m256i *)(p + 32));
#if defined(__GNUC__) && !defined(F52_GCC_LEGACY)
    __asm__("" : "+x"(lo), "+x"(hi));   /* keep the two halves in registers (MLP) */
#endif
    /* VSHUFFI64X2 (AVX-512F), imm 0x44 -> [lo.lo128, lo.hi128, hi.lo128, hi.hi128]:
     * the high 256 bits get hi.  Pure AVX-512F (VINSERTI32X8 would need AVX-512DQ). */
    return _mm512_shuffle_i64x2(_mm512_castsi256_si512(lo), _mm512_castsi256_si512(hi), 0x44);
}

/* Pin the vector in a register so gcc cannot fold the load into a later load-op and
 * drag the L2-miss latency onto the accumulator chain. */
#if defined(__GNUC__) && !defined(F52_GCC_LEGACY)
#define F52_REG(v) __asm__("" : "+v"(v))
#else
#define F52_REG(v) ((void)0)
#endif

static inline F52_AINLINE F52_CONST uint64_t f52_reduce(__m512i sum) {
    /* 8->4->2->1 horizontal XOR reduce; the final 64-bit pair is combined in scalar
     * (avoids a constant-index permute; _mm_extract_epi64 works on 32-bit). */
    __m512i t = _mm512_xor_si512(sum, _mm512_shuffle_i64x2(sum, sum, 0x4E));
    t = _mm512_xor_si512(t, _mm512_shuffle_i64x2(t, t, 0xB1));
    __m128i lo = _mm512_castsi512_si128(t);
    return (uint64_t)_mm_extract_epi64(lo, 0) ^ (uint64_t)_mm_extract_epi64(lo, 1);
}
#endif /* F52_HAVE_AVX512IFMA */

static inline F52_AINLINE F52_CONST uint64_t f52_bswap64(const uint64_t x) {
#if defined(_MSC_VER)
    return _byteswap_uint64(x);
#else
    return __builtin_bswap64(x);
#endif
}
static inline F52_AINLINE F52_CONST uint32_t f52_bswap32(const uint32_t x) {
#if defined(_MSC_VER)
    return _byteswap_ulong(x);
#else
    return __builtin_bswap32(x);
#endif
}
/* rotate: well-defined for any count (unsigned shift, no x>>64 or -INT_MIN UB),
 * compiles to a single rol/ror. */
static inline F52_AINLINE F52_CONST uint64_t f52_rotl(const uint64_t x, const int count) {
#if defined(_MSC_VER)
    return _rotl64(x, count);
#else
    const unsigned r = (unsigned)count & 63u;
    return (x << r) | (x >> ((64u - r) & 63u));
#endif
}
static inline F52_AINLINE F52_CONST uint64_t f52_rotr(const uint64_t x, const int count) {
#if defined(_MSC_VER)
    return _rotr64(x, count);
#else
    const unsigned r = (unsigned)count & 63u;
    return (x >> r) | (x << ((64u - r) & 63u));
#endif
}

/* 64x64 -> 128 unsigned multiply: native __int128 on 64-bit GCC/Clang, _umul128 on
 * MSVC x64, 32x32 decomposition on 32-bit (all bit-identical).  F52_MUL_LO/HI extract
 * the low/high 64 bits of the product. */
#if defined(__SIZEOF_INT128__)
typedef __uint128_t f52_u128;
static inline F52_AINLINE F52_CONST f52_u128 f52_mul128(const uint64_t a, const uint64_t b) {
    return (f52_u128)a * b;
}
#  define F52_MUL_LO(m) ((uint64_t)(m))
#  define F52_MUL_HI(m) ((uint64_t)((m) >> 64))
#elif defined(_MSC_VER) && defined(_M_X64)
typedef struct { uint64_t lo, hi; } f52_u128;
static inline F52_AINLINE F52_CONST f52_u128 f52_mul128(const uint64_t a, const uint64_t b) {
    f52_u128 r;
    r.lo = _umul128(a, b, &r.hi);
    return r;
}
#  define F52_MUL_LO(m) ((m).lo)
#  define F52_MUL_HI(m) ((m).hi)
#else
typedef struct { uint64_t lo, hi; } f52_u128;
static inline F52_AINLINE F52_CONST f52_u128 f52_mul128(const uint64_t a, const uint64_t b) {
    const uint64_t a0 = a & 0xFFFFFFFFu, a1 = a >> 32;
    const uint64_t b0 = b & 0xFFFFFFFFu, b1 = b >> 32;
    const uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    const uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    f52_u128 r;
    r.lo = (mid << 32) | (p00 & 0xFFFFFFFFu);
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return r;
}
#  define F52_MUL_LO(m) ((m).lo)
#  define F52_MUL_HI(m) ((m).hi)
#endif

/* Parameterized avalanche: shift->multiply->shift (sms); shift==F52_SKIP_SHIFT skips a
 * stage (covering sm/ms/sms); constant-folded, no runtime branch. */
#define F52_SKIP_SHIFT 64
static inline F52_AINLINE F52_CONST uint64_t f52_avalanche64_sms(uint64_t x, const int shift1,
                                           const uint64_t magic, const int shift2) {
    if (shift1 != F52_SKIP_SHIFT) x ^= x >> shift1;
    x *= magic;
    if (shift2 != F52_SKIP_SHIFT) x ^= x >> shift2;
    return x;
}

/* Statement-block variant of sms: modifies (x) in place, expanding textually to avoid a
 * callee-saved push/pop (e.g. push rbx in the short le8 branch), helping g++ avoid spills.
 * Semantically identical to f52_avalanche64_sms; arguments must be side-effect-free lvalues.
 * shift is masked &63 (avoids a shift>=width warning when shift==F52_SKIP_SHIFT). */
#define F52_AVALANCHE64_SMS(x, shift1, magic, shift2) { \
        if ((shift1) != F52_SKIP_SHIFT) (x) ^= (x) >> ((shift1) & 63); \
        (x) *= (magic); \
        if ((shift2) != F52_SKIP_SHIFT) (x) ^= (x) >> ((shift2) & 63); \
    }

/* 128-bit dual finalizer: one f52_avalanche64_sms on each of (lo_in,hi_in); the seed is
 * mixed in by the caller. */
static inline F52_AINLINE void f52_avalanche64x2(const uint64_t lo_in, const uint64_t hi_in,
                                     uint64_t * F52_RESTRICT const lo, uint64_t * F52_RESTRICT const hi,
                                     const int s1_lo, const uint64_t magic_lo, const int s2_lo,
                                     const int s1_hi, const uint64_t magic_hi, const int s2_hi) {
    *lo = f52_avalanche64_sms(lo_in, s1_lo, magic_lo, s2_lo);
    *hi = f52_avalanche64_sms(hi_in, s1_hi, magic_hi, s2_hi);
}

/* Combine two u64 into one: fold the 128-bit product halves (m.H ^ m.L) plus
 * bswap64(lo) + hi crossover. */
static inline F52_AINLINE F52_CONST uint64_t f52_avalanche64_fold(const uint64_t lo, const uint64_t hi) {
    const f52_u128 m = f52_mul128(lo, hi);
    return f52_bswap64(lo) + hi + (F52_MUL_LO(m) ^ F52_MUL_HI(m));
}

/* nano: (ml,mh) = lo*hi + same-side add (no bswap); inputs must already be dense. */
static inline F52_AINLINE void f52_avalanche128_nano(const uint64_t lo, const uint64_t hi,
                                          uint64_t * F52_RESTRICT const ml, uint64_t * F52_RESTRICT const mh) {
    const f52_u128 m = f52_mul128(lo, hi);
    *ml = F52_MUL_LO(m) + lo;
    *mh = F52_MUL_HI(m) + hi;
}

/* Lossless Lai-Massey bijection: t=lo-hi, f=fold(t*rotl(t,rot)), ml=lo+f, mh=hi+f.
 * A strict 128->128 bijection; invariant ml-mh=lo-hi, so the preceding stage must densify. */
#define F52_LM_ROT 37   /* rotation distance (odd, coprime to 64) */

static inline F52_AINLINE void f52_avalanche128_lm(const uint64_t lo, const uint64_t hi, const int rot,
                                          uint64_t * F52_RESTRICT const ml, uint64_t * F52_RESTRICT const mh) {
    const uint64_t t = lo - hi;
    const f52_u128 t2 = f52_mul128(t, f52_rotl(t, rot));
    const uint64_t f = F52_MUL_LO(t2) ^ F52_MUL_HI(t2);
    *ml = lo + f;
    *mh = hi + f;
}

#if F52_HAVE_AVX512IFMA
static inline F52_AINLINE F52_CONST __m512i f52_avalanche_v(__m512i x, const uint64_t magic, const unsigned s1, const unsigned s2) {
    x = _mm512_xor_si512(x, _mm512_srli_epi64(x, s1));
    /* 32x32->32 (VPMULLD, AVX-512F) rather than 64x64->64 (VPMULLQ, AVX-512DQ);
     * magic's low 32 bits are odd, so each 32-bit lane stays a bijection. */
    x = _mm512_mullo_epi32(x, _mm512_set1_epi32((int)(uint32_t)magic));
    x = _mm512_xor_si512(x, _mm512_srli_epi64(x, s2));
    return x;
}
#endif /* F52_HAVE_AVX512IFMA */

/* ---- short-input (<=16B) paths (scalar) ----
 *
 * Fixed-width (2^p) loads: a 1..3-byte index trick, two overlapping 4B reads for 4..8,
 * two overlapping 8B reads for 9..16 — avoids a variable-length memcpy. */

/* rd32/64/128 interpret input as little-endian: byteswap on big-endian machines so the
 * same byte sequence hashes identically across endianness.  MSVC targets are all LE and
 * lack __BYTE_ORDER__. */
#if defined(_MSC_VER)
#  define F52_IS_BE 0
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define F52_IS_BE 1
#else
#  define F52_IS_BE 0
#endif

/* x86/x86_64 are always little-endian; the SIMD path has no byte swap, so a misconfigured
 * endianness is a compile-time error. */
#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && F52_IS_BE
#  error "x86/64 target must be little-endian (F52_IS_BE must be 0)"
#endif

static inline F52_AINLINE uint32_t f52_rd32(const uint8_t * const p) {
    uint32_t v; memcpy(&v, p, 4);
    return F52_IS_BE ? f52_bswap32(v) : v;
}
static inline F52_AINLINE uint64_t f52_rd64(const uint8_t * const p) {
    uint64_t v; memcpy(&v, p, 8);
    return F52_IS_BE ? f52_bswap64(v) : v;
}
/* Read 16B and split lo/hi (LE: lo=p[0..7]); each half is byte-swapped on BE.  Two rd64
 * calls (not __uint128_t) so it works on 32-bit. */
static inline F52_AINLINE void f52_rd128(const uint8_t *const p, uint64_t *const lo, uint64_t *const hi) {
    *lo = f52_rd64(p);
    *hi = f52_rd64(p + 8);
}

/* seed pre-mix: mode=1 default rotl(seed,32)+M1; modes 2/3 are the medium A/B additive
 * mix + magic rotate. */
static inline F52_AINLINE F52_CONST uint64_t f52_seed_mix(const uint64_t seed, const int mode, const int shift) {
    if (mode==2) return seed + f52_rotl(F52_M2, shift);   /* medium A: additive mix + magic rotate */
    if (mode==3) return seed + f52_rotl(F52_M4, shift);   /* medium B */
    return f52_rotl(seed, 32) + F52_M1;                   /* default mode=1 */
}

static inline F52_AINLINE uint64_t f52_mix_le7(const uint8_t * const p, const size_t n) {
    assert(n <= 7);
    if (F52_LIKELY(n >= 4)) {
        const uint64_t lo = f52_rd32(p);
        const uint64_t hi = f52_rd32(p + n - 4);
        return ((uint64_t)n << 60) + ((hi << 28) ^ lo);
    }
    if (F52_LIKELY(n)) {
        const uint64_t c0 = p[0];
        const uint64_t ctail = p[n - 1];
        const uint64_t cshift = p[n >> 1];
        return ((uint64_t)n << 60) + (c0 << 33) + (ctail << 17) + cshift;
    }
    return 0;
}

/* Symmetric-fold square (64-bit Lai-Massey):
 *   y = x ^ rotl(x,32)  -> y is symmetric (lo32 == hi32 == t)
 *   y *= y (low 64)      -> t^2 + t^2<<33 (cross-term spread, no 128-bit hi carry)
 *   x ^= y ^ rotl(y,32)   -> strict bijection preserving the invariant t=lo^hi
 * Statement-block macro (not do-while(0), no const on locals) so g++ does not spill.
 * A later multiply by any odd magic stays bijective. */
#define F52_AVALANCHE64_LM(x) { \
        uint64_t _f52_y = (x) ^ f52_rotl((x), 32); \
        uint64_t _f52_yy = _f52_y * _f52_y; \
        (x) ^= _f52_yy ^ f52_rotl(_f52_yy, 32); \
    }

/* Short-key (<=8B) finalizer: split seed mix + xorshift + symmetric-fold square (lm) + imul.
 *   len==8: seed += (seed<<14)+P1;  len<8: seed += (seed<<10)+M2
 *     (splitting P1/M2 lets the two shifts differ, and distinct seed constants prevent CSE
 *      from merging the branches).
 *   x ^= seed;  x ^= x>>11;  x = lm(x);  seed ^= rotl(seed,33);  x+=seed; x*=P1; x^=x>>22. */
static inline uint64_t f52_short64_le8(const uint8_t * const p, const size_t len, uint64_t seed) {
    uint64_t x;
    assert(len <= 8);

    if (len == 8) {
        seed += (seed << 14) + F52_P1; /* P1 */
        x = f52_rd64(p);
    } else {
        seed += (seed << 10) + F52_M2; /* M2 (differs from P1 => two shifts can differ) */
        x = f52_mix_le7(p, len);
    }

    x ^= seed;
    x ^= x >> 11;                                    /* T0 xorshift spread */
    F52_AVALANCHE64_LM(x);

    seed ^= f52_rotl(seed, 33);
    x += seed; F52_AVALANCHE64_SMS(x, F52_SKIP_SHIFT, F52_P1, 22);
    return x;
}

static inline uint64_t f52_short64_9_16(const uint8_t * const p, const size_t len, uint64_t seed) {
    assert(len >= 9 && len <= 16);
    /* 9-16B: overlapping 8B reads (front/back) + seed mix, then two data x data
     * multiplies (nano crossover + fold) to finish. */
    uint64_t sl = seed + f52_rotl(F52_M1, (int)len);
    uint64_t sh = f52_seed_mix(seed, 1, 0);
    uint64_t lo = f52_rd64(p)           ^ sl;
    uint64_t hi = f52_rd64(p + len - 8) ^ sh;
    f52_avalanche128_nano(lo, hi, &lo, &hi);
    return f52_avalanche64_fold(lo + seed, hi);
}

static inline F52_AINLINE void f52_mix_le15(const uint8_t * const p, const size_t len,
                                uint64_t * F52_RESTRICT const lo, uint64_t * F52_RESTRICT const hi) {
    assert(len <= 15);

    if (F52_LIKELY(len >= 8)) {
        *lo = f52_rd64(p);
        *hi = ((uint64_t)len << 60) + (f52_rd64(p + len - 8)>>4);
        return;
    }
    if (F52_LIKELY(len >= 4)) {
        *lo = f52_rd32(p);
        *hi = ((uint64_t)len << 60) + f52_rd32(p + len - 4);
        return;
    }
    if (F52_LIKELY(len)) {
        uint64_t c0 = p[0];
        uint64_t ctail = p[len - 1];
        uint64_t cshift = p[len >> 1];
        *lo = (c0 << 24) + cshift;
        *hi = ((uint64_t)len << 60) + ctail;
        return;
    }
    *lo = *hi = 0;
}

static inline void f52_short128_le16(const uint8_t * const p, const size_t len, const uint64_t seed,
                                     uint64_t * F52_RESTRICT const lo, uint64_t * F52_RESTRICT const hi) {
    uint64_t il, ih, sl, sh;
    assert(len <= 16);
    if (len == 16) {
        sl = seed + F52_P2;
        sh = f52_rotl(seed, 32) + F52_P1;
        f52_rd128(p, &il, &ih);
    } else {
        sl = seed + F52_P1;
        sh = f52_rotl(seed, 32) + F52_P2;
        f52_mix_le15(p, len, &il, &ih);
    }

    il ^= sl;       ih ^= sh;
    il ^= il >> 16; ih *= F52_P1;
    f52_avalanche128_lm(il, ih, F52_LM_ROT, &il, &ih);
    f52_avalanche64x2(il + seed, ih + seed, lo, hi, 35, F52_P2, 28, 37, F52_P1, 32);
}

/* medium path (17-96B): scalar self-feedback A,B state — each value is both an accumulator
 * and a multiply operand for the next round.  The raw A/B addition keeps all input
 * information (multiply never truncates).  Per 16B block:
 *   A+=d0; B+=d1; A+=Low52(A*B); B=ror(B,12); B+=bits[76..128)(A*B).
 * 64/128 share this core; only the final A,B -> output compression differs. */
/* laneoff: shared by SIMD and scalar.  off[i] = P1*(i+1) ^ P2*(i>>1): the P2 term breaks
 * the symmetry of the purely linear P1 multiples. */
F52_ALIGN64 static const uint64_t f52_laneoff[8] = {
    F52_P1,                   F52_P1 * 2,
    F52_P1 * 3 ^ F52_P2,      F52_P1 * 4 ^ F52_P2,
    F52_P1 * 5 ^ F52_P2 * 2,  F52_P1 * 6 ^ F52_P2 * 2,
    F52_P1 * 7 ^ F52_P2 * 3,  F52_P1 * 8 ^ F52_P2 * 3,
};
/* _mm512_load_si512(f52_laneoff) reads a full 512 bits, so the table must be exactly
 * 8 x u64 (or it overruns). */
F52_STATIC_ASSERT(sizeof(f52_laneoff) == 8 * sizeof(uint64_t), "f52_laneoff must be 8 u64");

#if F52_HAVE_AVX512IFMA
/* broadcast seed + laneoff XOR, initializing the 14 accumulators of the medium loop and
 * long path.  ov is loaded once by the caller and reused; k=0..13 -> P2*1..14 separates
 * the accumulators, laneoff separates the lanes within one vector. */
static inline F52_AINLINE F52_CONST __m512i f52_seed_vector(const uint64_t seed, const uint64_t k, const __m512i ov) {
    return _mm512_xor_si512(_mm512_set1_epi64((int64_t)(seed + F52_P2 * (k + 1))), ov);
}

/* Initialize A0..A6/B0..B6 from seed: one broadcast + laneoff XOR per accumulator. */
#define F52_OFFV() _mm512_load_si512((const __m512i *)f52_laneoff)
#define F52_INIT() \
    do { \
        __m512i f52_ov = F52_OFFV(); \
        A0 = f52_seed_vector(seed, 0,  f52_ov); B0 = f52_seed_vector(seed, 1,  f52_ov); \
        A1 = f52_seed_vector(seed, 2,  f52_ov); B1 = f52_seed_vector(seed, 3,  f52_ov); \
        A2 = f52_seed_vector(seed, 4,  f52_ov); B2 = f52_seed_vector(seed, 5,  f52_ov); \
        A3 = f52_seed_vector(seed, 6,  f52_ov); B3 = f52_seed_vector(seed, 7,  f52_ov); \
        A4 = f52_seed_vector(seed, 8,  f52_ov); B4 = f52_seed_vector(seed, 9,  f52_ov); \
        A5 = f52_seed_vector(seed, 10, f52_ov); B5 = f52_seed_vector(seed, 11, f52_ov); \
        A6 = f52_seed_vector(seed, 12, f52_ov); B6 = f52_seed_vector(seed, 13, f52_ov); \
    } while (0)
#endif /* F52_HAVE_AVX512IFMA */

/* medium mix core (shared by 64/128): block0 is computed first (the multiply hides the
 * switch jump), middle blocks advance a pointer via fallthrough, the final block is a
 * branchless full-block overlapping read.  A single switch dispatch -> fewest mispredicts. */
static inline void f52_medium_mix_body(const uint8_t * const p, const size_t len, const uint64_t seed,
                                       uint64_t * F52_RESTRICT const outA, uint64_t * F52_RESTRICT const outB) {
    /* seed mixes additively (mode=2/3, shift=len/2 and len): under sparse seed/key, XOR
     * would cancel identical bits. */
    uint64_t A = f52_seed_mix(seed, 2, (int)(len / 2));
    uint64_t B = f52_seed_mix(seed, 3, (int)len);

    /* Per block (16B = 2 u64): A+=d0; B+=d1; pr=A*B; A+=low52(pr); B=ror12(B);
     * B+=bits[76..128)(pr).  One full 64x64->128 product; A and B come from the same pr
     * (exact — unlike the IFMA truncation in the long loop). */
#define F52_MCORE(p) \
    do { \
        uint64_t d0, d1; \
        f52_rd128(p, &d0, &d1); \
        A += d0; B += d1; \
        f52_u128 pr_ = f52_mul128(A, B); \
        A += F52_MUL_LO(pr_) & 0xFFFFFFFFFFFFFULL; \
        B = f52_rotr(B, 12); \
        B += F52_MUL_HI(pr_) >> 12; \
    } while (0)

    F52_MCORE(p);        /* block0 first (directly at p) */

    /* Middle full blocks.  The switch dispatches on nfull (fallthrough): nfull=5->4 blocks
     * ... 2->1 block, otherwise (17-32) no middle block.  Each case reads rd128(q) then
     * q+=16 -> forward. */
    const uint8_t * q = p + 16;
    const size_t nfull = (len - 1) >> 4;
    switch (nfull) {
        case 5: F52_MCORE(q); q += 16;  /* fallthrough */
        case 4: F52_MCORE(q); q += 16;  /* fallthrough */
        case 3: F52_MCORE(q); q += 16;  /* fallthrough */
        case 2: F52_MCORE(q); q += 16;  /* fallthrough */
        default: break;
    }
#undef F52_MCORE

    /* Final block: always a full-block overlapping read of [len-16, len), branchless, no
     * self-feedback multiply (saves latency).  The l/h cross-multiply (h+M3)*(l+M4) is the
     * only strongly l/h-coupled nonlinear pre-mix, and it stays off the critical path. */
    {
        uint64_t l, h;
        f52_rd128(p + len - 16, &l, &h);
        f52_u128 m_ = f52_mul128(h + F52_M3, l + F52_M4);
        h += F52_MUL_HI(m_); l += F52_MUL_LO(m_);
        A += l; B += h;
    }

    *outA = A;
    *outB = B;
}

static inline uint64_t f52_medium64_scalar(const uint8_t * const p, const size_t len, const uint64_t seed) {
    assert(len >= 17 && len <= 96);
    uint64_t A, B;
    f52_medium_mix_body(p, len, seed, &A, &B);
    /* nano crossover + fold finalizer (seed mixes in via fold's A+seed). */
    f52_avalanche128_nano(A, B, &A, &B);
    return f52_avalanche64_fold(A + seed, B);
}

static inline void f52_medium128_scalar(const uint8_t * const p, const size_t len, const uint64_t seed,
                                 uint64_t * F52_RESTRICT const out) {
    assert(len >= 17 && len <= 96);
    uint64_t A, B;
    f52_medium_mix_body(p, len, seed, &A, &B);    /* final-block cross-multiply pre-mix (already l/h crossed) */
    /* lm crossover (strict 128->128 bijection); final av64x2 mixes len via seed+len. */
    f52_avalanche128_lm(A, B, F52_LM_ROT, &A, &B);
    f52_avalanche64x2(A + seed + len, B + seed + len, out, out + 1, 35, F52_P2, 28, 37, F52_P1, 32);
}

#if F52_HAVE_AVX512IFMA
/* ---- shared accumulation core ---- */

/* Long path (len>=896): 7 self-feedback lanes, software-pipelined (this round's loads are
 * consumed only next round, hiding L2 latency behind a full round of madd52).  Per lane,
 * per round:
 *   A+=d0; B+=d1; sA=A>>12; A=madd52lo(A,A,B); B=ror(B,12); B=madd52hi(B,sA,B). */

#define F52_LD14(p) \
    do { \
        d0 = f52_ld(p);          F52_REG(d0); \
        d1 = f52_ld((p) + 64);   F52_REG(d1); \
        d2 = f52_ld((p) + 128);  F52_REG(d2); \
        d3 = f52_ld((p) + 192);  F52_REG(d3); \
        d4 = f52_ld((p) + 256);  F52_REG(d4); \
        d5 = f52_ld((p) + 320);  F52_REG(d5); \
        d6 = f52_ld((p) + 384);  F52_REG(d6); \
        d7 = f52_ld((p) + 448);  F52_REG(d7); \
        d8 = f52_ld((p) + 512);  F52_REG(d8); \
        d9 = f52_ld((p) + 576);  F52_REG(d9); \
        d10 = f52_ld((p) + 640); F52_REG(d10); \
        d11 = f52_ld((p) + 704); F52_REG(d11); \
        d12 = f52_ld((p) + 768); F52_REG(d12); \
        d13 = f52_ld((p) + 832); F52_REG(d13); \
    } while (0)

/* misaligned variant: each 64B window via two pinned 32B loads + a shuffle. */
#define F52_LD14_32(p) \
    do { \
        d0 = f52_ld32(p);          F52_REG(d0); \
        d1 = f52_ld32((p) + 64);   F52_REG(d1); \
        d2 = f52_ld32((p) + 128);  F52_REG(d2); \
        d3 = f52_ld32((p) + 192);  F52_REG(d3); \
        d4 = f52_ld32((p) + 256);  F52_REG(d4); \
        d5 = f52_ld32((p) + 320);  F52_REG(d5); \
        d6 = f52_ld32((p) + 384);  F52_REG(d6); \
        d7 = f52_ld32((p) + 448);  F52_REG(d7); \
        d8 = f52_ld32((p) + 512);  F52_REG(d8); \
        d9 = f52_ld32((p) + 576);  F52_REG(d9); \
        d10 = f52_ld32((p) + 640); F52_REG(d10); \
        d11 = f52_ld32((p) + 704); F52_REG(d11); \
        d12 = f52_ld32((p) + 768); F52_REG(d12); \
        d13 = f52_ld32((p) + 832); F52_REG(d13); \
    } while (0)

/* consume the loaded d0..d13 into the accumulators */
#define F52_CONSUME7() \
    do { \
        A0 = _mm512_add_epi64(A0, d0);   B0 = _mm512_add_epi64(B0, d1); \
        A1 = _mm512_add_epi64(A1, d2);   B1 = _mm512_add_epi64(B1, d3); \
        A2 = _mm512_add_epi64(A2, d4);   B2 = _mm512_add_epi64(B2, d5); \
        A3 = _mm512_add_epi64(A3, d6);   B3 = _mm512_add_epi64(B3, d7); \
        A4 = _mm512_add_epi64(A4, d8);   B4 = _mm512_add_epi64(B4, d9); \
        A5 = _mm512_add_epi64(A5, d10);  B5 = _mm512_add_epi64(B5, d11); \
        A6 = _mm512_add_epi64(A6, d12);  B6 = _mm512_add_epi64(B6, d13); \
    } while (0)

/* mixing body: an srli snapshot decouples the two IFMAs (madd52lo reads old A,B, madd52hi
 * reads the snapshot sA + rotated B), no spill. */
#define F52_BODY7_LANE(A, B) \
    { __m512i f52_sA = _mm512_srli_epi64(A, 12); \
      A = _mm512_madd52lo_epu64(A, A, B); \
      B = F52_ROR512(B, 12); \
      B = _mm512_madd52hi_epu64(B, f52_sA, B); }
#define F52_BODY7() \
    do { \
        F52_BODY7_LANE(A0, B0) F52_BODY7_LANE(A1, B1) \
        F52_BODY7_LANE(A2, B2) F52_BODY7_LANE(A3, B3) \
        F52_BODY7_LANE(A4, B4) F52_BODY7_LANE(A5, B5) \
        F52_BODY7_LANE(A6, B6) \
    } while (0)

/* pipelined round: consume previous loads, issue next round's loads, mix. */
#define F52_PIPE7(pnext) \
    do { \
        F52_CONSUME7(); \
        F52_LD14(pnext); \
        F52_BODY7(); \
    } while (0)

/* misaligned-load variant of the pipelined round. */
#define F52_PIPE7_32(pnext) \
    do { \
        F52_CONSUME7(); \
        F52_LD14_32(pnext); \
        F52_BODY7(); \
    } while (0)

/* drain round: consume the last loaded group, mix, no further load. */
#define F52_FINAL7() \
    do { \
        F52_CONSUME7(); \
        F52_BODY7(); \
    } while (0)

/* fresh tail round: loads only the remaining k = ceil(remain/64) fresh 64B chunks (ending
 * at input+len), reusing the previous strip's d[0..14-k-1] prefix.  This is a deliberate
 * load-saving choice, not a true sliding window — every byte is still mixed at least once. */
#define F52_TAIL7_32(pend, k) \
    do { \
        switch (k) { \
            case 14: d0  = f52_ld32((pend) - 896); F52_REG(d0);  /* fallthrough */ \
            case 13: d1  = f52_ld32((pend) - 832); F52_REG(d1);  /* fallthrough */ \
            case 12: d2  = f52_ld32((pend) - 768); F52_REG(d2);  /* fallthrough */ \
            case 11: d3  = f52_ld32((pend) - 704); F52_REG(d3);  /* fallthrough */ \
            case 10: d4  = f52_ld32((pend) - 640); F52_REG(d4);  /* fallthrough */ \
            case 9:  d5  = f52_ld32((pend) - 576); F52_REG(d5);  /* fallthrough */ \
            case 8:  d6  = f52_ld32((pend) - 512); F52_REG(d6);  /* fallthrough */ \
            case 7:  d7  = f52_ld32((pend) - 448); F52_REG(d7);  /* fallthrough */ \
            case 6:  d8  = f52_ld32((pend) - 384); F52_REG(d8);  /* fallthrough */ \
            case 5:  d9  = f52_ld32((pend) - 320); F52_REG(d9);  /* fallthrough */ \
            case 4:  d10 = f52_ld32((pend) - 256); F52_REG(d10); /* fallthrough */ \
            case 3:  d11 = f52_ld32((pend) - 192); F52_REG(d11); /* fallthrough */ \
            case 2:  d12 = f52_ld32((pend) - 128); F52_REG(d12); /* fallthrough */ \
            case 1:  d13 = f52_ld32((pend) - 64);  F52_REG(d13); /* fallthrough */ \
            default: break; \
        } \
        F52_CONSUME7(); \
        F52_BODY7(); \
    } while (0)

/* accumulate: pipelined over 896B groups (loads deferred one round so the L2
 * latency is hidden); the tail then loads only the ceil(remain/64) fresh 64B
 * chunks (reusing the previous round's registers for the rest).
 * Only called for len >= 896 (the medium loop covers up to 895). */
#define F52_ACCUMULATE_WITH(LD, PIPE, TAIL) \
    do { \
        size_t f52_i, f52_n; \
        /* ceil(len/896): widen to u64 first so +895 cannot overflow on 32-bit (4 GiB inputs \
         * are realistic there); on 64-bit only an input near UINT64_MAX could still overflow \
         * (impractical). */ \
        f52_n = (size_t)(((uint64_t)len + 895) / 896); \
        LD(input); \
        for (f52_i = 0; f52_i + 1 < f52_n - 1; f52_i++) { \
            PIPE(input + (f52_i + 1) * 896); \
        } \
        F52_FINAL7(); \
        if (f52_n > 1) \
            TAIL(input + len, (len - (f52_n - 1) * 896 + 63) / 64); \
    } while (0)

/* accumulate: pipelined over 896B groups (loads deferred one round hide L2 latency); each
 * load flavor reads the same bytes, so the hash is identical.  The main loop uses loadu for
 * short/aligned inputs and merge32 (2x32B loads + a shuffle) for large misaligned ones; the
 * tail uses merge32 to cover only the fresh bytes. */
#define F52_LOADU_MAX (55 * 896)
#define F52_ACCUMULATE() \
    do { \
        if (F52_LIKELY(len <= F52_LOADU_MAX || f52_off == 0)) \
            F52_ACCUMULATE_WITH(F52_LD14, F52_PIPE7, F52_TAIL7_32); /* prologue+loop loadu, partial merge32 */ \
        else \
            F52_ACCUMULATE_WITH(F52_LD14, F52_PIPE7_32, F52_TAIL7_32); /* prologue loadu, loop+partial merge32 */ \
    } while (0)

/* [97, 896B) medium loop: 7 independent 128B lanes, three switch stages load / seed+ifma / reduce. */

/* one medium lane: seed (2k,2k+1) -> add dA,dB -> madd52 mix. */
#define F52_MLANE(A, B, k, dA, dB, ov) \
    do { \
        A = f52_seed_vector(seed, 2 * (k), ov); \
        B = f52_seed_vector(seed, 2 * (k) + 1, ov); \
        A = _mm512_add_epi64(A, dA); \
        B = _mm512_add_epi64(B, dB); \
        { __m512i f52_sA = _mm512_srli_epi64(A, 12); \
          A = _mm512_madd52lo_epu64(A, A, B); \
          B = F52_ROR512(B, 12); \
          B = _mm512_madd52hi_epu64(B, f52_sA, B); } \
    } while (0)

/* In debug builds, zero-initialize the d/acc registers (guards against a future change
 * missing a case -> UB); not expanded in release (the call site's pragma silences the
 * false positive).  ⚠ Before editing F52_MEDIUM_LOOP's switch (nblocks/nlanes cases), run
 * DEBUG_ZEROINIT over all lengths 97-895 — in release a missing case is silent UB. */
#ifndef NDEBUG
#define F52_DEBUG_ZEROINIT \
        f52_A = f52_B = f52_C = f52_D = f52_E = f52_F = f52_G = \
        f52_H = f52_I = f52_J = f52_K = f52_L = f52_M = f52_N = \
        f52_d0 = f52_d1 = f52_d2 = f52_d3 = f52_d4 = f52_d5 = f52_d6 = \
        f52_d7 = f52_d8 = f52_d9 = f52_d10 = f52_d11 = f52_td0 = f52_td1 = _mm512_setzero_si512();
#else
#define F52_DEBUG_ZEROINIT
#endif

#define F52_MEDIUM_LOOP(outA, outB) \
    do { \
        size_t f52_nblocks = len >> 7;                 /* full 128B blocks: 0..6 */ \
        size_t f52_tail = len & 127; \
        size_t f52_nlanes = f52_nblocks + (f52_tail ? 1 : 0);  /* 1..7 */ \
        __m512i f52_A, f52_B, f52_C, f52_D, f52_E, f52_F, f52_G, \
                f52_H, f52_I, f52_J, f52_K, f52_L, f52_M, f52_N; \
        __m512i f52_d0, f52_d1, f52_d2, f52_d3, f52_d4, f52_d5, f52_d6, \
                f52_d7, f52_d8, f52_d9, f52_d10, f52_d11, f52_td0, f52_td1; \
        /* debug-only zero-init (guards against a missing case -> UB); release pays nothing. */ \
        F52_DEBUG_ZEROINIT \
        /* ---- switch LOAD ---- */ \
        switch (f52_nblocks) { \
            case 6: f52_d10 = f52_ld(input + 640); f52_d11 = f52_ld(input + 704);  /* fallthrough */ \
            case 5: f52_d8  = f52_ld(input + 512); f52_d9  = f52_ld(input + 576);  /* fallthrough */ \
            case 4: f52_d6  = f52_ld(input + 384); f52_d7  = f52_ld(input + 448);  /* fallthrough */ \
            case 3: f52_d4  = f52_ld(input + 256); f52_d5  = f52_ld(input + 320);  /* fallthrough */ \
            case 2: f52_d2  = f52_ld(input + 128); f52_d3  = f52_ld(input + 192);  /* fallthrough */ \
            case 1: f52_d0  = f52_ld(input + 0);   f52_d1  = f52_ld(input + 64);   /* fallthrough */ \
            default: break; \
        } \
        if (f52_tail) { \
            /* final 64B window: overlapping read at input+len-64 (len>=64 always holds). */ \
            f52_td0 = f52_ld(input + len - 64); \
            f52_td1 = (f52_tail >= 64) ? f52_ld(input + (f52_nblocks << 7)) \
                                       : _mm512_setzero_si512(); \
        } \
        /* ---- switch SEED+IFMA (merged) ---- */ \
        { __m512i f52_ov = F52_OFFV(); \
        switch (f52_nblocks) { \
            case 6: F52_MLANE(f52_K, f52_L, 5, f52_d10, f52_d11, f52_ov);  /* fallthrough */ \
            case 5: F52_MLANE(f52_I, f52_J, 4, f52_d8,  f52_d9,  f52_ov);  /* fallthrough */ \
            case 4: F52_MLANE(f52_G, f52_H, 3, f52_d6,  f52_d7,  f52_ov);  /* fallthrough */ \
            case 3: F52_MLANE(f52_E, f52_F, 2, f52_d4,  f52_d5,  f52_ov);  /* fallthrough */ \
            case 2: F52_MLANE(f52_C, f52_D, 1, f52_d2,  f52_d3,  f52_ov);  /* fallthrough */ \
            case 1: F52_MLANE(f52_A, f52_B, 0, f52_d0,  f52_d1,  f52_ov);  /* fallthrough */ \
            default: break; \
        } \
        if (f52_tail) { \
            switch (f52_nblocks) { /* tail lane = nblocks */ \
                case 0: F52_MLANE(f52_A, f52_B, 0, f52_td0, f52_td1, f52_ov); break; \
                case 1: F52_MLANE(f52_C, f52_D, 1, f52_td0, f52_td1, f52_ov); break; \
                case 2: F52_MLANE(f52_E, f52_F, 2, f52_td0, f52_td1, f52_ov); break; \
                case 3: F52_MLANE(f52_G, f52_H, 3, f52_td0, f52_td1, f52_ov); break; \
                case 4: F52_MLANE(f52_I, f52_J, 4, f52_td0, f52_td1, f52_ov); break; \
                case 5: F52_MLANE(f52_K, f52_L, 5, f52_td0, f52_td1, f52_ov); break; \
                default: F52_MLANE(f52_M, f52_N, 6, f52_td0, f52_td1, f52_ov); break; \
            } \
        } \
        } \
        /* ---- switch REDUCE ---- */ \
        { __m512i f52_RA = _mm512_setzero_si512(); \
          __m512i f52_RB = _mm512_setzero_si512(); \
          switch (f52_nlanes) { \
              case 7: \
                  f52_RA = _mm512_add_epi64(f52_RA, F52_ROL512(f52_M, 53)); \
                  f52_RB = _mm512_add_epi64(f52_RB, F52_ROL512(f52_N, 53));  /* fallthrough */ \
              case 6: \
                  f52_RA = _mm512_xor_si512(f52_RA, F52_ROL512(f52_L, 37)); \
                  f52_RB = _mm512_xor_si512(f52_RB, F52_ROL512(f52_K, 37));  /* fallthrough */ \
              case 5: \
                  f52_RA = _mm512_add_epi64(f52_RA, F52_ROL512(f52_I, 13)); \
                  f52_RB = _mm512_add_epi64(f52_RB, F52_ROL512(f52_J, 13));  /* fallthrough */ \
              case 4: \
                  f52_RA = _mm512_xor_si512(f52_RA, F52_ROL512(f52_H, 51)); \
                  f52_RB = _mm512_xor_si512(f52_RB, F52_ROL512(f52_G, 51));  /* fallthrough */ \
              case 3: \
                  f52_RA = _mm512_add_epi64(f52_RA, F52_ROL512(f52_E, 34)); \
                  f52_RB = _mm512_add_epi64(f52_RB, F52_ROL512(f52_F, 34));  /* fallthrough */ \
              case 2: \
                  f52_RA = _mm512_xor_si512(f52_RA, F52_ROL512(f52_D, 17)); \
                  f52_RB = _mm512_xor_si512(f52_RB, F52_ROL512(f52_C, 17));  /* fallthrough */ \
              default: \
                  f52_RA = _mm512_add_epi64(f52_RA, f52_A); \
                  f52_RB = _mm512_add_epi64(f52_RB, f52_B); \
          } \
          (outA) = f52_avalanche_v(f52_RA, F52_P1, 37, 32); \
          (outB) = f52_avalanche_v(f52_RB, F52_P2, 35, 28); \
        } \
    } while (0)

F52_AVX512_FN
static uint64_t f52_medium64_loop_avx512(const uint8_t * const input, size_t len, uint64_t seed) {
    __m512i f52_MA, f52_MB;
    assert(len >= 97 && len < 896);   /* ensures nblocks in [0,6], so every switch is exhaustive */
    /* With F52_MEDIUM_LOOP's switch dispatch GCC cannot prove the per-lane registers are
     * initialized -> -Wmaybe-uninitialized; no real UB, so silence it locally. */
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
    F52_MEDIUM_LOOP(f52_MA, f52_MB);
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic pop
#endif
    /* A/B fold, then a single reduce. */
    __m512i sum = _mm512_xor_si512(
        _mm512_xor_si512(f52_MA, f52_MB),
        _mm512_xor_si512(_mm512_srli_epi64(f52_MA, 32), _mm512_srli_epi64(f52_MB, 32)));
    uint64_t h = f52_reduce(sum);
    /* full avalanche split into two sms (one +sl per layer).  sl uses seed_mix mode3 to mix
     * len additively. */
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}

F52_AVX512_FN
static void f52_medium128_loop_avx512(const uint8_t * const input, size_t len, uint64_t seed,
                                      uint64_t out[2]) {
    __m512i f52_MA, f52_MB;
    assert(len >= 97 && len < 896);
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
    F52_MEDIUM_LOOP(f52_MA, f52_MB);
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic pop
#endif
    /* sl = seed_mix mode3 mixes len in; sh = bswap(sl) makes the two lanes asymmetric so
     * the lm difference decorrelates. */
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    const uint64_t sh = f52_bswap64(sl);
    uint64_t xlo = f52_reduce(f52_MA) + sl;
    uint64_t xhi = f52_reduce(f52_MB) + sh;
    /* lm crossover (unified with medium128_scalar, strict bijection). */
    f52_avalanche128_lm(xlo, xhi, F52_LM_ROT, &xlo, &xhi);
    f52_avalanche64x2(xlo + sl, xhi + sh, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* ---- 64-bit ---- */

/* Long path for inputs >= 896B with AVX-512 */
F52_AVX512_FN
static uint64_t f52_long64_avx512(const void * const key, size_t len, uint64_t seed) {
    const uint8_t * const input = (const uint8_t *)key;
    assert(len >= 896);
    const size_t f52_off = (uintptr_t)input & 63;
    __m512i A0, A1, A2, A3, A4, A5, A6, B0, B1, B2, B3, B4, B5, B6;
    __m512i d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13;
    F52_INIT();
    F52_ACCUMULATE();
    __m512i sum = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(A0, A1), _mm512_xor_si512(A2, A3)),
        _mm512_xor_si512(_mm512_xor_si512(A4, A5), A6));
    sum = _mm512_xor_si512(sum,
        _mm512_xor_si512(_mm512_xor_si512(B0, B1), _mm512_xor_si512(B2, B3)));
    sum = _mm512_xor_si512(sum,
        _mm512_xor_si512(_mm512_xor_si512(B4, B5), B6));
    uint64_t h = f52_reduce(sum);
    /* full avalanche split into two sms (one +sl per layer) for enough spread on an all-zero
     * key.  sl uses seed_mix mode3 to mix len additively. */
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}
#endif /* F52_HAVE_AVX512IFMA */

/* ==================== scalar fallback (f52_v8: 8x u64, mirrors __m512i) ====================
 * Compiled only when F52_HAVE_AVX512IFMA==0; bit-identical to the SIMD path. */
#if !F52_HAVE_AVX512IFMA

typedef struct { uint64_t v[8]; } f52_v8;

static inline F52_AINLINE f52_v8 f52_v8_set1(const uint64_t x) {
    f52_v8 r; int i; for (i = 0; i < 8; i++) r.v[i] = x; return r;
}
static inline F52_AINLINE f52_v8 f52_v8_zero(void) {
    f52_v8 r; int i; for (i = 0; i < 8; i++) r.v[i] = 0; return r;
}
/* 64B -> 8 lanes (4x rd128, no alignment concerns). */
static inline F52_AINLINE f52_v8 f52_v8_load(const uint8_t * const p) {
    f52_v8 r;
    f52_rd128(p,      &r.v[0], &r.v[1]);
    f52_rd128(p + 16, &r.v[2], &r.v[3]);
    f52_rd128(p + 32, &r.v[4], &r.v[5]);
    f52_rd128(p + 48, &r.v[6], &r.v[7]);
    return r;
}
static inline F52_AINLINE f52_v8 f52_v8_add(f52_v8 a, const f52_v8 b) {
    int i; for (i = 0; i < 8; i++) a.v[i] += b.v[i]; return a;
}
static inline F52_AINLINE f52_v8 f52_v8_xor(f52_v8 a, const f52_v8 b) {
    int i; for (i = 0; i < 8; i++) a.v[i] ^= b.v[i]; return a;
}
static inline F52_AINLINE f52_v8 f52_v8_srli(f52_v8 a, const int n) {
    int i; for (i = 0; i < 8; i++) a.v[i] >>= n; return a;
}
static inline F52_AINLINE f52_v8 f52_v8_rol(f52_v8 a, const int n) {
    int i; for (i = 0; i < 8; i++) a.v[i] = f52_rotl(a.v[i], n); return a;
}
static inline F52_AINLINE uint64_t f52_v8_reduce(const f52_v8 a) {   /* XOR of 8 lanes */
    uint64_t x = 0; int i; for (i = 0; i < 8; i++) x ^= a.v[i]; return x;
}

/* per-lane mix (mirrors F52_BODY7_LANE/MLANE): A+=low52(A*B); B=ror12;
 * B+=High52((A>>12)*(B>>12)).  madd52lo needs no operand mask; madd52hi's &M52 collapses
 * to >>12 under the A>>12 / ror(B,12) usage. */
static inline F52_AINLINE void f52_v8_mix(f52_v8 * const A, f52_v8 * const B) {
    int i;
    for (i = 0; i < 8; i++) {
        const uint64_t a = A->v[i], b = B->v[i];
        const f52_u128 m1 = f52_mul128(a, b);
        A->v[i] = a + (F52_MUL_LO(m1) & F52_M52);
        const uint64_t br = f52_rotr(b, 12);
        const f52_u128 m2 = f52_mul128(a >> 12, b >> 12);
        B->v[i] = br + ((F52_MUL_LO(m2) >> 52) | (F52_MUL_HI(m2) << 12));
    }
}

/* per-lane avalanche_v (mirrors f52_avalanche_v): 64-bit srli/xor + 32-bit mullo. */
static inline F52_AINLINE f52_v8 f52_v8_avalanche(f52_v8 x, const uint64_t magic, const unsigned s1, const unsigned s2) {
    const uint32_t m = (uint32_t)magic;
    int i;
    for (i = 0; i < 8; i++) {
        uint64_t v = x.v[i] ^ (x.v[i] >> s1);
        v = (uint64_t)((uint32_t)v * m) | ((uint64_t)((uint32_t)(v >> 32) * m) << 32);
        x.v[i] = v ^ (v >> s2);
    }
    return x;
}

/* medium loop (97-895B) scalar core: load+seed+mix+cross-lane reduce, lane-equivalent to
 * F52_MEDIUM_LOOP. */
static void f52_medium_loop_scalar_core(const uint8_t * const input, const size_t len, const uint64_t seed,
                                        f52_v8 * const outRA, f52_v8 * const outRB) {
    const size_t nblocks = len >> 7;
    const size_t tail = len & 127;
    const size_t nlanes = nblocks + (tail ? 1 : 0);
    f52_v8 LA[7], LB[7];
    size_t k; int i;

    for (k = 0; k < nblocks; k++) {
        const f52_v8 dA = f52_v8_load(input + (k << 7));
        const f52_v8 dB = f52_v8_load(input + (k << 7) + 64);
        LA[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 1));
        LB[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 2));
        for (i = 0; i < 8; i++) {
            LA[k].v[i] = (LA[k].v[i] ^ f52_laneoff[i]) + dA.v[i];
            LB[k].v[i] = (LB[k].v[i] ^ f52_laneoff[i]) + dB.v[i];
        }
        f52_v8_mix(&LA[k], &LB[k]);
    }
    if (tail) {
        const f52_v8 td0 = f52_v8_load(input + len - 64);
        const f52_v8 td1 = (tail >= 64) ? f52_v8_load(input + (nblocks << 7)) : f52_v8_zero();
        k = nblocks;
        LA[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 1));
        LB[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 2));
        for (i = 0; i < 8; i++) {
            LA[k].v[i] = (LA[k].v[i] ^ f52_laneoff[i]) + td0.v[i];
            LB[k].v[i] = (LB[k].v[i] ^ f52_laneoff[i]) + td1.v[i];
        }
        f52_v8_mix(&LA[k], &LB[k]);
    }
    /* cross-lane reduce (mirrors F52_MEDIUM_LOOP's switch; A/B cross over, alternating add/xor). */
    {
        f52_v8 ra = f52_v8_zero(), rb = f52_v8_zero();
        switch (nlanes) {
            case 7: ra = f52_v8_add(ra, f52_v8_rol(LA[6], 53)); rb = f52_v8_add(rb, f52_v8_rol(LB[6], 53)); /* fallthrough */
            case 6: ra = f52_v8_xor(ra, f52_v8_rol(LB[5], 37)); rb = f52_v8_xor(rb, f52_v8_rol(LA[5], 37)); /* fallthrough */
            case 5: ra = f52_v8_add(ra, f52_v8_rol(LA[4], 13)); rb = f52_v8_add(rb, f52_v8_rol(LB[4], 13)); /* fallthrough */
            case 4: ra = f52_v8_xor(ra, f52_v8_rol(LB[3], 51)); rb = f52_v8_xor(rb, f52_v8_rol(LA[3], 51)); /* fallthrough */
            case 3: ra = f52_v8_add(ra, f52_v8_rol(LA[2], 34)); rb = f52_v8_add(rb, f52_v8_rol(LB[2], 34)); /* fallthrough */
            case 2: ra = f52_v8_xor(ra, f52_v8_rol(LB[1], 17)); rb = f52_v8_xor(rb, f52_v8_rol(LA[1], 17)); /* fallthrough */
            default: ra = f52_v8_add(ra, LA[0]); rb = f52_v8_add(rb, LB[0]);
        }
        *outRA = ra; *outRB = rb;
    }
}

F52_NOINLINE
static uint64_t f52_medium64_loop_scalar(const uint8_t * const input, const size_t len, const uint64_t seed) {
    f52_v8 RA, RB;
    assert(len >= 97 && len < 896);
    f52_medium_loop_scalar_core(input, len, seed, &RA, &RB);
    RA = f52_v8_avalanche(RA, F52_P1, 37, 32);
    RB = f52_v8_avalanche(RB, F52_P2, 35, 28);
    const f52_v8 sum = f52_v8_xor(f52_v8_xor(RA, RB),
                                  f52_v8_xor(f52_v8_srli(RA, 32), f52_v8_srli(RB, 32)));
    uint64_t h = f52_v8_reduce(sum);
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}

F52_NOINLINE
static void f52_medium128_loop_scalar(const uint8_t * const input, const size_t len, const uint64_t seed, uint64_t out[2]) {
    f52_v8 RA, RB;
    assert(len >= 97 && len < 896);
    f52_medium_loop_scalar_core(input, len, seed, &RA, &RB);
    RA = f52_v8_avalanche(RA, F52_P1, 37, 32);
    RB = f52_v8_avalanche(RB, F52_P2, 35, 28);
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    const uint64_t sh = f52_bswap64(sl);
    uint64_t xlo = f52_v8_reduce(RA) + sl;
    uint64_t xhi = f52_v8_reduce(RB) + sh;
    f52_avalanche128_lm(xlo, xhi, F52_LM_ROT, &xlo, &xhi);
    f52_avalanche64x2(xlo + sl, xhi + sh, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* long path (>=896B) scalar core: 14 accumulators + strip/tail, byte-equivalent to
 * F52_ACCUMULATE (including the tail's deliberate "refresh only the last ceil(remain/64)
 * 64B chunks, reuse the previous strip's prefix" choice). */
static void f52_long_scalar_core(const uint8_t * const input, const size_t len, const uint64_t seed,
                                 f52_v8 outA[7], f52_v8 outB[7]) {
    /* ceil(len/896): widen to u64 first (see F52_ACCUMULATE_WITH) so +895 cannot overflow
     * on 32-bit. */
    const size_t n = (size_t)(((uint64_t)len + 895) / 896);
    f52_v8 A[7], B[7], d[14];
    size_t s, k; int i;

    for (k = 0; k < 7; k++) {
        A[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 1));
        B[k] = f52_v8_set1(seed + F52_P2 * (2 * k + 2));
        for (i = 0; i < 8; i++) {
            A[k].v[i] ^= f52_laneoff[i];
            B[k].v[i] ^= f52_laneoff[i];
        }
    }
    for (s = 0; s + 1 < n; s++) {                      /* n-1 full 896B strips */
        for (k = 0; k < 14; k++) d[k] = f52_v8_load(input + s * 896 + k * 64);
        for (k = 0; k < 7; k++) { A[k] = f52_v8_add(A[k], d[2 * k]); B[k] = f52_v8_add(B[k], d[2 * k + 1]); }
        for (k = 0; k < 7; k++) f52_v8_mix(&A[k], &B[k]);
    }
    {                                                  /* tail */
        const size_t remain = len - (n - 1) * 896;
        const size_t nt = (remain + 63) / 64;
        const uint8_t * const pend = input + len;
        for (k = 0; k < nt; k++) d[14 - nt + k] = f52_v8_load(pend - (nt - k) * 64);
        for (k = 0; k < 7; k++) { A[k] = f52_v8_add(A[k], d[2 * k]); B[k] = f52_v8_add(B[k], d[2 * k + 1]); }
        for (k = 0; k < 7; k++) f52_v8_mix(&A[k], &B[k]);
    }
    for (k = 0; k < 7; k++) { outA[k] = A[k]; outB[k] = B[k]; }
}

F52_NOINLINE
static uint64_t f52_long64_scalar(const void * const key, const size_t len, const uint64_t seed) {
    const uint8_t * const input = (const uint8_t *)key;
    f52_v8 A[7], B[7], sum = f52_v8_zero();
    int k;
    assert(len >= 896);
    f52_long_scalar_core(input, len, seed, A, B);
    for (k = 0; k < 7; k++) { sum = f52_v8_xor(sum, A[k]); sum = f52_v8_xor(sum, B[k]); }
    uint64_t h = f52_v8_reduce(sum);
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}

F52_NOINLINE
static void f52_long128_scalar(const void * const key, const size_t len, const uint64_t seed, uint64_t out[2]) {
    const uint8_t * const input = (const uint8_t *)key;
    f52_v8 A[7], B[7];
    assert(len >= 896);
    f52_long_scalar_core(input, len, seed, A, B);
    /* lo/hi cross-reduce (byte-for-byte identical to the SIMD cross A/B) */
    const f52_v8 lo = f52_v8_add(
        f52_v8_xor(f52_v8_add(f52_v8_xor(A[0], B[1]), f52_v8_xor(A[1], B[2])),
                   f52_v8_add(f52_v8_xor(A[2], B[3]), f52_v8_xor(A[3], B[4]))),
        f52_v8_xor(f52_v8_add(f52_v8_xor(A[4], B[5]), f52_v8_xor(A[5], B[6])),
                   f52_v8_xor(A[6], B[0])));
    const f52_v8 hi = f52_v8_add(
        f52_v8_xor(f52_v8_add(f52_v8_add(A[0], B[1]), f52_v8_add(A[1], B[2])),
                   f52_v8_add(f52_v8_add(A[2], B[3]), f52_v8_add(A[3], B[4]))),
        f52_v8_xor(f52_v8_add(f52_v8_add(A[4], B[5]), f52_v8_add(A[5], B[6])),
                   f52_v8_add(A[6], B[0])));
    uint64_t rlo = f52_v8_reduce(lo);
    uint64_t rhi = f52_v8_reduce(hi);
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    uint64_t x = (rlo ^ f52_rotl(rhi, 17)) + sl;
    uint64_t y = (rhi ^ f52_rotl(rlo, 23)) + f52_rotl(sl, 32);
    f52_avalanche128_lm(x, y, F52_LM_ROT, &x, &y);
    f52_avalanche64x2(x + sl, y + sl, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

#endif /* !F52_HAVE_AVX512IFMA */

/* Public symbol dispatch: SIMD (_avx512) under F52_HAVE_AVX512IFMA, else scalar (_scalar). */
#if F52_HAVE_AVX512IFMA
#  define f52_medium64_loop  f52_medium64_loop_avx512
#  define f52_medium128_loop f52_medium128_loop_avx512
#  define f52_long64         f52_long64_avx512
#  define f52_long128        f52_long128_avx512
#else
#  define f52_medium64_loop  f52_medium64_loop_scalar
#  define f52_medium128_loop f52_medium128_loop_scalar
#  define f52_long64         f52_long64_scalar
#  define f52_long128        f52_long128_scalar
#endif

/* ---- 128-bit ---- */

#if F52_HAVE_AVX512IFMA
/* Long path for inputs >= 896B with AVX-512 */
F52_AVX512_FN
static void f52_long128_avx512(const void * const key, size_t len, uint64_t seed, uint64_t out[2]) {
    const uint8_t * const input = (const uint8_t *)key;
    assert(len >= 896);
    const size_t f52_off = (uintptr_t)input & 63;
    __m512i A0, A1, A2, A3, A4, A5, A6, B0, B1, B2, B3, B4, B5, B6;
    __m512i d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13;
    F52_INIT();
    F52_ACCUMULATE();
    /* cross A/B: lo uses xor-cross pairs, hi uses add-cross pairs — breaks the dA<->dB swap
     * symmetry that separate A/B would otherwise have. */
    __m512i lo = _mm512_add_epi64(
        _mm512_xor_si512(_mm512_add_epi64(_mm512_xor_si512(A0, B1), _mm512_xor_si512(A1, B2)),
                          _mm512_add_epi64(_mm512_xor_si512(A2, B3), _mm512_xor_si512(A3, B4))),
        _mm512_xor_si512(_mm512_add_epi64(_mm512_xor_si512(A4, B5), _mm512_xor_si512(A5, B6)),
                          _mm512_xor_si512(A6, B0)));
    __m512i hi = _mm512_add_epi64(
        _mm512_xor_si512(_mm512_add_epi64(_mm512_add_epi64(A0, B1), _mm512_add_epi64(A1, B2)),
                          _mm512_add_epi64(_mm512_add_epi64(A2, B3), _mm512_add_epi64(A3, B4))),
        _mm512_xor_si512(_mm512_add_epi64(_mm512_add_epi64(A4, B5), _mm512_add_epi64(A5, B6)),
                          _mm512_add_epi64(A6, B0)));
    uint64_t rlo = f52_reduce(lo);
    uint64_t rhi = f52_reduce(hi);
    /* asymmetric two-lane mix of rlo/rhi (both depend on all accumulators), then lm -> av64x2. */
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    uint64_t x = (rlo ^ f52_rotl(rhi, 17)) + sl;
    uint64_t y = (rhi ^ f52_rotl(rlo, 23)) + f52_rotl(sl, 32);
    f52_avalanche128_lm(x, y, F52_LM_ROT, &x, &y);
    f52_avalanche64x2(x + sl, y + sl, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* These private SIMD macros are used only inside the long/medium loop; #undef them to keep
 * the outer scope clean. */
#undef F52_MEDIUM_LOOP
#undef F52_MLANE
#undef F52_ACCUMULATE
#undef F52_LOADU_MAX
#undef F52_ACCUMULATE_WITH
#undef F52_INIT
#undef F52_OFFV
#undef F52_TAIL7_32
#undef F52_FINAL7
#undef F52_PIPE7_32
#undef F52_PIPE7
#undef F52_BODY7
#undef F52_BODY7_LANE
#undef F52_CONSUME7
#undef F52_LD14_32
#undef F52_LD14
#undef F52_AVX512_FN
#undef F52_ROL512
#undef F52_ROR512
#undef F52_REG
#undef F52_DEBUG_ZEROINIT
#endif /* F52_HAVE_AVX512IFMA */

/* 64-bit entry point. */
static inline uint64_t fifty2hash64(const void * const key, const size_t len, const uint64_t seed) {
    const uint8_t * const input = (const uint8_t *)key;
    if (F52_LIKELY(len <= 8)) {
        if (F52_UNLIKELY(len == 8))
            return f52_short64_le8(input, 8, seed);
        return f52_short64_le8(input, len, seed);
    }

    if (len <= 16) {
        if (len == 16)
            return f52_short64_9_16(input, 16, seed);
        return f52_short64_9_16(input, len, seed);
    }

    if (F52_LIKELY(len <= 96))
        return f52_medium64_scalar(input, len, seed);
    if (len < 896)
        return f52_medium64_loop(input, len, seed);
    return f52_long64(key, len, seed);
}

/* 128-bit entry point.  out[0] = low 64 (low half of the value), out[1] = high 64 (high
 * half); the input key is interpreted little-endian (like rd32/64/128).  Length dispatch:
 * <=16 / 17-96 / 97-895 / >=896. */
static inline void fifty2hash128(const void * const key, const size_t len, const uint64_t seed, uint64_t out[2]) {
    const uint8_t * const input = (const uint8_t *)key;
    if (F52_LIKELY(len <= 16)) {
        if (F52_UNLIKELY(len == 16)) {
            f52_short128_le16(input, 16, seed, out, out + 1);
            return;
        }
        f52_short128_le16(input, len, seed, out, out + 1);
        return;
    }

    if (F52_LIKELY(len <= 96)) {
        f52_medium128_scalar(input, len, seed, out);
        return;
    }
    if (len < 896) {
        f52_medium128_loop(input, len, seed, out);
        return;
    }
    f52_long128(key, len, seed, out);
}

#ifdef __cplusplus
}
#endif

/* ---- internal macro cleanup: undef everything the consumer does not need, so the
 *      header leaves only F52_VERSION / F52_HAVE_AVX512IFMA and the two entry points.
 *      (All references were expanded during preprocessing, so this is behavior-neutral.
 *      #undef on a macro that is undefined on some configs, e.g. F52_GCC_LEGACY, is a no-op.) */
#ifdef F52_UNDEF_INLINE
#  undef inline
#  undef F52_UNDEF_INLINE
#endif
#undef F52_AINLINE
#undef F52_CONST
#undef F52_NOINLINE
#undef F52_LIKELY
#undef F52_UNLIKELY
#undef F52_RESTRICT
#undef F52_ALIGN64
#undef F52_GCC_LEGACY
#undef F52_STATIC_ASSERT
#undef F52_SA_CAT
#undef F52_SA_CAT_I
#undef F52_MUL_LO
#undef F52_MUL_HI
#undef F52_SKIP_SHIFT
#undef F52_AVALANCHE64_SMS
#undef F52_AVALANCHE64_LM
#undef F52_IS_BE
#undef F52_P1
#undef F52_P2
#undef F52_P3
#undef F52_M1
#undef F52_M2
#undef F52_M3
#undef F52_M4
#undef F52_M52
#undef F52_LM_ROT
#undef f52_medium64_loop
#undef f52_medium128_loop
#undef f52_long64
#undef f52_long128

#endif /* FIFTY2HASH_H */
