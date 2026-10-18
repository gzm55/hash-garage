/*
 * 52hash.h — IFMA-based hash: data x data multiply + additive seed/len mixing.
 *
 * Non-cryptographic: for hash tables, dedup, checksums. Not collision-resistant;
 * do not use for security purposes.
 *
 * Uses AVX-512 IFMA (F52_HAVE_AVX512IFMA) when available; otherwise a scalar
 * fallback (f52_v8) produces bit-identical results. Portable across GCC/Clang/MSVC
 * and 32/64-bit.
 *
 * The 64- and 128-bit variants share the mixing core but use different finalizers,
 * so the low 64 bits of fifty2hash128(x) != fifty2hash64(x); never substitute.
 *
 * Length tiers: <=16 short / 17-96 medium / 97-895 medium loop / >=896 long.
 *
 * For a fixed seed the short path is injective over lengths 0-7 (64b) / 0-15 (128b),
 * and lengths 8 (64b) / 16 (128b) are full-width bijections; no cross-length
 * collision-freedom is guaranteed between shorter lengths and the full width.
 */
#ifndef FIFTY2HASH_H
#define FIFTY2HASH_H

/* Version. Bump on each release. */
#define F52_VERSION 1

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#if defined(_MSC_VER)
#  include <intrin.h>   /* _byteswap_*, _rotl64/_rotr64, _umul128 */
#endif

/* Pre-C99 C has no `inline`; map it away (undone at the end of this header). */
#if !defined(__cplusplus) && !(defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L))
#  define inline
#  define F52_UNDEF_INLINE 1
#endif

/* GCC/Clang define __AVX512IFMA__ under -mavx512ifma / -march=native; MSVC does not,
 * so define F52_FORCE_AVX512IFMA (with /arch:AVX512) there. */
#if defined(__AVX512IFMA__) || defined(F52_FORCE_AVX512IFMA)
#  define F52_HAVE_AVX512IFMA 1
#else
#  define F52_HAVE_AVX512IFMA 0
#endif

#if F52_HAVE_AVX512IFMA
#  include <immintrin.h>
#endif

/* F52_AINLINE force-inline; F52_CONST pure; F52_NOINLINE; F52_LIKELY/UNLIKELY;
 * F52_RESTRICT; F52_ALIGN64. Do not mark const functions that touch memory. */
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

/* GCC<10 ICEs on __attribute__((target)) + inline asm; drop both there (the TU is
 * already compiled with -mavx512ifma). */
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 10
#  define F52_GCC_LEGACY 1
#endif

/* File-scope static assert; pre-C11/C++11 falls back to a negative array named by
 * two-level __COUNTER__ concat. */
#if defined(__cplusplus) && (__cplusplus >= 201103L)
#  define F52_STATIC_ASSERT(c, m) static_assert((c), m)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#  define F52_STATIC_ASSERT(c, m) _Static_assert((c), m)
#else
#  define F52_SA_CAT_I(a, b) a##b
#  define F52_SA_CAT(a, b)  F52_SA_CAT_I(a, b)
#  define F52_STATIC_ASSERT(c, m) typedef char F52_SA_CAT(f52_static_assert_failed_, __COUNTER__)[(c) ? 1 : -1]
#endif

/* GNU/Clang use function-level target(avx512f,avx512ifma)+noinline; MSVC relies on
 * TU-level /arch:AVX512 (no function target); legacy GCC drops the target. */
#if F52_HAVE_AVX512IFMA
#  if defined(_MSC_VER)
#    define F52_AVX512_FN __declspec(noinline)
#  elif defined(F52_GCC_LEGACY)
#    define F52_AVX512_FN __attribute__((noinline))
#  else
#    define F52_AVX512_FN __attribute__((target("avx512f,avx512ifma"), noinline))
#  endif
/* MSVC lacks _mm512_rol/ror_epi64; shift+or is bit-identical per lane (0 < n < 64). */
#  if defined(_MSC_VER)
#    define F52_ROL512(x, n) _mm512_or_si512(_mm512_slli_epi64((x), (n)), _mm512_srli_epi64((x), 64 - (n)))
#    define F52_ROR512(x, n) _mm512_or_si512(_mm512_srli_epi64((x), (n)), _mm512_slli_epi64((x), 64 - (n)))
#  else
#    define F52_ROL512(x, n) _mm512_rol_epi64((x), (n))
#    define F52_ROR512(x, n) _mm512_ror_epi64((x), (n))
#  endif
#endif

/* Multipliers P1/P2/P3 must be odd (bijective); M1-M4 are additive magics (need not be). */
#define F52_P1 0x9E3779B97F4A7C15ULL
#define F52_P2 0xC2B2AE3D27D4EB4FULL
#define F52_P3 0xCE516090AD952CC7ULL
#define F52_M1 0x165667B19E3779F9ULL
#define F52_M2 0xC6A4A7935BD1E994ULL
#define F52_M3 0xFF51AFD7ED558CCDULL
#define F52_M4 0xD6E8FEB86659FD92ULL
#define F52_M52 0xFFFFFFFFFFFFFULL   /* 52-bit mask (IFMA truncation) */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- portable scalar helpers ---- */

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
/* rotate: unsigned shift, defined for any count. */
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

/* 64x64->128: __int128 (GCC/Clang 64-bit), _umul128 (MSVC x64), 32x32 (32-bit). */
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

/* ---- avalanche family ---- */

/* shift->multiply->shift; shift==F52_SKIP_SHIFT skips a stage (sm/ms/sms). */
#define F52_SKIP_SHIFT 64
static inline F52_AINLINE F52_CONST uint64_t f52_avalanche64_sms(uint64_t x, const int shift1,
                                           const uint64_t magic, const int shift2) {
    if (shift1 != F52_SKIP_SHIFT) x ^= x >> shift1;
    x *= magic;
    if (shift2 != F52_SKIP_SHIFT) x ^= x >> shift2;
    return x;
}

/* In-place sms (textually expanded to avoid a callee-saved spill in short le8);
 * arguments must be side-effect-free lvalues; shift masked &63. */
#define F52_AVALANCHE64_SMS(x, shift1, magic, shift2) { \
        if ((shift1) != F52_SKIP_SHIFT) (x) ^= (x) >> ((shift1) & 63); \
        (x) *= (magic); \
        if ((shift2) != F52_SKIP_SHIFT) (x) ^= (x) >> ((shift2) & 63); \
    }

/* 128-bit dual finalizer: one sms per half; seed mixed in by the caller. */
static inline F52_AINLINE void f52_avalanche64x2(const uint64_t lo_in, const uint64_t hi_in,
                                     uint64_t * F52_RESTRICT const lo, uint64_t * F52_RESTRICT const hi,
                                     const int s1_lo, const uint64_t magic_lo, const int s2_lo,
                                     const int s1_hi, const uint64_t magic_hi, const int s2_hi) {
    *lo = f52_avalanche64_sms(lo_in, s1_lo, magic_lo, s2_lo);
    *hi = f52_avalanche64_sms(hi_in, s1_hi, magic_hi, s2_hi);
}

/* Combine two u64: fold 128-bit product halves + bswap/lo+hi crossover. */
static inline F52_AINLINE F52_CONST uint64_t f52_avalanche64_fold(const uint64_t lo, const uint64_t hi) {
    const f52_u128 m = f52_mul128(lo, hi);
    return f52_bswap64(lo) + hi + (F52_MUL_LO(m) ^ F52_MUL_HI(m));
}

/* nano: (ml,mh) = lo*hi + same-side add; inputs must already be dense. */
static inline F52_AINLINE void f52_avalanche128_nano(const uint64_t lo, const uint64_t hi,
                                          uint64_t * F52_RESTRICT const ml, uint64_t * F52_RESTRICT const mh) {
    const f52_u128 m = f52_mul128(lo, hi);
    *ml = F52_MUL_LO(m) + lo;
    *mh = F52_MUL_HI(m) + hi;
}

/* Lossless Lai-Massey bijection: t=lo-hi, f=fold(t*rotl(t,rot)), out=lo/hi+f. */
#define F52_LM_ROT 37   /* odd, coprime to 64 */
static inline F52_AINLINE void f52_avalanche128_lm(const uint64_t lo, const uint64_t hi, const int rot,
                                          uint64_t * F52_RESTRICT const ml, uint64_t * F52_RESTRICT const mh) {
    const uint64_t t = lo - hi;
    const f52_u128 t2 = f52_mul128(t, f52_rotl(t, rot));
    const uint64_t f = F52_MUL_LO(t2) ^ F52_MUL_HI(t2);
    *ml = lo + f;
    *mh = hi + f;
}

/* ---- endianness + readers + seed mix ---- */

/* rd32/64/128 interpret input little-endian (byteswap on BE); MSVC is always LE. */
#if defined(_MSC_VER)
#  define F52_IS_BE 0
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define F52_IS_BE 1
#else
#  define F52_IS_BE 0
#endif

/* The SIMD path has no byte swap, so a misconfigured endianness must fail at compile time. */
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
/* Read 16B into lo/hi (two rd64, so 32-bit-friendly). */
static inline F52_AINLINE void f52_rd128(const uint8_t *const p, uint64_t *const lo, uint64_t *const hi) {
    *lo = f52_rd64(p);
    *hi = f52_rd64(p + 8);
}

/* seed pre-mix: mode=1 rotl(seed,32)+M1; modes 2/3 are the medium A/B additive mixes. */
static inline F52_AINLINE F52_CONST uint64_t f52_seed_mix(const uint64_t seed, const int mode, const int shift) {
    if (mode==2) return seed + f52_rotl(F52_M2, shift);
    if (mode==3) return seed + f52_rotl(F52_M4, shift);
    return f52_rotl(seed, 32) + F52_M1;
}

/* ---- short-input (<=16B) paths (scalar) ----
 * Fixed-width (2^p) loads avoid a variable-length memcpy. */

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

/* 64-bit Lai-Massey: y=x^rotl(x,32); y*=y; x^=y^rotl(y,32). Statement-block macro
 * (no do-while, no const locals) so g++ does not spill; a later odd multiply stays bijective. */
#define F52_AVALANCHE64_LM(x) { \
        uint64_t _f52_y = (x) ^ f52_rotl((x), 32); \
        uint64_t _f52_yy = _f52_y * _f52_y; \
        (x) ^= _f52_yy ^ f52_rotl(_f52_yy, 32); \
    }

/* Short-key (<=8B) finalizer: split seed mix + xorshift + lm + sms. The P1/M2 seed
 * constants differ so the two branches cannot be CSE-merged (letting the shifts differ). */
static inline uint64_t f52_short64_le8(const uint8_t * const p, const size_t len, uint64_t seed) {
    uint64_t x;
    assert(len <= 8);

    if (len == 8) {
        seed += (seed << 14) + F52_P1;
        x = f52_rd64(p);
    } else {
        seed += (seed << 10) + F52_M2;
        x = f52_mix_le7(p, len);
    }

    x ^= seed;
    x ^= x >> 11;
    F52_AVALANCHE64_LM(x);

    seed ^= f52_rotl(seed, 33);
    x += seed; F52_AVALANCHE64_SMS(x, F52_SKIP_SHIFT, F52_P1, 22);
    return x;
}

static inline uint64_t f52_short64_9_16(const uint8_t * const p, const size_t len, uint64_t seed) {
    assert(len >= 9 && len <= 16);
    /* overlapping 8B reads + seed mix, then two data x data multiplies to finish. */
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

/* ---- medium path (17-96B): scalar self-feedback A,B state. Per 16B block:
 * A+=d0; B+=d1; A+=low52(A*B); B=ror(B,12); B+=bits[76..128)(A*B).
 * 64/128 share this core; only the final compression differs. ---- */

/* laneoff: shared by SIMD and scalar; off[i]=P1*(i+1)^P2*(i>>1). */
F52_ALIGN64 static const uint64_t f52_laneoff[8] = {
    F52_P1,                   F52_P1 * 2,
    F52_P1 * 3 ^ F52_P2,      F52_P1 * 4 ^ F52_P2,
    F52_P1 * 5 ^ F52_P2 * 2,  F52_P1 * 6 ^ F52_P2 * 2,
    F52_P1 * 7 ^ F52_P2 * 3,  F52_P1 * 8 ^ F52_P2 * 3,
};
/* _mm512_load_si512 reads a full 512 bits, so the table must be exactly 8 x u64. */
F52_STATIC_ASSERT(sizeof(f52_laneoff) == 8 * sizeof(uint64_t), "f52_laneoff must be 8 u64");

/* medium mix core (shared 64/128): block0 first, middle blocks advance via fallthrough,
 * final block is a branchless overlapping read. */
static inline void f52_medium_mix_body(const uint8_t * const p, const size_t len, const uint64_t seed,
                                       uint64_t * F52_RESTRICT const outA, uint64_t * F52_RESTRICT const outB) {
    /* additive seed mix (mode 2/3): XOR would cancel identical bits under sparse seed. */
    uint64_t A = f52_seed_mix(seed, 2, (int)(len / 2));
    uint64_t B = f52_seed_mix(seed, 3, (int)len);

#define F52_MCORE(p) \
    do { \
        uint64_t d0, d1; \
        f52_rd128(p, &d0, &d1); \
        A += d0; B += d1; \
        f52_u128 pr_ = f52_mul128(A, B); \
        A += F52_MUL_LO(pr_) & F52_M52; \
        B = f52_rotr(B, 12); \
        B += F52_MUL_HI(pr_) >> 12; \
    } while (0)

    F52_MCORE(p);

    /* middle full blocks: nfull=5->4 ... 2->1, otherwise none. */
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

    /* final block: overlapping read of [len-16,len), no self-feedback multiply. */
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
    f52_avalanche128_nano(A, B, &A, &B);
    return f52_avalanche64_fold(A + seed, B);
}

static inline void f52_medium128_scalar(const uint8_t * const p, const size_t len, const uint64_t seed,
                                 uint64_t * F52_RESTRICT const out) {
    assert(len >= 17 && len <= 96);
    uint64_t A, B;
    f52_medium_mix_body(p, len, seed, &A, &B);
    f52_avalanche128_lm(A, B, F52_LM_ROT, &A, &B);
    f52_avalanche64x2(A + seed + len, B + seed + len, out, out + 1, 35, F52_P2, 28, 37, F52_P1, 32);
}

/* ==================== SIMD (AVX-512 IFMA) ==================== */
#if F52_HAVE_AVX512IFMA

static inline F52_AINLINE __m512i f52_ld(const uint8_t * const p) {
    return _mm512_loadu_si512((const void *)p);
}

/* misaligned-friendly 64B load: two 32B loads + shuffle (reads the same bytes as f52_ld). */
static inline F52_AINLINE __m512i f52_ld32(const uint8_t * const p) {
    __m256i lo = _mm256_loadu_si256((const __m256i *)p);
    __m256i hi = _mm256_loadu_si256((const __m256i *)(p + 32));
#if defined(__GNUC__) && !defined(F52_GCC_LEGACY)
    __asm__("" : "+x"(lo), "+x"(hi));   /* keep halves in registers (MLP) */
#endif
    return _mm512_shuffle_i64x2(_mm512_castsi256_si512(lo), _mm512_castsi256_si512(hi), 0x44);
}

/* Pin the vector in a register so gcc cannot fold the load into a later load-op. */
#if defined(__GNUC__) && !defined(F52_GCC_LEGACY)
#define F52_REG(v) __asm__("" : "+v"(v))
#else
#define F52_REG(v) ((void)0)
#endif

static inline F52_AINLINE F52_CONST uint64_t f52_reduce(__m512i sum) {
    __m512i t = _mm512_xor_si512(sum, _mm512_shuffle_i64x2(sum, sum, 0x4E));
    t = _mm512_xor_si512(t, _mm512_shuffle_i64x2(t, t, 0xB1));
    __m128i lo = _mm512_castsi512_si128(t);
    return (uint64_t)_mm_extract_epi64(lo, 0) ^ (uint64_t)_mm_extract_epi64(lo, 1);
}

/* per-lane avalanche: 32x32->32 mullo (AVX-512F) keeps each 32-bit lane a bijection
 * since magic's low 32 bits are odd. */
static inline F52_AINLINE F52_CONST __m512i f52_avalanche_v(__m512i x, const uint64_t magic, const unsigned s1, const unsigned s2) {
    x = _mm512_xor_si512(x, _mm512_srli_epi64(x, s1));
    x = _mm512_mullo_epi32(x, _mm512_set1_epi32((int)(uint32_t)magic));
    x = _mm512_xor_si512(x, _mm512_srli_epi64(x, s2));
    return x;
}

/* broadcast seed + laneoff XOR; ov loaded once by the caller. */
static inline F52_AINLINE F52_CONST __m512i f52_seed_vector(const uint64_t seed, const uint64_t k, const __m512i ov) {
    return _mm512_xor_si512(_mm512_set1_epi64((int64_t)(seed + F52_P2 * (k + 1))), ov);
}
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

/* ---- long path (>=896B): 7 self-feedback lanes, software-pipelined. Per lane per round:
 * A+=d0; B+=d1; sA=A>>12; A=madd52lo(A,A,B); B=ror(B,12); B=madd52hi(B,sA,B).
 * This round's loads are consumed next round (hides L2 latency). ---- */

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

/* srli snapshot decouples the two IFMAs (madd52lo reads old A,B; madd52hi reads sA+rot B). */
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

#define F52_PIPE7(pnext) \
    do { \
        F52_CONSUME7(); \
        F52_LD14(pnext); \
        F52_BODY7(); \
    } while (0)

#define F52_PIPE7_32(pnext) \
    do { \
        F52_CONSUME7(); \
        F52_LD14_32(pnext); \
        F52_BODY7(); \
    } while (0)

#define F52_FINAL7() \
    do { \
        F52_CONSUME7(); \
        F52_BODY7(); \
    } while (0)

/* tail: load only ceil(remain/64) fresh 64B chunks, reuse the previous strip's prefix
 * (deliberate load-saving, not a true sliding window). */
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

#define F52_ACCUMULATE_WITH(PIPE) \
    do { \
        size_t f52_i, f52_n; \
        /* ceil(len/896); widen to u64 first so +895 cannot overflow on 32-bit. */ \
        f52_n = (size_t)(((uint64_t)len + 895) / 896); \
        F52_LD14(input); \
        for (f52_i = 0; f52_i + 1 < f52_n - 1; f52_i++) { \
            PIPE(input + (f52_i + 1) * 896); \
        } \
        F52_FINAL7(); \
        if (f52_n > 1) \
            F52_TAIL7_32(input + len, (len - (f52_n - 1) * 896 + 63) / 64); \
    } while (0)

#define F52_LOADU_MAX (55 * 896)
#define F52_ACCUMULATE() \
    do { \
        if (F52_LIKELY(len <= F52_LOADU_MAX || f52_off == 0)) \
            F52_ACCUMULATE_WITH(F52_PIPE7); \
        else \
            F52_ACCUMULATE_WITH(F52_PIPE7_32); \
    } while (0)

/* ---- medium loop [97, 896B): 7 independent 128B lanes. ---- */

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

/* Debug-only zero-init guards against a missing switch case -> UB; release pays nothing. */
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
        size_t f52_nblocks = len >> 7; \
        size_t f52_tail = len & 127; \
        size_t f52_nlanes = f52_nblocks + (f52_tail ? 1 : 0); \
        __m512i f52_A, f52_B, f52_C, f52_D, f52_E, f52_F, f52_G, \
                f52_H, f52_I, f52_J, f52_K, f52_L, f52_M, f52_N; \
        __m512i f52_d0, f52_d1, f52_d2, f52_d3, f52_d4, f52_d5, f52_d6, \
                f52_d7, f52_d8, f52_d9, f52_d10, f52_d11, f52_td0, f52_td1; \
        F52_DEBUG_ZEROINIT \
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
            f52_td0 = f52_ld(input + len - 64); \
            f52_td1 = (f52_tail >= 64) ? f52_ld(input + (f52_nblocks << 7)) \
                                       : _mm512_setzero_si512(); \
        } \
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
            switch (f52_nblocks) { \
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

/* 64-bit medium loop (97-895B). */
F52_AVX512_FN
static uint64_t f52_medium64_loop_avx512(const uint8_t * const input, size_t len, uint64_t seed) {
    __m512i f52_MA, f52_MB;
    assert(len >= 97 && len < 896);
    /* GCC cannot prove the per-lane registers are initialized through the switch. */
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
    F52_MEDIUM_LOOP(f52_MA, f52_MB);
#if defined(__GNUC__) && !defined(__clang__)
    #pragma GCC diagnostic pop
#endif
    __m512i sum = _mm512_xor_si512(
        _mm512_xor_si512(f52_MA, f52_MB),
        _mm512_xor_si512(_mm512_srli_epi64(f52_MA, 32), _mm512_srli_epi64(f52_MB, 32)));
    uint64_t h = f52_reduce(sum);
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}

/* 128-bit medium loop (97-895B). */
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
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    const uint64_t sh = f52_bswap64(sl);   /* keep the two lanes asymmetric */
    uint64_t xlo = f52_reduce(f52_MA) + sl;
    uint64_t xhi = f52_reduce(f52_MB) + sh;
    f52_avalanche128_lm(xlo, xhi, F52_LM_ROT, &xlo, &xhi);
    f52_avalanche64x2(xlo + sl, xhi + sh, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* 64-bit long path (>=896B). */
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
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    h = f52_avalanche64_sms(h + sl, 32, F52_P3, F52_SKIP_SHIFT);
    h = f52_avalanche64_sms(h + sl, 34, F52_P3, 22);
    return h;
}

/* 128-bit long path (>=896B). */
F52_AVX512_FN
static void f52_long128_avx512(const void * const key, size_t len, uint64_t seed, uint64_t out[2]) {
    const uint8_t * const input = (const uint8_t *)key;
    assert(len >= 896);
    const size_t f52_off = (uintptr_t)input & 63;
    __m512i A0, A1, A2, A3, A4, A5, A6, B0, B1, B2, B3, B4, B5, B6;
    __m512i d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13;
    F52_INIT();
    F52_ACCUMULATE();
    /* lo uses xor-cross pairs, hi uses add-cross pairs (breaks the dA<->dB swap symmetry). */
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
    const uint64_t sl = f52_seed_mix(seed + (uint64_t)len, 3, (int)len);
    uint64_t x = (rlo ^ f52_rotl(rhi, 17)) + sl;
    uint64_t y = (rhi ^ f52_rotl(rlo, 23)) + f52_rotl(sl, 32);
    f52_avalanche128_lm(x, y, F52_LM_ROT, &x, &y);
    f52_avalanche64x2(x + sl, y + sl, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* #undef the SIMD-only macros so they do not leak past this block. */
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
static inline F52_AINLINE uint64_t f52_v8_reduce(const f52_v8 a) {
    uint64_t x = 0; int i; for (i = 0; i < 8; i++) x ^= a.v[i]; return x;
}

/* per-lane mix (mirrors F52_BODY7_LANE/MLANE): A+=low52(A*B); B=ror12;
 * B+=High52((A>>12)*(B>>12)). */
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

/* per-lane avalanche (mirrors f52_avalanche_v): 64-bit srli/xor + 32-bit mullo. */
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

/* medium loop (97-895B) scalar core, lane-equivalent to F52_MEDIUM_LOOP. */
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
    const uint64_t sh = f52_bswap64(sl);   /* keep the two lanes asymmetric */
    uint64_t xlo = f52_v8_reduce(RA) + sl;
    uint64_t xhi = f52_v8_reduce(RB) + sh;
    f52_avalanche128_lm(xlo, xhi, F52_LM_ROT, &xlo, &xhi);
    f52_avalanche64x2(xlo + sl, xhi + sh, &out[0], &out[1], 35, F52_P2, 28, 37, F52_P1, 32);
}

/* long path (>=896B) scalar core, byte-equivalent to F52_ACCUMULATE. */
static void f52_long_scalar_core(const uint8_t * const input, const size_t len, const uint64_t seed,
                                 f52_v8 outA[7], f52_v8 outB[7]) {
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
    for (s = 0; s + 1 < n; s++) {
        for (k = 0; k < 14; k++) d[k] = f52_v8_load(input + s * 896 + k * 64);
        for (k = 0; k < 7; k++) { A[k] = f52_v8_add(A[k], d[2 * k]); B[k] = f52_v8_add(B[k], d[2 * k + 1]); }
        for (k = 0; k < 7; k++) f52_v8_mix(&A[k], &B[k]);
    }
    {
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

/* Dispatch to the SIMD or scalar loop by F52_HAVE_AVX512IFMA. */
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

/* ---- entry points ---- */

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

/* out[0]=low 64, out[1]=high 64. */
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

/* #undef everything the consumer does not need, leaving only F52_VERSION /
 * F52_HAVE_AVX512IFMA and the two entry points. */
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
