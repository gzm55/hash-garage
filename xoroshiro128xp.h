/* xoroshiro128^* (xoroshiro128xp.h) -- xoroshiro128 with a shared-offset
 * (65535*n1) scramble; two 64-bit outputs per 128-bit state per step.
 *
 *     n1   = x0 ^ x1
 *     sr   = (n1 << 16) - n1              (= 65535 * n1 = (2^16 - 1) * n1)
 *     out0 = x0 + rotl(sr,  8)
 *     out1 = x1 + rotl(sr, 16)
 *     x0'  = rotl(x0, 24) ^ n1 ^ (n1 << 16)
 *     x1'  = rotl(n1, 37)
 *
 * sr is the only nonlinear step; (2^16*n1 - n1) borrows from bit 2 up, so only
 * bits 0-1 of sr stay GF(2)-affine (a 2-bit window, vs 17 for the (n1<<t)+n1
 * form).  The two rotations differ (8 vs 16) so sr cannot cancel between out0
 * and out1, and both sample sr[48..63], above that window -- so the LSB
 * linearity of xoroshiro128+ (out = x0+x1) is gone.  (n1<<16) is shared with
 * the state update, so a step is 13 vector ops.
 *
 * (out0, out1) is surjective, not injective (~63.2% coverage).  The reachable
 * state set is 2^128-1 (all-zero excluded), so the words are balanced only up
 * to one; see the f64 note.
 *
 * 4 groups x 8 lanes = 32 independent xoroshiro128 states (period 2^128-1, full
 * cycle), filled per step into one 64-word (512-byte) block:
 *     buf[g*16 + 0..7]  = out0 of lanes 0..7 of group g
 *     buf[g*16 + 8..15] = out1 of lanes 0..7 of group g
 * Two consecutive words therefore always come from different streams.
 *
 * ISA: AVX-512 (zmm), AVX2 (ymm), AArch64 NEON (128-bit), or scalar; all
 * bit-identical (KAT in xoroshiro128xp-selftest.c).  Byte-multiple rotations
 * use vpshufb (AVX-512BW/AVX2) or vqtbl1q_u8 (NEON).  Below AVX2 only the
 * scalar source runs, auto-vectorized (restrict, no carried dependence).
 * XRSR128_XP_FORCE_SCALAR forces the scalar path.
 *
 * Measured (Xeon Gold 5318Y, prng-speed, min of 5, ns/word): AVX-512 0.126,
 * AVX2 0.212; scalar -march=native 0.170, -mavx2 0.323, -msse3 0.709.
 *
 * Validation: TestU01 SmallCrush/Crush/pseudoDIEHARD/BigCrush
 * (160/160 on 4/6 seedbases, 2 with one borderline p), PractRand 128 GB x3
 * (no anomalies), hwd-repr to 10 TB, Vigna coll-birth + birthday spacings,
 * SmokeRand brief/default/full -- all pass.  Bit-identical across AVX-512
 * (with/without BW), AVX2, NEON and scalar; matches the scalar reference
 * byte-for-byte (4 seeds x 4096 words).
 *
 * Depends only on <stdint.h>/<stddef.h>/<string.h> (+ <immintrin.h> or
 * <arm_neon.h> for a vector path).  C99 and C++11+.
 */

#ifndef XRSR128_XP_H
#define XRSR128_XP_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* ---- ISA selection ---- */
/* ------------------------------------------------------------------ */

#if defined(XRSR128_XP_FORCE_SCALAR)
#  define XRSR128_XP_USE_AVX512 0
#  define XRSR128_XP_USE_AVX2   0
#  define XRSR128_XP_USE_NEON   0
#else
#  if defined(__AVX512F__)
#    define XRSR128_XP_USE_AVX512 1
#  else
#    define XRSR128_XP_USE_AVX512 0
#  endif
#  if defined(__AVX2__)
#    define XRSR128_XP_USE_AVX2 1
#  else
#    define XRSR128_XP_USE_AVX2 0
#  endif
/* AArch64 always has Advanced SIMD; use it only when no x86 vector path. */
#  if (defined(__ARM_NEON) || defined(__ARM_NEON__)) && !XRSR128_XP_USE_AVX512 && !XRSR128_XP_USE_AVX2
#    define XRSR128_XP_USE_NEON 1
#  else
#    define XRSR128_XP_USE_NEON 0
#  endif
#endif

/* vpshufb needs AVX-512BW (zmm) or AVX2 (ymm); without BW the zmm path uses vprolq for byte rotations. */
#if XRSR128_XP_USE_AVX512 && defined(__AVX512BW__)
#  define XRSR128_XP_BYTE_ROT512 1
#else
#  define XRSR128_XP_BYTE_ROT512 0
#endif
#if (!XRSR128_XP_USE_AVX512) && XRSR128_XP_USE_AVX2
#  define XRSR128_XP_BYTE_ROT256 1
#else
#  define XRSR128_XP_BYTE_ROT256 0
#endif
/* AArch64 vqtbl1q_u8 is the vpshufb equivalent: a byte permute per 128-bit lane. */
#if XRSR128_XP_USE_NEON
#  define XRSR128_XP_BYTE_ROT_NEON 1
#else
#  define XRSR128_XP_BYTE_ROT_NEON 0
#endif

#if XRSR128_XP_USE_AVX512 || XRSR128_XP_USE_AVX2
#  include <immintrin.h>
#elif XRSR128_XP_USE_NEON
#  include <arm_neon.h>
#endif

#if defined(_MSC_VER)
#  define XRSR128_XP_ALIGN16 __declspec(align(16))
#  define XRSR128_XP_ALIGN64 __declspec(align(64))
#elif defined(__GNUC__)
#  define XRSR128_XP_ALIGN16 __attribute__((aligned(16)))
#  define XRSR128_XP_ALIGN64 __attribute__((aligned(64)))
#else
#  define XRSR128_XP_ALIGN16
#  define XRSR128_XP_ALIGN64
#endif

/* Scalar-path hints: restrict (dst != state) + ivdep, so GCC/Clang widen the 8-lane loop. */
#if defined(__clang__)
#  define XRSR128_XP_RESTRICT __restrict
#  define XRSR128_XP_VECTOR_HINT _Pragma("clang loop vectorize(enable)")
#elif defined(__GNUC__)
#  define XRSR128_XP_RESTRICT __restrict
#  define XRSR128_XP_VECTOR_HINT _Pragma("GCC ivdep")
#elif defined(_MSC_VER)
#  define XRSR128_XP_RESTRICT __restrict
#  define XRSR128_XP_VECTOR_HINT
#else
#  define XRSR128_XP_RESTRICT
#  define XRSR128_XP_VECTOR_HINT
#endif

/* ------------------------------------------------------------------ */
/* ---- parameters ---- */
/* ------------------------------------------------------------------ */

#define XRSR128_XP_GROUPS   4                 /* 4 groups x 8 lanes = 32 streams     */
#define XRSR128_XP_STREAMS  8                 /* logical lanes per group             */
#define XRSR128_XP_BUF      (XRSR128_XP_GROUPS * XRSR128_XP_STREAMS * 2)  /* 2 words/stream = 512 B */
#define XRSR128_XP_P1       ((uint64_t)0x9E3779B97F4A7C15ULL)  /* golden gamma      */
#define XRSR128_XP_SALT     ((uint64_t)0xD1B54A32D192ED03ULL)  /* seed decorrelation*/

/* A chunk is LANES u64; a group is CHUNKS chunks (LANES*CHUNKS == STREAMS). Scalar = LANES==1, so one struct covers every ISA. */
#if XRSR128_XP_USE_AVX512
typedef __m512i     xrsr128_xp_chunk_t;
#  define XRSR128_XP_LANES 8
#elif XRSR128_XP_USE_AVX2
typedef __m256i     xrsr128_xp_chunk_t;
#  define XRSR128_XP_LANES 4
#elif XRSR128_XP_USE_NEON
typedef uint64x2_t  xrsr128_xp_chunk_t;
#  define XRSR128_XP_LANES 2
#else
typedef uint64_t    xrsr128_xp_chunk_t;
#  define XRSR128_XP_LANES 1
#endif
#define XRSR128_XP_CHUNKS (XRSR128_XP_STREAMS / XRSR128_XP_LANES)
#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(XRSR128_XP_LANES * XRSR128_XP_CHUNKS == XRSR128_XP_STREAMS, "chunk split");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(XRSR128_XP_LANES * XRSR128_XP_CHUNKS == XRSR128_XP_STREAMS, "chunk split");
#endif

/* rotl for a single word */
static inline uint64_t xrsr128_xp_rotl64(const uint64_t x, const int k) {
    return (x << k) | (x >> (64 - k));
}

/* splitmix64 step, used only to expand the 64-bit seed */
static inline uint64_t xrsr128_xp_splitmix(uint64_t * const x) {
    uint64_t z = (*x += XRSR128_XP_P1);
    z = (z ^ (z >> 30)) * (uint64_t)0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * (uint64_t)0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ------------------------------------------------------------------ */
/* ---- state (one struct for every ISA) ---- */
/* ------------------------------------------------------------------ */

typedef struct {
    xrsr128_xp_chunk_t s0[XRSR128_XP_GROUPS][XRSR128_XP_CHUNKS];
    xrsr128_xp_chunk_t s1[XRSR128_XP_GROUPS][XRSR128_XP_CHUNKS];
    XRSR128_XP_ALIGN64 uint64_t buf[XRSR128_XP_BUF];
    unsigned pos;
} xrsr128_xp_t;

/* Seed (any 64-bit value): splitmix64 into buf (GROUPS*STREAMS*2 words), then copy to s0/s1; buf is scratch (pos starts at BUF). */
static inline void xrsr128_xp_init(xrsr128_xp_t * const r, const uint64_t seed) {
    const size_t n = (size_t)XRSR128_XP_GROUPS * XRSR128_XP_STREAMS;
    uint64_t x = seed ^ XRSR128_XP_SALT;
    int g, j;
    for (g = 0; g < XRSR128_XP_GROUPS; g++)
        for (j = 0; j < XRSR128_XP_STREAMS; j++) {
            r->buf[g * XRSR128_XP_STREAMS + j]     = xrsr128_xp_splitmix(&x);   /* s0 */
            r->buf[n + g * XRSR128_XP_STREAMS + j] = xrsr128_xp_splitmix(&x);   /* s1 */
        }
    /* a xoroshiro128 state must not be all-zero */
    for (g = 0; g < XRSR128_XP_GROUPS; g++)
        for (j = 0; j < XRSR128_XP_STREAMS; j++)
            if (!(r->buf[g * XRSR128_XP_STREAMS + j] | r->buf[n + g * XRSR128_XP_STREAMS + j]))
                r->buf[g * XRSR128_XP_STREAMS + j] = XRSR128_XP_P1;
    memcpy(r->s0, r->buf,     n * sizeof(uint64_t));
    memcpy(r->s1, r->buf + n, n * sizeof(uint64_t));
    r->pos = XRSR128_XP_BUF;
}

#if !(XRSR128_XP_USE_AVX512 || XRSR128_XP_USE_AVX2 || XRSR128_XP_USE_NEON)

/* ---- scalar path (chunk_type == uint64_t) ---- */

/* Scalar source: direct stores + restrict (dst != state) + no carried dependence, so the auto-vectorizer widens the 8-lane loop. */
static inline void xrsr128_xp_fill_scalar(xrsr128_xp_t * const XRSR128_XP_RESTRICT r,
                                   uint64_t * const XRSR128_XP_RESTRICT out, const size_t nblk) {
    size_t b;
    int g, j;
    for (b = 0; b < nblk; b++) {
        uint64_t * const ob = out + b * (XRSR128_XP_GROUPS * 16);
        for (g = 0; g < XRSR128_XP_GROUPS; g++) {
            uint64_t * const o = ob + g * 16;
            XRSR128_XP_VECTOR_HINT
            for (j = 0; j < XRSR128_XP_STREAMS; j++) {
                const uint64_t x0 = r->s0[g][j], x1 = r->s1[g][j];
                const uint64_t n1 = x0 ^ x1;
                const uint64_t sr = (n1 << 16) - n1;         /* *65535 */
                o[j] = x0 + xrsr128_xp_rotl64(sr, 8);
                o[8 + j] = x1 + xrsr128_xp_rotl64(sr, 16);
                r->s0[g][j] = xrsr128_xp_rotl64(x0, 24) ^ n1 ^ (n1 << 16);
                r->s1[g][j] = xrsr128_xp_rotl64(n1, 37);
            }
        }
    }
}

#endif /* scalar path */

/* ------------------------------------------------------------------ */
/* ---- vector paths ---- */
/* ------------------------------------------------------------------ */

#if XRSR128_XP_USE_AVX512 || XRSR128_XP_USE_AVX2 || XRSR128_XP_USE_NEON

#if XRSR128_XP_USE_AVX512
#  define XRSR128_XP_XOR(a, b)   _mm512_xor_si512((a), (b))
#  define XRSR128_XP_ADD(a, b)   _mm512_add_epi64((a), (b))
#  define XRSR128_XP_SUB(a, b)   _mm512_sub_epi64((a), (b))
#  define XRSR128_XP_SLLI(a, n)  _mm512_slli_epi64((a), (n))
#  define XRSR128_XP_ROL(a, n)   _mm512_rol_epi64((a), (n))
#  define XRSR128_XP_LOAD(p)     _mm512_loadu_si512((const void *)(p))
/* unaligned store: fill_u64 writes into a caller buffer with no alignment guarantee. */
#  define XRSR128_XP_STORE(p, v) _mm512_storeu_si512((void *)(p), (v))
#elif XRSR128_XP_USE_AVX2
#  define XRSR128_XP_XOR(a, b)   _mm256_xor_si256((a), (b))
#  define XRSR128_XP_ADD(a, b)   _mm256_add_epi64((a), (b))
#  define XRSR128_XP_SUB(a, b)   _mm256_sub_epi64((a), (b))
#  define XRSR128_XP_SLLI(a, n)  _mm256_slli_epi64((a), (n))
#  define XRSR128_XP_ROL(a, n) \
      _mm256_or_si256(_mm256_slli_epi64((a), (n)), _mm256_srli_epi64((a), 64 - (n)))
#  define XRSR128_XP_LOAD(p)     _mm256_loadu_si256((const __m256i *)(const void *)(p))
#  define XRSR128_XP_STORE(p, v) _mm256_storeu_si256((__m256i *)(void *)(p), (v))
#else  /* NEON (AArch64): 4 chunks x 2 lanes per group */
#  define XRSR128_XP_XOR(a, b)   veorq_u64((a), (b))
#  define XRSR128_XP_ADD(a, b)   vaddq_u64((a), (b))
#  define XRSR128_XP_SUB(a, b)   vsubq_u64((a), (b))
#  define XRSR128_XP_SLLI(a, n)  vshlq_n_u64((a), (n))
#  define XRSR128_XP_ROL(a, n) \
      vorrq_u64(vshlq_n_u64((a), (n)), vshrq_n_u64((a), 64 - (n)))
/* vld1q/vst1q accept any alignment on AArch64; unaligned destinations are fine. */
#  define XRSR128_XP_LOAD(p)     vld1q_u64((const uint64_t *)(const void *)(p))
#  define XRSR128_XP_STORE(p, v) vst1q_u64((uint64_t *)(void *)(p), (v))
#endif

#if XRSR128_XP_BYTE_ROT512 || XRSR128_XP_BYTE_ROT256 || XRSR128_XP_BYTE_ROT_NEON
/* rotl by 8k bits inside every 64-bit lane is a byte permutation: one vpshufb
 * (vqtbl1q_u8 on NEON).  The index pattern is a single 128-bit lane (two 64-bit
 * groups) and repeats, so one 16-byte constant broadcast to the register is
 * enough.  Index p of a 64-bit group reads byte (p - k) mod 8 of the same group. */
XRSR128_XP_ALIGN16 static const uint64_t xrsr128_xp_rolmask[3][2] = {
    { (uint64_t)0x0605040302010007ULL, (uint64_t)0x0e0d0c0b0a09080fULL },
    { (uint64_t)0x0504030201000706ULL, (uint64_t)0x0d0c0b0a09080f0eULL },
    { (uint64_t)0x0403020100070605ULL, (uint64_t)0x0c0b0a09080f0e0dULL }
};
#endif

/* k = 1..3 bytes, always a compile-time constant at the call sites */
#if XRSR128_XP_BYTE_ROT512
static inline xrsr128_xp_chunk_t xrsr128_xp_vrolb(xrsr128_xp_chunk_t x, const int k) {
    const __m512i m = _mm512_broadcast_i32x4(
        _mm_loadu_si128((const __m128i *)(const void *)xrsr128_xp_rolmask[k - 1]));
    return _mm512_shuffle_epi8(x, m);
}
#  define XRSR128_XP_ROL_BYTE(x, k)  xrsr128_xp_vrolb((x), (k))
#elif XRSR128_XP_BYTE_ROT256
static inline xrsr128_xp_chunk_t xrsr128_xp_vrolb(xrsr128_xp_chunk_t x, const int k) {
    const __m256i m = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)(const void *)xrsr128_xp_rolmask[k - 1]));
    return _mm256_shuffle_epi8(x, m);
}
#  define XRSR128_XP_ROL_BYTE(x, k)  xrsr128_xp_vrolb((x), (k))
#elif XRSR128_XP_BYTE_ROT_NEON
static inline xrsr128_xp_chunk_t xrsr128_xp_vrolb(xrsr128_xp_chunk_t x, const int k) {
    const uint8x16_t m = vld1q_u8((const uint8_t *)xrsr128_xp_rolmask[k - 1]);
    return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(x), m));
}
#  define XRSR128_XP_ROL_BYTE(x, k)  xrsr128_xp_vrolb((x), (k))
#else
#  define XRSR128_XP_ROL_BYTE(x, k)  XRSR128_XP_ROL((x), (k) * 8)
#endif

/* buffer index of lane j, word w (0=out0, 1=out1) of group g, chunk c */
#define XRSR128_XP_IDX(g, w, c, j) ((((g) * 2 + (w)) * 8) + (c) * XRSR128_XP_LANES + (j))

/* Fill nblk 64-word blocks.  NEON nblk>1: each 2-group half sweeps all blocks with its 16 state vectors resident (state loaded/stored once per half); nblk==1 or non-NEON: per block. */
static inline void xrsr128_xp_fill_vect(xrsr128_xp_t * const r, uint64_t * const XRSR128_XP_RESTRICT out, const size_t nblk) {
#if XRSR128_XP_USE_NEON
    if (nblk > 1) {
        unsigned h; int c, g; size_t b;
        for (h = 0; h < 2; h++) {
            const unsigned g0 = h * 2;
            xrsr128_xp_chunk_t S0[2][XRSR128_XP_CHUNKS], S1[2][XRSR128_XP_CHUNKS];
            for (g = 0; g < 2; g++) for (c = 0; c < XRSR128_XP_CHUNKS; c++) {
                S0[g][c] = r->s0[g0 + g][c]; S1[g][c] = r->s1[g0 + g][c];
            }
            for (b = 0; b < nblk; b++) {
                uint64_t * const o = out + b * (XRSR128_XP_GROUPS * 16);
                for (c = 0; c < XRSR128_XP_CHUNKS; c++) for (g = 0; g < 2; g++) {
                    const xrsr128_xp_chunk_t x0 = S0[g][c], x1 = S1[g][c];
                    const xrsr128_xp_chunk_t n1 = XRSR128_XP_XOR(x1, x0);
                    const xrsr128_xp_chunk_t sr = XRSR128_XP_SUB(XRSR128_XP_SLLI(n1, 16), n1);        /* *65535 */
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g0 + g, 0, c, 0)], XRSR128_XP_ADD(x0, XRSR128_XP_ROL_BYTE(sr, 8/8)));
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g0 + g, 1, c, 0)], XRSR128_XP_ADD(x1, XRSR128_XP_ROL_BYTE(sr, 16/8)));
                    S0[g][c] = XRSR128_XP_XOR(XRSR128_XP_ROL_BYTE(x0, 24/8), XRSR128_XP_XOR(n1, XRSR128_XP_SLLI(n1, 16)));
                    S1[g][c] = XRSR128_XP_ROL(n1, 37);
                }
            }
            for (g = 0; g < 2; g++) for (c = 0; c < XRSR128_XP_CHUNKS; c++) {
                r->s0[g0 + g][c] = S0[g][c]; r->s1[g0 + g][c] = S1[g][c];
            }
        }
        return;
    }
#endif
    {
        size_t b; int c, g;
        for (b = 0; b < nblk; b++) {
            uint64_t * const o = out + b * (XRSR128_XP_GROUPS * 16);
            for (c = 0; c < XRSR128_XP_CHUNKS; c++)
                for (g = 0; g < XRSR128_XP_GROUPS; g++) {
                    const xrsr128_xp_chunk_t x0 = r->s0[g][c], x1 = r->s1[g][c];
                    const xrsr128_xp_chunk_t n1 = XRSR128_XP_XOR(x1, x0);
                    const xrsr128_xp_chunk_t sr = XRSR128_XP_SUB(XRSR128_XP_SLLI(n1, 16), n1);        /* *65535 */
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g, 0, c, 0)], XRSR128_XP_ADD(x0, XRSR128_XP_ROL_BYTE(sr, 8/8)));
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g, 1, c, 0)], XRSR128_XP_ADD(x1, XRSR128_XP_ROL_BYTE(sr, 16/8)));
                    r->s0[g][c] = XRSR128_XP_XOR(XRSR128_XP_ROL_BYTE(x0, 24/8), XRSR128_XP_XOR(n1, XRSR128_XP_SLLI(n1, 16)));
                    r->s1[g][c] = XRSR128_XP_ROL(n1, 37);
                }
        }
    }
}

#  define xrsr128_xp_fill xrsr128_xp_fill_vect

#else  /* scalar only */

#  define xrsr128_xp_fill xrsr128_xp_fill_scalar

#endif

/* ------------------------------------------------------------------ */
/* ---- public API ---- */
/* ------------------------------------------------------------------ */

/* one 64-bit output */
static inline uint64_t xrsr128_xp_u64(xrsr128_xp_t * const r) {
    if (r->pos >= XRSR128_XP_BUF) {
        xrsr128_xp_fill(r, r->buf, 1);
        r->pos = 0;
    }
    return r->buf[r->pos++];
}

/* Bulk: n words to dst, no copy or alignment requirement.  Use a large n -- the 128-bit state stays in registers only within one call (AVX-512: 1024-word ~0.126 vs 64-word ~0.201 ns/word); use non-temporal stores if dst streams to DRAM. */
static inline void xrsr128_xp_fill_u64(xrsr128_xp_t * const r, uint64_t * const XRSR128_XP_RESTRICT dst,
                                const size_t n) {
    size_t i = 0, m;
    if (r->pos < XRSR128_XP_BUF) {                        /* drain the current block */
        m = (size_t)XRSR128_XP_BUF - r->pos;
        if (m > n) m = n;
        memcpy(dst, r->buf + r->pos, m * sizeof(uint64_t));
        r->pos += (unsigned)m;
        i = m;
    }
    {                                              /* whole blocks at once    */
        const size_t nb = (n - i) / (size_t)XRSR128_XP_BUF;
        if (nb) { xrsr128_xp_fill(r, dst + i, nb); i += nb * (size_t)XRSR128_XP_BUF; }
    }
    if (i < n) {                                   /* tail via the block       */
        xrsr128_xp_fill(r, r->buf, 1);
        memcpy(dst + i, r->buf, (n - i) * sizeof(uint64_t));
        r->pos = (unsigned)(n - i);
    }
}

/* f64/f64s are exact projections of one 64-bit draw (uniform grid).  Exception: 2^128-1 reachable states => word 0 has 2^64-1 preimages, so 0.0 / -1.0 each lose 3.4e-38 probability; every other point is exact. */

/* [0,1), 53-bit mantissa (uses the top 53 bits); 1.0 never returned. */
static inline double xrsr128_xp_f64(xrsr128_xp_t * const r) {
    return (double)(xrsr128_xp_u64(r) >> 11) * (1.0 / 9007199254740992.0);
}

/* [-1,1), 54 bits: sign bit from a discarded low bit; includes -1, excludes +1. */
static inline double xrsr128_xp_f64s(xrsr128_xp_t * const r) {
    const int64_t k = (int64_t)(xrsr128_xp_u64(r) >> 10) - (INT64_C(1) << 53);
    return (double)k * (1.0 / 9007199254740992.0);
}

#endif /* XRSR128_XP_H */
