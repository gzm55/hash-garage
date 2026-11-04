/* xoroshiro128^* (xoroshiro128xp.h) -- xoroshiro128 with a shared-offset
 * (65535*n1) scramble; two 64-bit outputs per 128-bit state per step.
 *
 *     n1   = x0 ^ x1
 *     sr   = (n1 << 16) - n1              (= 65535 * n1 = (2^16 - 1) * n1)
 *     out0 = x0 + rotl(sr, ROT0)
 *     out1 = x1 + rotl(sr, ROT1)
 *     x0'  = rotl(x0, 24) ^ n1 ^ (n1 << 16)
 *     x1'  = rotl(n1, 37)
 *
 * sr is the only nonlinear step; (2^16*n1 - n1) borrows from bit 2 up, so only
 * bits 0-1 of sr stay GF(2)-affine (a 2-bit window, vs 17 for the (n1<<t)+n1
 * form).  The two rotations differ (ROT0 vs ROT1, default 8 vs 16) so sr cannot cancel between out0
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

/* Version. Bump on each release. */
#define XRSR128_XP_VERSION 2

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

/* Branch hint for the rare refill path in u64() (no-op off GCC/Clang). */
#if defined(__GNUC__) || defined(__clang__)
#  define XRSR128_XP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define XRSR128_XP_UNLIKELY(x) (x)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* ---- parameters ---- */
/* ------------------------------------------------------------------ */

#define XRSR128_XP_GROUPS   4                 /* 4 groups x 8 lanes = 32 streams     */
#define XRSR128_XP_STREAMS  8                 /* logical lanes per group             */
#define XRSR128_XP_BUF      (XRSR128_XP_GROUPS * XRSR128_XP_STREAMS * 2)  /* 2 words/stream = 512 B */
#define XRSR128_XP_P1       ((uint64_t)0x9E3779B97F4A7C15ULL)  /* golden gamma      */
#define XRSR128_XP_SALT     ((uint64_t)0xD1B54A32D192ED03ULL)  /* seed decorrelation*/
#define XRSR128_XP_2M53     (1.0 / 9007199254740992.0)         /* 2^-53, the f64 scale */
#define XRSR128_XP_ROT0     8                 /* out0 = x0 + rotl(sr, ROT0)          */
#define XRSR128_XP_ROT1     16                /* out1 = x1 + rotl(sr, ROT1)          */

/* Jump polynomials: entry [k] = x^(2^k) mod P (xoroshiro128 characteristic
 * polynomial), as a 128-bit coefficient vector (lo,hi); bit i set = T^i term.
 * Same transition as xoroshiro128, so [64]/[96] equal Vigna JUMP/LONG_JUMP.
 * Generated offline; #if 0 self-check below reproduces this table. */
XRSR128_XP_ALIGN16 static const uint64_t xrsr128_xp_jump_poly[128][2] = {
    { UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000000000004), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000000000010), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000000000100), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000000010000), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000100000000), UINT64_C(0x0000000000000000) },
    { UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001) },
    { UINT64_C(0x095b8f76579aa001), UINT64_C(0x0008828e513b43d5) },
    { UINT64_C(0x162ad6ec01b26eae), UINT64_C(0x7a8ff5b1c465a931) },
    { UINT64_C(0xb4fbaa5c54ee8b8f), UINT64_C(0xb18b0d36cd81a8f5) },
    { UINT64_C(0x1207a1706bebb202), UINT64_C(0x23ac5e0ba1cecb29) },
    { UINT64_C(0x2c88ef71166bc53d), UINT64_C(0xbb18e9c8d463bb1b) },
    { UINT64_C(0xc3865bb154e9be10), UINT64_C(0xe3fbe606ef4e8e09) },
    { UINT64_C(0x1a9fc99fa7818274), UINT64_C(0x28faaaebb31ee2db) },
    { UINT64_C(0x588abd4c2ce2ba80), UINT64_C(0x30a7c4eef203c7eb) },
    { UINT64_C(0x9c90debc053e8cef), UINT64_C(0xa425003f3220a91d) },
    { UINT64_C(0xb82ca99a09a4e71e), UINT64_C(0x81e1dd96586cf985) },
    { UINT64_C(0x35d69e118698a31d), UINT64_C(0x4f7fd3dfbb820bfb) },
    { UINT64_C(0x49613606c466efd3), UINT64_C(0xfee2760ef3a900b3) },
    { UINT64_C(0xbd031d011900a9e5), UINT64_C(0xf0df0531f434c57d) },
    { UINT64_C(0x235e761b3b378590), UINT64_C(0x442576715266740c) },
    { UINT64_C(0x3710a7ae7945df77), UINT64_C(0x1e8bae8f680d2b35) },
    { UINT64_C(0x75d8e7dbceda609c), UINT64_C(0xfd7027fe6d2f6764) },
    { UINT64_C(0xde2cba60cd3332b5), UINT64_C(0x28eff231ad438124) },
    { UINT64_C(0x377e64c4e80a06fa), UINT64_C(0x1808760d0a0909a1) },
    { UINT64_C(0x0cf0a2225da7fb95), UINT64_C(0xb9a362fafedfe9d2) },
    { UINT64_C(0x2bab58a3cadfc0a3), UINT64_C(0xf57881ab117349fd) },
    { UINT64_C(0x8d51ecdb9ed82455), UINT64_C(0x849272241425c996) },
    { UINT64_C(0x521b29d0a57326c1), UINT64_C(0xf1ccb8898cbc07cd) },
    { UINT64_C(0xfbe65017abec72dd), UINT64_C(0x61179e44214caafa) },
    { UINT64_C(0x6c446b9bc95c267b), UINT64_C(0xd9aa6b1e93fbb6e4) },
    { UINT64_C(0x64f80248d23655c6), UINT64_C(0x86e3772194563f6d) },
    { UINT64_C(0xfad843622b252c78), UINT64_C(0xd4e95eef9edbdbc6) },
    { UINT64_C(0x598742bbfddde630), UINT64_C(0x05667023c584a68a) },
    { UINT64_C(0x3a9d7dce072134a6), UINT64_C(0x401aacf87a5e21ee) },
    { UINT64_C(0xf0cc32eaf522f0e0), UINT64_C(0xe114b1e65a950e43) },
    { UINT64_C(0xeb2beaa80d3fd8a7), UINT64_C(0x905dff85834fb8d1) },
    { UINT64_C(0x61f29536e1bb6b99), UINT64_C(0xc449c069734817cb) },
    { UINT64_C(0x390cd235d35187da), UINT64_C(0x1e5bc0fe7032f3df) },
    { UINT64_C(0x744e5f1168ba3345), UINT64_C(0x3f399e6f1ea22dbc) },
    { UINT64_C(0x8cc9aa88a153f5f8), UINT64_C(0xd47a02636f041cca) },
    { UINT64_C(0x08d037056c80b9e0), UINT64_C(0xf83c06b106d3b7ab) },
    { UINT64_C(0x4ce3c123d196bf7a), UINT64_C(0x14223eedae116a83) },
    { UINT64_C(0xb1b206870da4e89a), UINT64_C(0x24bfd164204335ae) },
    { UINT64_C(0x207bb2453717cf67), UINT64_C(0x4a5953c8f4bc2a51) },
    { UINT64_C(0xa14e342bb11ff7e6), UINT64_C(0xf6b3f196dc551ccf) },
    { UINT64_C(0x5422bca5015dd3b7), UINT64_C(0x5b6233b76fa214d7) },
    { UINT64_C(0xede7341c00c65b85), UINT64_C(0xf20d7136458bd924) },
    { UINT64_C(0xd769cfc9028deb78), UINT64_C(0x9b19ba6b3752065a) },
    { UINT64_C(0xc7b0e531abe7e4bd), UINT64_C(0x4f27796502238c48) },
    { UINT64_C(0x1c6d3ba4bb94182a), UINT64_C(0xb7b17dcd25003305) },
    { UINT64_C(0x3ae9471d0e2d0bcf), UINT64_C(0xaaae579366147d07) },
    { UINT64_C(0x8f9cd3794ca46fbf), UINT64_C(0x0d56bb288c661ccf) },
    { UINT64_C(0xdb2ad4e9c15a9d4e), UINT64_C(0x0402342eedff424c) },
    { UINT64_C(0x79e061af5be21395), UINT64_C(0x4e71559e6d0e7f00) },
    { UINT64_C(0x96e7d88c0794e785), UINT64_C(0x8367af1c9d6c1406) },
    { UINT64_C(0xccdda809db64b3e7), UINT64_C(0x0dbfcd2453d1d33f) },
    { UINT64_C(0x6c64681c21cd0286), UINT64_C(0x3309e57f180d4ff6) },
    { UINT64_C(0xacb8d4c6ba67113e), UINT64_C(0xb439f330ab3b9715) },
    { UINT64_C(0xbad04ca5d96e2cd3), UINT64_C(0xc58f079d0205bcf3) },
    { UINT64_C(0xebfbc2723a906760), UINT64_C(0x09417d8c80a37aa7) },
    { UINT64_C(0x38ac01316167183d), UINT64_C(0x52f51ac639e09712) },
    { UINT64_C(0x7a134006d4efa484), UINT64_C(0xf37ead6ea53b96ba) },
    { UINT64_C(0x351561e58f8572d4), UINT64_C(0xdc1c01799cb8d734) },
    { UINT64_C(0xdf900294d8f554a5), UINT64_C(0x170865df4b3201fc) },
    { UINT64_C(0x2992ead4972eaed2), UINT64_C(0xb2a7b279a8cb1f50) },
    { UINT64_C(0xc026a7d9e04a7700), UINT64_C(0xe7859c665be57882) },
    { UINT64_C(0xb4cb6197dea2b1fe), UINT64_C(0x4b4a7aa8c389701c) },
    { UINT64_C(0x0dcfc5b909e7df4d), UINT64_C(0xadb7753d55646eef) },
    { UINT64_C(0x468431669864f789), UINT64_C(0xc80926301806a352) },
    { UINT64_C(0x22b6c1736285fcc8), UINT64_C(0xc05da051ec96af1d) },
    { UINT64_C(0x74c1daac8729d8bb), UINT64_C(0xf88f6bac8fd30448) },
    { UINT64_C(0x847757c126b23e45), UINT64_C(0x752b98d002c408f7) },
    { UINT64_C(0x0f9eaa62d0c9e2a3), UINT64_C(0x1aa7bc96dbace110) },
    { UINT64_C(0x7475d71b98314377), UINT64_C(0xc469b29353a4984b) },
    { UINT64_C(0xbbb7d266d61c85ea), UINT64_C(0x4b6dd41bce3bb499) },
    { UINT64_C(0xc419b3742570e16f), UINT64_C(0xe023777e70b3a2f8) },
    { UINT64_C(0x2a71db3a3ce8b968), UINT64_C(0x131e94fb35203d80) },
    { UINT64_C(0x2897bb8961b4dce9), UINT64_C(0x9240c95b1e7fa08b) },
    { UINT64_C(0xf0fc3553d7881d5f), UINT64_C(0xb879fca0915f893f) },
    { UINT64_C(0xe754db3fbc7536bc), UINT64_C(0x2adca86fbefe1366) },
    { UINT64_C(0x0a9e201adfe7baa9), UINT64_C(0x0a40a688d77855ba) },
    { UINT64_C(0x1d0d601e49c35837), UINT64_C(0x17771c905e0775a8) },
    { UINT64_C(0x9b031395aec7b584), UINT64_C(0x2cf775e419a607e0) },
    { UINT64_C(0x79ead2eeddf66699), UINT64_C(0x93a7cf27dec9b306) },
    { UINT64_C(0xe1b9805c107679fc), UINT64_C(0x93615189fe85b7d5) },
    { UINT64_C(0x2c3925dcd790e3d6), UINT64_C(0x466421124b50fbfb) },
    { UINT64_C(0xdca9b0fa4e95600e), UINT64_C(0x1cda7bd04e3bb94b) },
    { UINT64_C(0xefc7905e1cbb5ffb), UINT64_C(0x5ec431d73bbfe49f) },
    { UINT64_C(0x854414811d534483), UINT64_C(0x31a1f85fd532f302) },
    { UINT64_C(0xadb9ba2958f30b6e), UINT64_C(0xed9b991c09177e2f) },
    { UINT64_C(0x76f8fdf26b0d1cbb), UINT64_C(0x38d9e87dffdfca70) },
    { UINT64_C(0x51f21cddcebdb8c7), UINT64_C(0xd8e9e7254052af4d) },
    { UINT64_C(0xa03f796efb295305), UINT64_C(0x62769780d13fbc08) },
    { UINT64_C(0x4f2083f6b19e628a), UINT64_C(0x66e5456c2eaedbff) },
    { UINT64_C(0x8b2be9cd79734bed), UINT64_C(0xace8d6ce8e3fba17) },
    { UINT64_C(0xd2a98b26625eee7b), UINT64_C(0xdddf9b1090aa7ac1) },
    { UINT64_C(0x4fff128094edd94c), UINT64_C(0x00d67dc46ad28695) },
    { UINT64_C(0x726438e9a1d3c6ea), UINT64_C(0xf9540570703e7cf3) },
    { UINT64_C(0x92cc6a0937c9d34e), UINT64_C(0x066a9599766619b5) },
    { UINT64_C(0xc5730de058e1047f), UINT64_C(0xa4e540c7ac49aa1b) },
    { UINT64_C(0xe408bbecda066551), UINT64_C(0xc2edfc1ab51c00ad) },
    { UINT64_C(0xc5477ea8821ce588), UINT64_C(0xf11753a4339e78c3) },
    { UINT64_C(0x3c6058e633063180), UINT64_C(0xbb42e906efb12540) },
    { UINT64_C(0xbec40e0518086e21), UINT64_C(0x4e86f36c495eeedb) },
    { UINT64_C(0x465276434fd98954), UINT64_C(0xe8345a7c487fefd6) },
    { UINT64_C(0x3adaea5cdfe12e3b), UINT64_C(0x688b762874221434) },
    { UINT64_C(0xc9dffa95904e99b1), UINT64_C(0x833801923a05f253) },
    { UINT64_C(0xa10c3fb0b18df787), UINT64_C(0x58a00d23a8086646) },
    { UINT64_C(0xa4e41f760281c3d0), UINT64_C(0xec69708d487dbfc4) },
    { UINT64_C(0xb8880fff0e41261c), UINT64_C(0x47176f17de7ff0e9) },
    { UINT64_C(0x58ee3b30f542767e), UINT64_C(0x4f40c533643920ea) },
    { UINT64_C(0x15f2d25b60c5acd7), UINT64_C(0x83fd48d6b9620584) },
    { UINT64_C(0xe448c83950a687ea), UINT64_C(0x0ce303c7d3aabbc8) },
    { UINT64_C(0xa6ff7863c363cfd4), UINT64_C(0x1746715df0dd8fe3) },
    { UINT64_C(0x7e9d8517b195d9c9), UINT64_C(0xc00185964caef8bb) },
    { UINT64_C(0x40ddb4daf3fbdda8), UINT64_C(0xb6bde02bd004b144) },
    { UINT64_C(0x7a794b820672a49b), UINT64_C(0xba43c63ec5a9f187) },
    { UINT64_C(0xc1be31e7536236fb), UINT64_C(0x2467071b1d261621) },
    { UINT64_C(0xf0eec34daea486fb), UINT64_C(0x5a6fc0435f011daa) },
    { UINT64_C(0xf42c01a2a3815db4), UINT64_C(0xa5af34331c044d81) },
    { UINT64_C(0xdf7964c343b312de), UINT64_C(0xdb43b553cd16ea44) },
    { UINT64_C(0x8454182464c29903), UINT64_C(0x432c2bbcd03e65f6) },
    { UINT64_C(0x7b6c0ecc6cb5adbb), UINT64_C(0xcdf56412d1e7ba6e) },
    { UINT64_C(0x380b97764c9f7748), UINT64_C(0xac13c8b2ff838036) },
    { UINT64_C(0x1868a9f5a4fd4d64), UINT64_C(0x71d208cc2e5c56e9) },
    { UINT64_C(0xe89f5fe075d74a79), UINT64_C(0xd1d08a01b73de005) },
    { UINT64_C(0x25aa87f3c2704c69), UINT64_C(0xa9495c12936ad0fd) },
};


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
                o[j] = x0 + xrsr128_xp_rotl64(sr, XRSR128_XP_ROT0);
                o[8 + j] = x1 + xrsr128_xp_rotl64(sr, XRSR128_XP_ROT1);
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

/* Output rotate for the vector path: byte-rotate fast path only when the
 * distance is a multiple of 8; otherwise a general vector rotate. */
#if (XRSR128_XP_ROT0 % 8) == 0
#  define XRSR128_XP_ROT0V(x)  XRSR128_XP_ROL_BYTE((x), XRSR128_XP_ROT0 / 8)
#else
#  define XRSR128_XP_ROT0V(x)  XRSR128_XP_ROL((x), XRSR128_XP_ROT0)
#endif
#if (XRSR128_XP_ROT1 % 8) == 0
#  define XRSR128_XP_ROT1V(x)  XRSR128_XP_ROL_BYTE((x), XRSR128_XP_ROT1 / 8)
#else
#  define XRSR128_XP_ROT1V(x)  XRSR128_XP_ROL((x), XRSR128_XP_ROT1)
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
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g0 + g, 0, c, 0)], XRSR128_XP_ADD(x0, XRSR128_XP_ROT0V(sr)));
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g0 + g, 1, c, 0)], XRSR128_XP_ADD(x1, XRSR128_XP_ROT1V(sr)));
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
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g, 0, c, 0)], XRSR128_XP_ADD(x0, XRSR128_XP_ROT0V(sr)));
                    XRSR128_XP_STORE(&o[XRSR128_XP_IDX(g, 1, c, 0)], XRSR128_XP_ADD(x1, XRSR128_XP_ROT1V(sr)));
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
/* ---- jump (advance all 32 streams by 2^k / arbitrary blocks) ---- */
/* 1 step = every stream advances once = one XRSR128_XP_BUF-word block.
 * The per-stream transition is exactly xoroshiro128, so the jump
 * polynomials are xoroshiro128's (verified against Vigna JUMP/LONG_JUMP). */

/* internal: one xoroshiro128 transition (lo = s0, hi = s1) */
static inline void xrsr128_xp_step1(uint64_t * const lo, uint64_t * const hi) {
    const uint64_t s0 = *lo, s1 = *hi, n1 = s0 ^ s1;
    *lo = xrsr128_xp_rotl64(s0, 24) ^ n1 ^ (n1 << 16);
    *hi = xrsr128_xp_rotl64(n1, 37);
}

/* advanced: advance all 32 streams by 2^k steps (k &= 127, Frobenius period).
 * Scalar, branch-free loops -> auto-vectorizes across the 32 streams. */
static inline void xrsr128_xp_jump2k(xrsr128_xp_t * const r, unsigned k) {
    enum { NS = XRSR128_XP_GROUPS * XRSR128_XP_STREAMS };   /* 32 streams */
    uint64_t a0[NS] = {0}, a1[NS] = {0}, b0[NS], b1[NS];
    uint64_t plo, phi;
    int i, j;
    k &= 127u;
    plo = xrsr128_xp_jump_poly[k][0]; phi = xrsr128_xp_jump_poly[k][1];
    memcpy(b0, r->s0, sizeof b0); memcpy(b1, r->s1, sizeof b1);
    for (i = 0; i < 128; i++) {
        const uint64_t bit  = (i < 64) ? (plo >> i) : (phi >> (i - 64));
        const uint64_t mask = (uint64_t)0 - (bit & 1u);      /* all-ones or all-zeros */
        XRSR128_XP_VECTOR_HINT
        for (j = 0; j < NS; j++) { a0[j] ^= b0[j] & mask; a1[j] ^= b1[j] & mask; }
        XRSR128_XP_VECTOR_HINT
        for (j = 0; j < NS; j++) xrsr128_xp_step1(&b0[j], &b1[j]);
    }
    memcpy(r->s0, a0, sizeof a0); memcpy(r->s1, a1, sizeof a1);
    r->pos = XRSR128_XP_BUF;
}

/* advanced: advance all 32 streams by an arbitrary 128-bit number of steps */
static inline void xrsr128_xp_jump128(xrsr128_xp_t * const r, const uint64_t hi, const uint64_t lo) {
    int k;
    for (k = 0; k < 64; k++) if ((lo >> k) & 1u) xrsr128_xp_jump2k(r, (unsigned)k);
    for (k = 0; k < 64; k++) if ((hi >> k) & 1u) xrsr128_xp_jump2k(r, (unsigned)(64 + k));
}

/* ------------------------------------------------------------------ */
/* ---- public API ---- */
/* ------------------------------------------------------------------ */

/* one 64-bit output */
static inline uint64_t xrsr128_xp_u64(xrsr128_xp_t * const r) {
    if (XRSR128_XP_UNLIKELY(r->pos >= XRSR128_XP_BUF)) {
        xrsr128_xp_fill(r, r->buf, 1);
        r->pos = 0;
    }
    return r->buf[r->pos++];
}

/* Bulk: n words to dst, no copy or alignment requirement.  Use a large n -- the 128-bit state stays in registers only within one call (AVX-512: 1024-word ~0.126 vs 64-word ~0.201 ns/word); use non-temporal stores if dst streams to DRAM. */
static inline void xrsr128_xp_fill_u64(xrsr128_xp_t * const r, uint64_t * const XRSR128_XP_RESTRICT dst,
                                const size_t n) {
    size_t i = 0;
    if (r->pos < XRSR128_XP_BUF) {                        /* drain the current block */
        const size_t left = (size_t)XRSR128_XP_BUF - r->pos;
        const size_t m = left < n ? left : n;
        memcpy(dst, r->buf + r->pos, m * sizeof(uint64_t));
        r->pos += (unsigned)m;
        i = m;
    }
    {                                              /* whole blocks at once    */
        const size_t nb = (n - i) / (size_t)XRSR128_XP_BUF;
        xrsr128_xp_fill(r, dst + i, nb);           /* nb==0: no-op (0-trip loop) */
        i += nb * (size_t)XRSR128_XP_BUF;
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
    return (double)(xrsr128_xp_u64(r) >> 11) * XRSR128_XP_2M53;
}

/* [-1,1), 54 bits: sign bit from a discarded low bit; includes -1, excludes +1. */
static inline double xrsr128_xp_f64s(xrsr128_xp_t * const r) {
    const int64_t k = (int64_t)(xrsr128_xp_u64(r) >> 10) - (INT64_C(1) << 53);
    return (double)k * XRSR128_XP_2M53;
}

/* Bulk [0,1): n doubles identical to n consecutive f64() calls.  The u64 stream
 * is produced in chunks (a multiple of the 64-word block), then converted by a
 * plain scalar loop the compiler can auto-vectorize (the shift + u64->f64 + scale). */
static inline void xrsr128_xp_fill_f64(xrsr128_xp_t * const r,
                                       double * const XRSR128_XP_RESTRICT dst, size_t n) {
    enum { XRSR128_XP_CHUNK = 256 };            /* multiple of XRSR128_XP_BUF */
    XRSR128_XP_ALIGN64 uint64_t tmp[XRSR128_XP_CHUNK];
    double *p = dst;
    while (n >= XRSR128_XP_CHUNK) {             /* full chunks, c == CHUNK (no ternary) */
        xrsr128_xp_fill_u64(r, tmp, XRSR128_XP_CHUNK);
        XRSR128_XP_VECTOR_HINT
        for (size_t j = 0; j < XRSR128_XP_CHUNK; j++)   /* < 2^53: int64 cast -> cheaper signed u64->f64 */
            p[j] = (double)(int64_t)(tmp[j] >> 11) * XRSR128_XP_2M53;
        p += XRSR128_XP_CHUNK; n -= XRSR128_XP_CHUNK;
    }
    if (n) {                                    /* tail < CHUNK */
        xrsr128_xp_fill_u64(r, tmp, n);
        XRSR128_XP_VECTOR_HINT
        for (size_t j = 0; j < n; j++)
            p[j] = (double)(int64_t)(tmp[j] >> 11) * XRSR128_XP_2M53;
    }
}

/* Bulk [-1,1): n doubles identical to n consecutive f64s() calls. */
static inline void xrsr128_xp_fill_f64s(xrsr128_xp_t * const r,
                                        double * const XRSR128_XP_RESTRICT dst, size_t n) {
    enum { XRSR128_XP_CHUNK = 256 };            /* multiple of XRSR128_XP_BUF */
    XRSR128_XP_ALIGN64 uint64_t tmp[XRSR128_XP_CHUNK];
    double *p = dst;
    while (n >= XRSR128_XP_CHUNK) {             /* full chunks, c == CHUNK (no ternary) */
        xrsr128_xp_fill_u64(r, tmp, XRSR128_XP_CHUNK);
        XRSR128_XP_VECTOR_HINT
        for (size_t j = 0; j < XRSR128_XP_CHUNK; j++) {
            const int64_t k = (int64_t)(tmp[j] >> 10) - (INT64_C(1) << 53);
            p[j] = (double)k * XRSR128_XP_2M53;
        }
        p += XRSR128_XP_CHUNK; n -= XRSR128_XP_CHUNK;
    }
    if (n) {                                    /* tail < CHUNK */
        xrsr128_xp_fill_u64(r, tmp, n);
        XRSR128_XP_VECTOR_HINT
        for (size_t j = 0; j < n; j++) {
            const int64_t k = (int64_t)(tmp[j] >> 10) - (INT64_C(1) << 53);
            p[j] = (double)k * XRSR128_XP_2M53;
        }
    }
}


/* Jump 2^64 steps (Vigna "jump"): parallel streams stay 2^64 blocks apart. */
static inline void xrsr128_xp_jump(xrsr128_xp_t * const r) {
    xrsr128_xp_jump128(r, UINT64_C(1), 0);
}
/* Jump 2^96 steps (Vigna "long_jump"). */
static inline void xrsr128_xp_long_jump(xrsr128_xp_t * const r) {
    xrsr128_xp_jump128(r, UINT64_C(1) << 32, 0);
}

/* ------------------------------------------------------------------ */
/* ---- single stream (one xoroshiro128 lane) -- advanced, for testing ---- */
/* One of the 32 lanes standalone: 128-bit state, two outputs (out0, out1)
 * per step.  Scalar.  Emit via xrsr128_xp1_u64() (alternating out0/out1) or
 * xrsr128_xp1_fill().  A single lane's long-run quality depends on ROT0/ROT1;
 * the vetted high-quality output is the 32-stream interleaving. */
typedef struct {
    uint64_t s0, s1;      /* xoroshiro128 state                     */
    uint64_t pending;     /* cached out1 while out0 is being emitted */
    unsigned phase;       /* 0: emit out0 next; 1: emit pending      */
} xrsr128_xp1_t;

static inline void xrsr128_xp1_init(xrsr128_xp1_t * const s, const uint64_t seed) {
    uint64_t x = seed ^ XRSR128_XP_SALT;
    s->s0 = xrsr128_xp_splitmix(&x);
    s->s1 = xrsr128_xp_splitmix(&x);
    if (!(s->s0 | s->s1)) s->s0 = XRSR128_XP_P1;
    s->pending = 0; s->phase = 0;
}

/* advance one step: state -> state, and emit the pair (o0 = out0, o1 = out1) */
static inline void xrsr128_xp1_next(xrsr128_xp1_t * const s,
                                    uint64_t * const o0, uint64_t * const o1) {
    const uint64_t n1 = s->s0 ^ s->s1, sr = (n1 << 16) - n1;
    *o0 = s->s0 + xrsr128_xp_rotl64(sr, XRSR128_XP_ROT0);
    *o1 = s->s1 + xrsr128_xp_rotl64(sr, XRSR128_XP_ROT1);
    xrsr128_xp_step1(&s->s0, &s->s1);
}

static inline uint64_t xrsr128_xp1_u64(xrsr128_xp1_t * const s) {
    uint64_t o0, o1;
    if (s->phase) { s->phase = 0; return s->pending; }
    xrsr128_xp1_next(s, &o0, &o1);
    s->pending = o1; s->phase = 1;
    return o0;
}

static inline void xrsr128_xp1_fill(xrsr128_xp1_t * const s,
                                    uint64_t * const XRSR128_XP_RESTRICT dst, const size_t n) {
    size_t i = 0;
    if (s->phase) { dst[i++] = s->pending; s->phase = 0; }
    while (i + 1 < n) {
        uint64_t o0, o1;
        xrsr128_xp1_next(s, &o0, &o1);
        dst[i] = o0; dst[i + 1] = o1;
        i += 2;
    }
    if (i < n) {                                   /* one leftover: emit out0, cache out1 */
        uint64_t o0, o1;
        xrsr128_xp1_next(s, &o0, &o1);
        dst[i] = o0; s->pending = o1; s->phase = 1;
    }
}

static inline void xrsr128_xp1_jump2k(xrsr128_xp1_t * const s, unsigned k) {
    uint64_t a0 = 0, a1 = 0, b0 = s->s0, b1 = s->s1, plo, phi;
    int i;
    k &= 127u;
    plo = xrsr128_xp_jump_poly[k][0]; phi = xrsr128_xp_jump_poly[k][1];
    for (i = 0; i < 128; i++) {
        const uint64_t bit = (i < 64) ? (plo >> i) : (phi >> (i - 64));
        const uint64_t mask = (uint64_t)0 - (bit & 1u);
        a0 ^= b0 & mask; a1 ^= b1 & mask;
        xrsr128_xp_step1(&b0, &b1);
    }
    s->s0 = a0; s->s1 = a1;
    s->pending = 0; s->phase = 0;
}

#if 0 /* Jump-poly table self-check / regeneration.
 * Builds M (columns = step1(e_i)), squares it k times for M^(2^k), and recovers
 * the coefficient vector x^(2^k) mod P by exact GF(2) linear solve on the
 * Krylov basis of e_0 (rank 128). Verifies the hardcoded table equals the
 * recomputed one and that [64]/[96] match Vigna's xoroshiro128 constants.
 * Not compiled; kept for auditing. Drop into a scalar build to run. */
static int xrsr128_xp_jump_selftest(void) {
    uint64_t u[128][2], col[128][2], tmp[128][2], poly[128][2];
    int k, j, r, c, bad;
    uint64_t (*cur)[2] = col;
    /* Krylov basis e_0: u[j] = T^j e_0 */
    u[0][0] = 1; u[0][1] = 0;
    for (j = 1; j < 128; j++) { u[j][0] = u[j-1][0]; u[j][1] = u[j-1][1]; xrsr128_xp_step1(&u[j][0], &u[j][1]); }
    /* M columns = step1(e_j) */
    for (j = 0; j < 128; j++) { uint64_t lo = (j<64)?((uint64_t)1<<j):0, hi = (j>=64)?((uint64_t)1<<(j-64)):0; xrsr128_xp_step1(&lo, &hi); col[j][0]=lo; col[j][1]=hi; }
    for (k = 0; k < 128; k++) {
        uint64_t A[128][2], wlo = cur[0][0], whi = cur[0][1], slo = 0, shi = 0;
        int where[128]; uint8_t b[128];
        for (r = 0; r < 128; r++) { uint64_t alo=0, ahi=0; for (j=0;j<128;j++){ uint64_t bit=(r<64)?((u[j][0]>>r)&1):((u[j][1]>>(r-64))&1); if(bit){ if(j<64)alo|=(uint64_t)1<<j; else ahi|=(uint64_t)1<<(j-64);} } A[r][0]=alo;A[r][1]=ahi; b[r]=(r<64)?((wlo>>r)&1):((whi>>(r-64))&1); }
        for (j=0;j<128;j++) where[j]=-1;
        { int row=0; for(c=0;c<128&&row<128;c++){ int sel=-1; for(r=row;r<128;r++){ uint64_t bit=(c<64)?((A[r][0]>>c)&1):((A[r][1]>>(c-64))&1); if(bit){sel=r;break;} } if(sel<0)continue; { uint64_t t0=A[row][0],t1=A[row][1];uint8_t tb=b[row]; A[row][0]=A[sel][0];A[row][1]=A[sel][1];b[row]=b[sel]; A[sel][0]=t0;A[sel][1]=t1;b[sel]=tb; } for(r=0;r<128;r++){ if(r==row)continue; uint64_t bit=(c<64)?((A[r][0]>>c)&1):((A[r][1]>>(c-64))&1); if(bit){A[r][0]^=A[row][0];A[r][1]^=A[row][1];b[r]^=b[row];} } where[c]=row; row++; } }
        for (c=0;c<128;c++) if (where[c]>=0 && b[where[c]]) { if(c<64) slo|=(uint64_t)1<<c; else shi|=(uint64_t)1<<(c-64); }
        poly[k][0]=slo; poly[k][1]=shi;
        for (j=0;j<128;j++){ uint64_t a0=0,a1=0; for(r=0;r<64;r++)if((cur[j][0]>>r)&1){a0^=cur[r][0];a1^=cur[r][1];} for(r=0;r<64;r++)if((cur[j][1]>>r)&1){a0^=cur[64+r][0];a1^=cur[64+r][1];} tmp[j][0]=a0;tmp[j][1]=a1; }
        memcpy(cur, tmp, sizeof col);
    }
    bad = 0;
    for (k = 0; k < 128; k++) if (poly[k][0]!=xrsr128_xp_jump_poly[k][0] || poly[k][1]!=xrsr128_xp_jump_poly[k][1]) bad++;
    if (poly[64][0]!=UINT64_C(0xdf900294d8f554a5) || poly[64][1]!=UINT64_C(0x170865df4b3201fc)) bad++;
    if (poly[96][0]!=UINT64_C(0xd2a98b26625eee7b) || poly[96][1]!=UINT64_C(0xdddf9b1090aa7ac1)) bad++;
    return bad; /* 0 == table matches recompute and Vigna anchors */
}
#endif

/* Drop every internal macro; keep only the include guard and public API. */
#undef XRSR128_XP_USE_AVX512
#undef XRSR128_XP_USE_AVX2
#undef XRSR128_XP_USE_NEON
#undef XRSR128_XP_BYTE_ROT512
#undef XRSR128_XP_BYTE_ROT256
#undef XRSR128_XP_BYTE_ROT_NEON
#undef XRSR128_XP_ALIGN16
#undef XRSR128_XP_ALIGN64
#undef XRSR128_XP_RESTRICT
#undef XRSR128_XP_VECTOR_HINT
#undef XRSR128_XP_UNLIKELY
#undef XRSR128_XP_GROUPS
#undef XRSR128_XP_STREAMS
#undef XRSR128_XP_BUF
#undef XRSR128_XP_P1
#undef XRSR128_XP_SALT
#undef XRSR128_XP_LANES
#undef XRSR128_XP_CHUNKS
#undef XRSR128_XP_XOR
#undef XRSR128_XP_ADD
#undef XRSR128_XP_SUB
#undef XRSR128_XP_SLLI
#undef XRSR128_XP_ROL
#undef XRSR128_XP_LOAD
#undef XRSR128_XP_STORE
#undef XRSR128_XP_ROL_BYTE
#undef XRSR128_XP_IDX
#undef XRSR128_XP_2M53
#undef XRSR128_XP_ROT0
#undef XRSR128_XP_ROT1
#undef XRSR128_XP_ROT0V
#undef XRSR128_XP_ROT1V
#undef xrsr128_xp_fill

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XRSR128_XP_H */
