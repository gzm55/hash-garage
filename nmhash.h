/*
 * verification:
 * NMHASH32:
 *   rurban/smhasher: 0xDADAD92D
 *   demerphq/smhasher: 0x740DA204
 * NMHASH32X:
 *   rurban/smhasher: 0xB3AD8BB9
 *   demerphq/smhasher: 0xBCCA21BD
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _nmhash_h_
#define _nmhash_h_

#define NMH_VERSION 2-dev

#ifdef _MSC_VER
#  pragma warning(push, 3)
#endif

#if defined(__cplusplus) && __cplusplus < 201103L
#  define __STDC_CONSTANT_MACROS 1
#endif

#include <stdint.h>
#include <string.h>

#if defined(__GNUC__)
#  if defined(__AVX2__)
#    include <immintrin.h>
#  elif defined(__SSE2__)
#    include <emmintrin.h>
#  endif
#elif defined(_MSC_VER)
#  include <intrin.h>
#endif

#ifdef _MSC_VER
#  pragma warning(pop)
#endif

#if (defined(__GNUC__) && (__GNUC__ >= 3))  \
  || (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 800)) \
  || defined(__clang__)
#    define NMH_likely(x) __builtin_expect(x, 1)
#else
#    define NMH_likely(x) (x)
#endif

#if defined(__has_builtin)
#  if __has_builtin(__builtin_rotateleft32)
#    define NMH_rotl32 __builtin_rotateleft32 /* clang */
#  endif
#endif
#if !defined(NMH_rotl32)
#  if defined(_MSC_VER)
     /* Note: although _rotl exists for minGW (GCC under windows), performance seems poor */
#    define NMH_rotl32(x,r) _rotl(x,r)
#  else
#    define NMH_rotl32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#  endif
#endif

#if ((defined(sun) || defined(__sun)) && __cplusplus) /* Solaris includes __STDC_VERSION__ with C++. Tested with GCC 5.5 */
#  define NMH_RESTRICT /* disable */
#elif defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L   /* >= C99 */
#  define NMH_RESTRICT   restrict
#elif defined(__cplusplus) && (defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER))
#  define NMH_RESTRICT __restrict__
#elif defined(__cplusplus) && defined(_MSC_VER)
#  define NMH_RESTRICT __restrict
#else
#  define NMH_RESTRICT   /* disable */
#endif

/* endian macros */
#ifndef NMHASH_LITTLE_ENDIAN
#  if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || defined(__x86_64__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(__SDCC)
#    define NMHASH_LITTLE_ENDIAN 1
#  elif defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define NMHASH_LITTLE_ENDIAN 0
#  else
#    warning could not determine endianness! Falling back to little endian.
#    define NMHASH_LITTLE_ENDIAN 1
#  endif
#endif

/* vector macros */
#define NMH_SCALAR 0
#define NMH_SSE2   1
#define NMH_AVX2   2
#define NMH_AVX512 3

#ifndef NMH_VECTOR    /* can be defined on command line */
#  if defined(__AVX512BW__)
#    define NMH_VECTOR NMH_AVX512 /* _mm512_mullo_epi16 requires AVX512BW */
#  elif defined(__AVX2__)
#    define NMH_VECTOR NMH_AVX2  /* add '-mno-avx256-split-unaligned-load' and '-mn-oavx256-split-unaligned-store' for gcc */
#  elif defined(__SSE2__) || defined(_M_AMD64) || defined(_M_X64) || (defined(_M_IX86_FP) && (_M_IX86_FP == 2))
#    define NMH_VECTOR NMH_SSE2
#  else
#    define NMH_VECTOR NMH_SCALAR
#  endif
#endif

/* align macros */
#if defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)   /* C11+ */
#  include <stdalign.h>
#  define NMH_ALIGN(n)      alignas(n)
#elif defined(__GNUC__)
#  define NMH_ALIGN(n)      __attribute__ ((aligned(n)))
#elif defined(_MSC_VER)
#  define NMH_ALIGN(n)      __declspec(align(n))
#else
#  define NMH_ALIGN(n)   /* disabled */
#endif

#if NMH_VECTOR > 0
#  define NMH_ACC_ALIGN 64
#elif defined(__BIGGEST_ALIGNMENT__)
#  define NMH_ACC_ALIGN __BIGGEST_ALIGNMENT__
#elif defined(__SDCC)
#  define NMH_ACC_ALIGN 1
#else
#  define NMH_ACC_ALIGN 16
#endif

/* constants */

/* primes from xxh */
#define NMH_PRIME32_1  UINT32_C(0x9E3779B1)
#define NMH_PRIME32_2  UINT32_C(0x85EBCA77)
#define NMH_PRIME32_3  UINT32_C(0xC2B2AE3D)
#define NMH_PRIME32_4  UINT32_C(0x27D4EB2F)

/*! Pseudorandom secret taken directly from FARSH. */
NMH_ALIGN(NMH_ACC_ALIGN) static const uint32_t NMH_ACC_INIT[32] = {
	UINT32_C(0x71644897), UINT32_C(0xA20DF94E), UINT32_C(0x3819EF46), UINT32_C(0xA9DEACD8),
	UINT32_C(0xA8FA763F), UINT32_C(0xE39C343F), UINT32_C(0xF9DCBBC7), UINT32_C(0xC70B4F1D),
	UINT32_C(0x8A51E04B), UINT32_C(0xCDB45931), UINT32_C(0xC89F7EC9), UINT32_C(0xD9787364),

	UINT32_C(0xB8FE6C39), UINT32_C(0x23A44BBE), UINT32_C(0x7C01812C), UINT32_C(0xF721AD1C),
	UINT32_C(0xDED46DE9), UINT32_C(0x839097DB), UINT32_C(0x7240A4A4), UINT32_C(0xB7B3671F),
	UINT32_C(0xCB79E64E), UINT32_C(0xCCC0E578), UINT32_C(0x825AD07D), UINT32_C(0xCCFF7221),
	UINT32_C(0xB8084674), UINT32_C(0xF743248E), UINT32_C(0xE03590E6), UINT32_C(0x813A264C),
	UINT32_C(0x3C2852BB), UINT32_C(0x91C300CB), UINT32_C(0x88D0658B), UINT32_C(0x1B532EA3),
};

#if defined(_MSC_VER) && _MSC_VER >= 1914
#  pragma warning(push)
#  pragma warning(disable: 5045)
#endif
#ifdef __SDCC
#  define const
#  pragma save
#  pragma disable_warning 110
#  pragma disable_warning 126
#endif

/* read functions */
static inline
uint32_t
NMH_readLE32(const void *const p)
{
	uint32_t v;
	memcpy(&v, p, 4);
#	if (NMHASH_LITTLE_ENDIAN)
	return v;
#	elif defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
	return __builtin_bswap32(v);
#	elif defined(_MSC_VER)
	return _byteswap_ulong(v);
#	else
	return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
#	endif
}

static inline
uint16_t
NMH_readLE16(const void *const p)
{
	uint16_t v;
	memcpy(&v, p, 2);
#	if (NMHASH_LITTLE_ENDIAN)
	return v;
#	else
	return (uint16_t)((v << 8) | (v >> 8));
#	endif
}

static inline
uint32_t
NMHASH32_0to8(uint32_t const x, uint32_t const seed2)
{
	/* base mixer: [-6 -12 776bf593 -19 11 3fb39c65 -15 -9 e9139917 -11 16] = 0.027071104091278835 */
#	define __NMH_M1 UINT32_C(0x776BF593)
#	define __NMH_M2 UINT32_C(0x3FB39C65)
#	define __NMH_M3V2 UINT32_C(0xE9139917)

#	if NMH_VECTOR == NMH_SCALAR
	{
		union { uint32_t u32; uint16_t u16[2]; } vx;
		vx.u32 = x;
		vx.u32 ^= (vx.u32 >> 12) ^ (vx.u32 >> 6);
		vx.u16[0] *= (uint16_t)(__NMH_M1 & 0xFFFF);
		vx.u16[1] *= (uint16_t)(__NMH_M1 >> 16);
		vx.u32 ^= (vx.u32 << 11) ^ ( vx.u32 >> 19);
		vx.u16[0] *= (uint16_t)(__NMH_M2 & 0xFFFF);
		vx.u16[1] *= (uint16_t)(__NMH_M2 >> 16);
		vx.u32 ^= seed2;
		vx.u32 ^= (vx.u32 >> 15) ^ ( vx.u32 >> 9);
		vx.u16[0] *= (uint16_t)(__NMH_M3V2 & 0xFFFF);
		vx.u16[1] *= (uint16_t)(__NMH_M3V2 >> 16);
		vx.u32 ^= (vx.u32 << 16) ^ ( vx.u32 >> 11);
		return vx.u32;
	}
#	else /* at least NMH_SSE2 */
	{
		__m128i hv = _mm_setr_epi32((int)x, 0, 0, 0);
		const __m128i sv = _mm_setr_epi32((int)seed2, 0, 0, 0);
		const uint32_t *const result = (const uint32_t*)&hv;

		hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_srli_epi32(hv, 12)), _mm_srli_epi32(hv, 6));
		hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)__NMH_M1, 0, 0, 0));
		hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_slli_epi32(hv, 11)), _mm_srli_epi32(hv, 19));
		hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)__NMH_M2, 0, 0, 0));

		hv = _mm_xor_si128(hv, sv);

		hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_srli_epi32(hv, 15)), _mm_srli_epi32(hv, 9));
		hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)__NMH_M3V2, 0, 0, 0));
		hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_slli_epi32(hv, 16)), _mm_srli_epi32(hv, 11));

		return *result;
	}
#	endif

#	undef __NMH_M1
#	undef __NMH_M2
#	undef __NMH_M3V2
}

typedef enum { NMH_AVALANCHE_FULL=0, NMH_AVALANCHE_INNER=1 } NMH_AVALANCHE;

#define __NMH_M3 UINT32_C(0xCCE5196D)
#define __NMH_M4 UINT32_C(0x464BE229)

static inline
uint32_t
NMHASH32_avalanche32(uint32_t const x, NMH_AVALANCHE const type)
{
	/* [-21 -8 cce5196d 12 -7 464be229 -21 -8] = 3.2267098842182733 */
	union { uint32_t u32; uint16_t u16[2]; } vx;
	vx.u32 = x;
	vx.u32    ^= (vx.u32 >> 8) ^ (vx.u32 >> 21);
	vx.u16[0] = (uint16_t)(vx.u16[0] * (uint16_t)(__NMH_M3 & 0xFFFF));
	vx.u16[1] = (uint16_t)(vx.u16[1] * (uint16_t)(__NMH_M3 >> 16));
	vx.u32    ^= (vx.u32 << 12) ^ (vx.u32 >> 7);
	vx.u16[0] = (uint16_t)(vx.u16[0] * (uint16_t)(__NMH_M4 & 0xFFFF));
	vx.u16[1] = (uint16_t)(vx.u16[1] * (uint16_t)(__NMH_M4 >> 16));
	if (NMH_AVALANCHE_FULL == type) {
		return vx.u32 ^ (vx.u32 >> 8) ^ (vx.u32 >> 21);
	}
	return vx.u32;
}

static inline
uint32_t
NMHASH32_mix32(uint32_t const h, uint32_t const x, NMH_AVALANCHE const type)
{
        return NMHASH32_avalanche32(h ^ x, type);
}

#define __NMH_M4V2 UINT32_C(0xA9F36A97)
#define __NMH_M5V2 UINT32_C(0x8AC7BBE5)
#define __NMH_M6V2 UINT32_C(0xEA6B84EF)

static inline
uint32_t
NMHASH32_9to127(const uint8_t* const NMH_RESTRICT p, size_t const len, uint32_t const seed, NMH_AVALANCHE const type)
{
	/* base mixer: [a9f36a97 -12 -5 8ac7bbe5 -19 14 ea6b84ef -5 -11 ] = 1.5157011382153725 */
	uint32_t result = 0;
#	if NMH_VECTOR == NMH_SCALAR
	{
		union { uint32_t u32; uint16_t u16[2]; } x[4], y[4];
		uint32_t const sl = seed + (uint32_t)len;
		size_t j;
		x[0].u32 = NMH_PRIME32_1;
		x[1].u32 = NMH_PRIME32_2;
		x[2].u32 = NMH_PRIME32_3;
		x[3].u32 = NMH_PRIME32_4;
		for (j = 0; j < 4; ++j) y[j].u32 = sl;

		if (NMH_AVALANCHE_FULL == type) {
			/* 32 to 127 bytes */
			size_t const r = (len - 1) / 32;
			size_t i;
			for (i = 0; i < r; ++i) {
				for (j = 0; j < 4; ++j) x[j].u32 ^= NMH_readLE32(p + i * 32 + j * 4);
				for (j = 0; j < 4; ++j) y[j].u32 ^= NMH_readLE32(p + i * 32 + j * 4 + 16);
				for (j = 0; j < 4; ++j) x[j].u32 += y[j].u32;

				for (j = 0; j < 4; ++j) {
					x[j].u16[0] *= (uint16_t)(__NMH_M4V2 & 0xFFFF);
					x[j].u16[1] *= (uint16_t)(__NMH_M4V2 >> 16);
				}
				for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 >> 5) ^ (x[j].u32 >> 12);
				for (j = 0; j < 4; ++j) {
					x[j].u16[0] *= (uint16_t)(__NMH_M5V2 & 0xFFFF);
					x[j].u16[1] *= (uint16_t)(__NMH_M5V2 >> 16);
				}

				for (j = 0; j < 4; ++j) x[j].u32 ^= y[j].u32;

				for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 << 14) ^ (x[j].u32 >> 19);
				for (j = 0; j < 4; ++j) {
					x[j].u16[0] *= (uint16_t)(__NMH_M6V2 & 0xFFFF);
					x[j].u16[1] *= (uint16_t)(__NMH_M6V2 >> 16);
				}
				for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 >> 5) ^ (x[j].u32 >> 11);
			}
			for (j = 0; j < 4; ++j) x[j].u32 ^= NMH_readLE32(p + len - 32 + j * 4);
			for (j = 0; j < 4; ++j) y[j].u32 ^= NMH_readLE32(p + len - 16 + j * 4);
		} else {
			/* 9 to 32 bytes */
			x[0].u32 ^= NMH_readLE32(p);
			x[1].u32 ^= NMH_readLE32(p + ((len>>4)<<3));
			x[2].u32 ^= NMH_readLE32(p + len - 8);
			x[3].u32 ^= NMH_readLE32(p + len - 8 - ((len>>4)<<3));
			y[0].u32 ^= NMH_readLE32(p + 4);
			y[1].u32 ^= NMH_readLE32(p + ((len>>4)<<3) + 4);
			y[2].u32 ^= NMH_readLE32(p + len - 8 + 4);
			y[3].u32 ^= NMH_readLE32(p + len - 8 - ((len>>4)<<3) + 4);
		}

		for (j = 0; j < 4; ++j) x[j].u32 += y[j].u32;
		for (j = 0; j < 4; ++j) y[j].u32 ^= (y[j].u32 << 16) ^ (y[j].u32 >> 9);

		for (j = 0; j < 4; ++j) {
			x[j].u16[0] *= (uint16_t)(__NMH_M4V2 & 0xFFFF);
			x[j].u16[1] *= (uint16_t)(__NMH_M4V2 >> 16);
		}
		for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 >> 5) ^ (x[j].u32 >> 12);
		for (j = 0; j < 4; ++j) {
			x[j].u16[0] *= (uint16_t)(__NMH_M5V2 & 0xFFFF);
			x[j].u16[1] *= (uint16_t)(__NMH_M5V2 >> 16);
		}

		for (j = 0; j < 4; ++j) x[j].u32 ^= y[j].u32;

		for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 << 14) ^ (x[j].u32 >> 19);
		for (j = 0; j < 4; ++j) {
			x[j].u16[0] *= (uint16_t)(__NMH_M6V2 & 0xFFFF);
			x[j].u16[1] *= (uint16_t)(__NMH_M6V2 >> 16);
		}
		for (j = 0; j < 4; ++j) x[j].u32 ^= (x[j].u32 >> 5) ^ (x[j].u32 >> 11);

		x[0].u32 ^= NMH_PRIME32_1;
		x[1].u32 ^= NMH_PRIME32_2;
		x[2].u32 ^= NMH_PRIME32_3;
		x[3].u32 ^= NMH_PRIME32_4;

		for (j = 1; j < 4; ++j) x[0].u32 += x[j].u32;

		x[0].u32 ^= sl << 1;
		x[0].u16[0] *= (uint16_t)(__NMH_M6V2 & 0xFFFF);
		x[0].u16[1] *= (uint16_t)(__NMH_M6V2 >> 16);
		x[0].u32 ^= (x[0].u32 >> 5) ^ (x[0].u32 >> 10);

		result = x[0].u32;
	}
#	else /* at least NMH_SSE2 */
	{
		__m128i const h0 = _mm_setr_epi32((int)NMH_PRIME32_1, (int)NMH_PRIME32_2, (int)NMH_PRIME32_3, (int)NMH_PRIME32_4);
		__m128i const sl = _mm_set1_epi32((int)seed + (int)len);
		__m128i const m1 = _mm_set1_epi32((int)__NMH_M4V2);
		__m128i const m2 = _mm_set1_epi32((int)__NMH_M5V2);
		__m128i const m3 = _mm_set1_epi32((int)__NMH_M6V2);
		__m128i       x = h0;
		__m128i       y = sl;
		const uint32_t *const px = (const uint32_t*)&x;

		if (NMH_AVALANCHE_FULL == type) {
			/* 32 to 127 bytes */
			size_t const r = (len - 1) / 32;
			size_t i;
			for (i = 0; i < r; ++i) {
				x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)(p + i * 32)));
				y = _mm_xor_si128(y, _mm_loadu_si128((const __m128i *)(p + i * 32 + 16)));
				x = _mm_add_epi32(x, y);
				x = _mm_mullo_epi16(x, m1);
				x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 5)), _mm_srli_epi32(x, 12));
				x = _mm_mullo_epi16(x, m2);
				x = _mm_xor_si128(x, y);
				x = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x, 14)), _mm_srli_epi32(x, 19));
				x = _mm_mullo_epi16(x, m3);
				x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 5)), _mm_srli_epi32(x, 11));
			}
			x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)(p + len - 32)));
			y = _mm_xor_si128(y, _mm_loadu_si128((const __m128i *)(p + len - 16)));
		} else {
			/* 9 to 32 bytes */
			x = _mm_xor_si128(x, _mm_setr_epi32((int)NMH_readLE32(p), (int)NMH_readLE32(p + ((len>>4)<<3)), (int)NMH_readLE32(p + len - 8), (int)NMH_readLE32(p + len - 8 - ((len>>4)<<3))));
			y = _mm_xor_si128(y, _mm_setr_epi32((int)NMH_readLE32(p + 4), (int)NMH_readLE32(p + ((len>>4)<<3) + 4), (int)NMH_readLE32(p + len - 8 + 4), (int)NMH_readLE32(p + len - 8 - ((len>>4)<<3) + 4)));
		}

		x = _mm_add_epi32(x, y);

		y = _mm_xor_si128(_mm_xor_si128(y, _mm_slli_epi32(y, 16)), _mm_srli_epi32(y, 9));

		x = _mm_mullo_epi16(x, m1);
		x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 5)), _mm_srli_epi32(x, 12));
		x = _mm_mullo_epi16(x, m2);
		x = _mm_xor_si128(x, y);
		x = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x, 14)), _mm_srli_epi32(x, 19));
		x = _mm_mullo_epi16(x, m3);
		x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 5)), _mm_srli_epi32(x, 11));

		x = _mm_xor_si128(x, h0);
		x = _mm_add_epi32(x, _mm_srli_si128(x, 4));
		x = _mm_add_epi32(x, _mm_srli_si128(x, 8));

		x = _mm_xor_si128(x, _mm_slli_epi32(sl, 1));
		x = _mm_mullo_epi16(x, m3);
		x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 5)), _mm_srli_epi32(x, 10));

		result = *px;
	}
#	endif
	return *&result;
}

#undef __NMH_M4V2
#undef __NMH_M5V2
#undef __NMH_M6V2

NMH_ALIGN(NMH_ACC_ALIGN) static const uint32_t __NMH_M3_V[16] = {
	__NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
	__NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
};
NMH_ALIGN(NMH_ACC_ALIGN) static const uint32_t __NMH_M4_V[16] = {
	__NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4,
	__NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4, __NMH_M4,
};

#if NMH_VECTOR == NMH_SCALAR
#define NMHASH32_long_round NMHASH32_long_round_scalar
static inline
void
NMHASH32_long_round_scalar(uint32_t *const NMH_RESTRICT acc, const uint8_t* const NMH_RESTRICT p, const NMH_AVALANCHE type)
{
	/* breadth first calculation will hint some compiler to auto vectorize the code
	 * on gcc, the performance becomes 10x than the depth first, and about 80% of the manually vectorized code
	 */
	const size_t nbGroups = sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT);
	size_t i;

	for (i = 0; i < nbGroups; ++i) {
		acc[i] ^= NMH_readLE32(p + i * 4);
	}
	for (i = 0; i < nbGroups; ++i) {
		acc[i] ^= (acc[i] >> 8) ^ (acc[i] >> 21);
	}
	for (i = 0; i < nbGroups; ++i) {
		((uint16_t*)acc)[i] *= ((uint16_t*)__NMH_M3_V)[i];
	}
	for (i = 0; i < nbGroups; ++i) {
		((uint16_t*)acc)[nbGroups + i] *= ((uint16_t*)__NMH_M3_V)[i];
	}
	for (i = 0; i < nbGroups; ++i) {
		acc[i] ^= (acc[i] << 12) ^ (acc[i] >> 7);
	}
	for (i = 0; i < nbGroups; ++i) {
		((uint16_t*)acc)[i] *= ((uint16_t*)__NMH_M4_V)[i];
	}
	for (i = 0; i < nbGroups; ++i) {
		((uint16_t*)acc)[nbGroups + i] *= ((uint16_t*)__NMH_M4_V)[i];
	}

	if (NMH_AVALANCHE_FULL == type) {
		for (i = 0; i < nbGroups; ++i) {
			acc[i] ^= (acc[i] >> 8) ^ (acc[i] >> 21);
		}
	}
}
#endif

#define NMH_VECTOR_NB_GROUP (sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT) / (sizeof(vector_t) / sizeof(*NMH_ACC_INIT)))

#if NMH_VECTOR == NMH_SSE2
#define NMHASH32_long_round NMHASH32_long_round_sse2
static inline
void
NMHASH32_long_round_sse2(uint32_t *const NMH_RESTRICT acc, const uint8_t* const NMH_RESTRICT p, const NMH_AVALANCHE type)
{
	typedef __m128i vector_t;
	const vector_t *const NMH_RESTRICT m1   = (const vector_t *)__NMH_M3_V;
	const vector_t *const NMH_RESTRICT m2   = (const vector_t *)__NMH_M4_V;
	      vector_t *const              xacc = (      vector_t *)acc;
	      vector_t *const              xp   = (      vector_t *)p;
	      vector_t                     data[NMH_VECTOR_NB_GROUP];
	size_t i;

	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		data[i] = _mm_loadu_si128(xp + i);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm_xor_si128(xacc[i], data[i]);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm_xor_si128(_mm_xor_si128(xacc[i], _mm_srli_epi32(xacc[i], 8)), _mm_srli_epi32(xacc[i], 21));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm_mullo_epi16(xacc[i], *m1);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm_xor_si128(_mm_xor_si128(xacc[i], _mm_slli_epi32(xacc[i], 12)), _mm_srli_epi32(xacc[i], 7));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm_mullo_epi16(xacc[i], *m2);
	}

	if (NMH_AVALANCHE_FULL == type) {
		for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
			xacc[i] = _mm_xor_si128(_mm_xor_si128(xacc[i], _mm_srli_epi32(xacc[i], 8)), _mm_srli_epi32(xacc[i], 21));
		}
	}
}
#endif

#if NMH_VECTOR == NMH_AVX2
#define NMHASH32_long_round NMHASH32_long_round_avx2
static inline
void
NMHASH32_long_round_avx2(uint32_t *const NMH_RESTRICT acc, const uint8_t* const NMH_RESTRICT p, const NMH_AVALANCHE type)
{
	typedef __m256i vector_t;
	const vector_t *const NMH_RESTRICT m1   = (const vector_t * NMH_RESTRICT)__NMH_M3_V;
	const vector_t *const NMH_RESTRICT m2   = (const vector_t * NMH_RESTRICT)__NMH_M4_V;
	      vector_t *const              xacc = (      vector_t *             )acc;
	      vector_t *const              xp   = (      vector_t *             )p;
	      vector_t                     data[NMH_VECTOR_NB_GROUP];
	size_t i;

	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		data[i] = _mm256_loadu_si256(xp + i);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm256_xor_si256(xacc[i], data[i]);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm256_xor_si256(_mm256_xor_si256(xacc[i], _mm256_srli_epi32(xacc[i], 8)), _mm256_srli_epi32(xacc[i], 21));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm256_mullo_epi16(xacc[i], *m1);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm256_xor_si256(_mm256_xor_si256(xacc[i], _mm256_slli_epi32(xacc[i], 12)), _mm256_srli_epi32(xacc[i], 7));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm256_mullo_epi16(xacc[i], *m2);
	}

	if (NMH_AVALANCHE_FULL == type) {
		for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
			xacc[i] = _mm256_xor_si256(_mm256_xor_si256(xacc[i], _mm256_srli_epi32(xacc[i], 8)), _mm256_srli_epi32(xacc[i], 21));
		}
	}
}
#endif

#if NMH_VECTOR == NMH_AVX512
#define NMHASH32_long_round NMHASH32_long_round_avx512
static inline
void
NMHASH32_long_round_avx512(uint32_t *const NMH_RESTRICT acc, const uint8_t* const NMH_RESTRICT p, const NMH_AVALANCHE type)
{
	typedef __m512i vector_t;
	const vector_t *const NMH_RESTRICT m1   = (const vector_t * NMH_RESTRICT)__NMH_M3_V;
	const vector_t *const NMH_RESTRICT m2   = (const vector_t * NMH_RESTRICT)__NMH_M4_V;
	      vector_t *const              xacc = (      vector_t *             )acc;
	      vector_t *const              xp   = (      vector_t *             )p;
	      vector_t                     data[NMH_VECTOR_NB_GROUP];
	size_t i;

	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		data[i] = _mm512_loadu_si512(xp + i);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm512_xor_si512(xacc[i], data[i]);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm512_xor_si512(_mm512_xor_si512(xacc[i], _mm512_srli_epi32(xacc[i], 8)), _mm512_srli_epi32(xacc[i], 21));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm512_mullo_epi16(xacc[i], *m1);
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm512_xor_si512(_mm512_xor_si512(xacc[i], _mm512_slli_epi32(xacc[i], 12)), _mm512_srli_epi32(xacc[i], 7));
	}
	for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
		xacc[i] = _mm512_mullo_epi16(xacc[i], *m2);
	}

	if (NMH_AVALANCHE_FULL == type) {
		for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
			xacc[i] = _mm512_xor_si512(_mm512_xor_si512(xacc[i], _mm512_srli_epi32(xacc[i], 8)), _mm512_srli_epi32(xacc[i], 21));
		}
	}
}
#endif

static inline
uint32_t
NMHASH32X_avalanche32_m2(uint32_t x)
{
	/* mixer with 2 mul from skeeto/hash-prospector:
	 * [15 d168aaad 15 af723597 15] = 0.15983776156606694
	 */
	x ^= x >> 15;
	x *= UINT32_C(0xD168AAAD);
	x ^= x >> 15;
	x *= UINT32_C(0xAF723597);
	x ^= x >> 15;
	return x;
}

static inline
uint32_t
NMHASH32X_avalanche32_m3(uint32_t x, uint32_t const seed)
{
	/* [bdab1ea9 18 a7896a1b 12 83796a2d 16] = 0.092922873297662509 */
	x ^= seed;
	x *= UINT32_C(0xbdab1ea9);
	x += seed << 31 | seed >> 1;
	x ^= x >> 18;
	x *= UINT32_C(0xa7896a1b);
	x ^= x >> 12;
	x *= UINT32_C(0x83796a2d);
	x ^= x >> 16;
	return x;
}

static inline
uint32_t
NMHASH32_merge_acc(uint32_t *const NMH_RESTRICT acc, const size_t len, NMH_AVALANCHE const type)
{
#	if SIZE_MAX > UINT32_C(-1)
	uint32_t sum = (uint32_t)(len >> 32);
#	else
	uint32_t sum = 0;
#	endif
	size_t i;
	for (i = 0; i < sizeof(NMH_ACC_INIT)/sizeof(*NMH_ACC_INIT); ++i) {
		acc[i] ^= NMH_ACC_INIT[i];
	}
	for (i = 0; i < sizeof(NMH_ACC_INIT)/sizeof(*NMH_ACC_INIT); ++i) {
		sum += acc[i];
	}
	if (NMH_AVALANCHE_FULL == type) {
		/* for NMHASH32X */
		return NMHASH32X_avalanche32_m2(sum ^ (uint32_t)len);
	} else {
		/* for NMHASH32 */
		return NMHASH32_mix32(sum, (uint32_t)len, NMH_AVALANCHE_FULL);
	}
}

static
uint32_t
NMHASH32_long(const uint8_t* const NMH_RESTRICT p, size_t const len, uint32_t const seed, NMH_AVALANCHE const type)
{
	NMH_ALIGN(NMH_ACC_ALIGN) uint32_t acc[sizeof(NMH_ACC_INIT)/sizeof(*NMH_ACC_INIT)];
	size_t const nbRounds = (len - 1) / sizeof(acc);
	size_t i;

	/* init */
	for (i = 0; i < sizeof(NMH_ACC_INIT)/sizeof(*NMH_ACC_INIT); ++i) {
		acc[i] = NMH_ACC_INIT[i] + seed;
	}

	for (i = 0; i < nbRounds; ++i) {
		NMHASH32_long_round(acc, p + i * sizeof(acc), NMH_AVALANCHE_INNER);
	}
	NMHASH32_long_round(acc, p + len - sizeof(acc), NMH_AVALANCHE_FULL);

	return NMHASH32_merge_acc(acc, len, type);
}

#undef __NMH_M3
#undef __NMH_M4
#undef NMH_VECTOR_NB_GROUP

static inline
uint32_t
NMHASH32(const void* const NMH_RESTRICT input, size_t const len, uint32_t seed)
{
	const uint8_t *const p = (const uint8_t *)input;
	if (NMH_likely(len <= 32)) {
		if(NMH_likely(len > 8)) {
			return NMHASH32_9to127(p, len, seed, NMH_AVALANCHE_INNER);
		}
		if(NMH_likely(len > 4)) {
			uint32_t x = NMH_readLE32(p);
			uint32_t y = NMH_readLE32(p + len - 4) ^ (NMH_PRIME32_4 + 2 + seed);
			x += y;
			x ^= x << (len + 7);
			return NMHASH32_0to8(x, NMH_rotl32(y, 5));
		} else {
			union { uint32_t u32; uint16_t u16[2]; uint8_t u8[4]; } data;
			switch (len) {
				case 0: seed += NMH_PRIME32_2;
					data.u32 = 0;
					break;
				case 1: seed += NMH_PRIME32_2 + (UINT32_C(1) << 24) + (1 << 1);
					data.u32 = p[0];
					break;
				case 2: seed += NMH_PRIME32_2 + (UINT32_C(2) << 24) + (2 << 1);
					data.u32 = NMH_readLE16(p);
					break;
				case 3: seed += NMH_PRIME32_2 + (UINT32_C(3) << 24) + (3 << 1);
					data.u16[1] = p[2];
					data.u16[0] = NMH_readLE16(p);
					break;
				case 4: seed += NMH_PRIME32_3;
					data.u32 = NMH_readLE32(p);
					break;
				default: return 0;
			}
			return NMHASH32_0to8(data.u32 + seed, NMH_rotl32(seed, 5));
		}
	}
	if (NMH_likely(len < 128)) {
		return NMHASH32_9to127(p, len, seed, NMH_AVALANCHE_FULL);
	}
	return NMHASH32_long(p, len, seed, NMH_AVALANCHE_INNER);
}

static inline
uint32_t
NMHASH32X_5to8(const uint8_t* const NMH_RESTRICT p, size_t const len, uint32_t const seed)
{
	/* - 5 to 9 bytes
	 * - mixer: [11049a7d 23 bcccdc7b 12 065e9dad 12] = 0.16577596555667246 */

	uint32_t       x = NMH_readLE32(p);
	uint32_t const y = NMH_readLE32(p + len - 4) ^ (NMH_PRIME32_4 + 2 + seed);
	x += y;
	x ^= x >> len;
	x *= 0x11049a7d;
	x ^= x >> 23;
	x *= 0xbcccdc7b;
	x ^= NMH_rotl32(y, 3);
	x ^= x >> 12;
	x *= 0x065e9dad;
	x ^= x >> 12;
	return x;
}

static inline
uint32_t
NMHASH32X_9to127(const uint8_t* const NMH_RESTRICT p, size_t const len, uint32_t const seed)
{
	/* - at least 9 bytes
	 * - base mixer: [11049a7d 23 bcccdc7b 12 065e9dad 12] = 0.16577596555667246
	 * - tail mixer: [16 a52fb2cd 15 551e4d49 16] = 0.17162579707098322
	 */

	uint32_t x = NMH_PRIME32_3;
	uint32_t y = seed;
	uint32_t a = NMH_PRIME32_2;
	uint32_t b = (uint16_t)seed;
	size_t i, r = (len - 1) / 16;

	for (i = 0; i < r; ++i) {
		x ^= NMH_readLE32(p + i * 16 + 0);
		y ^= NMH_readLE32(p + i * 16 + 4);
		x ^= y;
		x *= UINT32_C(0x11049a7d);
		x ^= x >> 23;
		x *= UINT32_C(0xbcccdc7b);
		y  = NMH_rotl32(y, 1);
		x ^= y;
		x ^= x >> 12;
		x *= UINT32_C(0x065e9dad);
		x ^= x >> 12;

		a ^= NMH_readLE32(p + i * 16 + 8);
		b ^= NMH_readLE32(p + i * 16 + 12);
		a ^= b;
		a *= UINT32_C(0x11049a7d);
		a ^= a >> 23;
		a *= UINT32_C(0xbcccdc7b);
		b  = NMH_rotl32(b, 1);
		a ^= b;
		a ^= a >> 12;
		a *= UINT32_C(0x065e9dad);
		a ^= a >> 12;
	}

	if (NMH_likely(((uint8_t)len-1) & 8)) {
		if (NMH_likely(((uint8_t)len-1) & 4)) {
			a ^= NMH_readLE32(p + r * 16 + 0);
			b ^= NMH_readLE32(p + r * 16 + 4);
			a ^= b;
			a *= UINT32_C(0x11049a7d);
			a ^= a >> 23;
			a *= UINT32_C(0xbcccdc7b);
			a ^= NMH_rotl32(b, 1);
			a ^= a >> 12;
			a *= UINT32_C(0x065e9dad);
		} else {
			a ^= NMH_readLE32(p + r * 16) + b;
			a ^= a >> 16;
			a *= UINT32_C(0xA52FB2CD);
			a ^= a >> 15;
			a *= UINT32_C(0x551E4D49);
		}

		x ^= NMH_readLE32(p + len - 8);
		y ^= NMH_readLE32(p + len - 4);
		x ^= y;
		x *= UINT32_C(0x11049a7d);
		x ^= x >> 23;
		x *= UINT32_C(0xbcccdc7b);
		x ^= NMH_rotl32(y, 1);
		x ^= x >> 12;
		x *= UINT32_C(0x065e9dad);
	} else {
		if (NMH_likely(((uint8_t)len-1) & 4)) {
			a ^= NMH_readLE32(p + r * 16) + b;
			a ^= a >> 16;
			a *= UINT32_C(0xA52FB2CD);
			a ^= a >> 15;
			a *= UINT32_C(0x551E4D49);
		}
		x ^= NMH_readLE32(p + len - 4) + y;
		x ^= x >> 16;
		x *= UINT32_C(0xA52FB2CD);
		x ^= x >> 15;
		x *= UINT32_C(0x551E4D49);
	}

	x ^= (uint32_t)len;
	x ^= NMH_rotl32(a, 3); /* rotate one lane to pass Diff test */
	x ^= x >> 14;
	x *= UINT32_C(0x141CC535);

	return x;
}

/* use 32*32->32 multiplication for short hash */
static inline
uint32_t
NMHASH32X(const void* const NMH_RESTRICT input, size_t const len, uint32_t seed)
{
	const uint8_t *const p = (const uint8_t *)input;
	if (NMH_likely(len <= 8)) {
		if (NMH_likely(len > 4)) {
			return NMHASH32X_5to8(p, len, seed);
		} else {
			/* 0-4 bytes */
			union { uint32_t u32; uint16_t u16[2]; uint8_t u8[4]; } data;
			switch (len) {
				case 0: seed += NMH_PRIME32_2;
					data.u32 = 0;
					break;
				case 1: seed += NMH_PRIME32_2 + (UINT32_C(1) << 24) + (1 << 1);
					data.u32 = p[0];
					break;
				case 2: seed += NMH_PRIME32_2 + (UINT32_C(2) << 24) + (2 << 1);
					data.u32 = NMH_readLE16(p);
					break;
				case 3: seed += NMH_PRIME32_2 + (UINT32_C(3) << 24) + (3 << 1);
					data.u16[1] = p[2];
					data.u16[0] = NMH_readLE16(p);
					break;
				case 4: seed += NMH_PRIME32_1;
					data.u32 = NMH_readLE32(p);
					break;
				default: return 0;
			}
			return NMHASH32X_avalanche32_m3(data.u32, seed);
		}
	}
	if (NMH_likely(len < 128)) {
		return NMHASH32X_9to127(p, len, seed);
	}
	return NMHASH32_long(p, len, seed, NMH_AVALANCHE_FULL);
}

#if defined(_MSC_VER) && _MSC_VER >= 1914
#  pragma warning(pop)
#endif
#ifdef __SDCC
#  pragma restore
#  undef const
#endif

#endif /* _nmhash_h_ */

#ifdef __cplusplus
}
#endif
