/*
 *  802.11 WEP / WPA-PSK Key Cracker
 *
 *  Cell Broadband Engine Support
 *  Copyright (c) 2008 Michael Buesch <mb@bu3sch.de>
 *
 *  PMK calculation derived from Christophe Devine's implementation
 *  Copyright (C) 2001-2004  Christophe Devine
 *
 *  SHA1 code derived from libgcrypt
 *  Copyright (C) 1998, 2001, 2002, 2003, 2008 Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  HMAC code derived from LUKS cryptsetup
 *  Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.
 *
 *  HMAC -- LICENSE TERMS -- START
 *
 *  The free distribution and use of this software in both source and binary
 *  form is allowed (with or without changes) provided that:
 *
 *  1. distributions of this source code include the above copyright
 *     notice, this list of conditions and the following disclaimer;
 *
 *  2. distributions in binary form include the above copyright
 *     notice, this list of conditions and the following disclaimer
 *     in the documentation and/or other associated materials;
 *
 *  3. the copyright holder's name is not used to endorse products
 *     built using this software without specific written permission.
 *
 *  ALTERNATIVELY, provided that this notice is retained in full, this product
 *  may be distributed under the terms of the GNU General Public License (GPL),
 *  in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 *  DISCLAIMER
 *
 *  This software is provided 'as is' with no explicit or implied warranties
 *  in respect of its properties, including, but not limited to, correctness
 *  and/or fitness for purpose.
 *
 *  HMAC -- LICENSE TERMS -- END
 */

#include "aircrack-ng-wpa-spe.h"

#include <spu_mfcio.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>


#define ALIGN			__attribute__((aligned(16)))

#ifndef WORDS_BIGENDIAN
# define WORDS_BIGENDIAN	1 /* Cell is BigEndian */
#endif

static __vector uint32_t zero_vect = (__vector uint32_t) { 0, 0, 0, 0, };


typedef struct {
	/* The SIMD code depends on the struct layout!
	 * Don't add variables inbetween. */
	uint32_t	h0 ALIGN;
	uint32_t	h1;
	uint32_t	h2;
	uint32_t	h3;
	uint32_t	h4;
	uint32_t	nblocks;
	uint32_t	count;
	uint32_t	__padding;
	unsigned char	buf[64] ALIGN;
} SHA1_CONTEXT;

#define HASH_INPUT_SIZE		64 /* SHA1 block size */
#define HASH_OUTPUT_SIZE	20 /* SHA1 digest size */
typedef struct {
	unsigned char	key[HASH_INPUT_SIZE] ALIGN;
	SHA1_CONTEXT	ctx[1];
	unsigned long	klen;
} hmac_ctx;
#define HMAC_OK                0
#define HMAC_BAD_MODE         -1
#define HMAC_IN_DATA  0xffffffff



static void sha1_init(SHA1_CONTEXT *hd)
{
	hd->h0 = 0x67452301;
	hd->h1 = 0xefcdab89;
	hd->h2 = 0x98badcfe;
	hd->h3 = 0x10325476;
	hd->h4 = 0xc3d2e1f0;
	hd->nblocks = 0;
	hd->count = 0;
}

static inline void sha1_context_clone(SHA1_CONTEXT *dest, const SHA1_CONTEXT *src)
{
	__vector uint32_t *a, *b;

	/* This depends on the struct layout! */

	/* Copy the first 16 bytes. */
	a = (__vector uint32_t *)(&dest->h0);
	b = (__vector uint32_t *)(&src->h0);
	*a = spu_or(*b, zero_vect);
	/* Copy the next 16 bytes. */
	a = (__vector uint32_t *)(&dest->h4);
	b = (__vector uint32_t *)(&src->h4);
	*a = spu_or(*b, zero_vect);
	/* And finally the buffer, if needed. */
	if (src->count)
		memcpy(dest->buf, src->buf, src->count);
}

#define rol32(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )

/* SHA-1 round function macros. */
#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )
#define M(i) ( tm =    x[ i    &0x0f]  \
                     ^ x[(i-14)&0x0f]  \
	 	     ^ x[(i-8) &0x0f]  \
                     ^ x[(i-3) &0x0f], \
                     (x[i&0x0f] = rol32(tm, 1)))
#define R(a,b,c,d,e,f,k,m)  do { e += rol32( a, 5 )   \
	                              + f( b, c, d )  \
		 		      + k	      \
			 	      + m;	      \
				 b = rol32( b, 30 );  \
			       } while(0)

/* Transform NBLOCKS of each 64 bytes (16 32-bit words) at DATA. */
static void sha1_transform(SHA1_CONTEXT *hd, const unsigned char *data, size_t nblocks)
{
	uint32_t a, b, c, d, e; /* Local copies of the chaining variables.  */
	uint32_t tm;            /* Helper.  */
	uint32_t x[16];                  /* The array we work on. */

	/* Loop over all blocks.  */
	for ( ;nblocks; nblocks--) {
#ifdef WORDS_BIGENDIAN
		memcpy (x, data, 64);
		data += 64;
#else
		{
			int i;
			unsigned char *p;

			for(i=0, p=(unsigned char*)x; i < 16; i++, p += 4 ) {
				p[3] = *data++;
				p[2] = *data++;
				p[1] = *data++;
				p[0] = *data++;
			}
		}
#endif
		/* Get the values of the chaining variables. */
		a = hd->h0;
		b = hd->h1;
		c = hd->h2;
		d = hd->h3;
		e = hd->h4;

		/* Transform. */
		R( a, b, c, d, e, F1, K1, x[ 0] );
		R( e, a, b, c, d, F1, K1, x[ 1] );
		R( d, e, a, b, c, F1, K1, x[ 2] );
		R( c, d, e, a, b, F1, K1, x[ 3] );
		R( b, c, d, e, a, F1, K1, x[ 4] );
		R( a, b, c, d, e, F1, K1, x[ 5] );
		R( e, a, b, c, d, F1, K1, x[ 6] );
		R( d, e, a, b, c, F1, K1, x[ 7] );
		R( c, d, e, a, b, F1, K1, x[ 8] );
		R( b, c, d, e, a, F1, K1, x[ 9] );
		R( a, b, c, d, e, F1, K1, x[10] );
		R( e, a, b, c, d, F1, K1, x[11] );
		R( d, e, a, b, c, F1, K1, x[12] );
		R( c, d, e, a, b, F1, K1, x[13] );
		R( b, c, d, e, a, F1, K1, x[14] );
		R( a, b, c, d, e, F1, K1, x[15] );
		R( e, a, b, c, d, F1, K1, M(16) );
		R( d, e, a, b, c, F1, K1, M(17) );
		R( c, d, e, a, b, F1, K1, M(18) );
		R( b, c, d, e, a, F1, K1, M(19) );
		R( a, b, c, d, e, F2, K2, M(20) );
		R( e, a, b, c, d, F2, K2, M(21) );
		R( d, e, a, b, c, F2, K2, M(22) );
		R( c, d, e, a, b, F2, K2, M(23) );
		R( b, c, d, e, a, F2, K2, M(24) );
		R( a, b, c, d, e, F2, K2, M(25) );
		R( e, a, b, c, d, F2, K2, M(26) );
		R( d, e, a, b, c, F2, K2, M(27) );
		R( c, d, e, a, b, F2, K2, M(28) );
		R( b, c, d, e, a, F2, K2, M(29) );
		R( a, b, c, d, e, F2, K2, M(30) );
		R( e, a, b, c, d, F2, K2, M(31) );
		R( d, e, a, b, c, F2, K2, M(32) );
		R( c, d, e, a, b, F2, K2, M(33) );
		R( b, c, d, e, a, F2, K2, M(34) );
		R( a, b, c, d, e, F2, K2, M(35) );
		R( e, a, b, c, d, F2, K2, M(36) );
		R( d, e, a, b, c, F2, K2, M(37) );
		R( c, d, e, a, b, F2, K2, M(38) );
		R( b, c, d, e, a, F2, K2, M(39) );
		R( a, b, c, d, e, F3, K3, M(40) );
		R( e, a, b, c, d, F3, K3, M(41) );
		R( d, e, a, b, c, F3, K3, M(42) );
		R( c, d, e, a, b, F3, K3, M(43) );
		R( b, c, d, e, a, F3, K3, M(44) );
		R( a, b, c, d, e, F3, K3, M(45) );
		R( e, a, b, c, d, F3, K3, M(46) );
		R( d, e, a, b, c, F3, K3, M(47) );
		R( c, d, e, a, b, F3, K3, M(48) );
		R( b, c, d, e, a, F3, K3, M(49) );
		R( a, b, c, d, e, F3, K3, M(50) );
		R( e, a, b, c, d, F3, K3, M(51) );
		R( d, e, a, b, c, F3, K3, M(52) );
		R( c, d, e, a, b, F3, K3, M(53) );
		R( b, c, d, e, a, F3, K3, M(54) );
		R( a, b, c, d, e, F3, K3, M(55) );
		R( e, a, b, c, d, F3, K3, M(56) );
		R( d, e, a, b, c, F3, K3, M(57) );
		R( c, d, e, a, b, F3, K3, M(58) );
		R( b, c, d, e, a, F3, K3, M(59) );
		R( a, b, c, d, e, F4, K4, M(60) );
		R( e, a, b, c, d, F4, K4, M(61) );
		R( d, e, a, b, c, F4, K4, M(62) );
		R( c, d, e, a, b, F4, K4, M(63) );
		R( b, c, d, e, a, F4, K4, M(64) );
		R( a, b, c, d, e, F4, K4, M(65) );
		R( e, a, b, c, d, F4, K4, M(66) );
		R( d, e, a, b, c, F4, K4, M(67) );
		R( c, d, e, a, b, F4, K4, M(68) );
		R( b, c, d, e, a, F4, K4, M(69) );
		R( a, b, c, d, e, F4, K4, M(70) );
		R( e, a, b, c, d, F4, K4, M(71) );
		R( d, e, a, b, c, F4, K4, M(72) );
		R( c, d, e, a, b, F4, K4, M(73) );
		R( b, c, d, e, a, F4, K4, M(74) );
		R( a, b, c, d, e, F4, K4, M(75) );
		R( e, a, b, c, d, F4, K4, M(76) );
		R( d, e, a, b, c, F4, K4, M(77) );
		R( c, d, e, a, b, F4, K4, M(78) );
		R( b, c, d, e, a, F4, K4, M(79) );

		/* Update the chaining variables. */
		hd->h0 += a;
		hd->h1 += b;
		hd->h2 += c;
		hd->h3 += d;
		hd->h4 += e;
	}
}

static inline void sha1_may_flush_buffer(SHA1_CONTEXT *hd)
{
	if (hd->count == 64) { /* Flush the buffer. */
		sha1_transform( hd, hd->buf, 1 );
		hd->count = 0;
		hd->nblocks++;
	}
}

/* Update the message digest with the contents
 * of INBUF with length INLEN. */
static void sha1_write(SHA1_CONTEXT *hd, const void *inbuf_arg, size_t inlen)
{
	const unsigned char *inbuf = inbuf_arg;
	size_t nblocks;

	sha1_may_flush_buffer(hd);

	if (hd->count) {
		for (; inlen && hd->count < 64; inlen--)
			hd->buf[hd->count++] = *inbuf++;
		sha1_may_flush_buffer(hd);
		if (!inlen)
			return;
	}

	nblocks = inlen / 64;
	if (nblocks) {
		sha1_transform (hd, inbuf, nblocks);
		hd->count = 0;
		hd->nblocks += nblocks;
		inlen -= nblocks * 64;
		inbuf += nblocks * 64;
	}

	/* Save remaining bytes.  */
	for (; inlen && hd->count < 64; inlen--)
		hd->buf[hd->count++] = *inbuf++;
}

/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest. */
static void sha1_final(SHA1_CONTEXT *hd)
{
	uint32_t t, msb, lsb;

	sha1_may_flush_buffer(hd);

	t = hd->nblocks;
	/* multiply by 64 to make a byte count */
	lsb = t << 6;
	msb = t >> 26;
	/* add the count */
	t = lsb;
	if( (lsb += hd->count) < t )
		msb++;
	/* multiply by 8 to make a bit count */
	t = lsb;
	lsb <<= 3;
	msb <<= 3;
	msb |= t >> 29;

	if( hd->count < 56 ) { /* enough room */
		hd->buf[hd->count++] = 0x80; /* pad */
		while( hd->count < 56 )
			hd->buf[hd->count++] = 0;  /* pad */
	} else { /* need one extra block */
		hd->buf[hd->count++] = 0x80; /* pad character */
		while( hd->count < 64 )
			hd->buf[hd->count++] = 0;
		sha1_may_flush_buffer(hd);
		memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
	}
	/* append the 64 bit count */
#ifdef WORDS_BIGENDIAN
	*(uint32_t *)(hd->buf + 56) = msb;
	*(uint32_t *)(hd->buf + 60) = lsb;
#else /* little endian */
	hd->buf[56] = msb >> 24;
	hd->buf[57] = msb >> 16;
	hd->buf[58] = msb >>  8;
	hd->buf[59] = msb;
	hd->buf[60] = lsb >> 24;
	hd->buf[61] = lsb >> 16;
	hd->buf[62] = lsb >>  8;
	hd->buf[63] = lsb;
#endif
	sha1_transform( hd, hd->buf, 1 );

#if 0 /* SIMD optimized version below */
	unsigned char *p;
	p = hd->buf;
	#ifdef WORDS_BIGENDIAN
	#define X(a) do { *(uint32_t*)p = hd->h##a ; p += 4; } while(0)
	#else /* little endian */
	#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
	                  *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
	#endif
	X(0);
	X(1);
	X(2);
	X(3);
	X(4);
	#undef X
#endif
	{
		__vector uint32_t *a, *b;

		a = (__vector uint32_t *)(hd->buf);
		b = (__vector uint32_t *)(&hd->h0);
		*a = spu_or(*b, zero_vect); /* Copy h0-h3 */
		*(uint32_t *)(hd->buf + 16) = hd->h4; /* Copy h4 */
	}
}

static inline unsigned char * sha1_read(SHA1_CONTEXT *hd)
{
	return hd->buf;
}

static __vector uint32_t hmac_ipad = (__vector uint32_t) {
	0x36363636, 0x36363636, 0x36363636, 0x36363636, };
static __vector uint32_t hmac_opad = (__vector uint32_t) {
	0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, };

/* initialise the HMAC context to zero */
static void hmac_sha_begin(hmac_ctx cx[1])
{
	memset(cx->ctx, 0, sizeof(cx->ctx));
	cx->klen = 0;
}

/* input the HMAC key (can be called multiple times)    */
static int hmac_sha_key(const unsigned char key[], size_t key_len, hmac_ctx cx[1])
{
	if(cx->klen == HMAC_IN_DATA)                /* error if further key input   */
		return HMAC_BAD_MODE;               /* is attempted in data mode    */

	if(cx->klen + key_len > HASH_INPUT_SIZE) {  /* if the key has to be hashed  */
		if(cx->klen <= HASH_INPUT_SIZE) {
			/* if the hash has not yet been
			 * started, initialise it and
			 * hash stored key characters. */
			sha1_init(cx->ctx);
			sha1_write(cx->ctx, cx->key, cx->klen);
		}
		sha1_write(cx->ctx, key, key_len);  /* hash long key data into hash */
	} else                                      /* otherwise store key data     */
		memcpy(cx->key + cx->klen, key, key_len);

	cx->klen += key_len;                        /* update the key length count  */
	return HMAC_OK;
}

/* input the HMAC data (can be called multiple times) - */
/* note that this call terminates the key input phase   */
static void hmac_sha_data(const unsigned char data[], size_t data_len, hmac_ctx cx[1])
{
	unsigned int i;

	if(cx->klen != HMAC_IN_DATA) {                /* if not yet in data phase */
		if(cx->klen > HASH_INPUT_SIZE) {
			/* if key is being hashed
			 * complete the hash and
			 * store the result as the
			 * key and set new length. */
			sha1_final(cx->ctx);
			memcpy(cx->key, sha1_read(cx->ctx), 20);
			cx->klen = HASH_OUTPUT_SIZE;
		}

		/* pad the key if necessary */
		memset(cx->key + cx->klen, 0, HASH_INPUT_SIZE - cx->klen);

		/* xor ipad into key value  */
		/* SIMD optimized version below
		for(i = 0; i < (HASH_INPUT_SIZE >> 2); ++i)
			((uint32_t*)cx->key)[i] ^= 0x36363636;
		*/
		{
			__vector uint32_t *key = (__vector uint32_t *)(cx->key);

			for (i = 0; i < (HASH_INPUT_SIZE / 16); ++i)
				key[i] = spu_xor(key[i], hmac_ipad);
		}

		/* and start hash operation */
		sha1_init(cx->ctx);
		sha1_write(cx->ctx, cx->key, HASH_INPUT_SIZE);

		/* mark as now in data mode */
		cx->klen = HMAC_IN_DATA;
	}

	/* hash the data (if any)       */
//	if(data_len)
		sha1_write(cx->ctx, data, data_len);
}

/* compute and output the MAC value */
static void hmac_sha_end(unsigned char mac[], size_t mac_len, hmac_ctx cx[1])
{
	unsigned char dig[HASH_OUTPUT_SIZE];
	unsigned int i;

	/* if no data has been entered perform a null data phase */
/*
	if(cx->klen != HMAC_IN_DATA)
		hmac_sha_data((const unsigned char*)0, 0, cx);
*/

	/* complete the inner hash */
	sha1_final(cx->ctx);
	memcpy(dig, sha1_read(cx->ctx), HASH_OUTPUT_SIZE);

	/* set outer key value using opad and removing ipad */
	/* SIMD optimized version below
	for(i = 0; i < (HASH_INPUT_SIZE >> 2); ++i)
		((uint32_t*)cx->key)[i] ^= 0x36363636 ^ 0x5c5c5c5c;
	*/
	{
		__vector uint32_t *key = (__vector uint32_t *)(cx->key);

		for (i = 0; i < (HASH_INPUT_SIZE / 16); ++i) {
			key[i] = spu_xor(key[i], hmac_ipad);
			key[i] = spu_xor(key[i], hmac_opad);
		}
	}

	/* perform the outer hash operation */
	sha1_init(cx->ctx);
	sha1_write(cx->ctx, cx->key, HASH_INPUT_SIZE);
	sha1_write(cx->ctx, dig, HASH_OUTPUT_SIZE);
	sha1_final(cx->ctx);
	/* output the hash value */
	memcpy(mac, sha1_read(cx->ctx), mac_len);
}

/* 'do it all in one go' subroutine     */
static void hmac_sha(const unsigned char key[], size_t key_len,
		     const unsigned char data[], size_t data_len,
		     unsigned char mac[], size_t mac_len)
{
	hmac_ctx cx[1];

	hmac_sha_begin(cx);
	hmac_sha_key(key, key_len, cx);
	hmac_sha_data(data, data_len, cx);
	hmac_sha_end(mac, mac_len, cx);
}

static void cell_calc_pmk(char *essid, uint8_t essid_size,
			  const char *key, unsigned char *pmk)
{
	int i;
	unsigned int slen, klen;
	unsigned char buffer[65] ALIGN;
	SHA1_CONTEXT ctx_ipad;
	SHA1_CONTEXT ctx_opad;
	SHA1_CONTEXT sha1_ctx;

	slen = essid_size + 4;
	klen = strlen(key);

	/* setup the inner and outer contexts */

	memset( buffer, 0, sizeof( buffer ) );
	strncpy( (char *) buffer, key, sizeof( buffer ) - 1 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x36;

	sha1_init( &ctx_ipad );
	sha1_write( &ctx_ipad, buffer, 64 );

	for( i = 0; i < 64; i++ )
		buffer[i] ^= 0x6A;

	sha1_init( &ctx_opad );
	sha1_write( &ctx_opad, buffer, 64 );

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	hmac_sha((unsigned char *)key, klen,
		 (unsigned char *)essid, slen,
		 pmk, 20);
	memcpy( buffer, pmk, 20 );

	for( i = 1; i < 4096; i++ )
	{
		sha1_context_clone(&sha1_ctx, &ctx_ipad);
		sha1_write( &sha1_ctx, buffer, 20 );
		sha1_final(&sha1_ctx);
		memcpy(buffer, sha1_read(&sha1_ctx), 20);

		sha1_context_clone(&sha1_ctx, &ctx_opad);
		sha1_write( &sha1_ctx, buffer, 20 );
		sha1_final(&sha1_ctx);
		memcpy(buffer, sha1_read(&sha1_ctx), 20);

		/* Optimized version below
		for( j = 0; j < 20; j++ )
			pmk[j] ^= buffer[j];
		*/
		{
			uint32_t *_pmk = (uint32_t *)(pmk + sizeof(uint32_t) * 4);
			uint32_t *_buf = (uint32_t *)(buffer + sizeof(uint32_t) * 4);

			*(__vector uint32_t *)pmk = spu_xor(*(__vector uint32_t *)pmk,
							    *(__vector uint32_t *)buffer);
			*_pmk ^= *_buf;
		}
	}

	essid[slen - 1] = '\2';
	hmac_sha((unsigned char *)key, klen,
		 (unsigned char *)essid, slen,
		 pmk + 20, 20);
	memcpy( buffer, pmk + 20, 20 );

	for( i = 1; i < 4096; i++ )
	{
		sha1_context_clone(&sha1_ctx, &ctx_ipad);
		sha1_write( &sha1_ctx, buffer, 20 );
		sha1_final(&sha1_ctx);
		memcpy(buffer, sha1_read(&sha1_ctx), 20);

		sha1_context_clone(&sha1_ctx, &ctx_opad);
		sha1_write( &sha1_ctx, buffer, 20 );
		sha1_final(&sha1_ctx);
		memcpy(buffer, sha1_read(&sha1_ctx), 20);

		/* Optimized version below
		for( j = 0; j < 20; j++ )
			pmk[j + 20] ^= buffer[j];
		*/
		{
			/* Cannot use SIMD, because pmk+20 is not 16-aligned */
			*(uint32_t *)(pmk + 20 + 0)  ^= *(uint32_t *)(buffer + 0);
			*(uint32_t *)(pmk + 20 + 4)  ^= *(uint32_t *)(buffer + 4);
			*(uint32_t *)(pmk + 20 + 8)  ^= *(uint32_t *)(buffer + 8);
			*(uint32_t *)(pmk + 20 + 12) ^= *(uint32_t *)(buffer + 12);
			*(uint32_t *)(pmk + 20 + 16) ^= *(uint32_t *)(buffer + 16);
		}
	}
}

int main(unsigned long long spe, unsigned long long argp, unsigned long long envp)
{
	unsigned int i, tag;

	static struct cell_spe_wpa_params params ALIGN;
	static char keys[1][128] ALIGN;
	static unsigned char pmks[1][128] ALIGN;
	static char essid[36 + 12] ALIGN;

	/* Fetch the parameter table via DMA */
	tag = 1;
	spu_mfcdma64(&params, mfc_ea2h(argp), mfc_ea2l(argp),
		     sizeof(params), tag, MFC_GET_CMD);
	spu_writech(MFC_WrTagMask, 1 << tag);
	spu_mfcstat(MFC_TAG_UPDATE_ALL);

	/* Fetch the essid via DMA */
	tag = 1;
	spu_mfcdma64(essid, mfc_ea2h(params.essid), mfc_ea2l(params.essid),
		     sizeof(essid), tag, MFC_GET_CMD);
	spu_writech(MFC_WrTagMask, 1 << tag);
	spu_mfcstat(MFC_TAG_UPDATE_ALL);

	/* Fetch the keys via DMA */
	for (i = 0; i < 1; i++) {
		tag = 1;
		spu_mfcdma64(keys[i], mfc_ea2h(params.keys[i]), mfc_ea2l(params.keys[i]),
			     sizeof(keys[i]), tag, MFC_GET_CMD);
		spu_writech(MFC_WrTagMask, 1 << tag);
		spu_mfcstat(MFC_TAG_UPDATE_ALL);
	}

	/* Calculate the PMKs */
	cell_calc_pmk(essid, params.essid_size, keys[0], pmks[0]);
//	cell_calc_pmk(essid, params.essid_size, keys[1], pmks[1]);

	/* Push the PMKs via DMA */
	for (i = 0; i < 1; i++) {
		tag = 1;
		spu_mfcdma64(pmks[i], mfc_ea2h(params.pmks[i]), mfc_ea2l(params.pmks[i]),
			     sizeof(pmks[i]), tag, MFC_PUT_CMD);
		spu_writech(MFC_WrTagMask, 1 << tag);
		spu_mfcstat(MFC_TAG_UPDATE_ALL);
	}

	return 0;
}