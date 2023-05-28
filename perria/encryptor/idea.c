/*
 *	idea.c - C source code for IDEA block cipher.
 *	IDEA (International Data Encryption Algorithm), formerly known as 
 *	IPES (Improved Proposed Encryption Standard).
 *	Algorithm developed by Xuejia Lai and James L. Massey, of ETH Zurich.
 *	This implementation modified and derived from original C code 
 *	developed by Xuejia Lai.  
 *	Zero-based indexing added, names changed from IPES to IDEA.
 *	CFB functions added.  Random number routines added.
 *
 *	Extensively optimized and restructured by Colin Plumb.
 *
 *	There are two adjustments that can be made to this code to
 *	speed it up.  Defaults may be used for PCs.  Only the -DIDEA32
 *	pays off significantly if selectively set or not set.
 *	Experiment to see what works best for your machine.
 *
 *	Multiplication: default is inline, -DAVOID_JUMPS uses a
 *		different version that does not do any conditional
 *		jumps (a few percent worse on a SPARC), while
 *		-DSMALL_CACHE takes it out of line to stay
 *		within a small on-chip code cache.
 *	Variables: normally, 16-bit variables are used, but some
 *		machines (notably RISCs) do not have 16-bit registers,
 *		so they do a great deal of masking.  -DIDEA32 uses "int"
 *		register variables and masks explicitly only where
 *		necessary.  On a SPARC, for example, this boosts
 *		performace by 30%.
 *
 *	The IDEA(tm) block cipher is covered by patents held by ETH and a
 *	Swiss company called Ascom-Tech AG.  The Swiss patent number is
 *	PCT/CH91/00117, the European patent number is EP 0 482 154 B1, and
 *	the U.S. patent number is US005214703.  IDEA(tm) is a trademark of
 *	Ascom-Tech AG.  There is no license fee required for noncommercial
 *	use.  Commercial users may obtain licensing details from Dieter
 *	Profos, Ascom Tech AG, Solothurn Lab, Postfach 151, 4502 Solothurn,
 *	Switzerland, Tel +41 65 242885, Fax +41 65 235761.
 *
 *	The IDEA block cipher uses a 64-bit block size, and a 128-bit key 
 *	size.  It breaks the 64-bit cipher block into four 16-bit words
 *	because all of the primitive inner operations are done with 16-bit 
 *	arithmetic.  It likewise breaks the 128-bit cipher key into eight 
 *	16-bit words.
 *
 *	For further information on the IDEA cipher, see the book:
 *	  Xuejia Lai, "On the Design and Security of Block Ciphers",
 *	  ETH Series on Information Processing (ed. J.L. Massey) Vol 1,
 *	  Hartung-Gorre Verlag, Konstanz, Switzerland, 1992.  ISBN
 *	  3-89191-573-X.
 *
 *	This code runs on arrays of bytes by taking pairs in big-endian
 *	order to make the 16-bit words that IDEA uses internally.  This
 *	produces the same result regardless of the byte order of the
 *	native CPU.
 */

#include <string.h>
#ifdef _MSC_VER
  #include "idea.h"
#else
  #include "idea.h"
#endif /* _MSC_VER */


#ifdef IDEA32	/* Use >16-bit temporaries */
#define low16(x) ((x) & 0xFFFF)
typedef unsigned int uint16;	/* at LEAST 16 bits, maybe more */
#else
#define low16(x) (x)	/* this is only ever applied to uint16's */
typedef word16 uint16;
#endif

#ifdef _GNUC_
/* __const__ simply means there are no side effects for this function,
 * which is useful info for the gcc optimizer
 */
#define CONST __const__
#else
#define CONST
#endif

/*
 *	Multiplication, modulo (2**16)+1
 * Note that this code is structured on the assumption that
 * untaken branches are cheaper than taken branches, and the
 * compiler doesn't schedule branches.
 */
#ifdef SMALL_CACHE
CONST static uint16
mul(register uint16 a, register uint16 b)
{
	register word32 p;

	p = (word32)a * b;
	if (p) {
		b = low16(p);
		a = p>>16;
		return (b - a) + (b < a);
	} else if (a) {
		return 1-b;
	} else {
		return 1-a;
	}
} /* mul */
#endif /* SMALL_CACHE */

/*
 * Compute the multiplicative inverse of x, modulo 65537, using Euclid's
 * algorithm. It is unrolled twice to avoid swapping the registers each
 * iteration, and some subtracts of t have been changed to adds.
 */
CONST static uint16
mulInv(uint16 x)     
{
	uint16 t0, t1;
	uint16 q, y;

	if (x <= 1)
		return x;	/* 0 and 1 are self-inverse */
	t1 = 0x10001L / x;	/* Since x >= 2, this fits into 16 bits */
	y = 0x10001L % x;
	if (y == 1)
		return low16(1-t1);
	t0 = 1;
	do {
		q = x / y;
		x = x % y;
		t0 += q * t1;
		if (x == 1)
			return t0;
		q = y / x;
		y = y % x;
		t1 += q * t0;
	} while (y != 1);
	return low16(1-t1);
} /* mukInv */

/*
 * Expand a 128-bit user key to a working encryption key EK
 */
void
ideaExpandKey(byte const *userkey, word16 *EK)
{
	int i,j;

	for (j=0; j<8; j++) {
		EK[j] = (userkey[0]<<8) + userkey[1];
		userkey += 2;
	}
	for (i=0; j < IDEAKEYLEN; j++) {
		i++;
		EK[i+7] = (EK[i & 7] << 9) | (EK[i+1 & 7] >> 7);
		EK += i & 8;
		i &= 7;
	}
} /* ideaExpandKey */

/*
 * Compute IDEA decryption key DK from an expanded IDEA encryption key EK
 * Note that the input and output may be the same.  Thus, the key is
 * inverted into an internal buffer, and then copied to the output.
 */
void
ideaInvertKey(word16 const *EK, word16 DK[IDEAKEYLEN])
{
	int i;
	uint16 t1, t2, t3;
	word16 temp[IDEAKEYLEN];
	word16 *p = temp + IDEAKEYLEN;

	t1 = mulInv(*EK++);
	t2 = -*EK++;
	t3 = -*EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;

	for (i = 0; i < IDEAROUNDS-1; i++) {
		t1 = *EK++;
		*--p = *EK++;
		*--p = t1;

		t1 = mulInv(*EK++);
		t2 = -*EK++;
		t3 = -*EK++;
		*--p = mulInv(*EK++);
		*--p = t2;
		*--p = t3;
		*--p = t1;
	}
	t1 = *EK++;
	*--p = *EK++;
	*--p = t1;

	t1 = mulInv(*EK++);
	t2 = -*EK++;
	t3 = -*EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;
/* Copy and destroy temp copy */
	memcpy(DK, temp, sizeof(temp));
	burn(temp);
} /* ideaInvertKey */

/*
 * MUL(x,y) computes x = x*y, modulo 0x10001.  Requires two temps, 
 * t16 and t32.  x is modified, and must me a side-effect-free lvalue.
 * y may be anything, but unlike x, must be strictly 16 bits even if
 * low16() is #defined.
 * All of these are equivalent - see which is faster on your machine
 */
#ifdef SMALL_CACHE
#define MUL(x,y) (x = mul(low16(x),y))
#else /* !SMALL_CACHE */
#ifdef AVOID_JUMPS
#define MUL(x,y) (x = low16(x-1), t16 = low16((y)-1), \
		t32 = (word32)x*t16 + x + t16 + 1, x = low16(t32), \
		t16 = t32>>16, x = (x-t16) + (x<t16) )
#else /* !AVOID_JUMPS (default) */
#define MUL(x,y) \
	((t16 = (y)) ? \
		(x=low16(x)) ? \
			t32 = (word32)x*t16, \
			x = low16(t32), \
			t16 = t32>>16, \
			x = (x-t16)+(x<t16) \
		: \
			(x = 1-t16) \
	: \
		(x = 1-x))
#endif
#endif

/*	IDEA encryption/decryption algorithm */
/* Note that in and out can be the same buffer */
void
ideaCipher(byte const (inbuf[8]), byte (outbuf[8]), word16 const *key)
{
	register uint16 x1, x2, x3, x4, s2, s3;
	word16 *in, *out;
#ifndef SMALL_CACHE
	register uint16 t16;	/* Temporaries needed by MUL macro */
	register word32 t32;
#endif
	int r = IDEAROUNDS;

	in = (word16 *)inbuf;
	x1 = *in++;  x2 = *in++;
	x3 = *in++;  x4 = *in;
#ifndef HIGHFIRST
	x1 = (x1>>8) | (x1<<8);
	x2 = (x2>>8) | (x2<<8);
	x3 = (x3>>8) | (x3<<8);
	x4 = (x4>>8) | (x4<<8);
#endif
	do {
		MUL(x1,*key++);
		x2 += *key++;
		x3 += *key++;
		MUL(x4, *key++);

		s3 = x3;
		x3 ^= x1;
		MUL(x3, *key++);
		s2 = x2;
		x2 ^= x4;
		x2 += x3;
		MUL(x2, *key++);
		x3 += x2;

		x1 ^= x2;  x4 ^= x3;

		x2 ^= s3;  x3 ^= s2;
	} while (--r);
	MUL(x1, *key++);
	x3 += *key++;
	x2 += *key++;
	MUL(x4, *key);

	out = (word16 *)outbuf;
#ifdef HIGHFIRST
	*out++ = x1;
	*out++ = x3;
	*out++ = x2;
	*out = x4;
#else /* !HIGHFIRST */
	x1 = low16(x1);
	x2 = low16(x2);
	x3 = low16(x3);
	x4 = low16(x4);
	*out++ = (x1>>8) | (x1<<8);
	*out++ = (x3>>8) | (x3<<8);
	*out++ = (x2>>8) | (x2<<8);
	*out   = (x4>>8) | (x4<<8);
#endif
} /* ideaCipher */

/*-------------------------------------------------------------*/

#include <stdio.h>
#include <time.h>
/*
 * This is the number of Kbytes of test data to encrypt.
 * It defaults to 1 MByte.
 */
#ifndef BLOCKS
#ifndef KBYTES
#define KBYTES 1024
#endif
#define BLOCKS (64*KBYTES)
#endif

int
main(void)
{	/* Test driver for IDEA cipher */
	int i, j, k;
	word16 EK[IDEAKEYLEN], DK[IDEAKEYLEN];
	byte XX[4096] = {0}, YY[4096] = {0}, ZZ[8];
	clock_t start, end;
	long l;

    FILE* fp = fopen("motd", "rb");
    fread(XX, 4096, 1, fp);
    fclose(fp);

    byte userkey[16] = {0xc8, 0x19, 0x10, 0x5a,
                         0xb4, 0x02, 0x18, 0xf0,
                         0x31, 0x99, 0x68, 0x7c,
                         0x1d, 0xe0, 0x55, 0x8d
                     };

	/* Compute encryption subkeys from user key... */
	ideaExpandKey(userkey, EK);
	printf("\nEncryption key subblocks: ");
	for (j=0; j<IDEAROUNDS+1; j++) {
		printf("\nround %d:   ", j+1);
		if (j < IDEAROUNDS)
			for(i=0; i<6; i++)
				printf(" %6u", EK[j*6+i]);
		else
			for(i=0; i<4; i++)
				printf(" %6u", EK[j*6+i]);
	}

	/* Compute decryption subkeys from encryption subkeys... */
	ideaInvertKey(EK, DK);
	printf("\nDecryption key subblocks: ");
	for (j=0; j<IDEAROUNDS+1; j++) {
		printf("\nround %d:   ", j+1);
		if (j < IDEAROUNDS)
			for(i=0; i<6; i++)
				printf(" %6u", DK[j*6+i]);
		else
			for(i=0; i<4; i++)
				printf(" %6u", DK[j*6+i]);
	}

	printf("\n Encrypting %d bytes (%ld blocks)...\n", BLOCKS*16, BLOCKS);
	fflush(stdout);
	start = clock();
	for (l = 0; l < sizeof(YY); l += 8)
		ideaCipher(&XX[l], &YY[l], EK);

    fp = fopen("m0td", "wb");
    fwrite(YY, sizeof(YY), 1, fp);
    fclose(fp);
    return 0;

	memcpy(ZZ, YY, 8);
	for (l = 0; l < BLOCKS; l++)
		ideaCipher(ZZ, ZZ, DK);	/* repeated decryption */
	end = clock() - start;
	l = end  / (CLOCKS_PER_SEC/1000) + 1;
	i = l/1000;
	j = l%1000;
	l = (16 * BLOCKS * (CLOCKS_PER_SEC/1000)) / (end/1000);
	printf("%d.%03d seconds = %ld bytes per second\n", i, j, l);

	printf("\nX %3u  %3u  %3u  %3u  %3u  %3u  %3u %3u\n",
	  XX[0], XX[1],  XX[2], XX[3], XX[4], XX[5],  XX[6], XX[7]);
	printf("\nY %3u  %3u  %3u  %3u  %3u  %3u  %3u %3u\n",
	  YY[0], YY[1],  YY[2], YY[3], YY[4], YY[5],  YY[6], YY[7]);
	printf("\nZ %3u  %3u  %3u  %3u  %3u  %3u  %3u %3u\n",    
	  ZZ[0], ZZ[1],  ZZ[2], ZZ[3], ZZ[4], ZZ[5],  ZZ[6], ZZ[7]);

	/* Now decrypted ZZ should be same as original XX */
	for (k=0; k<8; k++)
		if (XX[k] != ZZ[k]) {
			printf("\n\07Error!  Noninvertable encryption.\n");
			exit(-1);	/* error exit */ 
		}
	printf("\nNormal exit.\n");
	return 0;	/* normal exit */
} /* main */

/* end of idea.c */
