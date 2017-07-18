#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#include "mbedtls/aes.h"
#include "mbedtls/md.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  aescrypt2 <mode> <input filename> <output filename> <key>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: aescrypt2 0 file file.aes hex:E76B2413958B00E193\n" \
    "\n"

#if !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_MD_C) ||\
	!defined(MBEDTLS_ECDH_C) || \
	!defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
	!defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
	mbedtls_printf("MBEDTLS_AES_C and/or MBEDTLS_SHA256_C "
			"and/or MBEDTLS_FS_IO and/or MBEDTLS_MD_C "
			"not defined.\n");
	mbedtls_printf( "MBEDTLS_ECDH_C and/or "
			"MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
			"MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
			"not defined\n" );
	return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

int main(int argc, char *argv[]) {
// ECDHE context variable declarations
	int ret = 1;
	mbedtls_ecdh_context ctx_cli, ctx_srv;
	mbedtls_mpi z;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char cli_to_srv[32], srv_to_cli[32];
	const char pers[] = "ecdh";

// ECDHE context init
	mbedtls_ecdh_init(&ctx_cli);
	mbedtls_ecdh_init(&ctx_srv);
	mbedtls_ctr_drbg_init(&ctr_drbg);

//AES-128 variable declarations
	unsigned int i, n;
	int mode, lastn;
	size_t keylen;
	FILE *fkey, *fin = NULL, *fout = NULL;

	//AES context variable declarations
	char *p;
	unsigned char IV[16];
	unsigned char key[256];
	// unsigned char key1[256];
	unsigned char digest[32];
	unsigned char digest_dec[32];
	unsigned char buffer[1024];
	unsigned char diff;
	mbedtls_aes_context aes_ctx;
	mbedtls_md_context_t sha_ctx;

#if defined(_WIN32_WCE)
	long filesize, offset,offset1;
#elif defined(_WIN32)
	LARGE_INTEGER li_size;
	__int64 filesize, offset, offset1;
#else
	off_t filesize, offset,offset1;
#endif

	//AES context init
	mbedtls_aes_init(&aes_ctx);
	mbedtls_md_init(&sha_ctx);

	/*
	 * Entropy initialization using Deterministic Random Byte Generator
	 */

	mbedtls_printf("  . Seeding the random number generator...");
	//fflush( stdout );

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			(const unsigned char *) pers, sizeof pers)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	mbedtls_printf("  . Setting up client context...");
	//fflush( stdout );

	ret = mbedtls_ecp_group_load(&ctx_cli.grp, MBEDTLS_ECP_DP_CURVE25519);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_ecdh_gen_public(&ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q,
			mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&ctx_cli.Q.X, cli_to_srv, 32);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n",
				ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * Server: initialize context and generate keypair
	 */

	mbedtls_printf("  . Setting up server context...");
	//fflush( stdout );

	ret = mbedtls_ecp_group_load(&ctx_srv.grp, MBEDTLS_ECP_DP_CURVE25519);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_ecdh_gen_public(&ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q,
			mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecdh_gen_public returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_mpi_write_binary(&ctx_srv.Q.X, srv_to_cli, 32);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_binary returned %d\n",
				ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * Server: read peer's key and generate shared secret
	 */

	mbedtls_printf("  . Server reading client key and computing secret...");
	//fflush( stdout );

	ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_lset returned %d\n", ret);
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, cli_to_srv, 32);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_read_binary returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&ctx_srv.grp, &ctx_srv.z, &ctx_srv.Qp,
			&ctx_srv.d, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n",
				ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * Client: read peer's key and generate shared secret
	 */

	mbedtls_printf("  . Client reading server key and computing secret...");
	//fflush( stdout );

	ret = mbedtls_mpi_lset(&ctx_cli.Qp.Z, 1);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_lset returned %d\n", ret);
		goto exit;
	}

	ret = mbedtls_mpi_read_binary(&ctx_cli.Qp.X, srv_to_cli, 32);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_mpi_read_binary returned %d\n",
				ret);
		goto exit;
	}

	ret = mbedtls_ecdh_compute_shared(&ctx_cli.grp, &ctx_cli.z, &ctx_cli.Qp,
			&ctx_cli.d, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n",
				ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * Verification: are the computed secret equal?
	 */
	mbedtls_printf("  . Checking if both computed secrets are equal...");
	//fflush( stdout );

	ret = mbedtls_mpi_cmp_mpi(&ctx_cli.z, &ctx_srv.z);
	if (ret != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n",
				ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/* AES-128 bit encryption */

	ret = mbedtls_md_setup(&sha_ctx,
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	if (ret != 0) {
		mbedtls_printf("  ! mbedtls_md_setup() returned -0x%04x\n", -ret);
		goto exit;
	}

	/*
	 * Parse the command-line arguments.
	 */

	if (argc != 5) {
		mbedtls_printf( USAGE);

#if defined(_WIN32)
		mbedtls_printf("\n  Press Enter to exit this program.\n");
		//fflush( stdout );
		getchar();
#endif

		goto exit;
	}

	//mode = atoi( argv[1] );
	mode = 1;
	memset(IV, 0, sizeof(IV));
	memset(key, 0, sizeof(key));
	//memset(key1,0,sizeof(key1));
	memset(digest, 0, sizeof(digest));
	memset(buffer, 0, sizeof(buffer));

	if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
		mbedtls_fprintf( stderr, "invalide operation mode\n");
		goto exit;
	}

	if (strcmp(argv[2], argv[3]) == 0) {
		mbedtls_fprintf( stderr, "input and output filenames must differ\n");
		goto exit;
	}
	fin = fopen("G:\\test\\file.txt", "rb");
	if (fin == NULL) {
		mbedtls_fprintf( stderr, "fopen(%s,rb) failed\n", argv[2]);
		goto exit;
	}

	if ((fout = fopen("G:\\test\\file", "wb+")) == NULL) {
		mbedtls_fprintf( stderr, "fopen(%s,wb+) failed\n", argv[3]);
		goto exit;
	}

	/*
	 * Read the secret key and clean the command line.
	 */

	memcpy(&z, &ctx_cli.z, sizeof(ctx_cli.z));
	memcpy(key, z.p, sizeof(*(z.p)));
	keylen = strlen(key);
	/*
	 strcpy(argv[4],"3956421040424689310");

	 if( ( fkey = fopen( argv[4], "rb" ) ) != NULL )
	 {
	 keylen = fread( key, 1, sizeof( key ), fkey );
	 fclose( fkey );
	 }
	 else
	 {
	 if( memcmp( argv[4], "hex:", 4 ) == 0 )
	 {
	 p = &argv[4][4];
	 keylen = 0;

	 while( ( sscanf( p, "%02X", &n ) > 0 )&&
	 ( keylen < (int) sizeof( key ) ))
	 {
	 key[keylen++] = (unsigned char) n;
	 p += 2;
	 }
	 }
	 else
	 {
	 keylen = strlen( argv[4] );

	 if( keylen > (int) sizeof( key ) )
	 keylen = (int) sizeof( key );

	 memcpy( key, argv[4], keylen );
	 }
	 }

	 //memset( argv[4], 0, strlen( argv[4] ) );         */

	char test[] = "This is Hello world Test File.";
	char test_out[1024] = "";
	char test1[1024] = "";
	char * q;
	q = test;
	long testsize = sizeof(test);

	//uint8_t sz = sizeof(*(z.p));
	//memset(key1,0,sizeof(key1));
	//mbedtls_mpi_uint t_key=*(z.p);

	// memset( argv[4], 0, strlen( argv[4] ) );
#if defined(_WIN32_WCE)
	filesize = fseek( fin, 0L, SEEK_END );
#else
#if defined(_WIN32)
	/*
	 * Support large files (> 2Gb) on Win32
	 */

	li_size.QuadPart = 0;
	li_size.LowPart = SetFilePointer((HANDLE) _get_osfhandle(_fileno(fin)),
			li_size.LowPart, &li_size.HighPart, FILE_END);

	if (li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR) {
		mbedtls_fprintf( stderr, "SetFilePointer(0,FILE_END) failed\n");
		goto exit;
	}

	filesize = li_size.QuadPart;
#else
	if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
	{
		perror( "lseek" );
		goto exit;
	}
#endif
#endif

	if (fseek(fin, 0, SEEK_SET) < 0) {
		mbedtls_fprintf( stderr, "fseek(0,SEEK_SET) failed\n");
		goto exit;
	}

	// if( mode == MODE_ENCRYPT )

	/*
	 * Generate the initialization vector as:
	 * IV = SHA-256( filesize || filename )[0..15]
	 */
	for (i = 0; i < 8; i++)
		buffer[i] = (unsigned char) (testsize >> (i << 3));

	mbedtls_md_starts(&sha_ctx);
	mbedtls_md_update(&sha_ctx, buffer, 8);
	mbedtls_md_update(&sha_ctx, (unsigned char *) q, strlen(q));
	mbedtls_md_finish(&sha_ctx, digest);

	memcpy(IV, digest, 16);

	/*
	 * The last four bits in the IV are actually used
	 * to store the file size modulo the AES block size.
	 */
	lastn = (int) (testsize & 0x0F);

	IV[15] = (unsigned char) ((IV[15] & 0xF0) | lastn);

	/*
	 * Append the IV at the beginning of the output.
	 */
	memcpy(test_out, IV, 16);
	// if( fwrite( IV, 1, 16, fout ) != 16 )
	if (strlen(test_out) != 16) {
		mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16);
		goto exit;
	}

	/*
	 * Hash the IV and the secret key together 8192 times
	 * using the result to setup the AES context and HMAC.
	 */
	memset(digest, 0, 32);
	memcpy(digest, IV, 16);

	for (i = 0; i < 8192; i++) {
		mbedtls_md_starts(&sha_ctx);
		mbedtls_md_update(&sha_ctx, digest, 32);
		mbedtls_md_update(&sha_ctx, key, keylen);
		mbedtls_md_finish(&sha_ctx, digest);
	}

	// memset( key, 0, sizeof( key ) );
	mbedtls_aes_setkey_enc(&aes_ctx, digest, 128);
	mbedtls_md_hmac_starts(&sha_ctx, digest, 32);

	/*
	 * Encrypt and write the ciphertext.
	 */
	for (offset = 0; offset < testsize; offset += 16) {
		n = (testsize - offset > 16) ? 16 : (int) (testsize - offset);

		memcpy(buffer, &test[offset], n);

		//if( fread( buffer, 1, n, fin ) != (size_t) n )
		/*if (strlen((const char*)buffer)!= n)
		 {
		 mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", n );
		 goto exit;
		 }
		 */

		for (i = 0; i < 16; i++)
			buffer[i] = (unsigned char) (buffer[i] ^ IV[i]);

		mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, buffer, buffer);
		mbedtls_md_hmac_update(&sha_ctx, buffer, 16);

		memcpy(&test_out[offset + 16], buffer, 16);
		//if( fwrite( buffer, 1, 16, fout ) != 16 )
		/* if(strlen(test_out)!= 16)
		 {
		 mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
		 goto exit;
		 }
		 */

		memcpy(IV, buffer, 16);
	}

	/*
	 * Finally write the HMAC.
	 */
	mbedtls_md_hmac_finish(&sha_ctx, digest);
	memcpy(&test_out[offset + 16], digest, 32);

	//if( fwrite( digest, 1, 32, fout ) != 32 )
	/* if(strlen(test_out)!= 32)
	 {
	 mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 32 );
	 goto exit;
	 }
	 */

	//if( mode == MODE_DECRYPT )
	unsigned char tmp[16];
	long test_out_size = offset + 48;

	/*
	 *  The encrypted file must be structured as follows:
	 *
	 *        00 .. 15              Initialization Vector
	 *        16 .. 31              AES Encrypted Block #1
	 *           ..
	 *      N*16 .. (N+1)*16 - 1    AES Encrypted Block #N
	 *  (N+1)*16 .. (N+1)*16 + 32   HMAC-SHA-256(ciphertext)
	 */
	if (test_out_size < 48) {
		mbedtls_fprintf( stderr, "File too short to be encrypted.\n");
		goto exit;
	}

	if ((test_out_size & 0x0F) != 0) {
		mbedtls_fprintf( stderr, "File size not a multiple of 16.\n");
		goto exit;
	}

	/*
	 * Subtract the IV + HMAC length.(essentially  equal to 'offset'variable used during encryption)
	 */
	//test_out_size -= ( 16 + 32 );cant define this way as test_out size has no relation with output string

	/*
	 * Read the IV and original testsize modulo 16.
	 */
	memcpy(buffer, test_out, 16);
	//if( fread( buffer, 1, 16, fin ) != 16 )
	if (strlen((const char*) buffer) != 16) {
		mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16);
		goto exit;
	}

	memcpy(IV, buffer, 16);
	lastn = IV[15] & 0x0F;

	/*
	 * Hash the IV and the secret key together 8192 times
	 * using the result to setup the AES context and HMAC.
	 */
	memset(digest_dec, 0, 32);
	memcpy(digest_dec, IV, 16);

	for (i = 0; i < 8192; i++) {
		mbedtls_md_starts(&sha_ctx);
		mbedtls_md_update(&sha_ctx, digest_dec, 32);
		mbedtls_md_update(&sha_ctx, key, keylen);
		mbedtls_md_finish(&sha_ctx, digest_dec);
	}

	//memset( key, 0, sizeof( key ) );
	mbedtls_aes_setkey_dec(&aes_ctx, digest_dec, 128);
	mbedtls_md_hmac_starts(&sha_ctx, digest_dec, 32);

	/*
	 * Decrypt and write the plaintext.
	 */
	for (offset1 = 0; offset1 < offset; offset1 += 16) {

		memcpy(buffer, &test_out[offset1 + 16], 16);
		//if( fread( buffer, 1, 16, fin ) != 16 )
		/*if(strlen((const char*)buffer) != 16)
		 {
		 mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
		 goto exit;
		 }
		 */

		memcpy(tmp, buffer, 16);

		mbedtls_md_hmac_update(&sha_ctx, buffer, 16);
		mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, buffer, buffer);

		for (i = 0; i < 16; i++)
			buffer[i] = (unsigned char) (buffer[i] ^ IV[i]);

		memcpy(IV, tmp, 16);

		n = (lastn > 0 && offset1 == test_out_size - 16) ? lastn : 16;

		memcpy(&test1[offset1], buffer, n);

		//if( fwrite( buffer, 1, n, fout ) != (size_t) n )
		/*
		 if(strlen(test1)!= n)
		 {
		 mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", n );
		 goto exit;
		 }
		 */
	}

	/*
	 * Verify the message authentication code.
	 */
	mbedtls_md_hmac_finish(&sha_ctx, digest_dec);
	memcpy(buffer, &test_out[offset1 + 16], 32);
	/*if( fread( buffer, 1, 32, fin ) != 32 )
	 {
	 mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 32 );
	 goto exit;
	 }
	 */

	/* Use constant-time buffer comparison */
	diff = 0;
	for (i = 0; i < 32; i++)
		diff |= digest[i] ^ buffer[i];

	if (diff != 0) {
		mbedtls_fprintf( stderr, "HMAC check failed: wrong key, "
				"or file corrupted.\n");
		goto exit;
	}
	if (diff == 0) {
		mbedtls_fprintf( stderr, "HMAC check correct");
	}

	ret = 0;

	exit: if (fin)
		fclose(fin);
	if (fout)
		fclose(fout);

	memset(buffer, 0, sizeof(buffer));
	memset(digest, 0, sizeof(digest));
	memset(digest_dec, 0, sizeof(digest_dec));
	mbedtls_aes_free(&aes_ctx);
	mbedtls_md_free(&sha_ctx);

	return (ret);
}
#endif /* MBEDTLS_AES_C && MBEDTLS_SHA256_C && MBEDTLS_FS_IO */
