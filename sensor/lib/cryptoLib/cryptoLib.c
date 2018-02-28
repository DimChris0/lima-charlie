/*
Copyright 2015 refractionPOINT

Licensed under the Apache License, Version 2.0 ( the "License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define RPAL_FILE_ID   33

#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <cryptoLib/cryptoLib.h>


#pragma pack(push)
#pragma pack(1)
typedef struct
{
    RU8 symKey[ CRYPTOLIB_ASYM_2048_MIN_SIZE ];
    RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ];
    RU8 data[];
} _CryptoLib_FastAsymBuffer;
#pragma pack(pop)

typedef struct
{
    mbedtls_aes_context aes;
    RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ];
} _CryptoLib_SymContext;


static rMutex g_mutex = NULL;
static mbedtls_entropy_context g_entropy = { 0 };
static mbedtls_ctr_drbg_context g_rng = { 0 };


RBOOL
    CryptoLib_init
    (

    )
{
    RBOOL isSuccess = FALSE;
    RCHAR perso[] = "rp-cryptolib-for-lc";
    if( NULL != ( g_mutex = rMutex_create() ) )
    {
        mbedtls_entropy_init( &g_entropy );
        mbedtls_ctr_drbg_init( &g_rng );
        mbedtls_ctr_drbg_seed( &g_rng,
                               mbedtls_entropy_func,
                               &g_entropy,
                               (const unsigned char*)perso,
                               sizeof( perso ) - sizeof( RCHAR ) );
        isSuccess = TRUE;
    }

    return isSuccess;
}

RVOID
    CryptoLib_deinit
    (

    )
{
    if( rMutex_lock( g_mutex ) )
    {
        rMutex_free( g_mutex );
    }
}

RBOOL
    CryptoLib_sign
    (
        RPVOID bufferToSign,
        RU32 bufferSize,
        RU8 privKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ],
        RU8 pSignature[ CRYPTOLIB_SIGNATURE_SIZE ]
    )
{
    RBOOL isSuccess = FALSE;

    CryptoLib_Hash hash = { 0 };
    mbedtls_pk_context key = { 0 };
    mbedtls_rsa_context* rsa = NULL;
    
    if( NULL != bufferToSign &&
        0 != bufferSize &&
        NULL != privKey &&
        NULL != pSignature )
    {
        mbedtls_sha256( bufferToSign, bufferSize, (RPU8)&hash, 0 );
        
        mbedtls_pk_init( &key );

        if( 0 == mbedtls_pk_parse_key( &key, privKey, CRYPTOLIB_ASYM_KEY_SIZE_PRI, NULL, 0 ) )
	    {
            if( NULL != ( rsa = mbedtls_pk_rsa( key ) ) )
            {
                if( 0 == mbedtls_rsa_pkcs1_encrypt( rsa,
                                                    mbedtls_ctr_drbg_random,
                                                    &g_rng,
                                                    MBEDTLS_RSA_PRIVATE,
                                                    sizeof( hash ),
                                                    (RPU8)&hash,
                                                    pSignature ) )
                {
                    isSuccess = TRUE;
                }
            }
        }

        mbedtls_pk_free( &key );
    }

    return isSuccess;
}

RBOOL
    CryptoLib_verify
    (
        RPVOID bufferToVerify,
        RU32 bufferSize,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ],
        RU8 signature[ CRYPTOLIB_SIGNATURE_SIZE ]
    )
{
    RBOOL isSuccess = FALSE;

    RU8 hash[ CRYPTOLIB_ASYM_2048_MIN_SIZE ] = { 0 };
    CryptoLib_Hash actualHash = { 0 };
    mbedtls_pk_context key = { 0 };
    mbedtls_rsa_context* rsa = NULL;
    RSIZET outLength = 0;

    if( NULL != bufferToVerify &&
        0 != bufferSize &&
        NULL != pubKey &&
        NULL != signature )
    {
        mbedtls_sha256( bufferToVerify, bufferSize, (RPU8)&actualHash, 0 );
        
        mbedtls_pk_init( &key );

        if( 0 == mbedtls_pk_parse_public_key( &key, pubKey, CRYPTOLIB_ASYM_KEY_SIZE_PUB ) )
	    {
            if( NULL != ( rsa = mbedtls_pk_rsa( key ) ) )
            {
                if( 0 == mbedtls_rsa_pkcs1_decrypt( rsa, 
                                                    mbedtls_ctr_drbg_random, 
                                                    &g_rng,
                                                    MBEDTLS_RSA_PUBLIC, 
                                                    &outLength, 
                                                    signature, 
                                                    hash,
                                                    sizeof( hash ) ) )
                {
                    if( rpal_memory_simpleMemcmp( hash, &actualHash, sizeof( actualHash ) ) )
                    {
                        isSuccess = TRUE;
                    }
                }
            }
        }

        mbedtls_pk_free( &key );
    }

    return isSuccess;
}

CryptoLib_SymContext
    CryptoLib_symEncInitContext
    (
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ]
    )
{
    _CryptoLib_SymContext* ctx = NULL;

    if( NULL != key &&
        NULL != iv )
    {
        if( NULL != ( ctx = rpal_memory_alloc( sizeof( _CryptoLib_SymContext ) ) ) )
        {
            mbedtls_aes_init( &ctx->aes );

            if( 0 == mbedtls_aes_setkey_enc( &ctx->aes, key, 256 ) )
            {
                rpal_memory_memcpy( ctx->iv, iv, sizeof( ctx->iv ) );
            }
            else
            {
                rpal_memory_free( ctx );
                ctx = NULL;
            }
        }
    }

    return (CryptoLib_SymContext)ctx;
}

CryptoLib_SymContext
    CryptoLib_symDecInitContext
    (
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ]
    )
{
    _CryptoLib_SymContext* ctx = NULL;

    if( NULL != key &&
        NULL != iv )
    {
        if( NULL != ( ctx = rpal_memory_alloc( sizeof( _CryptoLib_SymContext ) ) ) )
        {
            mbedtls_aes_init( &ctx->aes );

            if( 0 == mbedtls_aes_setkey_dec( &ctx->aes, key, 256 ) )
            {
                rpal_memory_memcpy( ctx->iv, iv, sizeof( ctx->iv ) );
            }
            else
            {
                rpal_memory_free( ctx );
                ctx = NULL;
            }
        }
    }

    return (CryptoLib_SymContext)ctx;
}

RVOID
    CryptoLib_symFreeContext
    (
        CryptoLib_SymContext ctx
    )
{
    _CryptoLib_SymContext* pCtx = ctx;
    if( NULL != ctx )
    {
        mbedtls_aes_free( &pCtx->aes );
        rpal_memory_free( pCtx );
    }
}

RBOOL
    CryptoLib_symEncrypt
    (
        rBlob bufferToEncrypt,
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ],
        CryptoLib_SymContext optContext
    )
{
    RBOOL isSuccess = FALSE;

    mbedtls_aes_context aes = { 0 };
    RU32 nPadding = 0;
    RU32 index = 0;
    RU32 encryptedSize = 0;
    RU32 bufferSize = 0;
    RU8 padding[ CRYPTOLIB_SYM_MOD_SIZE ] = { 0 };
    RPU8 rawBuffer = NULL;
    _CryptoLib_SymContext* pCtx = ( _CryptoLib_SymContext*)optContext;

    if( NULL != bufferToEncrypt &&
        ( ( NULL != key &&
            NULL != iv ) ||
          NULL != optContext ) )
    {
        bufferSize = rpal_blob_getSize( bufferToEncrypt );
        nPadding = CRYPTOLIB_SYM_BUFFER_PADDING( bufferSize );
        encryptedSize = bufferSize + nPadding;

        // Setup the PKCS#7 padding.
        for( index = 0; index < nPadding; index++ )
        {
            padding[ index ] = (RU8)nPadding;
        }

        if( rpal_blob_add( bufferToEncrypt, padding, nPadding ) )
        {
            if( NULL != ( rawBuffer = rpal_blob_getBuffer( bufferToEncrypt ) ) )
            {
                if( NULL == optContext )
                {
                    mbedtls_aes_init( &aes );
                }

                if( NULL != optContext ||
                    0 == mbedtls_aes_setkey_enc( &aes, key, 256 ) )
                {
                    if( 0 == mbedtls_aes_crypt_cbc( NULL != pCtx ? &pCtx->aes : &aes,
                                                    MBEDTLS_AES_ENCRYPT,
                                                    encryptedSize,
                                                    NULL != pCtx ? pCtx->iv : iv,
                                                    rawBuffer,
                                                    rawBuffer ) )
                    {
                        isSuccess = TRUE;
                    }
                }

                if( NULL == optContext )
                {
                    mbedtls_aes_free( &aes );
                }
            }
        }
    }

    return isSuccess;
}

RBOOL
    CryptoLib_symDecrypt
    (
        rBlob bufferToDecrypt,
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ],
        CryptoLib_SymContext optContext
    )
{
    RBOOL isSuccess = FALSE;

    mbedtls_aes_context aes = { 0 };
    RU8 nPadding = 0;
    RU32 index = 0;
    RPU8 rawBuffer = NULL;
    RU32 bufferSize = 0;
    _CryptoLib_SymContext* pCtx = (_CryptoLib_SymContext*)optContext;

    if( NULL != bufferToDecrypt &&
        ( ( NULL != key &&
            NULL != iv ) ||
          NULL != optContext ) )
    {
        if( NULL == optContext )
        {
            mbedtls_aes_init( &aes );
        }

        if( NULL != optContext ||
            0 == mbedtls_aes_setkey_dec( &aes, key, 256 ) )
        {
            if( NULL != ( rawBuffer = rpal_blob_getBuffer( bufferToDecrypt ) ) )
            {
                bufferSize = rpal_blob_getSize( bufferToDecrypt );

                if( 0 == mbedtls_aes_crypt_cbc( NULL != pCtx ? &pCtx->aes : &aes,
                                                MBEDTLS_AES_DECRYPT,
                                                bufferSize,
                                                NULL != pCtx ? pCtx->iv : iv,
                                                rawBuffer,
                                                rawBuffer ) )
                {
                    nPadding = rawBuffer[ bufferSize - 1 ];

                    // Removing PKCS#7 padding
                    if( nPadding < bufferSize &&
                        CRYPTOLIB_SYM_MOD_SIZE >= nPadding )
                    {
                        isSuccess = TRUE;

                        for( index = bufferSize - 1; index > ( bufferSize - nPadding ); index-- )
                        {
                            if( rawBuffer[ index ] != nPadding )
                            {
                                isSuccess = FALSE;
                                break;
                            }
                        }

                        if( isSuccess )
                        {
                            isSuccess = rpal_blob_remove( bufferToDecrypt, 
                                                          bufferSize - nPadding, 
                                                          nPadding );
                        }
                    }
                }
            }
        }

        if( NULL == optContext )
        {
            mbedtls_aes_free( &aes );
        }
    }

    return isSuccess;
}

RBOOL
    CryptoLib_asymEncrypt
    (
        RPVOID bufferToEncrypt,
        RU32 bufferSize,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ],
        RPU8* pEncryptedBuffer,
        RU32* pEncryptedSize
    )
{
    RBOOL isSuccess = FALSE;

    mbedtls_pk_context key = { 0 };
    
    RSIZET outSize = 0;
    RPU8 outBuff = NULL;

    if( NULL != bufferToEncrypt &&
        0 != bufferSize &&
        NULL != pubKey &&
        NULL != pEncryptedBuffer &&
        NULL != pEncryptedSize )
    {
        mbedtls_pk_init( &key );

        if( 0 == mbedtls_pk_parse_public_key( &key, pubKey, CRYPTOLIB_ASYM_KEY_SIZE_PUB ) )
	    {
            outSize = MBEDTLS_MPI_MAX_SIZE;

            if( 0 < outSize )
            {
                if( bufferSize > outSize )
                {
                    outSize = bufferSize;
                }

                outBuff = rpal_memory_alloc( outSize );

                if( rpal_memory_isValid( outBuff ) )
                {
                    if( 0 == mbedtls_pk_encrypt( &key, 
                                                 bufferToEncrypt, 
                                                 bufferSize, 
                                                 outBuff, 
                                                 &outSize, 
                                                 outSize, 
                                                 mbedtls_ctr_drbg_random, 
                                                 &g_rng ) )
                    {
                        *pEncryptedBuffer = outBuff;
                        *pEncryptedSize = (RU32)outSize;

                        isSuccess = TRUE;
                    }
                    else
                    {
                        rpal_memory_free( outBuff );
                    }
                }
            }
        }

        mbedtls_pk_free( &key );
    }

    return isSuccess;
}

RBOOL
    CryptoLib_asymDecrypt
    (
        RPVOID bufferToDecrypt,
        RU32 bufferSize,
        RU8 priKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ],
        RPU8* pDecryptedBuffer,
        RU32* pDecryptedSize
    )
{
    RBOOL isSuccess = FALSE;

    mbedtls_pk_context key = { 0 };

    RSIZET outSize = 0;
    RPU8 outBuff = NULL;

    if( NULL != bufferToDecrypt &&
        0 != bufferSize &&
        NULL != priKey &&
        NULL != pDecryptedBuffer &&
        NULL != pDecryptedSize )
    {
        mbedtls_pk_init( &key );

        if( 0 == mbedtls_pk_parse_key( &key, priKey, CRYPTOLIB_ASYM_KEY_SIZE_PRI, NULL, 0 ) )
	    {
            outBuff = rpal_memory_alloc( bufferSize );

            if( rpal_memory_isValid( outBuff ) )
            {
                outSize = bufferSize;

                if( 0 == mbedtls_pk_decrypt( &key,
                                             bufferToDecrypt,
                                             bufferSize,
                                             outBuff,
                                             &outSize,
                                             outSize,
                                             mbedtls_ctr_drbg_random,
                                             &g_rng ) )
                {
                    *pDecryptedBuffer = (RU8*)outBuff;
                    *pDecryptedSize = (RU32)outSize;

                    isSuccess = TRUE;
                }
                else
                {
                    rpal_memory_free( outBuff );
                }
            }
        }

        mbedtls_pk_free( &key );
    }

    return isSuccess;
}

RBOOL
    CryptoLib_genRandomBytes
    (
        RPU8 pRandBytes,
        RU32 bytesRequired
    )
{
    RBOOL isSuccess = FALSE;
    RU32 bytesLeft = bytesRequired;
    RU32 bytesRequesting = 0;
    RU32 offset = 0;

    if( NULL != pRandBytes &&
        0 != bytesRequired )
    {
        isSuccess = TRUE;

        while( 0 != bytesLeft )
        {
            bytesRequesting = MIN_OF( bytesLeft, MBEDTLS_CTR_DRBG_MAX_REQUEST );
            if( 0 != mbedtls_ctr_drbg_random( &g_rng, pRandBytes + offset, bytesRequesting ) )
            {
                isSuccess = FALSE;
                break;
            }

            bytesLeft -= bytesRequesting;
            offset += bytesRequesting;
        }
    }

    return isSuccess;
}

RBOOL
    CryptoLib_fastAsymEncrypt
    (
        rBlob bufferToEncrypt,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ]
    )
{
    RBOOL isSuccess = FALSE;

    RU8 symKey[ CRYPTOLIB_SYM_KEY_SIZE ] = {0};
    RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ] = {0};

    RPU8 tmpDecrypt = NULL;
    _CryptoLib_FastAsymBuffer asymBuffer = { 0 };
    RU32 tmpLength = 0;

    if( NULL != bufferToEncrypt &&
        NULL != pubKey )
    {
        if( CryptoLib_genRandomBytes( symKey, sizeof( symKey ) ) &&
            CryptoLib_genRandomBytes( iv, sizeof( iv ) ) )
        {
            if( CryptoLib_asymEncrypt( symKey, sizeof(symKey), pubKey, &tmpDecrypt, &tmpLength ) )
            {
                rpal_memory_memcpy( asymBuffer.symKey, tmpDecrypt, sizeof( asymBuffer.symKey ) );
                rpal_memory_free( tmpDecrypt );
                rpal_memory_memcpy( asymBuffer.iv, iv, sizeof( iv ) );

                if( CryptoLib_symEncrypt( bufferToEncrypt, symKey, iv, NULL ) )
                {
                    if( rpal_blob_insert( bufferToEncrypt, &asymBuffer, sizeof( asymBuffer ), 0 ) )
                    {
                        isSuccess = TRUE;
                    }
                }
            }

            rpal_memory_zero( symKey, sizeof( symKey ) );
            rpal_memory_zero( iv, sizeof( iv ) );
            rpal_memory_zero( &asymBuffer, sizeof( asymBuffer ) );
        }
    }

    return isSuccess;
}

RBOOL
    CryptoLib_fastAsymDecrypt
    (
        rBlob bufferToDecrypt,
        RU8 priKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ]
    )
{
    RBOOL isSuccess = FALSE;

    _CryptoLib_FastAsymBuffer* asymBuffer = NULL;
    RPU8 symKey = NULL;
    RU32 symSize = 0;
    RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ] = { 0 };

    if( NULL != bufferToDecrypt &&
        sizeof( _CryptoLib_FastAsymBuffer ) < rpal_blob_getSize( bufferToDecrypt ) &&
        NULL != priKey )
    {
        if( NULL != ( asymBuffer = rpal_blob_getBuffer( bufferToDecrypt ) ) )
        {
            if( CryptoLib_asymDecrypt( asymBuffer,
                                       CRYPTOLIB_ASYM_2048_MIN_SIZE,
                                       priKey,
                                       &symKey,
                                       &symSize ) )
            {
                rpal_memory_memcpy( iv, asymBuffer->iv, sizeof( iv ) );

                if( rpal_blob_remove( bufferToDecrypt, 0, sizeof( _CryptoLib_FastAsymBuffer ) ) &&
                    CryptoLib_symDecrypt( bufferToDecrypt,
                                          symKey,
                                          iv,
                                          NULL ) )
                {
                    isSuccess = TRUE;
                }

                rpal_memory_free( symKey );
            }
        }
    }

    return isSuccess;
}

RBOOL
    CryptoLib_hash
    (
        RPVOID buffer,
        RU32 bufferSize,
        CryptoLib_Hash* pHash
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != buffer &&
        0 != bufferSize &&
        NULL != pHash )
    {
        mbedtls_sha256( buffer, bufferSize, (RPU8)pHash, 0 );
        isSuccess = TRUE;
    }

    return isSuccess;
}


RBOOL
    CryptoLib_hashFile
    (
        RPNCHAR fileName,
        CryptoLib_Hash* pHash,
        RBOOL isAvoidTimestamps
    )
{
    RBOOL isSuccess = FALSE;

    mbedtls_sha256_context ctx = { 0 };
    RU8 buff[ 200 * 1024 ] = {0};
    rFile f = NULL;
    RU32 read = 0;

    if( NULL != fileName &&
        NULL != pHash )
    {
        if( rFile_open( fileName, &f, RPAL_FILE_OPEN_READ |
                                      RPAL_FILE_OPEN_EXISTING |
                                      ( isAvoidTimestamps ? RPAL_FILE_OPEN_AVOID_TIMESTAMPS : 0 ) ) )
        {
            mbedtls_sha256_init( &ctx );
            mbedtls_sha256_starts( &ctx, 0 );
            while( ( read = rFile_readUpTo( f, sizeof( buff ), buff ) ) > 0 )
            {
                mbedtls_sha256_update( &ctx, buff, read );
            }
            mbedtls_sha256_finish( &ctx, (RPU8)pHash );
            mbedtls_sha256_free( &ctx );
            isSuccess = TRUE;

            rFile_close( f );
        }
    }

    return isSuccess;
}
