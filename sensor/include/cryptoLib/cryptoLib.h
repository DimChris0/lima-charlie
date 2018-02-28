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

#ifndef _CRYPTO_LIB_H
#define _CRYPTO_LIB_H

#include <rpal/rpal.h>

#define CRYPTOLIB_SIGNATURE_SIZE            0x100
#define CRYPTOLIB_ASYM_KEY_SIZE_PUB         0x126
#define CRYPTOLIB_ASYM_KEY_SIZE_PRI         0x4A8
#define CRYPTOLIB_SYM_KEY_SIZE              0x20
#define CRYPTOLIB_SYM_IV_SIZE               0x10
#define CRYPTOLIB_ASYM_2048_MIN_SIZE        0x100
#define CRYPTOLIB_ASYM_MAX_SIZE             0xF5
#define CRYPTOLIB_HASH_SIZE                 0x20 // Sha-256
#define CRYPTOLIB_SYM_MOD_SIZE              0x10

typedef struct
{
    RU8 _[ CRYPTOLIB_HASH_SIZE ];
} CryptoLib_Hash;

typedef RPVOID CryptoLib_SymContext;

#define CRYPTOLIB_SYM_BUFFER_PADDING(size) ( ( CRYPTOLIB_SYM_MOD_SIZE - ( (size) % CRYPTOLIB_SYM_MOD_SIZE ) ) ? \
                                             ( CRYPTOLIB_SYM_MOD_SIZE - ( (size) % CRYPTOLIB_SYM_MOD_SIZE ) ) :\
                                             CRYPTOLIB_SYM_MOD_SIZE )

RBOOL
    CryptoLib_init
    (

    );

RVOID
    CryptoLib_deinit
    (

    );

RBOOL
    CryptoLib_sign
    (
        RPVOID bufferToSign,
        RU32 bufferSize,
        RU8 privKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ],
        RU8 pSignature[ CRYPTOLIB_SIGNATURE_SIZE ]
    );

RBOOL
    CryptoLib_verify
    (
        RPVOID bufferToVerify,
        RU32 bufferSize,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ],
        RU8 signature[ CRYPTOLIB_SIGNATURE_SIZE ]
    );

CryptoLib_SymContext
    CryptoLib_symEncInitContext
    (
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ]
    );

CryptoLib_SymContext
    CryptoLib_symDecInitContext
    (
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ]
    );

RVOID
    CryptoLib_symFreeContext
    (
        CryptoLib_SymContext ctx
    );

RBOOL
    CryptoLib_symEncrypt
    (
        rBlob bufferToEncrypt,
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ],
        CryptoLib_SymContext optContext
    );

RBOOL
    CryptoLib_symDecrypt
    (
        rBlob bufferToDecrypt,
        RU8 key[ CRYPTOLIB_SYM_KEY_SIZE ],
        RU8 iv[ CRYPTOLIB_SYM_IV_SIZE ],
        CryptoLib_SymContext optContext
    );

RBOOL
    CryptoLib_asymEncrypt
    (
        RPVOID bufferToEncrypt,
        RU32 bufferSize,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ],
        RPU8* pEncryptedBuffer,
        RU32* pEncryptedSize
    );

RBOOL
    CryptoLib_asymDecrypt
    (
        RPVOID bufferToDecrypt,
        RU32 bufferSize,
        RU8 priKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ],
        RPU8* pDecryptedBuffer,
        RU32* pDecryptedSize
    );

RBOOL
    CryptoLib_genRandomBytes
    (
        RPU8 pRandBytes,
        RU32  bytesRequired
    );

RBOOL
    CryptoLib_fastAsymEncrypt
    (
        rBlob bufferToEncrypt,
        RU8 pubKey[ CRYPTOLIB_ASYM_KEY_SIZE_PUB ]
    );

RBOOL
    CryptoLib_fastAsymDecrypt
    (
        rBlob bufferToDecrypt,
        RU8 priKey[ CRYPTOLIB_ASYM_KEY_SIZE_PRI ]
    );

RBOOL
    CryptoLib_hash
    (
        RPVOID buffer,
        RU32 bufferSize,
        CryptoLib_Hash* pHash
    );

RBOOL
    CryptoLib_hashFile
    (
        RPNCHAR fileName,
        CryptoLib_Hash* pHash,
        RBOOL isAvoidTimestamps
    );
    
#endif
