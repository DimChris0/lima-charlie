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

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <obsLib/obsLib.h>
#include <cryptoLib/cryptoLib.h>

#define  RPAL_FILE_ID           102

#define MAX_CACHE_SIZE                  (1024 * 1024 * 50)
#define DOCUMENT_MAX_SIZE               (1024 * 1024 * 15)

RPRIVATE rQueue g_createQueue = NULL;
RPRIVATE HObs g_matcher = NULL;

RPRIVATE HbsRingBuffer g_documentCache = NULL;
RPRIVATE RU32 g_cacheMaxSize = MAX_CACHE_SIZE;
RPRIVATE RU32 g_cacheSize = 0;
RPRIVATE rMutex g_cacheMutex = NULL;

typedef struct
{
    RPNCHAR expr;
    CryptoLib_Hash* pHash;

} DocSearchContext;

RPRIVATE
RVOID
    _freeEvt
    (
        rSequence evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rSequence_free( evt );
}

RPRIVATE
RVOID
    processFile
    (
        rSequence notif
    )
{
    RPNCHAR fileN = NULL;
    RPU8 fileContent = NULL;
    RU32 fileSize = 0;
    CryptoLib_Hash hash = { 0 };

    if( NULL != notif )
    {
        obsLib_resetSearchState( g_matcher );

        if( rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &fileN ) &&
            obsLib_setTargetBuffer( g_matcher,
                                    fileN, 
                                    rpal_string_strsize( fileN ) ) &&
            obsLib_nextHit( g_matcher, NULL, NULL ) )
        {
            // This means it's a file of interest.
            if( ( DOCUMENT_MAX_SIZE >= rpal_file_getSize( fileN, TRUE ) &&
                  rpal_file_read( fileN, &fileContent, &fileSize, TRUE ) &&
                  CryptoLib_hash( fileContent, fileSize, &hash ) ) ||
                CryptoLib_hashFile( fileN, &hash, TRUE ) )
            {
                rpal_debug_info( "new document acquired" );
                rSequence_unTaintRead( notif );
                rSequence_addBUFFER( notif, RP_TAGS_HASH, (RPU8)&hash, sizeof( hash ) );
            }
            else
            {
                rpal_debug_warning( "could not acquire document" );
                rSequence_unTaintRead( notif );
                rSequence_addRU32( notif, RP_TAGS_ERROR, rpal_error_getLast() );
            }

            // We acquired the hash, either by reading the entire file in memory
            // which we will use for caching, or if it was too big by hashing it
            // sequentially on disk.
            rSequence_removeElement( notif, RP_TAGS_HBS_THIS_ATOM, RPCM_BUFFER );
            hbs_publish( RP_TAGS_NOTIFICATION_NEW_DOCUMENT, notif );

            if( rMutex_lock( g_cacheMutex ) )
            {
                if( NULL == fileContent ||
                    !rSequence_addBUFFER( notif, RP_TAGS_FILE_CONTENT, fileContent, fileSize ) ||
                    !HbsRingBuffer_add( g_documentCache, notif ) )
                {
                    rSequence_free( notif );
                }

                rMutex_unlock( g_cacheMutex );
            }
            else
            {
                rSequence_free( notif );
            }

            if( NULL != fileContent )
            {
                rpal_memory_free( fileContent );
            }
        }
        else
        {
            rSequence_free( notif );
        }
    }
}

RPRIVATE
RPVOID
    parseDocuments
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence createEvt = NULL;
    
    UNREFERENCED_PARAMETER( ctx );

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( g_createQueue, &createEvt, NULL, MSEC_FROM_SEC( 1 ) ) )
        {
            processFile( createEvt );
        }
    }

    return NULL;
}

RPRIVATE
RBOOL
    findDoc
    (
        rSequence doc,
        DocSearchContext* ctx
    )
{
    RBOOL isMatch = FALSE;
    RPNCHAR filePathN = NULL;
    RPCHAR tmpA = NULL;
    RPWCHAR tmpW = NULL;
    CryptoLib_Hash* pHash = NULL;
    RU32 hashSize = 0;

    if( rpal_memory_isValid( doc ) &&
        NULL != ctx )
    {
        if( NULL == ctx->expr &&
            NULL == ctx->pHash )
        {
            return TRUE;
        }

        if( rSequence_getSTRINGA( doc, RP_TAGS_FILE_PATH, &tmpA ) )
        {
            filePathN = rpal_string_aton( tmpA );
        }
        else if( rSequence_getSTRINGW( doc, RP_TAGS_FILE_PATH, &tmpW ) )
        {
            filePathN = rpal_string_wton( tmpW );
        }
        
        rSequence_getBUFFER( doc, RP_TAGS_HASH, (RPU8*)&pHash, &hashSize );

        if( ( NULL == filePathN || NULL == ctx->expr || rpal_string_match( ctx->expr, filePathN, FALSE ) ) &&
            ( NULL == ctx->pHash || ( NULL == pHash && 0 == rpal_memory_memcmp( pHash, ctx->pHash, hashSize ) ) ) )
        {
            isMatch = TRUE;
        }
    }

    return isMatch;
}

RPRIVATE
RVOID
    getDocument
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    rSequence tmp = NULL;
    DocSearchContext ctx = { 0 };
    RPWCHAR tmpW = NULL;
    RPCHAR tmpA = NULL;
    RU32 hashSize = 0;
    rList foundDocs = NULL;
    UNREFERENCED_PARAMETER( notifId );

    if( NULL != notif )
    {
        if( rSequence_getSTRINGW( notif, RP_TAGS_STRING_PATTERN, &tmpW ) )
        {
            ctx.expr = rpal_string_wton( tmpW );
        }
        else if( rSequence_getSTRINGA( notif, RP_TAGS_STRING_PATTERN, &tmpA ) )
        {
            ctx.expr = rpal_string_aton( tmpA );
        }

        if( !rSequence_getBUFFER( notif, RP_TAGS_HASH, (RPU8*)&ctx.pHash, &hashSize ) ||
            sizeof( *ctx.pHash ) != hashSize )
        {
            // Unexpected hash size, let's not gamble 
            ctx.pHash = NULL;
        }
    }

    if( rMutex_lock( g_cacheMutex ) )
    {
        if( NULL != ( foundDocs = rList_new( RP_TAGS_FILE_INFO, RPCM_SEQUENCE ) ) )
        {
            while( HbsRingBuffer_find( g_documentCache, (HbsRingBufferCompareFunc)findDoc, &ctx, &tmp ) )
            {
                // TODO: optimize this since if we're dealing with large files
                // we will be temporarily using large amounts of duplicate memory.
                // We just need to do some shallow free of the datastructures
                // somehow.
                if( NULL != ( tmp = rSequence_duplicate( tmp ) ) )
                {
                    if( !rList_addSEQUENCE( foundDocs, tmp ) )
                    {
                        rSequence_free( tmp );
                    }
                }
            }

            if( !rSequence_addLIST( notif, RP_TAGS_FILES, foundDocs ) )
            {
                rList_free( foundDocs );
            }
        }

        rMutex_unlock( g_cacheMutex );

        hbs_publish( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REP, notif );
    }

    rpal_memory_free( ctx.expr );
}

RPRIVATE
RBOOL
    _addPattern
    (
        HObs matcher,
        RPNCHAR pattern,
        RBOOL isSuffix
    )
{
    RBOOL isSuccess = FALSE;
    RBOOL isCaseInsensitive = FALSE;
    RPNCHAR tmpN = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    // On Windows files and paths are not case sensitive.
    isCaseInsensitive = TRUE;
#endif
    if( rpal_string_expand( pattern, &tmpN ) )
    {
        isSuccess = obsLib_addStringPatternN( matcher, tmpN, isSuffix, isCaseInsensitive, NULL );
        rpal_memory_free( tmpN );
    }
    return isSuccess;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_18_events[] = { RP_TAGS_NOTIFICATION_NEW_DOCUMENT,
                                   RP_TAGS_NOTIFICATION_GET_DOCUMENT_REP,
                                   0 };

RBOOL
    collector_18_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    rList extensions = NULL;
    rList patterns = NULL;
    RPCHAR strA = NULL;
    RPWCHAR strW = NULL;
    RPNCHAR tmpN = NULL;
    RU32 maxSize = 0;

    if( NULL != hbsState )
    {
        if( NULL != config )
        {
            rSequence_getLIST( config, RP_TAGS_EXTENSIONS, &extensions );
            rSequence_getLIST( config, RP_TAGS_PATTERNS, &patterns );

            if( NULL != ( g_cacheMutex = rMutex_create() ) &&
                NULL != ( g_matcher = obsLib_new( 0, 0 ) ) )
            {
                g_cacheSize = 0;
                if( NULL != config &&
                    rSequence_getRU32( config, RP_TAGS_MAX_SIZE, &maxSize ) )
                {
                    g_cacheMaxSize = maxSize;
                }
                else
                {
                    g_cacheMaxSize = MAX_CACHE_SIZE;
                }
                
                if( NULL != ( g_documentCache = HbsRingBuffer_new( 0, g_cacheMaxSize ) ) )
                {
                    if( NULL == config )
                    {
                        // As a default we'll cache all new files
                        obsLib_addPattern( g_matcher, (RPU8)_NC( "" ), sizeof( RNCHAR ), NULL );
                    }
                    else
                    {
                        // If a config was provided we'll cache only certain extensions
                        // specified.
                        while( rList_getSTRINGA( extensions, RP_TAGS_EXTENSION, &strA ) )
                        {
                            if( NULL != ( tmpN = rpal_string_aton( strA ) ) )
                            {
                                if( _addPattern( g_matcher, tmpN, TRUE ) )
                                {
                                    rpal_debug_info( "doc ext(a): " RF_STR_N ":", tmpN );
                                }
                                rpal_memory_free( tmpN );
                            }
                        }

                        while( rList_getSTRINGW( extensions, RP_TAGS_EXTENSION, &strW ) )
                        {
                            if( NULL != ( tmpN = rpal_string_wton( strW ) ) )
                            {
                                if( _addPattern( g_matcher, tmpN, TRUE ) )
                                {
                                    rpal_debug_info( "doc ext(w): " RF_STR_N ":", tmpN );
                                }
                                rpal_memory_free( tmpN );
                            }
                        }

                        while( rList_getSTRINGA( patterns, RP_TAGS_STRING_PATTERN, &strA ) )
                        {
                            if( NULL != ( tmpN = rpal_string_aton( strA ) ) )
                            {
                                if( _addPattern( g_matcher, tmpN, FALSE ) )
                                {
                                    rpal_debug_info( "doc path(a): " RF_STR_N ":", tmpN );
                                }
                                rpal_memory_free( tmpN );
                            }
                        }

                        while( rList_getSTRINGW( patterns, RP_TAGS_STRING_PATTERN, &strW ) )
                        {
                            if( NULL != ( tmpN = rpal_string_wton( strW ) ) )
                            {
                                if( _addPattern( g_matcher, tmpN, FALSE ) )
                                {
                                    rpal_debug_info( "doc path(w): " RF_STR_N ":", tmpN );
                                }
                                rpal_memory_free( tmpN );
                            }
                        }
                    }

                    if( rQueue_create( &g_createQueue, _freeEvt, 200 ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, 0, g_createQueue, NULL ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, 0, NULL, getDocument ) &&
                        rThreadPool_task( hbsState->hThreadPool, parseDocuments, NULL ) )
                    {
                        isSuccess = TRUE;
                    }
                }
            }

            if( !isSuccess )
            {
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, g_createQueue, NULL );
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, getDocument );
                rQueue_free( g_createQueue );
                g_createQueue = NULL;

                obsLib_free( g_matcher );
                HbsRingBuffer_free( g_documentCache );
                g_matcher = NULL;
                g_documentCache = NULL;

                rMutex_free( g_cacheMutex );
                g_cacheMutex = NULL;
            }
        }
        else
        {
            // No config provided, it's ok.
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_18_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, g_createQueue, NULL );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, getDocument );
        rQueue_free( g_createQueue );
        g_createQueue = NULL;

        obsLib_free( g_matcher );
        HbsRingBuffer_free( g_documentCache );
        g_matcher = NULL;
        g_documentCache = NULL;

        rMutex_free( g_cacheMutex );
        g_cacheMutex = NULL;

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_18_update
    (
        HbsState* hbsState,
        rSequence update
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( update );

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
HBS_TEST_SUITE( 18 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}