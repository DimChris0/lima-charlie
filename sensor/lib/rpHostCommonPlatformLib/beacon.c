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

#include "beacon.h"
#include "configurations.h"
#include "globalContext.h"
#include "obfuscated.h"
#include <obfuscationLib/obfuscationLib.h>
#include <zlib/zlib.h>
#include <cryptoLib/cryptoLib.h>
#include "crypto.h"
#include <rpHostCommonPlatformLib/rTags.h>
#include <libOs/libOs.h>
#include "commands.h"
#include "crashHandling.h"
#include <networkLib/networkLib.h>
#include "git_info.h"
#include <processLib/processLib.h>

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <dlfcn.h>
#endif

#define RPAL_FILE_ID     50

//=============================================================================
//  Private defines and datastructures
//=============================================================================
#define FRAME_MAX_SIZE      (1024 * 1024 * 50)
#define CLOUD_SYNC_TIMEOUT  (MSEC_FROM_SEC(60 * 10))
#define TLS_CONNECT_TIMEOUT (30)
#define TLS_FIRST_RECV_TIMEOUT (10)
#define TLS_NORMAL_RECV_TIMEOUT (60 * 60 * 24)

RPRIVATE
struct
{
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
} g_tlsConnection;

RPRIVATE rMutex g_tlsMutex = NULL;;

//=============================================================================
//  Helpers
//=============================================================================
RPRIVATE_TESTABLE
rBlob
    wrapFrame
    (
        RpHcp_ModuleId moduleId,
        rList messages,
        RBOOL isIncludeUncompressedSize // For testing purposes
    )
{
    rBlob blob = NULL;
    RPU8 buffer = NULL;
    RSIZET size = 0;
    RU32 uncompressedSize = 0;

    if( NULL != messages &&
        NULL != ( blob = rpal_blob_create( 0, 0 ) ) )
    {
        if( !rpal_blob_add( blob, &moduleId, sizeof( moduleId ) ) ||
            !rList_serialise( messages, blob ) )
        {
            rpal_blob_free( blob );
            blob = NULL;
        }
        else
        {
            uncompressedSize = rpal_blob_getSize( blob );
            size = compressBound( uncompressedSize );
            uncompressedSize = rpal_hton32( uncompressedSize );
            if( NULL == ( buffer = rpal_memory_alloc( size ) ) ||
                Z_OK != compress( buffer, 
                                  (uLongf*)&size, 
                                  rpal_blob_getBuffer( blob ), 
                                  rpal_blob_getSize( blob ) ) ||
              !rpal_blob_freeBufferOnly( blob ) ||
              !rpal_blob_setBuffer( blob, buffer, (RU32)size ) ||
              ( isIncludeUncompressedSize && 
                !rpal_blob_insert( blob, &uncompressedSize, sizeof( uncompressedSize ), 0 ) ) )
            {
                rpal_memory_free( buffer );
                rpal_blob_free( blob );
                buffer = NULL;
                blob = NULL;
            }
        }
    }

    return blob;
}

RPRIVATE_TESTABLE
RBOOL
    unwrapFrame
    (
        rBlob frame,
        RpHcp_ModuleId* pModuleId,
        rList* pMessages
    )
{
    RBOOL isUnwrapped = FALSE;
    RSIZET uncompressedSize = 0;
    RPU8 uncompressedFrame = NULL;
    RU32 uncompErr = 0;
    RU32 bytesConsumed = 0;

    if( NULL != frame &&
        NULL != pModuleId &&
        NULL != pMessages )
    {
        uncompressedSize = rpal_ntoh32( *(RU32*)rpal_blob_getBuffer( frame ) );
        if( FRAME_MAX_SIZE >= uncompressedSize &&
            NULL != ( uncompressedFrame = rpal_memory_alloc( uncompressedSize ) ) )
        {
            if( Z_OK == ( uncompErr = uncompress( uncompressedFrame,
                                                  (uLongf*)&uncompressedSize,
                                                  (RPU8)( rpal_blob_getBuffer( frame ) ) + sizeof( RU32 ),
                                                  rpal_blob_getSize( frame ) ) ) )
            {
                *pModuleId = *(RpHcp_ModuleId*)uncompressedFrame;

                if( rList_deserialise( pMessages,
                                       uncompressedFrame + sizeof( RpHcp_ModuleId ),
                                       (RU32)uncompressedSize,
                                       &bytesConsumed ) )
                {
                    if( bytesConsumed + sizeof( RpHcp_ModuleId ) == uncompressedSize )
                    {
                        isUnwrapped = TRUE;
                    }
                    else
                    {
                        rpal_debug_warning( "deserialization buffer size mismatch" );
                        rList_free( *pMessages );
                        *pMessages = NULL;
                        *pModuleId = 0;
                    }
                }
                else
                {
                    rpal_debug_warning( "failed to deserialize frame" );
                }
            }
            else
            {
                rpal_debug_warning( "failed to decompress frame: %d", uncompErr );
            }

            rpal_memory_free( uncompressedFrame );
        }
        else
        {
            rpal_debug_warning( "invalid decompressed size %d", uncompressedSize );
        }
    }

    return isUnwrapped;
}

RPRIVATE_TESTABLE
RBOOL
    sendFrame
    (
        rpHCPContext* pContext,
        RpHcp_ModuleId moduleId,
        rList messages,
        RBOOL isForAnotherSensor
    )
{
    RBOOL isSent = FALSE;
    rBlob buffer = NULL;
    RU32 frameSize = 0;
    RS32 mbedRet = 0;
    RU32 toSend = 0;
    RPU8 buffToSend = NULL;
    RU32 offset = 0;

    if( NULL != pContext &&
        NULL != messages )
    {
        if( NULL != ( buffer = wrapFrame( moduleId, messages, isForAnotherSensor ) ) )
        {
            if( 0 != ( frameSize = rpal_blob_getSize( buffer ) ) &&
                0 != ( frameSize = rpal_hton32( frameSize ) ) &&
                rpal_blob_insert( buffer, &frameSize, sizeof( frameSize ), 0 ) )
            {
                toSend = rpal_blob_getSize( buffer );
                buffToSend = rpal_blob_getBuffer( buffer );
                
                do
                {
                    mbedRet = 0;

                    if( rMutex_lock( g_tlsMutex ) )
                    {
                        mbedRet = mbedtls_ssl_write( &g_tlsConnection.ssl, buffToSend + offset, toSend - offset );

                        rMutex_unlock( g_tlsMutex );
                    }

                    if( 0 < mbedRet )
                    {
                        offset += mbedRet;

                        if( offset == toSend )
                        {
                            isSent = TRUE;
                            break;
                        }
                    }
                    else if( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                             MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet )
                    {
                        break;
                    }
                } while( !rEvent_wait( pContext->isBeaconTimeToStop, 100 ) );
            }

            rpal_blob_free( buffer );
        }
    }

    return isSent;
}

RPRIVATE_TESTABLE
RBOOL
    recvFrame
    (
        rpHCPContext* pContext,
        RpHcp_ModuleId* targetModuleId,
        rList* pMessages,
        RU32 timeoutSec
    )
{
    RBOOL isSuccess = FALSE;
    RU32 frameSize = 0;
    rBlob frame = NULL;
    RS32 mbedRet = 0;
    RU32 offset = 0;
    RTIME endTime = ( 0 == timeoutSec ? 0 : rpal_time_getLocal() + timeoutSec );
    
    if( NULL != pContext &&
        NULL != targetModuleId &&
        NULL != pMessages )
    {
        do
        {
            mbedRet = 0;

            if( rMutex_lock( g_tlsMutex ) )
            {
                mbedRet = mbedtls_ssl_read( &g_tlsConnection.ssl, (RPU8)&frameSize + offset, sizeof( frameSize ) - offset );

                rMutex_unlock( g_tlsMutex );
            }

            if( 0 < mbedRet )
            {
                offset += mbedRet;
                if( offset == sizeof( frameSize ) )
                {
                    isSuccess = TRUE;
                    break;
                }
            }
            else if( 0 == mbedRet ||
                     MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY  == mbedRet )
            {
                break;
            }
            else if( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                     MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet )
            {
                break;
            }
        } while( !rEvent_wait( pContext->isBeaconTimeToStop, 100 ) &&
                 ( 0 == endTime || rpal_time_getLocal() <= endTime ) );

        if( isSuccess )
        {
            isSuccess = FALSE;
            offset = 0;

            frameSize = rpal_ntoh32( frameSize );
            if( FRAME_MAX_SIZE >= frameSize &&
                0 != frameSize &&
                NULL != ( frame = rpal_blob_create( frameSize, 0 ) ) &&
                rpal_blob_add( frame, NULL, frameSize ) )
            {
                do
                {
                    mbedRet = 0;

                    if( rMutex_lock( g_tlsMutex ) )
                    {
                        mbedRet = mbedtls_ssl_read( &g_tlsConnection.ssl, (RPU8)rpal_blob_getBuffer( frame ) + offset, frameSize - offset );

                        rMutex_unlock( g_tlsMutex );
                    }

                    if( 0 < mbedRet )
                    {
                        offset += mbedRet;
                        if( offset == frameSize )
                        {
                            isSuccess = TRUE;
                            break;
                        }
                    }
                    else if( 0 == mbedRet ||
                        MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == mbedRet )
                    {
                        break;
                    }
                    else if( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                             MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet )
                    {
                        break;
                    }
                } while( !rEvent_wait( pContext->isBeaconTimeToStop, 100 ) &&
                         ( 0 == endTime || rpal_time_getLocal() <= endTime ) );
            }
        }

        if( isSuccess )
        {
            isSuccess = FALSE;

            if( unwrapFrame( frame, targetModuleId, pMessages ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_warning( "failed to unwrap frame" );
            }
        }

        rpal_blob_free( frame );
    }

    return isSuccess;
}

RPRIVATE
rList
    generateHeaders
    (
        RBOOL isInitialGeneration
    )
{
    rList wrapper = NULL;
    rSequence headers = NULL;
    rSequence hcpId = NULL;
    RPCHAR hostName = NULL;

    RPU8 crashContext = NULL;
    RU32 crashContextSize = 0;
    RU8 defaultCrashContext = 1;
    RPNCHAR currentPath = NULL;
    CryptoLib_Hash currentHash = { 0 };

    if( NULL != ( wrapper = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( headers = rSequence_new() ) )
        {
            if( rList_addSEQUENCE( wrapper, headers ) )
            {
                // We only check for crash contexts on the inital header generation after
                // a startup since we will create a crash context right after.
                if( isInitialGeneration )
                {
                    // First let's check if we have a crash context already present
                    // which would indicate we did not shut down properly
                    if( !acquireCrashContextPresent( &crashContext, &crashContextSize ) )
                    {
                        crashContext = NULL;
                        crashContextSize = 0;
                    }
                    else
                    {
                        rSequence_addBUFFER( headers, RP_TAGS_HCP_CRASH_CONTEXT, crashContext, crashContextSize );
                        rpal_memory_free( crashContext );
                        crashContext = NULL;
                        crashContextSize = 0;
                    }

                    // Set a default crashContext to be removed before exiting
                    setCrashContext( &defaultCrashContext, sizeof( defaultCrashContext ) );
                }

                // This is our identity
                if( NULL != ( hcpId = hcpIdToSeq( g_hcpContext.currentId ) ) )
                {
                    if( !rSequence_addSEQUENCE( headers, RP_TAGS_HCP_IDENT, hcpId ) )
                    {
                        rSequence_free( hcpId );
                    }
                }

                // The current host name
                if( NULL != ( hostName = libOs_getHostName() ) )
                {
                    rSequence_addSTRINGA( headers, RP_TAGS_HOST_NAME, hostName );
                    rpal_memory_free( hostName );
                }

                // Current internal IP address
                rSequence_addIPV4( headers, RP_TAGS_IP_ADDRESS, libOs_getMainIp() );

                // Enrollment token as received during enrollment
                if( NULL != g_hcpContext.enrollmentToken &&
                    0 != g_hcpContext.enrollmentTokenSize )
                {
                    rSequence_addBUFFER( headers,
                                         RP_TAGS_HCP_ENROLLMENT_TOKEN,
                                         g_hcpContext.enrollmentToken,
                                         g_hcpContext.enrollmentTokenSize );
                }

                // The current version running.
                rSequence_addRU32( headers, RP_TAGS_PACKAGE_VERSION, GIT_REVISION );

                // Get the hash of the current module.
                if( NULL != ( currentPath = processLib_getCurrentModulePath() ) )
                {
                    if( CryptoLib_hashFile( currentPath, &currentHash, FALSE ) )
                    {
                        rSequence_addBUFFER( headers, RP_TAGS_HASH, (RPU8)&currentHash, sizeof( currentHash ) );
                    }
                    else
                    {
                        rpal_debug_warning( "could not get current HCP hash." );
                    }

                    rpal_memory_free( currentPath );
                }
                else
                {
                    rpal_debug_warning( "could not get current HCP path." );
                }
            }
            else
            {
                rSequence_free( headers );
                rList_free( wrapper );
                wrapper = NULL;
            }
        }
        else
        {
            rList_free( wrapper );
            wrapper = NULL;
        }
    }

    return wrapper;
}

//=============================================================================
//  Base beacon
//=============================================================================
RPRIVATE
RU32
    RPAL_THREAD_FUNC thread_sync
    (
        RPVOID context
    )
{
    rList wrapper = NULL;
    rSequence message = NULL;
    rList modList = NULL;
    rSequence modEntry = NULL;
    RU32 moduleIndex = 0;

    RU32 timeout = MSEC_FROM_SEC( 30 );
    RBOOL isEnrolled = FALSE;

    UNREFERENCED_PARAMETER( context );

    // Blanket wait initially to give it a chance to connect.
    rEvent_wait( g_hcpContext.isCloudOnline, MSEC_FROM_SEC( 5 ) );

    do
    {
        if( NULL != getC2PublicKey() )
        {
            isEnrolled = TRUE;
        }

        if( !rEvent_wait( g_hcpContext.isCloudOnline, 0 ) )
        {
            // Not online, no need to try.
            continue;
        }

        rpal_debug_info( "Currently online, sync." );

        if( NULL != ( wrapper = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
        {
            if( NULL != ( message = rSequence_new() ) )
            {
                // Add some basic info
                rSequence_addRU32( message, RP_TAGS_MEMORY_USAGE, rpal_memory_totalUsed() );
                rSequence_addTIMESTAMP( message, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() );

                if( NULL != ( modList = rList_new( RP_TAGS_HCP_MODULE, RPCM_SEQUENCE ) ) )
                {
                    for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
                    {
                        if( NULL != g_hcpContext.modules[ moduleIndex ].hModule )
                        {
                            if( NULL != ( modEntry = rSequence_new() ) )
                            {
                                if( !rSequence_addBUFFER( modEntry,
                                                          RP_TAGS_HASH,
                                                          (RPU8)&( g_hcpContext.modules[ moduleIndex ].hash ),
                                                          sizeof( g_hcpContext.modules[ moduleIndex ].hash ) ) ||
                                    !rSequence_addRU8( modEntry,
                                                       RP_TAGS_HCP_MODULE_ID,
                                                       g_hcpContext.modules[ moduleIndex ].id ) ||
                                    !rList_addSEQUENCE( modList, modEntry ) )
                                {
                                    break;
                                }

                                // We take the opportunity to cleanup the list of modules...
                                if( rpal_thread_wait( g_hcpContext.modules[ moduleIndex ].hThread, 0 ) )
                                {
                                    // This thread has exited, which is our signal that the module
                                    // has stopped executing...
                                    rEvent_free( g_hcpContext.modules[ moduleIndex ].isTimeToStop );
                                    rpal_thread_free( g_hcpContext.modules[ moduleIndex ].hThread );
                                    if( g_hcpContext.modules[ moduleIndex ].isOsLoaded )
                                    {
#ifdef RPAL_PLATFORM_WINDOWS
                                        FreeLibrary( (HMODULE)( g_hcpContext.modules[ moduleIndex ].hModule ) );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                                        dlclose( g_hcpContext.modules[ moduleIndex ].hModule );
#endif
                                    }
                                    else
                                    {
                                        MemoryFreeLibrary( g_hcpContext.modules[ moduleIndex ].hModule );
                                    }
                                    rpal_memory_zero( &( g_hcpContext.modules[ moduleIndex ] ),
                                                      sizeof( g_hcpContext.modules[ moduleIndex ] ) );

                                    if( !rSequence_addRU8( modEntry, RP_TAGS_HCP_MODULE_TERMINATED, 1 ) )
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if( !rSequence_addLIST( message, RP_TAGS_HCP_MODULES, modList ) )
                    {
                        rList_free( modList );
                    }
                }

                if( !rList_addSEQUENCE( wrapper, message ) )
                {
                    rSequence_free( message );
                }
            }

            if( doSend( RP_HCP_MODULE_ID_HCP, wrapper ) )
            {
                // On successful sync, wait full period before another sync.
                if( isEnrolled )
                {
                    timeout = CLOUD_SYNC_TIMEOUT;
                }
                else
                {
                    // We were not enrolled when we started this sync so we'll
                    // do another sync sooner.
                    timeout = MSEC_FROM_SEC( 10 );
                }
            }
            else
            {
                rpal_debug_warning( "sending sync failed, we may be offline" );
            }

            rList_free( wrapper );
        }
    } while( !rEvent_wait( g_hcpContext.isBeaconTimeToStop, timeout ) );

    rEvent_unset( g_hcpContext.isCloudOnline );

    return 0;
}

RPRIVATE
RVOID
    closeCloudConnection
    (

    )
{
    if( rMutex_lock( g_tlsMutex ) )
    {
        mbedtls_ssl_close_notify( &g_tlsConnection.ssl );
        mbedtls_net_free( &g_tlsConnection.server_fd );
        if( NULL != getC2PublicKey() )
        {
            mbedtls_x509_crt_free( &g_tlsConnection.cacert );
        }
        mbedtls_ssl_free( &g_tlsConnection.ssl );
        mbedtls_ssl_config_free( &g_tlsConnection.conf );
        mbedtls_ctr_drbg_free( &g_tlsConnection.ctr_drbg );
        mbedtls_entropy_free( &g_tlsConnection.entropy );

        rpal_memory_zero( &g_tlsConnection, sizeof( g_tlsConnection ) );

        rMutex_unlock( g_tlsMutex );
    }
}

RPRIVATE
RU32
    RPAL_THREAD_FUNC thread_conn
    (
        RPVOID context
    )
{
    OBFUSCATIONLIB_DECLARE( defaultDest, RP_HCP_CONFIG_HOME_URL_DEFAULT );

    RPCHAR currentDest = NULL;
    RU16 currentPort = 0;
    RCHAR currentPortStr[ 6 ] = { 0 };
    rThread syncThread = NULL;
    RBOOL isFirstConnection = TRUE;

    UNREFERENCED_PARAMETER( context );

    if( NULL == ( syncThread = rpal_thread_new( thread_sync, NULL ) ) )
    {
        rpal_debug_error( "could not start sync thread" );
        return 0;
    }
    
    while( !rEvent_wait( g_hcpContext.isBeaconTimeToStop, 0 ) )
    {
        RBOOL isHandshakeComplete = FALSE;
        RBOOL isHeadersSent = FALSE;

        
        RS32 mbedRet = 0;
        RTIME tlsConnectTimeout = rpal_time_getLocal() + TLS_CONNECT_TIMEOUT;

        rMutex_lock( g_tlsMutex );

        rpal_memory_zero( &g_tlsConnection, sizeof( g_tlsConnection ) );

        mbedtls_net_init( &g_tlsConnection.server_fd );
        mbedtls_ssl_init( &g_tlsConnection.ssl );
        mbedtls_ssl_config_init( &g_tlsConnection.conf );
        mbedtls_x509_crt_init( &g_tlsConnection.cacert );
        mbedtls_ctr_drbg_init( &g_tlsConnection.ctr_drbg );
        mbedtls_entropy_init( &g_tlsConnection.entropy );

        if( 0 == ( mbedRet = mbedtls_ctr_drbg_seed( &g_tlsConnection.ctr_drbg,
                                                    mbedtls_entropy_func,
                                                    &g_tlsConnection.entropy,
                                                    NULL,
                                                    0 ) ) )
        {
            if( NULL == getC2PublicKey() )
            {
                rpal_debug_warning( "no c2 public key found, this is only ok if this is the first time the sensor is starting or in debugging." );
            }

            if( NULL == getC2PublicKey() ||
                0 == ( mbedRet = mbedtls_x509_crt_parse( &g_tlsConnection.cacert,
                                                         getC2PublicKey(),
                                                         rpal_string_strlenA( (RPCHAR)getC2PublicKey() ) + 1 ) ) )
            {
                // Figure out which destination to use.
                if( currentDest == g_hcpContext.primaryUrl )
                {
                    currentDest = g_hcpContext.secondaryUrl;
                    currentPort = g_hcpContext.secondaryPort;
                }
                else if( currentDest == g_hcpContext.secondaryUrl )
                {
                    currentDest = g_hcpContext.primaryUrl;
                    currentPort = g_hcpContext.primaryPort;
                }
                else if( (RPCHAR)defaultDest != currentDest )
                {
                    currentDest = g_hcpContext.primaryUrl;
                    currentPort = g_hcpContext.primaryPort;
                }

                if( NULL == currentDest )
                {
                    OBFUSCATIONLIB_TOGGLE( defaultDest );
                    currentDest = (RPCHAR)defaultDest;
                    currentPort = RP_HCP_CONFIG_HOME_PORT_DEFAULT;
                }

                if( 0 == currentPort ) currentPort = 443;
                rpal_string_itosA( currentPort, currentPortStr, 10 );

                if( 0 == ( mbedRet = mbedtls_net_connect( &g_tlsConnection.server_fd,
                                                          currentDest, 
                                                          currentPortStr, 
                                                          MBEDTLS_NET_PROTO_TCP ) ) )
                {
                    mbedtls_net_set_nonblock( &g_tlsConnection.server_fd );

                    if( 0 == ( mbedRet = mbedtls_ssl_config_defaults( &g_tlsConnection.conf,
                                                                      MBEDTLS_SSL_IS_CLIENT,
                                                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                                                      MBEDTLS_SSL_PRESET_DEFAULT ) ) )
                    {
#ifndef HCP_NO_TLS_VALIDATION
                        if( NULL != getC2PublicKey() )
                        {
                            mbedtls_ssl_conf_authmode( &g_tlsConnection.conf, MBEDTLS_SSL_VERIFY_REQUIRED );
                            mbedtls_ssl_conf_ca_chain( &g_tlsConnection.conf, &g_tlsConnection.cacert, NULL );
                        }
                        else
#endif
                        {
                            mbedtls_ssl_conf_authmode( &g_tlsConnection.conf, MBEDTLS_SSL_VERIFY_NONE );
                        }

                        mbedtls_ssl_conf_rng( &g_tlsConnection.conf, mbedtls_ctr_drbg_random, &g_tlsConnection.ctr_drbg );

                        if( 0 == ( mbedRet = mbedtls_ssl_setup( &g_tlsConnection.ssl, &g_tlsConnection.conf ) ) )
                        {
                            mbedtls_ssl_set_bio( &g_tlsConnection.ssl,
                                                 &g_tlsConnection.server_fd,
                                                 mbedtls_net_send,
                                                 mbedtls_net_recv,
                                                 NULL );

                            while( 0 != ( mbedRet = mbedtls_ssl_handshake( &g_tlsConnection.ssl ) ) )
                            {
                                if( ( MBEDTLS_ERR_SSL_WANT_READ != mbedRet &&
                                      MBEDTLS_ERR_SSL_WANT_WRITE != mbedRet ) ||
                                    rEvent_wait( g_hcpContext.isBeaconTimeToStop, 100 ) ||
                                    rpal_time_getLocal() > tlsConnectTimeout )
                                {
                                    break;
                                }
                            }

                            if( 0 == mbedRet )
                            {
                                if( NULL == getC2PublicKey() ||
                                    0 == ( mbedRet = mbedtls_ssl_get_verify_result( &g_tlsConnection.ssl ) ) )
                                {
                                    isHandshakeComplete = TRUE;
                                    rpal_debug_info( "TLS handshake complete." );
                                }
                                else
                                {
                                    rpal_debug_error( "failed to validate remote certificate: %d", mbedRet );
                                }
                            }
                            else
                            {
                                rpal_debug_error( "TLS handshake failed: %d", mbedRet );
                            }
                        }
                    }
                    else
                    {
                        rpal_debug_error( "error setting TLS defaults: %d", mbedRet );
                    }
                }
                else
                {
                    rpal_debug_error( "error connecting over TLS: %d", mbedRet );
                }
            }
            else
            {
                rpal_debug_error( "error parsing C2 cert: %d", mbedRet );
            }
        }
        else
        {
            rpal_debug_error( "failed to seed random number generator: %d", mbedRet );
        }

        rMutex_unlock( g_tlsMutex );
        
        if( isHandshakeComplete )
        {
            // Send the headers
            rList headers = generateHeaders( isFirstConnection );
            isFirstConnection = FALSE;
            if( NULL != headers )
            {
                if( sendFrame( &g_hcpContext, RP_HCP_MODULE_ID_HCP, headers, FALSE ) )
                {
                    isHeadersSent = TRUE;
                }

                rList_free( headers );
            }
        }
        else
        {
#ifdef RPAL_PLATFORM_DEBUG
            RCHAR tmpError[ 1024 ] = { 0 };
            mbedtls_strerror( mbedRet, tmpError, sizeof( tmpError ) );
            rpal_debug_warning( "failed to handshake: " RF_STR_A, tmpError );
#else
            rpal_debug_warning( "failed to handshake" );
#endif
        }

        if( !isHeadersSent )
        {
            rpal_debug_warning( "failed to send headers" );
            closeCloudConnection();
        }

        if( isHeadersSent )
        {
            // Notify the modules of the connect.
            RU32 moduleIndex = 0;
            RBOOL isNewConnection = TRUE;
            rpal_debug_info( "comms channel up with the cloud, waiting for first message" );

            do
            {
                rList messages = NULL;
                rSequence message = NULL;
                RpHcp_ModuleId targetModuleId = 0;

                // If this is a new connection, we expect a message from the cloud very 
                // shortly, otherwise it's a problem. But if the connection is established
                // we can wait for a very long time.
                if( !recvFrame( &g_hcpContext, 
                                &targetModuleId, 
                                &messages, 
                                isNewConnection ? TLS_FIRST_RECV_TIMEOUT : TLS_NORMAL_RECV_TIMEOUT ) )
                {
                    rpal_debug_warning( "error receiving frame" );
                    break;
                }

                // Secure channel is up and running as we've received successfully a single
                // message from the cloud, start receiving messages.
                if( isNewConnection )
                {
                    isNewConnection = FALSE;
                    rEvent_set( g_hcpContext.isCloudOnline );
                    rpal_debug_info( "first message received, signaling channel internally" );
                }

                // HCP is not a module so check manually
                if( RP_HCP_MODULE_ID_HCP == targetModuleId )
                {
                    while( rList_getSEQUENCE( messages, RP_TAGS_MESSAGE, &message ) )
                    {
                        processMessage( message );
                    }

                    // If we don't have a configStore with keys for a deployment we require the first
                    // HCP frame to come from the c2 to contain the new store, otherwise
                    // we consider it's not a valid c2 and reconnect. This is to protect a new sensor
                    // from contacting a rogue c2 and getting taskings from it.
                    if( NULL == getC2PublicKey() )
                    {
#ifndef HCP_NO_TLS_VALIDATION
                        rpal_debug_warning( "contacted the cloud but did not receive a valid enrollment, exiting" );
                        rList_free( messages );
                        messages = NULL;
                        break;
#endif
                    }
                }
                else
                {
                    // Look for the module this message is destined to
                    for( moduleIndex = 0; moduleIndex < ARRAY_N_ELEM( g_hcpContext.modules ); moduleIndex++ )
                    {
                        if( targetModuleId == g_hcpContext.modules[ moduleIndex ].id )
                        {
                            if( NULL != g_hcpContext.modules[ moduleIndex ].func_recvMessage )
                            {
                                while( rList_getSEQUENCE( messages, RP_TAGS_MESSAGE, &message ) )
                                {
                                    g_hcpContext.modules[ moduleIndex ].func_recvMessage( message );
                                }
                            }

                            break;
                        }
                    }
                }

                rList_free( messages );
            } while( !g_hcpContext.isDoReconnect &&
                     !rEvent_wait( g_hcpContext.isBeaconTimeToStop, 0 ) );

            rEvent_unset( g_hcpContext.isCloudOnline );

            if( g_hcpContext.isDoReconnect )
            {
                g_hcpContext.isDoReconnect = FALSE;
            }

            closeCloudConnection();

            rpal_debug_info( "comms with cloud down" );
        }

        rEvent_wait( g_hcpContext.isBeaconTimeToStop, MSEC_FROM_SEC( 5 ) );
        rpal_debug_warning( "cycling destination" );
    }

    rpal_thread_wait( syncThread, MSEC_FROM_SEC( 10 ) );
    rpal_thread_free( syncThread );

    return 0;
}

//=============================================================================
//  API
//=============================================================================
RBOOL
    startBeacons
    (

    )
{
    RBOOL isSuccess = FALSE;

    g_hcpContext.isBeaconTimeToStop = rEvent_create( TRUE );

    if( NULL != g_hcpContext.isBeaconTimeToStop )
    {
        if( NULL != ( g_tlsMutex = rMutex_create() ) )
        {
            g_hcpContext.hBeaconThread = rpal_thread_new( thread_conn, NULL );

            if( 0 != g_hcpContext.hBeaconThread )
            {
                isSuccess = TRUE;
            }
            else
            {
                rMutex_free( g_tlsMutex );
                g_tlsMutex = NULL;
                rEvent_free( g_hcpContext.isBeaconTimeToStop );
                g_hcpContext.isBeaconTimeToStop = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    stopBeacons
    (

    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != g_hcpContext.isBeaconTimeToStop )
    {
        rEvent_set( g_hcpContext.isBeaconTimeToStop );

        if( 0 != g_hcpContext.hBeaconThread )
        {
            rpal_thread_wait( g_hcpContext.hBeaconThread, MSEC_FROM_SEC( 40 ) );
            rpal_thread_free( g_hcpContext.hBeaconThread );

            isSuccess = TRUE;
        }

        rEvent_free( g_hcpContext.isBeaconTimeToStop );
        g_hcpContext.isBeaconTimeToStop = NULL;
        rMutex_free( g_tlsMutex );
        g_tlsMutex = NULL;
    }

    return isSuccess;
}

RBOOL
    doSend
    (
        RpHcp_ModuleId sourceModuleId,
        rList toSend
    )
{
    RBOOL isSuccess = FALSE;

    // Do not check for toSend not being NULL since we now use it as a small
    // backward compatible trick to trigger a disconnections.

    if( rEvent_wait( g_hcpContext.isCloudOnline, 0 ) )
    {
        isSuccess = sendFrame( &g_hcpContext, sourceModuleId, toSend, FALSE );

        if( !isSuccess )
        {
            closeCloudConnection();
        }
    }

    return isSuccess;
}
