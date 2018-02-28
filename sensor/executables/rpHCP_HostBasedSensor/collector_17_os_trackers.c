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
#include <processLib/processLib.h>
#include <libOs/libOs.h>
#include <cryptoLib/cryptoLib.h>


#define RPAL_FILE_ID       101

#define _DIFF_TIMEOUT       (1000*60*5)

RPRIVATE RU32 g_diff_timeout = _DIFF_TIMEOUT;

RPRIVATE
RS32
    _cmpHashes
    (
        CryptoLib_Hash* pHash1,
        CryptoLib_Hash* pHash2
    )
{
    RS32 ret = (RU32)(-1);

    if( NULL != pHash1 &&
        NULL != pHash2 )
    {
        ret = (RS32)rpal_memory_memcmp( pHash1, pHash2, sizeof( *pHash1 ) );
    }

    return ret;
}


RPRIVATE
RVOID
    _elemToHash
    (
        rSequence elem,
        CryptoLib_Hash* pHash
    )
{
    rBlob blob = NULL;

    if( rpal_memory_isValid( elem ) &&
        NULL != pHash &&
        NULL != ( blob = rpal_blob_create( 0, 0 ) ) )
    {
        if( rSequence_serialise( elem, blob ) )
        {
            CryptoLib_hash( (CryptoLib_Hash*)rpal_blob_getBuffer( blob ), rpal_blob_getSize( blob ), pHash );
        }

        rpal_blob_free( blob );
    }
}

RPRIVATE
RVOID
    _processSnapshot
    (
        rList snapshot,
        CryptoLib_Hash** prevSnapshot,
        RU32* prevNumElem,
        rpcm_tag elemTag,
        rpcm_tag notifTag
    )
{
    CryptoLib_Hash hash = { 0 };
    RU32 i = 0;
    CryptoLib_Hash* tmpSnap = NULL;
    rSequence elem = NULL;

    if( NULL == prevSnapshot ||
        NULL == prevNumElem )
    {
        return;
    }

    if( NULL != ( tmpSnap = rpal_memory_alloc( sizeof( hash ) * rList_getNumElements( snapshot ) ) ) )
    {
        i = 0;
        while( rList_getSEQUENCE( snapshot, elemTag, &elem ) )
        {
            _elemToHash( elem, &hash );
            tmpSnap[ i ] = hash;

            if( NULL != *prevSnapshot )
            {
                if( ( -1 ) == rpal_binsearch_array( *prevSnapshot,
                                                    *prevNumElem,
                                                    sizeof( hash ),
                                                    &hash,
                                                    (rpal_ordering_func)_cmpHashes ) )
                {
                    hbs_timestampEvent( elem, 0 );
                    hbs_publish( notifTag, elem );
                }
            }

            i++;
        }

        FREE_AND_NULL( *prevSnapshot );
        *prevSnapshot = tmpSnap;
        *prevNumElem = i;
        tmpSnap = NULL;
        rpal_sort_array( *prevSnapshot, *prevNumElem, sizeof( hash ), (rpal_ordering_func)_cmpHashes );
    }
}

RPRIVATE
RPVOID
    osTrackerDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    CryptoLib_Hash* prevServices = NULL;
    RU32 prevNServices = 0;

    CryptoLib_Hash* prevDrivers = NULL;
    RU32 prevNDrivers = 0;

    CryptoLib_Hash* prevAutoruns = NULL;
    RU32 prevNAutoruns = 0;

    rList snapshot = NULL;

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, g_diff_timeout ) )
    {
        rpal_debug_info( "looking for changes in os snapshots" );

        if( NULL != ( snapshot = libOs_getServices( TRUE ) ) )
        {
            _processSnapshot( snapshot, 
                              &prevServices, 
                              &prevNServices,
                              RP_TAGS_SVC, 
                              RP_TAGS_NOTIFICATION_SERVICE_CHANGE );

            rList_free( snapshot );
        }

        if( rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
        {
            break;
        }

#ifdef RPAL_PLATFORM_WINDOWS
// Drivers are only available on Windows
        if( NULL != ( snapshot = libOs_getDrivers( TRUE ) ) )
        {
            _processSnapshot( snapshot,
                              &prevDrivers,
                              &prevNDrivers,
                              RP_TAGS_SVC,
                              RP_TAGS_NOTIFICATION_DRIVER_CHANGE );

            rList_free( snapshot );
        }

        if( rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
        {
            break;
        }
#endif

#if defined( RPAL_PLATFORM_WINDOWS ) || defined( RPAL_PLATFORM_MACOSX )
// Services are currently only available on OSX and Windows
        if( NULL != ( snapshot = libOs_getAutoruns( TRUE ) ) )
        {
            _processSnapshot( snapshot,
                              &prevAutoruns,
                              &prevNAutoruns,
                              RP_TAGS_SVC,
                              RP_TAGS_NOTIFICATION_AUTORUN_CHANGE );

            rList_free( snapshot );
        }

        rpal_debug_info( "finished updating snapshots" );
#endif
    }

    FREE_AND_NULL( prevServices );
    FREE_AND_NULL( prevDrivers );
    FREE_AND_NULL( prevAutoruns );

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_17_events[] = { RP_TAGS_NOTIFICATION_SERVICE_CHANGE,
                                   RP_TAGS_NOTIFICATION_DRIVER_CHANGE,
                                   RP_TAGS_NOTIFICATION_AUTORUN_CHANGE,
                                   0 };

RBOOL
    collector_17_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState )
    {
        if( NULL != config )
        {
            rSequence_getRU32( config, RP_TAGS_TIMEDELTA, &g_diff_timeout );
        }

        if( rThreadPool_task( hbsState->hThreadPool, osTrackerDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_17_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        rpal_memory_isValid( config ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_17_update
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
HBS_TEST_SUITE( 17 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}