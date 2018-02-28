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


#define RPAL_FILE_ID       104

#define _DIFF_TIMEOUT       (1000*1)

RPRIVATE RU32 g_diff_timeout = _DIFF_TIMEOUT;

typedef struct
{
    CryptoLib_Hash hash;
    rSequence volume;
} _volEntry;

RPRIVATE
RS32
    _cmpHashes
    (
        CryptoLib_Hash* pHash1,
        CryptoLib_Hash* pHash2
    )
{
    RS32 ret = (RU32)( -1 );

    if( NULL != pHash1 &&
        NULL != pHash2 )
    {
        ret = (RS32)rpal_memory_memcmp( pHash1, pHash2, sizeof( *pHash1 ) );
    }

    return ret;
}

RPRIVATE
RPVOID
    volumeTrackerDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    _volEntry* prevVolumes = NULL;
    RU32 nVolumes = 0;
    rList snapshot = NULL;
    rList prevSnapshot = NULL;
    _volEntry* newVolumes = NULL;
    RU32 nNewVolumes = 0;
    rSequence volume = NULL;
    rBlob serial = NULL;
    RU32 i = 0;
    LibOsPerformanceProfile perfProfile = { 0 };

    UNREFERENCED_PARAMETER( ctx );

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
    perfProfile.lastTimeoutValue = 2000;
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 1;
    
    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        if( NULL != ( snapshot = libOs_getVolumes() ) )
        {
            if( NULL != ( newVolumes = rpal_memory_alloc( sizeof( *newVolumes ) *
                                                          rList_getNumElements( snapshot ) ) ) )
            {
                nNewVolumes = 0;

                while( !rEvent_wait( isTimeToStop, 0 ) &&
                       rList_getSEQUENCE( snapshot, RP_TAGS_VOLUME, &volume ) )
                {
                    libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

                    if( NULL != ( serial = rpal_blob_create( 0, 0 ) ) )
                    {
                        if( rSequence_serialise( volume, serial ) &&
                            CryptoLib_hash( rpal_blob_getBuffer( serial ),
                                            rpal_blob_getSize( serial ), 
                                            &( newVolumes[ nNewVolumes ].hash ) ) )
                        {
                            newVolumes[ nNewVolumes ].volume = volume;

                            if( NULL != prevVolumes &&
                                ( -1 ) == rpal_binsearch_array( prevVolumes,
                                                                nVolumes,
                                                                sizeof( *prevVolumes ),
                                                                &( newVolumes[ nNewVolumes ] ),
                                                                (rpal_ordering_func)_cmpHashes ) )
                            {
                                hbs_publish( RP_TAGS_NOTIFICATION_VOLUME_MOUNT, volume );
                                rpal_debug_info( "new volume mounted" );
                            }

                            nNewVolumes++;
                        }

                        rpal_blob_free( serial );
                    }
                }

                if( !rEvent_wait( isTimeToStop, 0 ) )
                {
                    rpal_sort_array( newVolumes,
                                     nNewVolumes,
                                     sizeof( *newVolumes ),
                                     (rpal_ordering_func)_cmpHashes );

                    for( i = 0; i < nVolumes; i++ )
                    {
                        libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

                        if( ( -1 ) == rpal_binsearch_array( newVolumes,
                                                            nNewVolumes,
                                                            sizeof( *newVolumes ),
                                                            &( prevVolumes[ i ].hash ),
                                                            (rpal_ordering_func)_cmpHashes ) )
                        {
                            hbs_publish( RP_TAGS_NOTIFICATION_VOLUME_UNMOUNT,
                                                   prevVolumes[ i ].volume );
                            rpal_debug_info( "volume unmounted" );
                        }
                    }
                }
            }

            if( NULL != prevSnapshot )
            {
                rList_free( prevSnapshot );
            }
            prevSnapshot = snapshot;
            if( NULL != prevVolumes )
            {
                rpal_memory_free( prevVolumes );
            }
            prevVolumes = newVolumes;
            nVolumes = nNewVolumes;
        }
    }
    
    if( NULL != prevSnapshot )
    {
        rList_free( prevSnapshot );
    }
    if( NULL != prevVolumes )
    {
        rpal_memory_free( prevVolumes );
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_19_events[] = { RP_TAGS_NOTIFICATION_VOLUME_MOUNT,
                                   RP_TAGS_NOTIFICATION_VOLUME_UNMOUNT,
                                   0 };

RBOOL
    collector_19_init
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
            if( !rSequence_getRU32( config, RP_TAGS_TIMEDELTA, &g_diff_timeout ) )
            {
                g_diff_timeout = _DIFF_TIMEOUT;
            }
        }

        if( rThreadPool_task( hbsState->hThreadPool, volumeTrackerDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_19_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_19_update
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
HBS_TEST_SUITE( 19 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}