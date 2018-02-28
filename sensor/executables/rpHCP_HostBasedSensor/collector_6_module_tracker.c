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
#include <processLib/processLib.h>
#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <kernelAcquisitionLib/common.h>

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#include <TlHelp32.h>
#endif

#define RPAL_FILE_ID         66

#define MAX_SNAPSHOT_SIZE 1536

typedef struct
{
    RU32 procId;
    RU64 baseAddr;
    RU64 size;
} _moduleHistEntry;

RPRIVATE
RS32
    _cmpModule
    (
        _moduleHistEntry* m1,
        _moduleHistEntry* m2
    )
{
    RS32 ret = 0;

    if( NULL != m1 &&
        NULL != m2 )
    {
        ret = (RS32)rpal_memory_memcmp( m1, m2, sizeof( *m1 ) );
    }

    return ret;
}

RPRIVATE
RPVOID
    modUserModeDiff
    (
        rEvent isTimeToStop
    )
{
    rBlob previousSnapshot = NULL;
    rBlob newSnapshot = NULL;
    _moduleHistEntry curModule = { 0 };
    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    rList modules = NULL;
    rSequence module = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };
    Atom parentAtom = { 0 };
    RU64 curTime = 0;

    perfProfile.enforceOnceIn = 1;
    perfProfile.lastTimeoutValue = 10;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 1;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) &&
           !kAcq_isAvailable() )
    {
        if( NULL != ( processes = processLib_getProcessEntries( FALSE ) ) )
        {
            if( NULL != ( newSnapshot = rpal_blob_create( 1000 * sizeof( _moduleHistEntry ),
                                                          1000 * sizeof( _moduleHistEntry ) ) ) )
            {
                libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

                curProc = processes;
                while( rpal_memory_isValid( isTimeToStop ) &&
#ifdef RPAL_PLATFORM_WINDOWS
                       !rEvent_wait( isTimeToStop, 0 ) &&
#else
                       // Module listing outside of 
                       !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 1 ) ) &&
#endif
                       0 != curProc->pid )
                {
                    if( NULL != ( modules = processLib_getProcessModules( curProc->pid ) ) )
                    {
                        curTime = rpal_time_getGlobalPreciseTime();

                        while( rpal_memory_isValid( isTimeToStop ) &&
                               !rEvent_wait( isTimeToStop, 0 ) &&
                               rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
                        {
                            libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

                            if( rSequence_getPOINTER64( module,
                                                        RP_TAGS_BASE_ADDRESS, 
                                                        &( curModule.baseAddr ) ) &&
                                rSequence_getRU64( module, 
                                                   RP_TAGS_MEMORY_SIZE, 
                                                   &(curModule.size) ) )
                            {
                                curModule.procId = curProc->pid;
                                rpal_blob_add( newSnapshot, &curModule, sizeof( curModule ) );
                                if( NULL != previousSnapshot &&
                                    -1 == rpal_binsearch_array( rpal_blob_getBuffer( previousSnapshot ),
                                                                rpal_blob_getSize( previousSnapshot ) /
                                                                    sizeof( _moduleHistEntry ),
                                                                sizeof( _moduleHistEntry ),
                                                                &curModule, 
                                                                (rpal_ordering_func)_cmpModule ) )
                                {
                                    hbs_timestampEvent( module, curTime );
                                    parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                                    parentAtom.key.process.pid = curProc->pid;
                                    if( atoms_query( &parentAtom, curTime ) )
                                    {
                                        HbsSetParentAtom( module, parentAtom.id );
                                    }
                                    rpal_memory_zero( &parentAtom, sizeof( parentAtom ) );
                                    hbs_publish( RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                                 module );
                                }
                            }
                        }

                        rList_free( modules );
                    }

                    curProc++;
                }

                if( !rpal_sort_array( rpal_blob_getBuffer( newSnapshot ),
                                      rpal_blob_getSize( newSnapshot ) / sizeof( _moduleHistEntry ),
                                      sizeof( _moduleHistEntry ),
                                      (rpal_ordering_func)_cmpModule ) )
                {
                    rpal_debug_warning( "error sorting modules" );
                }
            }

            rpal_memory_free( processes );
        }

        if( NULL != previousSnapshot )
        {
            rpal_blob_free( previousSnapshot );
        }
        previousSnapshot = newSnapshot;
        newSnapshot = NULL;
    }

    if( NULL != previousSnapshot )
    {
        rpal_blob_free( previousSnapshot );
    }

    return NULL;
}

RPRIVATE
RBOOL
    notifyOfKernelModule
    (
        KernelAcqModule* module
    )
{
    RBOOL isSuccess = FALSE;
    rSequence notif = NULL;
    RU32 pathLength = 0;
    RU32 i = 0;
    RPNCHAR dirSep = RPAL_FILE_LOCAL_DIR_SEP_N;
    RPNCHAR cleanPath = NULL;
    Atom parentAtom = { 0 };
    
    if( NULL != module )
    {
        if( NULL != ( notif = rSequence_new() ) )
        {
            module->ts += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

            hbs_timestampEvent( notif, module->ts );
            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            parentAtom.key.process.pid = module->pid;
            if( atoms_query( &parentAtom, module->ts ) )
            {
                HbsSetParentAtom( notif, parentAtom.id );
            }

            rSequence_addRU32( notif, RP_TAGS_PROCESS_ID, module->pid );
            rSequence_addPOINTER64( notif, RP_TAGS_BASE_ADDRESS, (RU64)module->baseAddress );
            rSequence_addRU64( notif, RP_TAGS_MEMORY_SIZE, module->imageSize );

            if( 0 != ( pathLength = rpal_string_strlen( module->path ) ) )
            {
                cleanPath = rpal_file_clean( module->path );
                rSequence_addSTRINGN( notif, RP_TAGS_FILE_PATH, cleanPath ? cleanPath : module->path );
                rpal_memory_free( cleanPath );

                // For compatibility with user mode we extract the module name.
                for( i = pathLength - 1; i != 0; i-- )
                {
                    if( dirSep[ 0 ] == module->path[ i ] )
                    {
                        i++;
                        break;
                    }
                }

                rSequence_addSTRINGN( notif, RP_TAGS_MODULE_NAME, &( module->path[ i ] ) );

                if( hbs_publish( RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                 notif ) )
                {
                    isSuccess = TRUE;
                }
            }

            rSequence_free( notif );
        }
    }

    return isSuccess;
}

RPRIVATE
RVOID
    modKernelModeDiff
    (
        rEvent isTimeToStop
    )
{
    RU32 i = 0;
    RU32 nScratch = 0;
    RU32 prev_nScratch = 0;
    KernelAcqModule new_from_kernel[ 200 ] = { 0 };
    KernelAcqModule prev_from_kernel[ 200 ] = { 0 };

    while( !rEvent_wait( isTimeToStop, 1000 ) )
    {
        nScratch = ARRAY_N_ELEM( new_from_kernel );
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        if( !kAcq_getNewModules( new_from_kernel, &nScratch ) )
        {
            rpal_debug_warning( "kernel acquisition for new modules failed" );
            break;
        }

        for( i = 0; i < prev_nScratch; i++ )
        {
            notifyOfKernelModule( &(prev_from_kernel[ i ]) );
        }

        rpal_memory_memcpy( prev_from_kernel, new_from_kernel, sizeof( prev_from_kernel ) );
        prev_nScratch = nScratch;
    }
}


RPRIVATE
RPVOID
    moduleDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            // We first attempt to get new modules through
            // the kernel mode acquisition driver
            rpal_debug_info( "running kernel acquisition module notification" );
            modKernelModeDiff( isTimeToStop );
        }
        // If the kernel mode fails, or is not available, try
        // to revert to user mode
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition module notification" );
            modUserModeDiff( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_6_events[] = { RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                  0 };

RBOOL
    collector_6_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rThreadPool_task( hbsState->hThreadPool, moduleDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_6_cleanup
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
    collector_6_update
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
HBS_TEST_SUITE( 6 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}