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

#define RPAL_FILE_ID                            96

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <libOs/libOs.h>
#include <notificationsLib/notificationsLib.h>
#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define _TIMEOUT_BETWEEN_THREAD             (5*1000)
#define _TIMEOUT_BETWEEN_CONSTANT_PROCESSS  (5*1000)
#define _MAX_CPU_WAIT                       (60)
#define _CPU_WATERMARK                      (50)

RPRIVATE rMutex g_oob_exec_mutex = NULL;

typedef struct
{
    RU64 base;
    RU64 size;
} _MemRange;

RPRIVATE
RBOOL
    isMemInModule
    (
        RU64 memBase,
        _MemRange* memRanges,
        RU32 nRanges
    )
{
    RBOOL isInMod = FALSE;
    RU32 i = 0;

    if( NULL != memRanges )
    {
        i = rpal_binsearch_array_closest( memRanges,
                                          nRanges,
                                          sizeof( _MemRange ),
                                          &memBase,
                                          (rpal_ordering_func)rpal_order_RU64,
                                          TRUE );
        if( (RU32)( -1 ) != i )
        {
            if( IS_WITHIN_BOUNDS( NUMBER_TO_PTR( memBase ),
                                  1,
                                  NUMBER_TO_PTR( memRanges[ i ].base ),
                                  memRanges[ i ].size ) )
            {
                isInMod = TRUE;
            }
        }
    }

    return isInMod;
}

RPRIVATE
RBOOL
    assembleRanges
    (
        rList mods,
        _MemRange** pRanges,
        RU32* pNRanges
    )
{
    RBOOL isSuccess = FALSE;
    _MemRange* memRanges = NULL;
    rSequence mod = NULL;
    RU64 base = 0;
    RU64 size = 0;
    RU32 i = 0;

    if( rpal_memory_isValid( mods ) &&
        NULL != pRanges &&
        NULL != pNRanges )
    {
        if( NULL != ( memRanges = rpal_memory_alloc( sizeof( _MemRange ) *
                                                     rList_getNumElements( mods ) ) ) )
        {
            rList_resetIterator( mods );

            while( rList_getSEQUENCE( mods, RP_TAGS_DLL, &mod ) )
            {
                if( rSequence_getPOINTER64( mod, RP_TAGS_BASE_ADDRESS, &base ) &&
                    rSequence_getRU64( mod, RP_TAGS_MEMORY_SIZE, &size ) )
                {
                    memRanges[ i ].base = base;
                    memRanges[ i ].size = size;
                    i++;
                }
            }

            if( rpal_sort_array( memRanges, 
                                 i, 
                                 sizeof( _MemRange ), 
                                 (rpal_ordering_func)rpal_order_RU64 ) )
            {
                isSuccess = TRUE;
                *pRanges = memRanges;
                *pNRanges = i;
            }
        }
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    isJITPresentInProcess
    (
        RU32 processId
    )
{
    RBOOL isJITPresent = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    rList mods = NULL;
    rSequence mod = NULL;
    RPWCHAR nameW = NULL;
    RWCHAR dotNetDir[] = _WCH( "\\windows\\microsoft.net\\" );
    
    if( NULL != ( mods = processLib_getProcessModules( processId ) ) )
    {
        while( rList_getSEQUENCE( mods, RP_TAGS_DLL, &mod ) )
        {
            if( rSequence_getSTRINGN( mod, RP_TAGS_FILE_PATH, &nameW ) )
            {
                if( NULL != rpal_string_stristr( nameW, dotNetDir ) )
                {
                    isJITPresent = TRUE;
                    break;
                }
            }
        }

        rList_free( mods );
    }
#endif

    return isJITPresent;
}


RPRIVATE
RPVOID
    lookForExecOobIn
    (
        rEvent isTimeToStop,
        RU32 processId,
        rSequence originalRequest,
        LibOsPerformanceProfile* perfProfile
    )
{
    rList mods = NULL;
    _MemRange* memRanges = NULL;
    RU32 nRanges = 0;
    rList threads = NULL;
    RU32 threadId = 0;
    rList stackTrace = NULL;
    rSequence frame = NULL;
    RU64 pc = 0;
    RBOOL isFound = FALSE;
    rList traces = NULL;
    rSequence notif = NULL;
    rSequence taggedTrace = NULL;
    RU32 curThreadId = 0;
    RU32 curProcId = 0;
    RBOOL isJITPresent = FALSE;
    RTIME runTime = 0;
    Atom parentAtom = { 0 };
    RU64 curTime = 0;

    curProcId = processLib_getCurrentPid();
    curThreadId = processLib_getCurrentThreadId();

    if( curProcId == processId )
    {
        return NULL;
    }

    if( !rMutex_lock( g_oob_exec_mutex ) )
    {
        return NULL;
    }

    runTime = rpal_time_getLocal();

    isJITPresent = isJITPresentInProcess( processId );

    rpal_debug_info( "looking for execution out of bounds in process %d.", processId );

    if( !isJITPresent &&
        NULL != ( traces = rList_new( RP_TAGS_STACK_TRACE, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( threads = processLib_getThreads( processId ) ) )
        {
            while( !rEvent_wait( isTimeToStop, 0 ) &&
                   rList_getRU32( threads, RP_TAGS_THREAD_ID, &threadId ) )
            {
                libOs_timeoutWithProfile( perfProfile, FALSE, isTimeToStop );

                // We get the modules for every thread right before getting the
                // stack trace to limit time difference between both snapshots.
                if( NULL != ( mods = processLib_getProcessModules( processId ) ) )
                {
                    if( assembleRanges( mods, &memRanges, &nRanges ) )
                    {
                        if( NULL != ( stackTrace = processLib_getStackTrace( processId, 
                                                                             threadId, 
                                                                             FALSE ) ) )
                        {
                            while( !rEvent_wait( isTimeToStop, 0 ) &&
                                   rList_getSEQUENCE( stackTrace, RP_TAGS_STACK_TRACE_FRAME, &frame ) )
                            {
                                if( rSequence_getRU64( frame, RP_TAGS_STACK_TRACE_FRAME_PC, &pc ) &&
                                    0 != pc &&
                                    !isMemInModule( pc, memRanges, nRanges ) )
                                {
                                    rpal_debug_info( "covert execution detected in pid %d at 0x%016llX.",
                                                     processId,
                                                     pc );

                                    // Note that we are not decorating the stack trace with symbols
                                    // anywhere as the Microsoft code contains memory leaks. The API
                                    // was clearly not written for long term continuous use in a process.

                                    if( NULL != ( taggedTrace = rSequence_new() ) )
                                    {
                                        if( rSequence_addRU32( taggedTrace, 
                                                               RP_TAGS_THREAD_ID, 
                                                               threadId ) &&
                                            rSequence_addLISTdup( taggedTrace,
                                                                  RP_TAGS_STACK_TRACE_FRAMES,
                                                                  stackTrace ) )
                                        {
                                            rList_addSEQUENCEdup( traces, taggedTrace );
                                            isFound = TRUE;
                                        }

                                        rSequence_free( taggedTrace );
                                    }
                                    break;
                                }
                            }

                            rList_free( stackTrace );
                        }

                        rpal_memory_free( memRanges );
                    }

                    rList_free( mods );
                }

                libOs_timeoutWithProfile( perfProfile, TRUE, isTimeToStop );
            }

            rList_free( threads );
        }

        rpal_debug_info( "finished scanning for exec oob in %d sec", rpal_time_getLocal() - runTime );

        if( isFound &&
            NULL != ( notif = processLib_getProcessInfo( processId, NULL ) ) )
        {
            curTime = rpal_time_getGlobalPreciseTime();

            if( !rSequence_addLIST( notif, RP_TAGS_STACK_TRACES, traces ) )
            {
                rList_free( traces );
            }

            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            parentAtom.key.process.pid = processId;
            if( atoms_query( &parentAtom, curTime ) )
            {
                HbsSetParentAtom( notif, parentAtom.id );
            }

            hbs_markAsRelated( originalRequest, notif );
            hbs_timestampEvent( notif, curTime );

            hbs_publish( RP_TAGS_NOTIFICATION_EXEC_OOB, notif );

            rSequence_free( notif );
        }
        else
        {
            rList_free( traces );
        }
    }
    else
    {
        rpal_debug_info( "process has JIT present, ignoring it" );
    }

    rMutex_unlock( g_oob_exec_mutex );

    return NULL;
}

RPRIVATE
RPVOID
    lookForExecOob
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 30 );
    perfProfile.lastTimeoutValue = MSEC_FROM_SEC( 5 );
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 100;

    if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
    {
        proc = procs;

        while( 0 != proc->pid &&
               rpal_memory_isValid( isTimeToStop ) &&
               !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
        {
            lookForExecOobIn( isTimeToStop, proc->pid, originalRequest, &perfProfile );
            proc++;
        }

        rpal_memory_free( procs );
    }

    return NULL;
}

RPRIVATE
RVOID
    scan_for_exec_oob
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = (RU32)( -1 );
    rEvent dummy = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };

    UNREFERENCED_PARAMETER( eventType );

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 30 );
    perfProfile.lastTimeoutValue = MSEC_FROM_SEC( 2 );
    perfProfile.targetCpuPerformance = 10;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET_WHEN_TASKED;
    perfProfile.timeoutIncrementPerSec = 100;

    rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid );

    if( NULL != ( dummy = rEvent_create( TRUE ) ) )
    {
        if( (RU32)( -1 ) == pid )
        {
            lookForExecOob( dummy, event );
        }
        else
        {
            lookForExecOobIn( dummy, pid, event, &perfProfile );
        }

        rEvent_free( dummy );
    }
}


RPRIVATE
RVOID
    scan_late_for_exec_oob
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList statefulEvents = NULL;
    rSequence statefulEvent = NULL;
    RU32 pid = (RU32)( -1 );
    LibOsPerformanceProfile perfProfile = { 0 };
    rEvent dummy = NULL;

    UNREFERENCED_PARAMETER( eventType );

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 30 );
    perfProfile.lastTimeoutValue = MSEC_FROM_SEC( 2 );
    perfProfile.targetCpuPerformance = 10;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET_WHEN_TASKED;
    perfProfile.timeoutIncrementPerSec = 100;

    if( rSequence_getLIST( event, RP_TAGS_EVENTS, &statefulEvents ) )
    {
        while( rList_getSEQUENCE( statefulEvents, RP_TAGS_INVALID, &statefulEvent ) )
        {
            if( rSequence_getRU32( statefulEvent, RP_TAGS_PROCESS_ID, &pid ) )
            {
                break;
            }
        }
    }
    
    if( (RU32)(-1) != pid &&
        NULL != ( dummy = rEvent_create( TRUE ) ) )
    {
        lookForExecOobIn( dummy, pid, event, &perfProfile );

        rEvent_free( dummy );
    }
}


RPRIVATE
RPVOID
    lookForExecOobConstantly
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 15 );
    perfProfile.lastTimeoutValue = MSEC_FROM_SEC( 1 );
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 50;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
        {
            proc = procs;

            while( 0 != proc->pid &&
                   rpal_memory_isValid( isTimeToStop ) &&
                   !rEvent_wait( isTimeToStop, _TIMEOUT_BETWEEN_CONSTANT_PROCESSS ) )
            {
                lookForExecOobIn( isTimeToStop, proc->pid, originalRequest, &perfProfile );

                libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

                proc++;
            }

            rpal_memory_free( procs );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_13_events[] = { RP_TAGS_NOTIFICATION_EXEC_OOB,
                                   0 };

RBOOL
    collector_13_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( NULL != ( g_oob_exec_mutex = rMutex_create() ) )
        {
            if( notifications_subscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         scan_for_exec_oob ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_LATE_MODULE_LOAD,
                                         NULL,
                                         0,
                                         NULL,
                                         scan_late_for_exec_oob ) &&
                rThreadPool_task( hbsState->hThreadPool, lookForExecOobConstantly, NULL ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ, NULL, scan_for_exec_oob );
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_LATE_MODULE_LOAD, NULL, scan_late_for_exec_oob );
                rMutex_free( g_oob_exec_mutex );
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_13_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ, NULL, scan_for_exec_oob );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_LATE_MODULE_LOAD, NULL, scan_late_for_exec_oob );
        rMutex_free( g_oob_exec_mutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_13_update
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
HBS_TEST_SUITE( 13 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}