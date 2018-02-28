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
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <kernelAcquisitionLib/common.h>

#ifdef RPAL_PLATFORM_WINDOWS
    #include <windows_undocumented.h>
    #include <TlHelp32.h>
#elif defined( RPAL_PLATFORM_MACOSX )
    #include <sys/types.h>
    #include <sys/sysctl.h>
#endif

#define RPAL_FILE_ID       63

#define MAX_SNAPSHOT_SIZE   1536
#define NO_PARENT_PID       ((RU32)(-1))
#define GENERATIONS_BEFORE_REPORTING    1

typedef struct
{
    RU32 pid;
    RU32 ppid;
    // TTL before a terminated process is reported.
    RU32 terminatedTtl;
    RTIME terminationTime;
} processEntry;

RPRIVATE
RBOOL
    getSnapshot
    (
        processEntry* toSnapshot,
        RU32* nElem
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;

    if( NULL != toSnapshot )
    {
        rpal_memory_zero( toSnapshot, sizeof( processEntry ) * MAX_SNAPSHOT_SIZE );
    }

    if( NULL != toSnapshot &&
        NULL != nElem )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        HANDLE hSnapshot = NULL;
        PROCESSENTRY32W procEntry = { 0 };
        procEntry.dwSize = sizeof( procEntry );

        if( INVALID_HANDLE_VALUE != ( hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ) )
        {
            if( Process32FirstW( hSnapshot, &procEntry ) )
            {
                isSuccess = TRUE;

                do
                {
                    if( 0 == procEntry.th32ProcessID )
                    {
                        continue;
                    }

                    toSnapshot[ i ].pid = procEntry.th32ProcessID;
                    toSnapshot[ i ].ppid = procEntry.th32ParentProcessID;
                    i++;
                } while( Process32NextW( hSnapshot, &procEntry ) &&
                         MAX_SNAPSHOT_SIZE > i );
            }

            CloseHandle( hSnapshot );
        }
#elif defined( RPAL_PLATFORM_LINUX )
        RCHAR procDir[] = "/proc/";
        rDir hProcDir = NULL;
        rFileInfo finfo = {0};

        if( rDir_open( (RPCHAR)&procDir, &hProcDir ) )
        {
            isSuccess = TRUE;

            while( rDir_next( hProcDir, &finfo ) &&
                   MAX_SNAPSHOT_SIZE > i )
            {
                if( rpal_string_stoi( (RPCHAR)finfo.fileName, &( toSnapshot[ i ].pid ), TRUE )
                    && 0 != toSnapshot[ i ].pid )
                {
                    toSnapshot[ i ].ppid = NO_PARENT_PID;
                    i++;
                }
            }

            rDir_close( hProcDir );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
        struct kinfo_proc* infos = NULL;
        size_t size = 0;
        int ret = 0;

        if( 0 == ( ret = sysctl( mib, ARRAY_N_ELEM( mib ), infos, &size, NULL, 0 ) ) )
        {
            if( NULL != ( infos = rpal_memory_alloc( size ) ) )
            {
                while( 0 != ( ret = sysctl( mib, ARRAY_N_ELEM( mib ), infos, &size, NULL, 0 ) ) && ENOMEM == errno )
                {
                    if( NULL == ( infos = rpal_memory_realloc( infos, size ) ) )
                    {
                        break;
                    }
                }
            }
        }

        if( 0 == ret && NULL != infos )
        {
            isSuccess = TRUE;
            size = size / sizeof( struct kinfo_proc );
            for( i = 0; i < size && MAX_SNAPSHOT_SIZE > i; i++ )
            {
                toSnapshot[ i ].pid = infos[ i ].kp_proc.p_pid;
                toSnapshot[ i ].ppid = infos[ i ].kp_eproc.e_ppid;
            }

            if( NULL != infos )
            {
                rpal_memory_free( infos );
                infos = NULL;
            }
        }
#endif

        rpal_sort_array( toSnapshot, 
                         i, 
                         sizeof( processEntry ), 
                         (rpal_ordering_func)rpal_order_RU32 );
        *nElem = i;
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    notifyOfProcess
    (
        RU32 pid,
        RU32 ppid,
        RBOOL isStarting,
        RPNCHAR optFilePath,
        RPNCHAR optCmdLine,
        RU32 optUserId,
        RU64 optTs
    )
{
    RBOOL isSuccess = FALSE;
    rSequence info = NULL;
    rSequence parentInfo = NULL;
    RPNCHAR cleanPath = NULL;
    Atom atom = { 0 };
    Atom parentAtom = { 0 };

    if( 0 == optTs )
    {
        optTs = rpal_time_getGlobalPreciseTime();
    }

    // The most time sensitive thing to do is register the atom.
    if( isStarting )
    {
        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = pid;
        atoms_register( &atom );
    }
    else
    {
        atoms_getOneTime( &atom );
    }

    if( NULL != ( info = rSequence_new() ) )
    {
        // If we got a real parent pid we'll include it right away since we don't want to
        // trust the UM info gathering anymore than we have to.
        if( NO_PARENT_PID != ppid )
        {
            rSequence_addRU32( info, RP_TAGS_PARENT_PROCESS_ID, ppid );
        }
        // Do the same with the UID, kernel (param) takes precedence.
        if( KERNEL_ACQ_NO_USER_ID != optUserId )
        {
            rSequence_addRU32( info, RP_TAGS_USER_ID, optUserId );
        }
    }

    // We only ever have priming information on new processes
    if( isStarting )
    {
        if( NULL != info )
        {
            // We prime the information with whatever was provided
            // to us by the kernel acquisition. If not available
            // we generate using the UM only way.
            if( 0 != rpal_string_strlen( optFilePath ) )
            {
                cleanPath = rpal_file_clean( optFilePath );
                rSequence_addSTRINGN( info, RP_TAGS_FILE_PATH, cleanPath ? cleanPath : optFilePath );
                rpal_memory_free( cleanPath );
            }

            if( 0 != rpal_string_strlen( optCmdLine ) )
            {
                rSequence_addSTRINGN( info, RP_TAGS_COMMAND_LINE, optCmdLine );
            }
        }

        // Fill in whatever is left with the UM info gathering.
        info = processLib_getProcessInfo( pid, info );
    }

    if( rpal_memory_isValid( info ) )
    {
        rSequence_addRU32( info, RP_TAGS_PROCESS_ID, pid );
        if( NO_PARENT_PID == ppid )
        {
            // If we didn't get a parent pid we'll try to use whatever we got from UM.
            rSequence_getRU32( info, RP_TAGS_PARENT_PROCESS_ID, &ppid );
        }
        hbs_timestampEvent( info, optTs );
        HbsSetThisAtom( info, atom.id );

        // We should have reliable information on ppid now (sometimes ppid is not available before
        // querying the process info).
        if( isStarting )
        {
            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            parentAtom.key.process.pid = ppid;
            if( atoms_query( &parentAtom, optTs ) )
            {
                // Update the main process with the parent.
                rpal_memory_memcpy( atom.parentId, parentAtom.id, HBS_ATOM_ID_SIZE );
                atoms_update( &atom );

                HbsSetParentAtom( info, parentAtom.id );
            }
        }
        else
        {
            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            parentAtom.key.process.pid = pid;
            if( atoms_query( &parentAtom, optTs ) )
            {
                HbsSetParentAtom( info, parentAtom.id );
            }
            atoms_remove( &parentAtom, optTs );
        }

        if( isStarting )
        {
            if( NULL != ( parentInfo = processLib_getProcessInfo( ppid, NULL ) ) &&
                !rSequence_addSEQUENCE( info, RP_TAGS_PARENT, parentInfo ) )
            {
                rSequence_free( parentInfo );
            }
        }

        if( isStarting )
        {
            if( hbs_publish( RP_TAGS_NOTIFICATION_NEW_PROCESS, info ) )
            {
                isSuccess = TRUE;
                rpal_debug_info( "new process starting: %d / %d", pid, ppid );
            }
        }
        else
        {
            if( hbs_publish( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, info ) )
            {
                isSuccess = TRUE;
                rpal_debug_info( "new process terminating: %d / %d", pid, ppid );
            }
        }

        rSequence_free( info );
    }
    else
    {
        rpal_debug_error( "could not allocate info on new process" );
    }

    return isSuccess;
}

RPRIVATE
RVOID
    procUserModeDiff
    (
        rEvent isTimeToStop
    )
{
    processEntry snapshot_1[ MAX_SNAPSHOT_SIZE ] = { 0 };
    processEntry snapshot_2[ MAX_SNAPSHOT_SIZE ] = { 0 };
    processEntry* currentSnapshot = snapshot_1;
    processEntry* previousSnapshot = snapshot_2;
    processEntry* tmpSnapshot = NULL;
    RBOOL isFirstSnapshots = TRUE;
    RU32 i = 0;
    RBOOL isFound = FALSE;
    RU32 nTmpElem = 0;
    RU32 nCurElem = 0;
    RU32 nPrevElem = 0;
    LibOsPerformanceProfile perfProfile = { 0 };

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
#ifdef RPAL_PLATFORM_LINUX
    perfProfile.lastTimeoutValue = 1000;
#else
    perfProfile.lastTimeoutValue = 100;
#endif
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 10;

    while( !rEvent_wait( isTimeToStop, 0 ) &&
           !kAcq_isAvailable() )
    {
        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        tmpSnapshot = currentSnapshot;
        currentSnapshot = previousSnapshot;
        previousSnapshot = tmpSnapshot;

        nTmpElem = nCurElem;
        nCurElem = nPrevElem;
        nPrevElem = nTmpElem;

        if( getSnapshot( currentSnapshot, &nCurElem ) )
        {
            if( isFirstSnapshots )
            {
                isFirstSnapshots = FALSE;
                continue;
            }

            // Diff to find new processes
            for( i = 0; i < nCurElem; i++ )
            {
                isFound = FALSE;

                if( (RU32)( -1 ) != rpal_binsearch_array( previousSnapshot,
                                                          nPrevElem,
                                                          sizeof( processEntry ),
                                                          &(currentSnapshot[ i ].pid),
                                                          (rpal_ordering_func)rpal_order_RU32 ) )
                {
                    isFound = TRUE;
                }

                if( !isFound )
                {
                    currentSnapshot[ i ].terminatedTtl = GENERATIONS_BEFORE_REPORTING;
                    currentSnapshot[ i ].terminationTime = 0;

                    if( !notifyOfProcess( currentSnapshot[ i ].pid,
                                          currentSnapshot[ i ].ppid,
                                          TRUE,
                                          NULL,
                                          NULL,
                                          KERNEL_ACQ_NO_USER_ID,
                                          0 ) )
                    {
                        rpal_debug_warning( "error reporting new process: %d",
                                            currentSnapshot[ i ].pid );
                    }
                }
            }

            // Diff to find terminated processes
            for( i = 0; i < nPrevElem; i++ )
            {
                isFound = FALSE;

                if( (RU32)( -1 ) != rpal_binsearch_array( currentSnapshot,
                                                          nCurElem,
                                                          sizeof( processEntry ),
                                                          &(previousSnapshot[ i ].pid),
                                                          (rpal_ordering_func)rpal_order_RU32 ) )
                {
                    isFound = TRUE;
                }

                if( !isFound )
                {
                    if( 0 == previousSnapshot[ i ].terminatedTtl )
                    {
                        if( !notifyOfProcess( previousSnapshot[ i ].pid,
                                              previousSnapshot[ i ].ppid,
                                              FALSE,
                                              NULL,
                                              NULL,
                                              KERNEL_ACQ_NO_USER_ID,
                                              previousSnapshot[ i ].terminationTime ) )
                        {
                            rpal_debug_warning( "error reporting terminated process: %d",
                                                previousSnapshot[ i ].pid );
                        }
                    }
                    else
                    {
                        // We wait for N generations before actually reporting it.
                        // We do this to delay artificially the event as this helps
                        // us avoid race conditions in secondary collectors without
                        // having to bend over backwards.
                        previousSnapshot[ i ].terminatedTtl--;
                        previousSnapshot[ i ].terminationTime = rpal_time_getGlobalPreciseTime();
                    }
                }
            }
        }

        libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );
    }
}

RPRIVATE
RVOID
    procKernelModeDiff
    (
        rEvent isTimeToStop
    )
{
    RU32 i = 0;
    RU32 nScratch = 0;
    RU32 nProcessEntries = 0;
    KernelAcqProcess new_from_kernel[ 200 ] = { 0 };
    processEntry tracking_user[ MAX_SNAPSHOT_SIZE ] = { 0 };
    processLibProcEntry* tmpProcesses = NULL;

    // Prime the list of tracked processes so we see them terminate.
    if( NULL != ( tmpProcesses = processLib_getProcessEntries( FALSE ) ) )
    {
        for( i = 0; i < MAX_SNAPSHOT_SIZE; i++ )
        {
            if( 0 == tmpProcesses[ i ].pid ) break;
            tracking_user[ i ].pid = tmpProcesses[ i ].pid;
            tracking_user[ i ].ppid = NO_PARENT_PID;
        }

        rpal_memory_free( tmpProcesses );
        tmpProcesses = NULL;
    }
    
    while( !rEvent_wait( isTimeToStop, 1000 ) )
    {
        nScratch = ARRAY_N_ELEM( new_from_kernel );
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        if( !kAcq_getNewProcesses( new_from_kernel, &nScratch ) )
        {
            rpal_debug_warning( "kernel acquisition for new processes failed" );
            break;
        }

        for( i = 0; i < nScratch; i++ )
        {
            new_from_kernel[ i ].ts += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );
            notifyOfProcess( new_from_kernel[ i ].pid,
                             new_from_kernel[ i ].ppid,
                             TRUE,
                             new_from_kernel[ i ].path,
                             new_from_kernel[ i ].cmdline,
                             new_from_kernel[ i ].uid,
                             new_from_kernel[ i ].ts );

            if( nProcessEntries >= ARRAY_N_ELEM( tracking_user ) )
            {
                continue;
            }

            tracking_user[ nProcessEntries ].pid = new_from_kernel[ i ].pid;
            tracking_user[ nProcessEntries ].ppid = new_from_kernel[ i ].ppid;
            tracking_user[ nProcessEntries ].terminatedTtl = GENERATIONS_BEFORE_REPORTING;
            tracking_user[ nProcessEntries ].terminationTime = 0;
            nProcessEntries++;
        }

        for( i = 0; i < nProcessEntries; i++ )
        {
            if( !processLib_isPidInUse( tracking_user[ i ].pid ) )
            {
                if( 0 == tracking_user[ i ].terminatedTtl )
                {
                    notifyOfProcess( tracking_user[ i ].pid,
                                     tracking_user[ i ].ppid,
                                     FALSE,
                                     NULL,
                                     NULL,
                                     KERNEL_ACQ_NO_USER_ID,
                                     tracking_user[ i ].terminationTime );
                    if( nProcessEntries != i + 1 )
                    {
                        rpal_memory_memmove( &( tracking_user[ i ] ),
                                             &( tracking_user[ i + 1 ] ),
                                             ( nProcessEntries - ( i + 1 ) ) * sizeof( *tracking_user ) );
                    }
                    nProcessEntries--;
                    i--;
                }
                else
                {
                    // We wait for N generations before actually reporting it.
                    // We do this to delay artificially the event as this helps
                    // us avoid race conditions in secondary collectors without
                    // having to bend over backwards.
                    tracking_user[ i ].terminatedTtl--;
                    tracking_user[ i ].terminationTime = rpal_time_getGlobalPreciseTime();
                }
            }
        }
    }
}

RPRIVATE
RPVOID
    processDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    RU32 i = 0;
    processLibProcEntry* tmpProcesses = NULL;
    Atom tmpAtom = { 0 };
    rSequence processInfo = NULL;

    UNREFERENCED_PARAMETER( ctx );

    // Prime the list of tracked processes so we have their Atoms.
    if( NULL != ( tmpProcesses = processLib_getProcessEntries( FALSE ) ) )
    {
        // Many collectors may rely on these existing processes for state
        // initialization, so we'll give them a chance to get subscribed.
        rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

        // We manually register a pid 0 to be used to represent kernel.
        tmpAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        tmpAtom.key.process.pid = 0;
        atoms_register( &tmpAtom );

        for( i = 0; i < MAX_SNAPSHOT_SIZE; i++ )
        {
            if( 0 == tmpProcesses[ i ].pid ) break;
            tmpAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            tmpAtom.key.process.pid = tmpProcesses[ i ].pid;
            atoms_register( &tmpAtom );

            if( NULL != ( processInfo = processLib_getProcessInfo( tmpProcesses[ i ].pid, NULL ) ) &&
                hbs_timestampEvent( processInfo, 0 ) &&
                HbsSetThisAtom( processInfo, tmpAtom.id ) )
            {
                hbs_publish( RP_TAGS_NOTIFICATION_EXISTING_PROCESS, processInfo );
                rSequence_free( processInfo );
            }
        }

        rpal_memory_free( tmpProcesses );
        tmpProcesses = NULL;
    }

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            // We first attempt to get new processes through
            // the kernel mode acquisition driver
            rpal_debug_info( "running kernel acquisition process notification" );
            procKernelModeDiff( isTimeToStop );
        }
        // If the kernel mode fails, or is not available, try
        // to revert to user mode
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition process notification" );
            procUserModeDiff( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_1_events[] = { RP_TAGS_NOTIFICATION_NEW_PROCESS,
                                  RP_TAGS_NOTIFICATION_TERMINATE_PROCESS,
                                  RP_TAGS_NOTIFICATION_EXISTING_PROCESS,
                                  0 };

RBOOL
    collector_1_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rThreadPool_task( hbsState->hThreadPool, processDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_1_cleanup
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
    collector_1_update
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
HBS_DECLARE_TEST( um_snapshot )
{
    RU32 nElem = 0;
    RBOOL isThisPidFound = FALSE;
    RU32 i = 0;
    RU32 thisPid = 0;

    processEntry snapshot[ MAX_SNAPSHOT_SIZE ] = { 0 };
    HBS_ASSERT_TRUE( getSnapshot( (processEntry*)&snapshot, &nElem ) );
    HBS_ASSERT_TRUE( 0 != nElem );
    HBS_ASSERT_TRUE( ARRAY_N_ELEM( snapshot ) > nElem );

    thisPid = processLib_getCurrentPid();

    for( i = 0; i < nElem; i++ )
    {
        if( thisPid == snapshot[ i ].pid )
        {
            isThisPidFound = TRUE;
            break;
        }
    }

    HBS_ASSERT_TRUE( isThisPidFound );
}

HBS_DECLARE_TEST( notify_process )
{
    RU32 pid = 42;
    RU32 ppid = 42;
    RU64 ts = 0;
    rQueue notifQueue = NULL;
    RU32 size = 0;
    rSequence notif = NULL;
    RU32 outPid = 0;
    RU32 outPpid = 0;
    RU64 outTs = 0;
    RPNCHAR outPath = NULL;
    RPNCHAR outCmdLine = NULL;
    RU32 outUserId = 0;
    RNCHAR path[] = { _NC( "test path" ) };
    RNCHAR cmdLine[] = { _NC( "test cmd" ) };
    RU32 userId = 24;
    Atom atom = { 0 };
    RU8 emptyAtomId[ HBS_ATOM_ID_SIZE ] = { 0 };

    // We base our test on our own PID to ensure we have something to look at.
    pid = processLib_getCurrentPid();
    ts = rpal_time_getLocal();
    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );

    // Register to the notifications we expect.
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, notifQueue, NULL ) );
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, 0, notifQueue, NULL ) );
    
    // The scenarios this function supports:

    // New process from UM with no authoritative info
    HBS_ASSERT_TRUE( notifyOfProcess( pid, ppid, TRUE, NULL, NULL, KERNEL_ACQ_NO_USER_ID, ts ) );
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 1 == size );
    HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &notif, NULL, 0 ) );
    if( HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &outPid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PARENT_PROCESS_ID, &outPpid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getTIMESTAMP( notif, RP_TAGS_TIMESTAMP, &outTs ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &outPath ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_COMMAND_LINE, &outCmdLine ) ) )
    {
#if defined(RPAL_PLATFORM_WINDOWS) || defined( RPAL_PLATFORM_MACOSX )
        // On Windows and OSX we don't have access to UID unless provided by the kernel.
        HBS_ASSERT_TRUE( !rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) );
#else
        // On Linux we get UID even from user mode.
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) );
#endif
        HBS_ASSERT_TRUE( pid == outPid );
        HBS_ASSERT_TRUE( ppid == outPpid );
        HBS_ASSERT_TRUE( ts == outTs );
        HBS_ASSERT_TRUE( NULL != outPath );
        HBS_ASSERT_TRUE( NULL != outCmdLine );

        // Also check that atoms get registered correctly
        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = pid;
        if( HBS_ASSERT_TRUE( atoms_query( &atom, rpal_time_getGlobalPreciseTime() ) ) )
        {
            HBS_ASSERT_TRUE( 0 != rpal_memory_memcmp( emptyAtomId, &atom.key, HBS_ATOM_ID_SIZE ) );
        }
    }
    rSequence_free( notif );

    // New process from KM with authoritative info
    HBS_ASSERT_TRUE( notifyOfProcess( pid, ppid, TRUE, path, cmdLine, userId, ts ) );
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 1 == size );
    HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &notif, NULL, 0 ) );
    if( HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &outPid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PARENT_PROCESS_ID, &outPpid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getTIMESTAMP( notif, RP_TAGS_TIMESTAMP, &outTs ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &outPath ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_COMMAND_LINE, &outCmdLine ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) ) )
    {
        HBS_ASSERT_TRUE( pid == outPid );
        HBS_ASSERT_TRUE( ppid == outPpid );
        HBS_ASSERT_TRUE( ts == outTs );
        HBS_ASSERT_TRUE( 0 == rpal_string_strcmp( path, outPath ) );
        HBS_ASSERT_TRUE( 0 == rpal_string_strcmp( cmdLine, outCmdLine ) );
        HBS_ASSERT_TRUE( userId == outUserId );

        // Also check that atoms get registered correctly
        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = pid;
        if( HBS_ASSERT_TRUE( atoms_query( &atom, rpal_time_getGlobalPreciseTime() ) ) )
        {
            HBS_ASSERT_TRUE( 0 != rpal_memory_memcmp( emptyAtomId, &atom.key, HBS_ATOM_ID_SIZE ) );
        }
    }
    rSequence_free( notif );

    // New process without a PPID info, make sure it gets populated
    HBS_ASSERT_TRUE( notifyOfProcess( pid, NO_PARENT_PID, TRUE, NULL, NULL, KERNEL_ACQ_NO_USER_ID, ts ) );
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 1 == size );
    HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &notif, NULL, 0 ) );
    if( HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &outPid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PARENT_PROCESS_ID, &outPpid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getTIMESTAMP( notif, RP_TAGS_TIMESTAMP, &outTs ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &outPath ) ) &&
        HBS_ASSERT_TRUE( rSequence_getSTRINGN( notif, RP_TAGS_COMMAND_LINE, &outCmdLine ) ) )
    {
#if defined(RPAL_PLATFORM_WINDOWS) || defined( RPAL_PLATFORM_MACOSX )
        // On Windows and OSX we don't have access to UID unless provided by the kernel.
        HBS_ASSERT_TRUE( !rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) );
#else
        // On Linux we get UID even from user mode.
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) );
#endif
        HBS_ASSERT_TRUE( pid == outPid );
        HBS_ASSERT_TRUE( ppid != outPpid );
        HBS_ASSERT_TRUE( ts == outTs );
        HBS_ASSERT_TRUE( NULL != outPath );
        HBS_ASSERT_TRUE( NULL != outCmdLine );

        // Also check that atoms get registered correctly
        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = pid;
        if( HBS_ASSERT_TRUE( atoms_query( &atom, rpal_time_getGlobalPreciseTime() ) ) )
        {
            HBS_ASSERT_TRUE( 0 != rpal_memory_memcmp( emptyAtomId, &atom.key, HBS_ATOM_ID_SIZE ) );
        }
    }
    rSequence_free( notif );

    // Terminated process
    // New process from UM with no authoritative info
    HBS_ASSERT_TRUE( notifyOfProcess( pid, ppid, FALSE, NULL, NULL, KERNEL_ACQ_NO_USER_ID, ts ) );
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 1 == size );
    HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &notif, NULL, 0 ) );
    if( HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &outPid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PARENT_PROCESS_ID, &outPpid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getTIMESTAMP( notif, RP_TAGS_TIMESTAMP, &outTs ) ) &&
        HBS_ASSERT_TRUE( !rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &outPath ) ) &&
        HBS_ASSERT_TRUE( !rSequence_getSTRINGN( notif, RP_TAGS_COMMAND_LINE, &outCmdLine ) ) &&
        HBS_ASSERT_TRUE( !rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) ) )
    {
        HBS_ASSERT_TRUE( pid == outPid );
        HBS_ASSERT_TRUE( 42 == outPpid );
        HBS_ASSERT_TRUE( ts == outTs );

        // Also check that atoms get registered correctly, in this case it's a termination so
        // wait a bit and make sure it's dead.
        rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = pid;
        HBS_ASSERT_TRUE( !atoms_query( &atom, rpal_time_getGlobalPreciseTime() ) );
    }
    rSequence_free( notif );

    // Failure scenarios:

    // We were somehow too slow and couldn't get the process info before it terminated.
    // This makes the assumption the process with PID 1 doesn't exist.
    HBS_ASSERT_TRUE( notifyOfProcess( 1, ppid, TRUE, NULL, NULL, KERNEL_ACQ_NO_USER_ID, ts ) );
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 1 == size );
    HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &notif, NULL, 0 ) );
    if( HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &outPid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PARENT_PROCESS_ID, &outPpid ) ) &&
        HBS_ASSERT_TRUE( rSequence_getTIMESTAMP( notif, RP_TAGS_TIMESTAMP, &outTs ) ) &&
        ( processLib_isPidInUse( 1 ) ||
          ( HBS_ASSERT_TRUE( !rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &outPath ) ) &&
            HBS_ASSERT_TRUE( !rSequence_getSTRINGN( notif, RP_TAGS_COMMAND_LINE, &outCmdLine ) ) &&
            HBS_ASSERT_TRUE( !rSequence_getRU32( notif, RP_TAGS_USER_ID, &outUserId ) ) ) ) )
    {
        HBS_ASSERT_TRUE( 1 == outPid );
        HBS_ASSERT_TRUE( ppid == outPpid );
        HBS_ASSERT_TRUE( ts == outTs );

        // Also check that atoms get registered correctly
        atom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        atom.key.process.pid = 1;
        if( HBS_ASSERT_TRUE( atoms_query( &atom, rpal_time_getGlobalPreciseTime() ) ) )
        {
            HBS_ASSERT_TRUE( 0 != rpal_memory_memcmp( emptyAtomId, &atom.key, HBS_ATOM_ID_SIZE ) );
        }
    }
    rSequence_free( notif );

    // Teardown
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, notifQueue, NULL );
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, notifQueue, NULL );
    rQueue_free( notifQueue );
}

RPRIVATE
RU32
RPAL_THREAD_FUNC
    _threadStubToThreadPool
    (
        rEvent isTimeToStop
    )
{
    processDiffThread( isTimeToStop, NULL );
    return 0;
}

HBS_DECLARE_TEST( um_diff_thread )
{
    rThread hThread = NULL;
    rEvent dummyStop = NULL;
    rQueue notifQueue = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    //RPNCHAR spawnCmd[] = { _NC( "ping 1.1.1.1 -n 5 -w 1000" ) };
    RCHAR spawnCmd[] = "c:\\windows\\system32\\ping.exe 1.1.1.1 -n 5 -w 1000";
    RNCHAR cmdMarker[] = _NC( "ping" );
    RU32 expectedRet = 1;
#else
    RNCHAR spawnCmd[] = _NC( "sleep 1" );
    RNCHAR cmdMarker[] = _NC( "sleep" );
    RU32 expectedRet = 0;
#endif
    RU32 ret = 0;
    RU32 size = 0;
    rSequence notif = NULL;
    RPNCHAR path = NULL;
    RPNCHAR tmpPath = NULL;
    RU32 targetPid = 0;
    RU32 pid = 0;
    RBOOL isTargetFoundStart = FALSE;
    RBOOL isTargetFoundStop = FALSE;

    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );

    // Register to the notifications we expect.
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, notifQueue, NULL ) );
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, 0, notifQueue, NULL ) );

    dummyStop = rEvent_create( TRUE );
    hThread = rpal_thread_new( _threadStubToThreadPool, dummyStop );
    HBS_ASSERT_TRUE( NULL != hThread );
    rpal_thread_sleep( MSEC_FROM_SEC( 15 ) );

    // Spawn a process
    HBS_ASSERT_TRUE( expectedRet == ( ret = system( (RPCHAR)spawnCmd ) ) );

    rpal_thread_sleep( MSEC_FROM_SEC( 20 ) );
    rEvent_set( dummyStop );
    rpal_thread_wait( hThread, RINFINITE );
    rEvent_free( dummyStop );
    rpal_thread_free( hThread );

    // Make sure we got both the start and stop.
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
    HBS_ASSERT_TRUE( 2 <= size );   // We check for greater since some unrelated process could have started too...

    // We make sure the sleeps are in the notifications as expected.
    while( !( isTargetFoundStart &&
              isTargetFoundStop ) &&
           rQueue_remove( notifQueue, &notif, NULL, 0 ) )
    {
        // We look for the process starting up and record the pid.
        if( NULL == path )
        {
            if( !rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &path ) ||
                NULL == rpal_string_stristr( path, (RPNCHAR)cmdMarker ) )
            {
                path = NULL;
            }
            else
            {
                HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &targetPid ) );
                isTargetFoundStart = TRUE;
            }
        }
        // Only process termination has no path.
        else if( !rSequence_getSTRINGN( notif, RP_TAGS_FILE_PATH, &tmpPath ) &&
                 HBS_ASSERT_TRUE( rSequence_getRU32( notif, RP_TAGS_PROCESS_ID, &pid ) ) )
        {
            // This means we've identified the target process, look for the termination
            if( pid == targetPid )
            {
                isTargetFoundStop = TRUE;
            }
        }

        rSequence_free( notif );
    }

    HBS_ASSERT_TRUE( isTargetFoundStart );
    HBS_ASSERT_TRUE( isTargetFoundStop );

    // Teardown
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, notifQueue, NULL );
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, notifQueue, NULL );
    rQueue_free( notifQueue );
}

HBS_TEST_SUITE( 1 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        HBS_RUN_TEST( um_snapshot );
        HBS_RUN_TEST( notify_process );
        HBS_RUN_TEST( um_diff_thread );

        isSuccess = TRUE;
    }

    return isSuccess;
}