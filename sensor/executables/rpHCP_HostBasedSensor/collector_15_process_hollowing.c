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


#define RPAL_FILE_ID                  98

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <processLib/processLib.h>
#include <libOs/libOs.h>
#include <obsLib/obsLib.h>

#define _SCRATCH_SIZE                   (1024*512)
#define _MIN_DISK_SAMPLE_SIZE           30
#define _MAX_DISK_SAMPLE_SIZE           100
#define _MIN_DISK_BIN_COVERAGE_PERCENT  50
#define _MIN_SAMPLE_STR_LEN             6
#define _MAX_SAMPLE_STR_LEN             40
#define _MAX_SAMPLE_SPECIAL_CHAR        0
#define _MIN_SAMPLE_MATCH_PERCENT       50

#define _CHECK_SEC_AFTER_PROCESS_CREATION   5000

#define _TIMEOUT_BETWEEN_MODULES                (5*1000)
#define _LARGE_PATTERNS                         (500)
#define _TIMEOUT_BETWEEN_MATCHES_LARGE_PATTERNS (5)
#define _TIMEOUT_BETWEEN_CONSTANT_PROCESSS      (30*1000)
#define _MAX_CPU_WAIT                           (60)
#define _CPU_WATERMARK                          (50)

#ifdef RPAL_PLATFORM_LINUX
#define _INITIAL_PROFILED_TIMEOUT               1000
#define _PROFILE_INCREMENT                      100
#else
#define _INITIAL_PROFILED_TIMEOUT               10
#define _PROFILE_INCREMENT                      1
#endif
#define _SANITY_CEILING                         MSEC_FROM_SEC( 2 )

RPRIVATE rQueue g_newProcessNotifications = NULL;


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
RBOOL
    _longestString
    (
        RPCHAR begin,
        RU32 max,
        RU32* toSkip,
        RU32* longestLength,
        RBOOL* isUnicode
    )
{
    RBOOL isSuccess = FALSE;
    RU32 size = 0;
    RWCHAR unicodeLow = 0xFF;
    RWCHAR unicodeHigh = ( (RWCHAR)( -1 ) ^ 0xFF );
    RPWCHAR possibleChar = NULL;
    RU32 nSpecialChar = 0;

    if( NULL != begin &&
        NULL != toSkip &&
        NULL != longestLength &&
        NULL != isUnicode )
    {
        *longestLength = 0;
        *toSkip = 0;

        for( size = 0; size < max; size++ )
        {
            if( 0 == begin[ size ] )
            {
                break;
            }
            else if( !rpal_string_charIsAscii( begin[ size ] ) ||
                     size == max - 1 )
            {
                // We're only looking for clean C NULL-terminated strings
                *toSkip = size + 1;
                return FALSE;
            }
            else if( rpal_string_charIsAscii( begin[ size ] ) &&
                     !rpal_string_charIsAlphaNum( begin[ size ] ) )
            {
                nSpecialChar++;
                if( nSpecialChar > _MAX_SAMPLE_SPECIAL_CHAR )
                {
                    // Too many special characters, may be binary data
                    *toSkip = size + 1;
                    return FALSE;
                }
            }
        }

        if( 1 == size )
        {
            // This looks like it might be the first character of a unicode
            // string. So let's look for one.
            *isUnicode = TRUE;

            for( size = 0; size < max; size += sizeof( RWCHAR ) )
            {
                possibleChar = (RPWCHAR)( begin + size );

                if( 0 == *possibleChar )
                {
                    break;
                }
                else
                {
                    if( !rpal_string_charIsAscii( (RCHAR)( *possibleChar & unicodeLow ) ) ||
                        0 != ( *possibleChar & unicodeHigh ) ||
                        size == max - sizeof( RWCHAR ) )
                    {
                        *toSkip = size + 1;
                        return FALSE;
                    }
                }
            }
        }

        *longestLength = size + 1;
        *toSkip = *longestLength;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RPRIVATE
HObs
    _getModuleDiskStringSample
    (
        RPNCHAR modulePath,
        RU32* pLastScratch,
        rEvent isTimeToStop,
        LibOsPerformanceProfile* perfProfile
    )
{
    HObs sample = NULL;
    RPU8 scratch = NULL;
    rFile hFile = NULL;
    RU32 read = 0;
    RPU8 start = NULL;
    RPU8 end = NULL;
    RU32 toSkip = 0;
    RU32 longestLength = 0;
    RBOOL isUnicode = FALSE;
    RPU8 sampleNumber = 0;
    rBloom stringsSeen = NULL;
    RU64 readOffset = 0;

    UNREFERENCED_PARAMETER( isTimeToStop );

    if( NULL != modulePath &&
        NULL != pLastScratch )
    {
        readOffset = *pLastScratch * _SCRATCH_SIZE;
        if( NULL != ( stringsSeen = rpal_bloom_create( _MAX_DISK_SAMPLE_SIZE, 0.0001 ) ) )
        {
            if( NULL != ( scratch = rpal_memory_alloc( _SCRATCH_SIZE ) ) )
            {
                if( rFile_open( modulePath, &hFile, RPAL_FILE_OPEN_EXISTING |
                                                    RPAL_FILE_OPEN_READ ) )
                {
                    if( readOffset == rFile_seek( hFile, 
                                                  readOffset, 
                                                  rFileSeek_SET ) &&
                        0 != ( read = rFile_readUpTo( hFile, _SCRATCH_SIZE, scratch ) ) )
                    {
                        if( NULL != ( sample = obsLib_new( _MAX_DISK_SAMPLE_SIZE, 0 ) ) )
                        {
                            ( *pLastScratch )++;
                            start = scratch;
                            end = scratch + read;

                            // We parse for strings up to 'read', we don't care about the 
                            // memory boundary, we might truncate some strings but we're
                            // sampling anyway.
                            while( !rEvent_wait( isTimeToStop, 0 ) &&
                                   ( start >= scratch ) && ( start >= scratch ) &&
                                   ( start + _MIN_SAMPLE_STR_LEN ) < ( scratch + read ) &&
                                   _MAX_DISK_SAMPLE_SIZE >= PTR_TO_NUMBER( sampleNumber ) )
                            {
                                libOs_timeoutWithProfile( perfProfile, TRUE, isTimeToStop );

                                isUnicode = FALSE;

                                if( _longestString( (RPCHAR)start,
                                                    (RU32)( end - start ),
                                                    &toSkip,
                                                    &longestLength,
                                                    &isUnicode ) &&
                                    _MIN_SAMPLE_STR_LEN <= longestLength &&
                                    _MAX_SAMPLE_STR_LEN >= longestLength )
                                {
                                    if( rpal_bloom_addIfNew( stringsSeen,
                                                             start,
                                                             longestLength ) )
                                    {
                                        if( obsLib_addPattern( sample,
                                                               start,
                                                               longestLength,
                                                               sampleNumber ) )
                                        {
                                            sampleNumber++;
                                        }
                                    }
                                }

                                start += toSkip;
                            }
                        }
                    }

                    rFile_close( hFile );
                }

                rpal_memory_free( scratch );
            }

            rpal_bloom_destroy( stringsSeen );
        }
    }

    return sample;
}

RPRIVATE
RU32
    _checkMemoryForStringSample
    (
        HObs sample,
        RU32 pid,
        RPVOID moduleBase,
        RU64 moduleSize,
        rEvent isTimeToStop,
        LibOsPerformanceProfile* perfProfile
    )
{
    RPU8 pMem = NULL;
    RU8* sampleList = NULL;
    RPU8 sampleNumber = 0;
    RU32 nSamples = 0;
    RU32 nSamplesFound = (RU32)(-1);

    UNREFERENCED_PARAMETER( isTimeToStop );

    if( NULL != sample &&
        0 != pid &&
        NULL != moduleBase &&
        0 != moduleSize &&
        _MIN_DISK_SAMPLE_SIZE <= ( nSamples = obsLib_getNumPatterns( sample ) ) )
    {
        if( NULL != ( sampleList = rpal_memory_alloc( sizeof( RU8 ) * nSamples ) ) )
        {
            rpal_memory_zero( sampleList, sizeof( RU8 ) * nSamples );

            if( processLib_getProcessMemory( pid, moduleBase, moduleSize, (RPVOID*)&pMem, TRUE ) )
            {
                if( obsLib_setTargetBuffer( sample, pMem, (RU32)moduleSize ) )
                {
                    while( !rEvent_wait( isTimeToStop, 0 ) &&
                           obsLib_nextHit( sample, (RPVOID*)&sampleNumber, NULL ) )
                    {
                        libOs_timeoutWithProfile( perfProfile, TRUE, isTimeToStop );

                        if( sampleNumber < (RPU8)NUMBER_TO_PTR( nSamples ) &&
                            0 == sampleList[ (RU32)PTR_TO_NUMBER( sampleNumber ) ] )
                        {
                            sampleList[ (RU32)PTR_TO_NUMBER( sampleNumber ) ] = 1;
                            nSamplesFound++;
                        }
                    }
                }

                rpal_memory_free( pMem );
            }
            else
            {
                rpal_debug_info( "failed to get memory for %d: 0x%016X ( 0x%016X ) error %d", 
                                 pid, 
                                 moduleBase, 
                                 moduleSize,
                                 rpal_error_getLast() );
            }

            rpal_memory_free( sampleList );
        }
    }

    return nSamplesFound;
}

RPRIVATE
rList
    _spotCheckProcess
    (
        rEvent isTimeToStop,
        RU32 pid,
        LibOsPerformanceProfile* perfProfile
    )
{
    rList hollowedModules = NULL;

    rList modules = NULL;
    rSequence module = NULL;
    RPNCHAR modulePath = NULL;
    RU32 fileSize = 0;
    RU64 moduleBase = 0;
    RU64 moduleSize = 0;
    HObs diskSample = NULL;
    rSequence hollowedModule = NULL;
    RU32 lastScratchIndex = 0;
    RU32 nSamplesFound = 0;
    RU32 nSamplesTotal = 0;
    RU32 tmpSamplesFound = 0;
    RU32 tmpSamplesSize = 0;
    RTIME runTime = 0;

    rpal_debug_info( "spot checking process %d", pid );

    if( NULL != ( modules = processLib_getProcessModules( pid ) ) )
    {
        while( !rEvent_wait( isTimeToStop, 0 ) &&
               rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
        {
            libOs_timeoutWithProfile( perfProfile, FALSE, isTimeToStop );
            runTime = rpal_time_getLocal();

            modulePath = NULL;
            lastScratchIndex = 0;

            if( ( rSequence_getSTRINGN( module, 
                                        RP_TAGS_FILE_PATH, 
                                        &modulePath ) ) &&
                rSequence_getPOINTER64( module, RP_TAGS_BASE_ADDRESS, &moduleBase ) &&
                rSequence_getRU64( module, RP_TAGS_MEMORY_SIZE, &moduleSize ) )
            {
                if( 0 != ( fileSize = rpal_file_getSize( modulePath, TRUE ) ) )
                {
                    nSamplesFound = 0;
                    nSamplesTotal = 0;
                    tmpSamplesFound = (RU32)( -1 );

                    while( !rEvent_wait( isTimeToStop, 0 ) &&
                            NULL != ( diskSample = _getModuleDiskStringSample( modulePath,
                                                                                &lastScratchIndex,
                                                                                isTimeToStop,
                                                                                perfProfile ) ) )
                    {
                        libOs_timeoutWithProfile( perfProfile, TRUE, isTimeToStop );

                        tmpSamplesSize = obsLib_getNumPatterns( diskSample );

                        if( 0 != tmpSamplesSize )
                        {
                            tmpSamplesFound = _checkMemoryForStringSample( diskSample,
                                                                            pid,
                                                                            NUMBER_TO_PTR( moduleBase ),
                                                                            moduleSize,
                                                                            isTimeToStop,
                                                                            perfProfile );
                            obsLib_free( diskSample );

                            if( (RU32)( -1 ) == tmpSamplesFound )
                            {
                                break;
                            }

                            nSamplesFound += tmpSamplesFound;
                            nSamplesTotal += tmpSamplesSize;

                            if( _MIN_DISK_SAMPLE_SIZE <= nSamplesTotal &&
                                ( _MIN_SAMPLE_MATCH_PERCENT < ( (RFLOAT)nSamplesFound /
                                                                nSamplesTotal ) * 100 ) &&
                                _MIN_DISK_BIN_COVERAGE_PERCENT <= (RFLOAT)( ( lastScratchIndex *
                                                                                _SCRATCH_SIZE ) /
                                                                            fileSize ) * 100 )
                            {
                                break;
                            }
                        }
                        else
                        {
                            obsLib_free( diskSample );
                        }
                    }
                }
                else
                {
                    rpal_debug_info( "could not get file information, not checking" );
                }

                rpal_debug_info( "process hollowing check found a match in %d ( %d / %d ) from %d passes in %d sec", 
                                    pid,  
                                    nSamplesFound, 
                                    nSamplesTotal,
                                    lastScratchIndex,
                                    rpal_time_getLocal() - runTime );
                    
                if( !rEvent_wait( isTimeToStop, 0 ) &&
                    (RU32)(-1) != tmpSamplesFound &&
                    _MIN_DISK_SAMPLE_SIZE <= nSamplesTotal &&
                    ( ( (RFLOAT)nSamplesFound / nSamplesTotal ) * 100 ) < _MIN_SAMPLE_MATCH_PERCENT )
                {
                    rpal_debug_info( "sign of process hollowing found in process %d", pid );

                    if( NULL != ( hollowedModule = rSequence_duplicate( module ) ) )
                    {
                        if( !rList_addSEQUENCE( hollowedModules, hollowedModule ) )
                        {
                            rSequence_free( hollowedModule );
                        }
                    }
                }
            }
            else
            {
                rpal_debug_info( "module missing characteristic" );
            }
        }

        rList_free( modules );
    }
    else
    {
        rpal_debug_info( "failed to get process modules, might be dead" );
    }

    return hollowedModules;
}

RPRIVATE
RPVOID
    spotCheckAllProcesses
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    rList hollowedModules = NULL;
    rSequence processInfo = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };
    Atom parentAtom = { 0 };

    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = _PROFILE_INCREMENT;
    perfProfile.enforceOnceIn = 7;
    perfProfile.lastTimeoutValue = _INITIAL_PROFILED_TIMEOUT;
    perfProfile.sanityCeiling = _SANITY_CEILING;

    if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
    {
        proc = procs;

        while( !rEvent_wait( isTimeToStop, 0 ) &&
               0 != proc->pid &&
               rpal_memory_isValid( isTimeToStop ) )
        {
            libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

            if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, proc->pid, &perfProfile ) ) )
            {
                if( NULL != ( processInfo = processLib_getProcessInfo( proc->pid, NULL ) ) ||
                    ( NULL != ( processInfo = rSequence_new() ) &&
                      rSequence_addRU32( processInfo, RP_TAGS_PROCESS_ID, proc->pid ) ) )
                {
                    if( !rSequence_addLIST( processInfo, RP_TAGS_MODULES, hollowedModules ) )
                    {
                        rList_free( hollowedModules );
                    }
                    else
                    {
                        parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                        parentAtom.key.process.pid = proc->pid;
                        if( atoms_query( &parentAtom, 0 ) )
                        {
                            HbsSetParentAtom( processInfo, parentAtom.id );
                        }

                        hbs_markAsRelated( originalRequest, processInfo );
                        hbs_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, processInfo );
                    }

                    rSequence_free( processInfo );
                }
                else
                {
                    rList_free( hollowedModules );
                }
            }
            proc++;
        }

        rpal_memory_free( procs );
    }

    return NULL;
}

RPRIVATE
RPVOID
    spotCheckProcessConstantly
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    rList hollowedModules = NULL;
    rSequence processInfo = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };
    Atom parentAtom = { 0 };

    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = _PROFILE_INCREMENT;
    perfProfile.enforceOnceIn = 1;
    perfProfile.lastTimeoutValue = _INITIAL_PROFILED_TIMEOUT;
    perfProfile.sanityCeiling = _SANITY_CEILING;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
        {
            proc = procs;

            while( 0 != proc->pid &&
                   rpal_memory_isValid( isTimeToStop ) &&
                   !rEvent_wait( isTimeToStop, 0 ) )
            {
                libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );

                if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, proc->pid, &perfProfile ) ) )
                {
                    if( NULL != ( processInfo = processLib_getProcessInfo( proc->pid, NULL ) ) ||
                        ( NULL != ( processInfo = rSequence_new() ) &&
                        rSequence_addRU32( processInfo, RP_TAGS_PROCESS_ID, proc->pid ) ) )
                    {
                        if( !rSequence_addLIST( processInfo, RP_TAGS_MODULES, hollowedModules ) )
                        {
                            rList_free( hollowedModules );
                        }
                        else
                        {
                            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                            parentAtom.key.process.pid = proc->pid;
                            if( atoms_query( &parentAtom, 0 ) )
                            {
                                HbsSetParentAtom( processInfo, parentAtom.id );
                            }

                            hbs_markAsRelated( originalRequest, processInfo );
                            hbs_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, 
                                         processInfo );
                        }

                        rSequence_free( processInfo );
                    }
                    else
                    {
                        rList_free( hollowedModules );
                    }
                }

                proc++;
            }

            rpal_memory_free( procs );
        }
    }

    return NULL;
}

RPRIVATE
RPVOID
    spotCheckNewProcesses
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    RU32 pid = 0;
    RTIME timestamp = 0;
    RTIME timeToWait = 0;
    RTIME now = 0;
    rSequence newProcess = NULL;
    rList hollowedModules = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };

    UNREFERENCED_PARAMETER( ctx );

    perfProfile.sanityCeiling = _SANITY_CEILING;
    perfProfile.lastTimeoutValue = _INITIAL_PROFILED_TIMEOUT;
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.enforceOnceIn = 7;
    perfProfile.timeoutIncrementPerSec = _PROFILE_INCREMENT;

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( g_newProcessNotifications, &newProcess, NULL, MSEC_FROM_SEC( 5 ) ) )
        {
            if( rSequence_getRU32( newProcess, RP_TAGS_PROCESS_ID, &pid ) &&
                rSequence_getTIMESTAMP( newProcess, RP_TAGS_TIMESTAMP, &timestamp ) )
            {
                timeToWait = timestamp + _CHECK_SEC_AFTER_PROCESS_CREATION;
                now = rpal_time_getGlobalPreciseTime();
                if( now < timeToWait )
                {
                    timeToWait = timeToWait - now;
                    if( _CHECK_SEC_AFTER_PROCESS_CREATION < timeToWait )
                    {
                        // Sanity check
                        timeToWait = _CHECK_SEC_AFTER_PROCESS_CREATION;
                    }
                    rpal_thread_sleep( (RU32)timeToWait );
                }

                if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, pid, &perfProfile ) ) )
                {
                    if( !rSequence_addLIST( newProcess, RP_TAGS_MODULES, hollowedModules ) )
                    {
                        rList_free( hollowedModules );
                    }
                    else
                    {
                        hbs_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, 
                                     newProcess );
                    }
                }
            }

            rSequence_free( newProcess );
        }
    }

    return NULL;
}

RPRIVATE
RVOID
    scan_for_hollowing
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = (RU32)( -1 );
    rEvent dummy = NULL;
    rList hollowedModules = NULL;
    rSequence process = NULL;
    LibOsPerformanceProfile perfProfile = { 0 };
    Atom parentAtom = { 0 };

    UNREFERENCED_PARAMETER( eventType );

    if( NULL != ( dummy = rEvent_create( TRUE ) ) )
    {
        perfProfile.targetCpuPerformance = 10;
        perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET_WHEN_TASKED;
        perfProfile.timeoutIncrementPerSec = _PROFILE_INCREMENT;
        perfProfile.enforceOnceIn = 7;
        perfProfile.lastTimeoutValue = _INITIAL_PROFILED_TIMEOUT;
        perfProfile.sanityCeiling = _SANITY_CEILING;

        if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
        {
            if( NULL != ( process = processLib_getProcessInfo( pid, NULL ) ) ||
                ( NULL != ( process = rSequence_new() ) &&
                  rSequence_addRU32( process, RP_TAGS_PROCESS_ID, pid ) ) )
            {
                if( NULL != ( hollowedModules = _spotCheckProcess( dummy, pid, &perfProfile ) ) )
                {
                    if( !rSequence_addLIST( process, RP_TAGS_MODULES, hollowedModules ) )
                    {
                        rList_free( hollowedModules );
                    }
                    else
                    {
                        parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                        parentAtom.key.process.pid = pid;
                        if( atoms_query( &parentAtom, 0 ) )
                        {
                            HbsSetParentAtom( process, parentAtom.id );
                        }

                        hbs_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH,
                                     process );
                    }
                }
            }

            if( rpal_memory_isValid( process ) )
            {
                rSequence_free( process );
            }
        }

        rEvent_free( dummy );
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_15_events[] = { RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH,
                                   0 };

RBOOL
    collector_15_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rQueue_create( &g_newProcessNotifications, _freeEvt, 20 ) )
        {
            if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                         NULL, 
                                         0, 
                                         g_newProcessNotifications, 
                                         NULL ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         scan_for_hollowing ) &&
                rThreadPool_task( hbsState->hThreadPool, spotCheckProcessConstantly, NULL ) &&
                rThreadPool_task( hbsState->hThreadPool, spotCheckNewProcesses, NULL ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                           g_newProcessNotifications, 
                                           NULL );
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH_REQ,
                                           NULL,
                                           scan_for_hollowing );
                rQueue_free( g_newProcessNotifications );
                g_newProcessNotifications = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_15_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                   g_newProcessNotifications, 
                                   NULL ) &&
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH_REQ,
                                   NULL,
                                   scan_for_hollowing ) )
    {
        if( rQueue_free( g_newProcessNotifications ) )
        {
            isSuccess = TRUE;
            g_newProcessNotifications = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    collector_15_update
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
HBS_TEST_SUITE( 15 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}