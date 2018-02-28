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
#include <rpHostCommonPlatformLib/rTags.h>
#include <stdint.h>

#pragma warning( push )
#pragma warning(disable:4201)
#pragma warning(disable:4324)
#include <yara.h>
#pragma warning( pop )

#define RPAL_FILE_ID        99


#define _TIMEOUT_BETWEEN_FILE_SCANS         (1000 * 60)

//=============================================================================
// YARA Required Shims
//=============================================================================
RPRIVATE
RVOID
    reportError
    (
        rSequence originalRequest,
        RU32 errorCode,
        RPCHAR errorStr
    )
{
    rSequence event = NULL;

    if( NULL != ( event = rSequence_new() ) )
    {
        hbs_markAsRelated( originalRequest, event );
        rSequence_addRU32( event, RP_TAGS_ERROR, errorCode );
        rSequence_addSTRINGA( event, RP_TAGS_ERROR_MESSAGE, errorStr ? errorStr : "" );
        hbs_timestampEvent( event, 0 );
        notifications_publish( RP_TAGS_NOTIFICATION_YARA_DETECTION, event );
        rSequence_free( event );
    }
}

RPRIVATE
size_t
    _yara_stream_read
    (
        void* ptr,
        size_t size,
        size_t count,
        void* user_data
    )
{
    size_t read = 0;
    rBlob pRules = user_data;
    RU32 toRead = (RU32)(count * size);

    if( NULL != ptr &&
        0 != size &&
        0 != count &&
        NULL != user_data )
    {
        if( rpal_blob_readBytes( pRules, toRead, ptr ) )
        {
            read = count;
        }
    }

    return read;
}

RPRIVATE
size_t
    _yara_stream_write
    (
        const void* ptr,
        size_t size,
        size_t count,
        void* user_data
    )
{
    size_t written = 0;
    rBlob pRules = user_data;
    RU32 toWrite = (RU32)(count * size);

    if( NULL != ptr &&
        0 != size &&
        0 != count &&
        NULL != user_data )
    {
        if( rpal_blob_add( pRules, (RPVOID)ptr, toWrite ) )
        {
            written = count;
        }
    }

    return written;
}

RPRIVATE
YR_RULES*
    loadYaraRules
    (
        RPU8 buffer,
        RU32 bufferSize
    )
{
    YR_RULES* rules = NULL;
    YR_STREAM stream = { 0 };

    stream.read = _yara_stream_read;
    stream.write = _yara_stream_write;
    if( NULL != ( stream.user_data = rpal_blob_createFromBuffer( buffer, bufferSize ) ) )
    {
        if( ERROR_SUCCESS != yr_rules_load_stream( &stream, &rules ) )
        {
            rules = NULL;
        }

        rpal_blob_freeWrapperOnly( stream.user_data );
    }

    return rules;
}

//=============================================================================
// Core Functions
//=============================================================================
RPRIVATE YR_RULES* g_global_rules = NULL;
RPRIVATE rMutex g_global_rules_mutex = NULL;
RPRIVATE rQueue g_async_files_to_scan = NULL;

typedef struct
{
    RU32 pid;
    RU64 regionBase;
    RU64 regionSize;
    rSequence processInfo; // Cached between matches
    rSequence moduleInfo;  // Cached between matches
    rSequence fileInfo;    // Cached between matches
} YaraMatchContext;

typedef struct
{
    RU64 base;
    RU64 size;
} _MemRange;

RPRIVATE
RVOID
    _freeSeq
    (
        rSequence seq,
        RU32 dummySize
    )
{
    UNREFERENCED_PARAMETER( dummySize );

    if( rpal_memory_isValid( seq ) )
    {
        rSequence_free( seq );
    }
}

RPRIVATE
int 
    _yaraMemMatchCallback
    (
        int message,
        void* message_data,
        void* user_data
    )
{
    YR_RULE* rule = (YR_RULE*)message_data;
    YaraMatchContext* context = (YaraMatchContext*)user_data;
    rSequence event = NULL;
    Atom parentAtom = { 0 };
    RU64 curTime = 0;

    if( CALLBACK_MSG_RULE_MATCHING == message &&
        NULL != message_data &&
        NULL != user_data )
    {
        if( NULL != ( event = rSequence_new() ) )
        {
            curTime = rpal_time_getGlobalPreciseTime();

            rSequence_addRU32( event, RP_TAGS_PROCESS_ID, context->pid );
            rSequence_addPOINTER64( event, RP_TAGS_BASE_ADDRESS, context->regionBase );
            rSequence_addRU64( event, RP_TAGS_MEMORY_SIZE, context->regionSize );

            hbs_markAsRelated( context->fileInfo, event );

            if( NULL == context->processInfo )
            {
                context->processInfo = processLib_getProcessInfo( context->pid, NULL );
            }

            if( NULL != context->processInfo )
            {
                rSequence_addSEQUENCE( event, RP_TAGS_PROCESS, rSequence_duplicate( context->processInfo ) );
            }

            if( NULL != context->moduleInfo )
            {
                rSequence_addSEQUENCE( event, RP_TAGS_DLL, rSequence_duplicate( context->moduleInfo ) );
            }

            rSequence_addSTRINGA( event, RP_TAGS_RULE_NAME, (char*)rule->identifier );

            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
            parentAtom.key.process.pid = context->pid;
            if( atoms_query( &parentAtom, curTime ) )
            {
                HbsSetParentAtom( event, parentAtom.id );
            }

            hbs_timestampEvent( event, curTime );
            hbs_publish( RP_TAGS_NOTIFICATION_YARA_DETECTION, event );

            rSequence_free( event );
        }
        else
        {
            rpal_debug_warning( "error creating event from Yara match" );
        }
    }

    return CALLBACK_CONTINUE;
}

RPRIVATE
RU32
    _scanProcessWith
    (
        RU32 pid,
        YaraMatchContext* matchContext,
        YR_RULES* rules,
        rEvent isTimeToStop
    )
{
    RU32 scanError = (RU32)(-1);
    rList modules = NULL;
    rSequence module = NULL;
    _MemRange* memRanges = NULL;
    RU32 i = 0;
    rList memoryMap = NULL;
    rSequence memoryRegion = NULL;
    RU8 memAccess = 0;
    RU64 mem = 0;
    RU64 memSize = 0;
    RPU8 buffer = NULL;

    // First pass is to scan known modules
    if( NULL != ( modules = processLib_getProcessModules( pid ) ) )
    {
        rpal_debug_info( "scanning process %d module memory with yara", pid );

        // We also generate an optimized list of module ranges for later
        if( NULL != ( memRanges = rpal_memory_alloc( sizeof( _MemRange ) *
                                                     rList_getNumElements( modules ) ) ) )
        {
            while( ( NULL == isTimeToStop || !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) ) &&
                   rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
            {
                if( rSequence_getPOINTER64( module, RP_TAGS_BASE_ADDRESS, &mem ) &&
                    rSequence_getRU64( module, RP_TAGS_MEMORY_SIZE, &memSize ) )
                {
                    memRanges[ i ].base = mem;
                    memRanges[ i ].size = memSize;
                    i++;

                    matchContext->regionBase = mem;
                    matchContext->regionSize = memSize;
                    matchContext->moduleInfo = module;

                    if( processLib_getProcessMemory( pid,
                                                     (RPVOID)NUMBER_TO_PTR( mem ),
                                                     memSize,
                                                     (RPVOID*)&buffer,
                                                     TRUE ) )
                    {
                        rpal_debug_info( "yara scanning module region of size 0x%lx", memSize );

                        if( NULL != rules ||
                            rMutex_lock( g_global_rules_mutex ) )
                        {
                            if( ERROR_SUCCESS != ( scanError = yr_rules_scan_mem( NULL == rules ? g_global_rules : rules,
                                                                                  buffer,
                                                                                  (size_t)memSize,
                                                                                  SCAN_FLAGS_FAST_MODE |
                                                                                  SCAN_FLAGS_PROCESS_MEMORY,
                                                                                  _yaraMemMatchCallback,
                                                                                  matchContext,
                                                                                  60 ) ) )
                            {
                                rpal_debug_warning( "Yara module scan error: %d 0x%lx 0x%lx: %d",
                                                    pid,
                                                    mem,
                                                    memSize,
                                                    scanError );
                            }

                            if( NULL == rules )
                            {
                                rMutex_unlock( g_global_rules_mutex );
                            }
                        }

                        rpal_memory_free( buffer );

                        rpal_debug_info( "finished region" );
                    }
                }
            }
        }

        rList_free( modules );
    }

    // Optimize the memory ranges
    if( rpal_memory_isValid( memRanges ) &&
        !rpal_sort_array( memRanges, i, sizeof( _MemRange ), (rpal_ordering_func)rpal_order_RU64 ) )
    {
        rpal_memory_free( memRanges );
        memRanges = NULL;
    }

    // Second pass is to go through executable non-module areas
    if( NULL != ( memoryMap = processLib_getProcessMemoryMap( pid ) ) )
    {
        rpal_debug_info( "scanning process %d non-module memory with yara", pid );

        while( ( NULL == isTimeToStop || !rEvent_wait(isTimeToStop, MSEC_FROM_SEC( 5 ) ) ) &&
               rList_getSEQUENCE( memoryMap, RP_TAGS_MEMORY_REGION, &memoryRegion ) )
        {
            if( rSequence_getPOINTER64( memoryRegion, RP_TAGS_BASE_ADDRESS, &mem ) &&
                rSequence_getRU64( memoryRegion, RP_TAGS_MEMORY_SIZE, &memSize ) &&
                rSequence_getRU8( memoryRegion, RP_TAGS_MEMORY_ACCESS, &memAccess ) &&
                ( PROCESSLIB_MEM_ACCESS_EXECUTE == memAccess ||
                  PROCESSLIB_MEM_ACCESS_EXECUTE_READ == memAccess ||
                  PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE == memAccess ||
                  PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE_COPY  == memAccess ) )
            {
                // If it's in a known module, skip
                if( (RU32)( -1 ) != rpal_binsearch_array_closest( memRanges,
                                                                  i,
                                                                  sizeof( _MemRange ),
                                                                  &mem,
                                                                  (rpal_ordering_func)rpal_order_RU64,
                                                                  TRUE ) )
                {
                    continue;
                }
                matchContext->regionBase = mem;
                matchContext->regionSize = memSize;
                matchContext->moduleInfo = NULL;

                if( processLib_getProcessMemory( pid,
                                                 (RPVOID)NUMBER_TO_PTR(mem),
                                                 memSize,
                                                 (RPVOID*)&buffer,
                                                 TRUE ) )
                {
                    rpal_debug_info( "yara scanning memory region of size 0x%lx", memSize );

                    if( NULL != rules ||
                        rMutex_lock( g_global_rules_mutex ) )
                    {
                        if( ERROR_SUCCESS != ( scanError = yr_rules_scan_mem( NULL == rules ? g_global_rules : rules,
                                                                              buffer,
                                                                              (size_t)memSize,
                                                                              SCAN_FLAGS_FAST_MODE |
                                                                              SCAN_FLAGS_PROCESS_MEMORY,
                                                                              _yaraMemMatchCallback,
                                                                              matchContext,
                                                                              60 ) ) )
                        {
                            rpal_debug_warning( "Yara memory scan error: %d 0x%lx 0x%lx: %d",
                                                pid,
                                                mem,
                                                memSize,
                                                scanError );
                        }

                        if( NULL == rules )
                        {
                            rMutex_unlock( g_global_rules_mutex );
                        }
                    }

                    rpal_memory_free( buffer );
                }
            }
        }

        rList_free( memoryMap );
    }

    if( rpal_memory_isValid( memRanges ) )
    {
        rpal_memory_free( memRanges );
    }

    return scanError;
}

RPRIVATE
RPVOID
    continuousMemScan
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    RU32 thisProcId = 0;
    YaraMatchContext matchContext = { 0 };
    RU32 scanError = 0;

    UNREFERENCED_PARAMETER( ctx );

    thisProcId = processLib_getCurrentPid();

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        // Wait until we have global rules to look for.
        if( rMutex_lock( g_global_rules_mutex ) )
        {
            if( NULL == g_global_rules )
            {
                rMutex_unlock( g_global_rules_mutex );
                rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 30 ) );
                continue;
            }
            rMutex_unlock( g_global_rules_mutex );
        }

        if( NULL != ( processes = processLib_getProcessEntries( TRUE ) ) )
        {
            curProc = processes;
            while( 0 != curProc->pid )
            {
                // We can't examine our own memory for the risk of tripping on the sigs themselves.
                if( curProc->pid == thisProcId ) continue;

                rpal_debug_info( "yara scanning pid %d", curProc->pid );

                matchContext.pid = curProc->pid;
                matchContext.processInfo = NULL;
                matchContext.moduleInfo = NULL;

                scanError = _scanProcessWith( curProc->pid, &matchContext, NULL, isTimeToStop );

                rSequence_free( matchContext.processInfo );

                if( rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 30 ) ) ) { break; }

                curProc++;
            }

            rpal_memory_free( processes );
        }
    }

    yr_finalize_thread();

    return NULL;
}


RPRIVATE
int
    _yaraFileMatchCallback
    (
        int message,
        void* message_data,
        void* user_data
    )
{
    YR_RULE* rule = (YR_RULE*)message_data;
    YaraMatchContext* context = (YaraMatchContext*)user_data;
    rSequence event = NULL;
    
    if( CALLBACK_MSG_RULE_MATCHING == message &&
        NULL != message_data &&
        NULL != user_data )
    {
        if( NULL != ( event = rSequence_duplicate( context->fileInfo ) ) )
        {
            rSequence_addSTRINGA( event, RP_TAGS_RULE_NAME, (char*)rule->identifier );

            hbs_publish( RP_TAGS_NOTIFICATION_YARA_DETECTION, event );

            rSequence_free( event );
        }
        else
        {
            rpal_debug_warning( "error creating event from Yara match" );
        }
    }

    return CALLBACK_CONTINUE;
}

RPRIVATE
RPVOID
    continuousFileScan
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence event = NULL;
    RU32 timeout = 0;
    RPNCHAR pathN = NULL;
    RPCHAR pathA = NULL;
    YaraMatchContext matchContext = { 0 };
    RU32 scanError = 0;
    rBloom knownFiles = NULL;

    UNREFERENCED_PARAMETER( ctx );

    if( NULL == ( knownFiles = rpal_bloom_create( 100000, 0.00001 ) ) )
    {
        return NULL;
    }

    while( !rEvent_wait( isTimeToStop, timeout ) )
    {
        if( rQueue_remove( g_async_files_to_scan, (RPVOID*)&event, NULL, MSEC_FROM_SEC( 2 ) ) )
        {
            if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &pathN ) &&
                rpal_bloom_addIfNew( knownFiles, pathN, rpal_string_strlen( pathN ) ) )
            {
                rpal_debug_info( "yara scanning " RF_STR_N, pathN );
                matchContext.fileInfo = event;

                if( NULL != ( pathA = rpal_string_ntoa( pathN ) ) )
                {
                    if( rMutex_lock( g_global_rules_mutex ) )
                    {
                        if( NULL != g_global_rules )
                        {
                            rpal_debug_info( "scanning continuous file with yara" );
                            if( ERROR_SUCCESS != ( scanError = yr_rules_scan_file( g_global_rules,
                                                                                   pathA,
                                                                                   SCAN_FLAGS_FAST_MODE,
                                                                                   _yaraFileMatchCallback,
                                                                                   &matchContext,
                                                                                   60 ) ) )
                            {
                                rpal_debug_warning( "Yara file scan error: %d", scanError );
                            }
                        }

                        rMutex_unlock( g_global_rules_mutex );
                    }

                    rpal_memory_free( pathA );
                }
            }

            rSequence_free( event );

            timeout = _TIMEOUT_BETWEEN_FILE_SCANS;
        }
        else
        {
            timeout = 0;
        }
    }

    rpal_bloom_destroy( knownFiles );

    yr_finalize_thread();

    return NULL;
}

RPRIVATE
RVOID
    updateSignatures
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPU8 buffer = NULL;
    RU32 bufferSize = 0;
    YR_RULES* rules = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getBUFFER( event, RP_TAGS_RULES, &buffer, &bufferSize ) )
        {
            if( NULL != ( rules = loadYaraRules( buffer, bufferSize ) ) )
            {
                if( rMutex_lock( g_global_rules_mutex ) )
                {
                    g_global_rules = rules;

                    rMutex_unlock( g_global_rules_mutex );
                }
                else
                {
                    yr_rules_destroy( rules );
                }
            }
        }
    }

    yr_finalize_thread();
}

RPRIVATE
RVOID
    doScan
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = 0;
    RPCHAR fileA = NULL;
    RPNCHAR procN = NULL;

    RPWCHAR fileW = NULL;
    RPWCHAR procW = NULL;
    RPCHAR procA = NULL;
    RPU8 rulesBuffer = NULL;
    RU32 rulesBufferSize = 0;
    YR_RULES* rules = NULL;
    YaraMatchContext matchContext = { 0 };
    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    RU32 scanError = 0;
    rSequence processInfo = NULL;
    RPNCHAR tmpN = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid );
        if( rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &fileW ) )
        {
            fileA = rpal_string_wtoa( fileW );
        }
        else if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &fileA ) )
        {
            fileA = rpal_string_strdupA( fileA );
        }
        else if( rSequence_getSTRINGW( event, RP_TAGS_PROCESS, &procW ) )
        {
            procN = rpal_string_wton( procW );
        }
        else if( rSequence_getSTRINGA( event, RP_TAGS_PROCESS, &procA ) )
        {
            procN = rpal_string_aton( procA );
        }

        if( rSequence_getBUFFER( event, RP_TAGS_RULES, &rulesBuffer, &rulesBufferSize ) )
        {
            rules = loadYaraRules( rulesBuffer, rulesBufferSize );
        }

        if( NULL != rules )
        {
            if( NULL != fileA )
            {
                rpal_debug_info( "scanning file with yara" );
                matchContext.fileInfo = event;

                // Scan this file
                if( ERROR_SUCCESS != ( scanError = yr_rules_scan_file( rules,
                                                                       fileA,
                                                                       SCAN_FLAGS_FAST_MODE,
                                                                       _yaraFileMatchCallback,
                                                                       &matchContext,
                                                                       60 ) ) )
                {
                    rpal_debug_warning( "Yara file scan error: %d", scanError );
                }
            }
            else if( NULL != procN )
            {
                // Scan processes matching
                if( NULL != ( processes = processLib_getProcessEntries( TRUE ) ) )
                {
                    curProc = processes;
                    while( 0 != curProc->pid )
                    {
                        if( NULL != ( processInfo = processLib_getProcessInfo( curProc->pid, NULL ) ) )
                        {
                            if( rSequence_getSTRINGN( processInfo, RP_TAGS_FILE_PATH, &tmpN ) )
                            {
                                if( rpal_string_match( procN, tmpN, RPAL_PLATFORM_FS_CASE_SENSITIVITY ) )
                                {
                                    matchContext.pid = curProc->pid;
                                    matchContext.processInfo = processInfo;

                                    scanError = _scanProcessWith( curProc->pid,
                                                                    &matchContext,
                                                                    rules,
                                                                    NULL );
                                }
                            }

                            rSequence_free( processInfo );
                        }

                        curProc++;
                    }

                    rpal_memory_free( processes );
                }
            }
            else if( 0 != pid )
            {
                // Scan this process
                matchContext.pid = pid;
                scanError = _scanProcessWith( pid, &matchContext, rules, NULL );
                rSequence_free( matchContext.processInfo );
            }
            else
            {
                // Scan all processes
                if( NULL != ( processes = processLib_getProcessEntries( TRUE ) ) )
                {
                    curProc = processes;
                    while( 0 != curProc->pid )
                    {
                        matchContext.pid = curProc->pid;

                        scanError = _scanProcessWith( curProc->pid, &matchContext, rules, NULL );
                        rSequence_free( matchContext.processInfo );

                        curProc++;
                    }
                        
                    rpal_memory_free( processes );
                }
            }

            yr_rules_destroy( rules );
        }
        else
        {
            rpal_debug_warning( "no rules in yara scan request" );
            hbs_sendCompletionEvent( event, 
                                     RP_TAGS_NOTIFICATION_YARA_DETECTION, 
                                     RPAL_ERROR_NOT_SUPPORTED, 
                                     "can't parse" );
        }

        rpal_memory_free( fileA );
        rpal_memory_free( procN );
    }

    rpal_debug_info( "finished on demand yara scan" );
    hbs_sendCompletionEvent( event,
                             RP_TAGS_NOTIFICATION_YARA_DETECTION,
                             scanError,
                             "done" );

    yr_finalize_thread();
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_16_events[] = { RP_TAGS_NOTIFICATION_YARA_DETECTION,
                                   0 };

RBOOL
    collector_16_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( 0 == yr_initialize() )
        {
            if( NULL != ( g_global_rules_mutex = rMutex_create() ) )
            {
                if( rQueue_create( &g_async_files_to_scan, _freeSeq, 100 ) )
                {
                    if( notifications_subscribe( RP_TAGS_NOTIFICATION_YARA_RULES_UPDATE,
                                                 NULL,
                                                 0,
                                                 NULL,
                                                 updateSignatures ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_YARA_SCAN,
                                                 NULL,
                                                 0,
                                                 NULL,
                                                 doScan ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                                 NULL,
                                                 0,
                                                 g_async_files_to_scan,
                                                 NULL ) )
                    {
                        isSuccess = TRUE;

                        if( !rThreadPool_task( hbsState->hThreadPool, continuousMemScan, NULL ) ||
                            !rThreadPool_task( hbsState->hThreadPool, continuousFileScan, NULL ) )
                        {
                            isSuccess = FALSE;
                        }
                    }
                }
            }
        }
    }

    if( !isSuccess )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_YARA_RULES_UPDATE, NULL, updateSignatures );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_YARA_SCAN, NULL, doScan );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, g_async_files_to_scan, NULL);
        rQueue_free( g_async_files_to_scan );
        g_async_files_to_scan = NULL;
        rMutex_free( g_global_rules_mutex );
        g_global_rules_mutex = NULL;

        yr_finalize();
    }

    return isSuccess;
}

RBOOL
    collector_16_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_YARA_RULES_UPDATE, NULL, updateSignatures );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_YARA_SCAN, NULL, doScan );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, g_async_files_to_scan, NULL );

        if( rMutex_lock( g_global_rules_mutex ) )
        {
            if( NULL != g_global_rules )
            {
                yr_rules_destroy( g_global_rules );
                g_global_rules = NULL;
            }

            rMutex_unlock( g_global_rules_mutex );
        }

        rQueue_free( g_async_files_to_scan );
        g_async_files_to_scan = NULL;

        rMutex_free( g_global_rules_mutex );
        g_global_rules_mutex = NULL;

        yr_finalize();

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_16_update
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
HBS_TEST_SUITE( 16 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}