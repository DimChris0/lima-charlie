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
#include <rpHostCommonPlatformIFaceLib/rpHostCommonPlatformIFaceLib.h>

#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <obfuscationLib/obfuscationLib.h>
#include <notificationsLib/notificationsLib.h>
#include <cryptoLib/cryptoLib.h>
#include <librpcm/librpcm.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include "collectors.h"
#include "keys.h"
#include "git_info.h"
#include <libOs/libOs.h>

#ifdef RPAL_PLATFORM_MACOSX
#include <Security/Authorization.h>
#endif

//=============================================================================
//  RP HCP Module Requirements
//=============================================================================
#define RPAL_FILE_ID 82
RpHcp_ModuleId g_current_Module_id = 2;

//=============================================================================
//  Global Behavior Variables
//=============================================================================
#define HBS_EXFIL_QUEUE_MAX_NUM                 5000
#define HBS_EXFIL_QUEUE_MAX_SIZE                (1024*1024*10)
#define HBS_MAX_OUBOUND_FRAME_SIZE              (100)
#define HBS_SYNC_INTERVAL                       (60*5)
#define HBS_KACQ_RETRY_N_FRAMES                 (10)

// Large blank buffer to be used to patch configurations post-build
#define _HCP_DEFAULT_STATIC_STORE_SIZE                          (1024 * 50)
#define _HCP_DEFAULT_STATIC_STORE_MAGIC                         { 0xFA, 0x57, 0xF0, 0x0D }
static RU8 g_patchedConfig[ _HCP_DEFAULT_STATIC_STORE_SIZE ] = _HCP_DEFAULT_STATIC_STORE_MAGIC;
#define _HCP_DEFAULT_STATIC_STORE_KEY                           { 0xFA, 0x75, 0x01 }

//=============================================================================
//  Global Context
//=============================================================================
HbsState g_hbs_state = { NULL,
                         NULL,
                         NULL,
                         NULL,
                         { 0 },
                         0,
                         0,
                         NULL,
                         { ENABLED_COLLECTOR( 0 ),
                           ENABLED_COLLECTOR( 1 ),
                           DISABLED_LINUX_COLLECTOR( 2 ),
                           ENABLED_COLLECTOR( 3 ),
                           ENABLED_COLLECTOR( 4 ),
                           DISABLED_COLLECTOR( 5 ),
                           ENABLED_WINDOWS_COLLECTOR( 6 ),
                           DISABLED_LINUX_COLLECTOR( 7 ),
                           ENABLED_COLLECTOR( 8 ),
                           ENABLED_COLLECTOR( 9 ),
                           ENABLED_COLLECTOR( 10 ),
                           ENABLED_COLLECTOR( 11 ),
                           DISABLED_COLLECTOR( 12 ),
                           DISABLED_COLLECTOR( 13 ),
                           ENABLED_COLLECTOR( 14 ),
                           DISABLED_COLLECTOR( 15 ),
                           DISABLED_COLLECTOR( 16 ),
                           ENABLED_COLLECTOR( 17 ),
                           DISABLED_LINUX_COLLECTOR( 18 ),
                           ENABLED_COLLECTOR( 19 ),
                           ENABLED_COLLECTOR( 20 ),
                           ENABLED_COLLECTOR( 21 ),
                           ENABLED_COLLECTOR( 22 ) } };
RU8* hbs_cloud_pub_key = hbs_cloud_default_pub_key;

//=============================================================================
//  Utilities
//=============================================================================
RPRIVATE
rSequence
    getStaticConfig
    (

    )
{
    RU8 magic[] = _HCP_DEFAULT_STATIC_STORE_MAGIC;
    rSequence config = NULL;
    RU32 unused = 0;
    RU8 key[] = _HCP_DEFAULT_STATIC_STORE_KEY;

    if( 0 != rpal_memory_memcmp( g_patchedConfig, magic, sizeof( magic ) ) )
    {
        obfuscationLib_toggle( g_patchedConfig, sizeof( g_patchedConfig ), key, sizeof( key ) );

        if( rSequence_deserialise( &config, g_patchedConfig, sizeof( g_patchedConfig ), &unused ) )
        {
            rpal_debug_info( "static store patched, using it as config" );
        }

        obfuscationLib_toggle( g_patchedConfig, sizeof( g_patchedConfig ), key, sizeof( key ) );
    }
    else
    {
        rpal_debug_info( "static store not patched, using defaults" );
    }

    return config;
}

RPRIVATE
RBOOL
    isHcpIdMatch
    (
        rpHCPId id1,
        rpHCPId id2
    )
{
    RBOOL isMatch = FALSE;
    rpHCPId wildcardId = { 0 };

    if( ( FIXED_BUFFERS_EQUAL( id1.sensor_id, id2.sensor_id ) ||
          FIXED_BUFFERS_EQUAL( id1.sensor_id, wildcardId.sensor_id ) ||
          FIXED_BUFFERS_EQUAL( id2.sensor_id, wildcardId.sensor_id ) ) &&
        ( FIXED_BUFFERS_EQUAL( id1.org_id, id2.org_id ) ||
          FIXED_BUFFERS_EQUAL( id1.org_id, wildcardId.org_id ) ||
          FIXED_BUFFERS_EQUAL( id2.org_id, wildcardId.org_id ) ) &&
        ( FIXED_BUFFERS_EQUAL( id1.ins_id, id2.ins_id ) ||
          FIXED_BUFFERS_EQUAL( id1.ins_id, wildcardId.ins_id ) ||
          FIXED_BUFFERS_EQUAL( id2.ins_id, wildcardId.ins_id ) ) &&
        ( id1.architecture == id2.architecture ||
          id1.architecture == wildcardId.architecture ||
          id2.architecture == wildcardId.architecture ) &&
        ( id1.platform == id2.platform ||
          id1.platform == wildcardId.platform ||
          id2.platform == wildcardId.platform ) )
    {
        isMatch = TRUE;
    }

    return isMatch;
}

#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
RBOOL
    WindowsSetPrivilege
    (
        HANDLE hToken,
        LPCTSTR lpszPrivilege,
        BOOL bEnablePrivilege
    )
{
    LUID luid;
    RBOOL bRet = FALSE;

    if( LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) )
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount = 1;
        tp.Privileges[ 0 ].Luid = luid;
        tp.Privileges[ 0 ].Attributes = ( bEnablePrivilege ) ? SE_PRIVILEGE_ENABLED : 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if( AdjustTokenPrivileges( hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL ) )
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet = ( GetLastError() == ERROR_SUCCESS );
        }
    }
    return bRet;
}


RPRIVATE
RBOOL
    WindowsGetPrivilege
    (
        RPCHAR privName
    )
{
    RBOOL isSuccess = FALSE;

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;

    hProcess = GetCurrentProcess();

    if( NULL != hProcess )
    {
        if( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken ) )
        {
            if( WindowsSetPrivilege( hToken, privName, TRUE ) )
            {
                isSuccess = TRUE;
            }

            CloseHandle( hToken );
        }
    }

    return isSuccess;
}
#endif

RPRIVATE
RBOOL
    getPrivileges
    (

    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    RCHAR strSeDebug[] = "SeDebugPrivilege";
    RCHAR strSeBackup[] = "SeBackupPrivilege";
    RCHAR strSeRestore[] = "SeRestorePrivilege";

    isSuccess = TRUE;

    if( !WindowsGetPrivilege( strSeDebug ) )
    {
        rpal_debug_warning( "error getting SeDebugPrivilege" );
        isSuccess = FALSE;
    }
    if( !WindowsGetPrivilege( strSeBackup ) )
    {
        rpal_debug_warning( "error getting SeBackupPrivilege" );
        isSuccess = FALSE;
    }
    if( !WindowsGetPrivilege( strSeRestore ) )
    {
        rpal_debug_warning( "error getting SeRestorePrivilege" );
        isSuccess = FALSE;
    }
#elif defined( RPAL_PLATFORM_LINUX )
    
#elif defined( RPAL_PLATFORM_MACOSX )
    /*
    OSStatus stat;
    AuthorizationItem taskport_item[] = {{"system.privilege.taskport:"}};
    AuthorizationRights rights = {1, taskport_item}, *out_rights = NULL;
    AuthorizationRef author;
    
    AuthorizationFlags auth_flags = kAuthorizationFlagExtendRights | 
                                    kAuthorizationFlagPreAuthorize | 
                                    ( 1 << 5);

    stat = AuthorizationCreate( NULL, kAuthorizationEmptyEnvironment, auth_flags, &author );
    if( stat != errAuthorizationSuccess )
    {
        isSuccess = TRUE;
    }
    else
    {
        stat = AuthorizationCopyRights( author, 
                                        &rights, 
                                        kAuthorizationEmptyEnvironment, 
                                        auth_flags, 
                                        &out_rights );
        if( stat == errAuthorizationSuccess )
        {
            isSuccess = TRUE;
        }
    }
    */
#endif

    return isSuccess;
}

RPRIVATE
RVOID
    freeExfilEvent
    (
        rSequence seq,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rSequence_free( seq );
}


RPRIVATE
RBOOL
    checkKernelAcquisition
    (

    )
{
    RBOOL isKernelInit = FALSE;

    if( !kAcq_init() )
    {
        rpal_debug_info( "kernel acquisition not initialized" );
    }
    else
    {
        if( kAcq_ping() )
        {
            rpal_debug_info( "kernel acquisition available" );
            isKernelInit = TRUE;
        }
        else
        {
            rpal_debug_info( "kernel acquisition not available" );
            kAcq_deinit();
        }
    }

    return isKernelInit;
}

RPRIVATE
RBOOL
    updateCollectorConfigs
    (
        rList newConfigs
    )
{
    RBOOL isSuccess = FALSE;
    RU8 unused = 0;
    RU32 i = 0;
    rSequence tmpConf = NULL;
    RU32 confId = 0;

    if( rpal_memory_isValid( newConfigs ) )
    {
        rpal_debug_info( "updating collector configurations." );
        
        for( i = 0; i < ARRAY_N_ELEM( g_hbs_state.collectors ); i++ )
        {
            if( NULL != g_hbs_state.collectors[ i ].conf )
            {
                rpal_debug_info( "freeing collector %d config.", i );
                rSequence_free( g_hbs_state.collectors[ i ].conf );
                g_hbs_state.collectors[ i ].conf = NULL;
            }
        }

        while( rList_getSEQUENCE( newConfigs, RP_TAGS_HBS_CONFIGURATION, &tmpConf ) )
        {
            if( rSequence_getRU32( tmpConf, RP_TAGS_HBS_CONFIGURATION_ID, &confId ) &&
                confId < ARRAY_N_ELEM( g_hbs_state.collectors ) )
            {
                if( rSequence_getRU8( tmpConf, RP_TAGS_IS_DISABLED, &unused ) )
                {
                    g_hbs_state.collectors[ confId ].isEnabled = FALSE;
                }
                else
                {
                    g_hbs_state.collectors[ confId ].isEnabled = TRUE;
                    g_hbs_state.collectors[ confId ].conf = rSequence_duplicate( tmpConf );
                    rpal_debug_info( "set new collector %d config.", confId );
                }
            }
        }
                
        isSuccess = TRUE;
    }

    return isSuccess;
}

RPRIVATE
RVOID
    shutdownCollectors
    (

    )
{
    RU32 i = 0;

    if( !rEvent_wait( g_hbs_state.isTimeToStop, 0 ) )
    {
        rpal_debug_info( "signaling to collectors to stop." );
        rEvent_set( g_hbs_state.isTimeToStop );

        if( NULL != g_hbs_state.hThreadPool )
        {
            rpal_debug_info( "destroying collector thread pool." );
            rThreadPool_destroy( g_hbs_state.hThreadPool, TRUE );
            g_hbs_state.hThreadPool = NULL;

            for( i = 0; i < ARRAY_N_ELEM( g_hbs_state.collectors ); i++ )
            {
                if( g_hbs_state.collectors[ i ].isEnabled )
                {
                    rpal_debug_info( "cleaning up collector %d.", i );
                    g_hbs_state.collectors[ i ].cleanup( &g_hbs_state, g_hbs_state.collectors[ i ].conf );
                    rSequence_free( g_hbs_state.collectors[ i ].conf );
                    g_hbs_state.collectors[ i ].conf = NULL;
                }
            }
        }
    }
}

RPRIVATE
RBOOL
    sendSingleMessageHome
    (
        rSequence message
    )
{
    RBOOL isSuccess = FALSE;

    rList messages = NULL;

    if( NULL != ( messages = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
    {
        if( rSequence_addSEQUENCE( messages, RP_TAGS_MESSAGE, message ) )
        {
            isSuccess = rpHcpI_sendHome( messages );
        }

        rList_shallowFree( messages );
    }

    return isSuccess;
}


RPRIVATE
RPVOID
    issueSync
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence wrapper = NULL;
    rSequence message = NULL;

    rThreadPoolTask* tasks = NULL;
    RU32 nTasks = 0;
    RU32 i = 0;
    rList taskList = NULL;
    rSequence task = NULL;
    RTIME threadTime = 0;
    rSequence procInfo = NULL;
    RU64 procMem = 0;
    rList updateList = NULL;

    UNREFERENCED_PARAMETER( ctx );

    if( rEvent_wait( isTimeToStop, 0 ) )
    {
        return NULL;
    }

    rpal_debug_info( "issuing sync to cloud" );

    if( NULL != ( wrapper = rSequence_new() ) )
    {
        if( NULL != ( message = rSequence_new() ) )
        {
            hbs_timestampEvent( message, 0 );

            if( rSequence_addSEQUENCE( wrapper, RP_TAGS_NOTIFICATION_SYNC, message ) )
            {
                if( rSequence_addBUFFER( message,
                                         RP_TAGS_HASH,
                                         g_hbs_state.currentConfigHash,
                                         sizeof( g_hbs_state.currentConfigHash ) ) )
                {
                    // The current version running.
                    rSequence_addRU32( message, RP_TAGS_PACKAGE_VERSION, GIT_REVISION );

                    // Is kernel acquisition currently available?
                    rSequence_addRU8( message, RP_TAGS_HCP_KERNEL_ACQ_AVAILABLE, (RU8)kAcq_isAvailable() );

                    // What is the global time offset?
                    rSequence_addTIMEDELTA( message, RP_TAGS_TIMEDELTA, rpal_time_getGlobalFromLocal( 0 ) );

                    // The managed memory usage.
                    rSequence_addRU32( message, RP_TAGS_MEMORY_USAGE, rpal_memory_totalUsed() );

                    // The current CPU percent usage for this process.
                    rSequence_addRU8( message, RP_TAGS_PERCENT_CPU, libOs_getCurrentProcessCpuUsage() );

                    // The current process memory usage.
                    if( NULL != ( procInfo = processLib_getProcessInfo( processLib_getCurrentPid(), NULL ) ) )
                    {
                        if( rSequence_getRU64( procInfo, RP_TAGS_MEMORY_USAGE, &procMem ) )
                        {
                            rSequence_addRU64( message, RP_TAGS_MEMORY_SIZE, procMem );
                        }

                        rSequence_free( procInfo );
                    }

                    // Add some timing context on running tasks.
                    if( rThreadPool_getRunning( g_hbs_state.hThreadPool, &tasks, &nTasks ) )
                    {
                        if( NULL != ( taskList = rList_new( RP_TAGS_THREADS, RPCM_SEQUENCE ) ) )
                        {
                            for( i = 0; i < nTasks; i++ )
                            {
                                if( NULL != ( task = rSequence_new() ) )
                                {
                                    rSequence_addRU32( task, RP_TAGS_THREAD_ID, tasks[ i ].tid );
                                    rSequence_addRU32( task, RP_TAGS_HCP_FILE_ID, tasks[ i ].fileId );
                                    rSequence_addRU32( task, RP_TAGS_HCP_LINE_NUMBER, tasks[ i ].lineNum );
                                    libOs_getThreadTime( tasks[ i ].tid, &threadTime );
                                    rSequence_addTIMEDELTA( task, RP_TAGS_TIMEDELTA, threadTime );

                                    if( !rList_addSEQUENCE( taskList, task ) )
                                    {
                                        rSequence_free( task );
                                    }
                                }
                            }

                            if( !rSequence_addLIST( message, RP_TAGS_THREADS, taskList ) )
                            {
                                rList_free( taskList );
                            }
                        }

                        rpal_memory_free( tasks );
                    }
                    
                    // Finally we will add the last updated timestamps for the collectors.
                    // This is used by the backend to determine which dynamic configs have been
                    // applied last on a per-sensor basis.
                    if( NULL != ( updateList = rList_new( RP_TAGS_TIMESTAMP, RPCM_RU64 ) ) )
                    {
                        for( i = 0; i < ARRAY_N_ELEM( g_hbs_state.collectors ); i++ )
                        {
                            rList_addRU64( updateList, g_hbs_state.collectors[ i ].lastConfUpdate );
                        }

                        if( !rSequence_addLIST( message, RP_TAGS_LAST_UPDATE, updateList ) )
                        {
                            rList_free( updateList );
                        }
                    }

                    if( !sendSingleMessageHome( wrapper ) )
                    {
                        rpal_debug_warning( "failed to send sync" );
                    }
                }
                    
                rSequence_free( wrapper );
            }
            else
            {
                rSequence_free( wrapper );
                rSequence_free( message );
            }
        }
        else
        {
            rSequence_free( wrapper );
        }
    }

    return NULL;
}

RPRIVATE
RBOOL
    startCollectors
    (

    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;

    rEvent_unset( g_hbs_state.isTimeToStop );
    if( NULL != ( g_hbs_state.hThreadPool = rThreadPool_create( 1, 
                                                                30,
                                                                MSEC_FROM_SEC( 10 ) ) ) )
    {
        isSuccess = TRUE;

        // We always schedule a boilerplate sync.
        rThreadPool_scheduleRecurring( g_hbs_state.hThreadPool, 
                                       HBS_SYNC_INTERVAL, 
                                       (rpal_thread_pool_func)issueSync, 
                                       NULL, 
                                       FALSE );

        for( i = 0; i < ARRAY_N_ELEM( g_hbs_state.collectors ); i++ )
        {
            if( g_hbs_state.collectors[ i ].isEnabled )
            {
                // The configuration per-collector is not persistent or transmitted through the
                // HBS profile so it needs to be reset when collectors start. This will be transmitted
                // in the next SYNC and we will receive new configurations then.
                g_hbs_state.collectors[ i ].lastConfUpdate = 0;

                if( !g_hbs_state.collectors[ i ].init( &g_hbs_state, g_hbs_state.collectors[ i ].conf ) )
                {
                    isSuccess = FALSE;
                    rpal_debug_warning( "collector %d failed to init.", i );
                }
                else
                {
                    rpal_debug_info( "collector %d started.", i );
                }
            }
            else
            {
                rpal_debug_info( "collector %d disabled.", i );
            }
        }
    }

    return isSuccess;
}

RPRIVATE
RVOID
    sendStartupEvent
    (

    )
{
    rSequence wrapper = NULL;
    rSequence startupEvent = NULL;

    if( NULL != ( wrapper = rSequence_new() ) )
    {
        if( NULL != ( startupEvent = rSequence_new() ) )
        {
            if( rSequence_addSEQUENCE( wrapper, RP_TAGS_NOTIFICATION_STARTING_UP, startupEvent ) )
            {
                hbs_timestampEvent( startupEvent, 0 );
                if( !rQueue_add( g_hbs_state.outQueue, wrapper, 0 ) )
                {
                    rSequence_free( wrapper );
                }
            }
            else
            {
                rSequence_free( wrapper );
                rSequence_free( startupEvent );
            }
        }
        else
        {
            rSequence_free( wrapper );
        }
    }
}

RPRIVATE
RVOID
    sendShutdownEvent
    (

    )
{
    rSequence wrapper = NULL;
    rSequence shutdownEvent = NULL;

    if( NULL != ( wrapper = rSequence_new() ) )
    {
        if( NULL != ( shutdownEvent = rSequence_new() ) )
        {
            if( rSequence_addSEQUENCE( wrapper, RP_TAGS_NOTIFICATION_SHUTTING_DOWN, shutdownEvent ) )
            {
                hbs_timestampEvent( shutdownEvent, 0 );
                // There is no point queuing it up since we're exiting
                // so we'll try to send it right away.
                sendSingleMessageHome( wrapper );
                rSequence_free( wrapper );
            }
            else
            {
                rSequence_free( wrapper );
                rSequence_free( shutdownEvent );
            }
        }
        else
        {
            rSequence_free( wrapper );
        }
    }
}

typedef struct
{
    RU32 eventId;
    rSequence event;
} _cloudNotifStub;

RPRIVATE
RPVOID
    _handleCloudNotification
    (
        rEvent isTimeToStop,
        _cloudNotifStub* pEventInfo
    )
{
    UNREFERENCED_PARAMETER( isTimeToStop );
    
    if( rpal_memory_isValid( pEventInfo ) )
    {
        if( rpal_memory_isValid( pEventInfo->event ) )
        {
            notifications_publish( pEventInfo->eventId, pEventInfo->event );
            rSequence_free( pEventInfo->event );
        }

        rpal_memory_free( pEventInfo );
    }
    
    return NULL;
}

RPRIVATE
RVOID
    publishCloudNotifications
    (
        rList notifications
    )
{
    rSequence notif = NULL;
    RPU8 buff = NULL;
    RU32 buffSize = 0;
    RPU8 sig = NULL;
    RU32 sigSize = 0;
    rpHCPId curId = { 0 };
    rSequence cloudEvent = NULL;
    rSequence targetId = { 0 };
    RU64 expiry = 0;
    rpHCPId tmpId = { 0 };
    rSequence receipt = NULL;
    _cloudNotifStub* cloudEventStub = NULL;
    RU32 error = RPAL_ERROR_SUCCESS;

    while( rList_getSEQUENCE( notifications, RP_TAGS_HBS_CLOUD_NOTIFICATION, &notif ) )
    {
        cloudEvent = NULL;

        if( NULL == cloudEventStub )
        {
            cloudEventStub = rpal_memory_alloc( sizeof( *cloudEventStub ) );
        }

        if( rSequence_getBUFFER( notif, RP_TAGS_BINARY, &buff, &buffSize ) &&
            rSequence_getBUFFER( notif, RP_TAGS_SIGNATURE, &sig, &sigSize ) &&
            CRYPTOLIB_SIGNATURE_SIZE <= sigSize )
        {
            if( CryptoLib_verify( buff, buffSize, hbs_cloud_pub_key, sig ) )
            {
                if( !rpHcpI_getId( &curId ) )
                {
                    rpal_debug_error( "error getting current id for cloud notifications." );
                }
                else
                {
                    if( !rSequence_deserialise( &cloudEvent, buff, buffSize, NULL ) )
                    {
                        cloudEvent = NULL;
                        rpal_debug_warning( "error deserializing cloud event." );
                    }
                }
            }
            else
            {
                rpal_debug_warning( "cloud event signature invalid." );
            }
        }

        if( rpal_memory_isValid( cloudEvent ) )
        {
            if( rSequence_getSEQUENCE( cloudEvent, RP_TAGS_HCP_IDENT, &targetId ) &&
                rSequence_getRU32( cloudEvent, RP_TAGS_HBS_NOTIFICATION_ID, &(cloudEventStub->eventId) ) &&
                rSequence_getSEQUENCE( cloudEvent, RP_TAGS_HBS_NOTIFICATION, &(cloudEventStub->event) ) )
            {
                if( !rSequence_getTIMESTAMP( cloudEvent, RP_TAGS_EXPIRY, &expiry ) )
                {
                    expiry = 0;
                }

                hbs_timestampEvent( cloudEvent, 0 );
                
                tmpId = rpHcpI_seqToHcpId( targetId );

                if( NULL != ( receipt = rSequence_new() ) )
                {
                    if( !rSequence_addSEQUENCE( receipt, 
                                                RP_TAGS_HBS_CLOUD_NOTIFICATION, 
                                                rSequence_duplicate( cloudEvent ) ) )
                    {
                        rSequence_free( receipt );
                        receipt = NULL;
                    }
                }

                if( isHcpIdMatch( curId, tmpId ) &&
                    ( 0 == expiry ||
                      rpal_time_getGlobal() <= expiry ) )
                {
                    if( NULL != ( cloudEventStub->event = rSequence_duplicate( cloudEventStub->event ) ) )
                    {
                        if( rThreadPool_task( g_hbs_state.hThreadPool, 
                                              (rpal_thread_pool_func)_handleCloudNotification,
                                              cloudEventStub ) )
                        {
                            // The handler will free this stub
                            cloudEventStub = NULL;
                            rpal_debug_info( "new cloud event published." );
                        }
                        else
                        {
                            rSequence_free( cloudEventStub->event );
                            cloudEventStub->event = NULL;
                            rpal_debug_error( "error publishing event from cloud." );
                        }
                    }
                }
                else
                {
                    rpal_debug_warning( "event expired or for wrong id." );
                    error = RPAL_ERROR_INVALID_PARAMETER;
                }

                if( NULL != receipt &&
                    ( !rSequence_addRU32( receipt, RP_TAGS_ERROR, error ) ||
                      !rQueue_add( g_hbs_state.outQueue, receipt, 0 ) ) )
                {
                    rSequence_free( receipt );
                    receipt = NULL;
                }
            }

            if( rpal_memory_isValid( cloudEvent ) )
            {
                rSequence_free( cloudEvent );
                cloudEvent = NULL;
            }
        }
    }

    if( NULL != cloudEventStub )
    {
        rpal_memory_free( cloudEventStub );
        cloudEventStub = NULL;
    }
}

RPRIVATE
RVOID
    runSelfTests
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList tests = NULL;
    rSequence collector = NULL;
    RU32 collectorId = 0;
    rQueue asserts = NULL;
    rSequence assert = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getLIST( event, RP_TAGS_HBS_CONFIGURATIONS, &tests ) )
        {
            if( rQueue_create( &asserts, rSequence_freeWithSize, 0 ) )
            {
                if( rMutex_lock( g_hbs_state.mutex ) )
                {
                    shutdownCollectors();

                    // Since all collectors are offline, we need to subscribe ourselves to test asserts
                    // and we can replay them back once collector 0 is back online (for exfil).
                    if( notifications_subscribe( RP_TAGS_NOTIFICATION_SELF_TEST_RESULT, NULL, 0, asserts, NULL ) )
                    {
                        while( rList_getSEQUENCE( tests, RP_TAGS_HBS_CONFIGURATION, &collector ) )
                        {
                            if( rSequence_getRU32( collector, RP_TAGS_HBS_CONFIGURATION_ID, &collectorId ) &&
                                ARRAY_N_ELEM( g_hbs_state.collectors ) > collectorId )
                            {
                                if( NULL != g_hbs_state.collectors[ collectorId ].test )
                                {
                                    SelfTestContext testCtx = { 0 };
                                    testCtx.config = collector;
                                    testCtx.originalTestRequest = event;

                                    if( !g_hbs_state.collectors[ collectorId ].test( &g_hbs_state, &testCtx ) )
                                    {
                                        rpal_debug_error( "error executing static self test on collector %d", collectorId );
                                    }

                                    rpal_debug_info( "Test finished: col %d, %d tests, %d failures.",
                                                     collectorId,
                                                     testCtx.nTests,
                                                     testCtx.nFailures );
                                    hbs_sendCompletionEvent( event, RP_TAGS_NOTIFICATION_SELF_TEST_RESULT, 0, NULL );
                                }
                            }
                            else
                            {
                                rpal_debug_error( "invalid collector id to test" );
                            }
                        }

                        // We also reset atoms to avoid pollution from tests.
                        atoms_deinit();
                        atoms_init();

                        notifications_unsubscribe( RP_TAGS_NOTIFICATION_SELF_TEST_RESULT, asserts, NULL );
                    }
                    else
                    {
                        rpal_debug_error( "failed to subscribe to test results" );
                    }

                    if( !startCollectors() )
                    {
                        rpal_debug_warning( "an error occured restarting collectors after tests" );
                    }

                    // Now we will replay all the asserts, collector 0 should pick them up if configured for that.
                    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );
                    while( rQueue_remove( asserts, &assert, NULL, 0 ) )
                    {
                        notifications_publish( RP_TAGS_NOTIFICATION_SELF_TEST_RESULT, assert );
                        rSequence_free( assert );
                    }

                    rMutex_unlock( g_hbs_state.mutex );
                }

                rQueue_free( asserts );
            }
            else
            {
                rpal_debug_error( "could not create assert collection for tests" );
            }
        }
    }
}

RPRIVATE
RVOID
    updateCollector
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 collectorId = 0;
    RTIME updateTimestamp = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_CONFIGURATION_ID, &collectorId ) &&
            collectorId < ARRAY_N_ELEM( g_hbs_state.collectors ) )
        {
            // The new config will be applied to the collector.
            rpal_debug_info( "received runtime collector update for " RF_U32, collectorId );
            if( g_hbs_state.collectors[ collectorId ].update( &g_hbs_state, event ) )
            {
                // If the update was successfully applied, we check if the event also contained a timestamp.
                if( rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &updateTimestamp ) )
                {
                    // A timestamp here is used a global generation of the update. This generation gets
                    // sent with every SYNC and is used by the cloud to determine statelessly if the sensor
                    // requires some new runtime configurations.
                    g_hbs_state.collectors[ collectorId ].lastConfUpdate = updateTimestamp;
                    rpal_debug_info( "collector " RF_U32 " generation now " RF_U64, updateTimestamp );
                }
            }
        }
    }
}

//=============================================================================
//  Entry Points
//=============================================================================
RVOID
    RpHcpI_receiveMessage
    (
        rSequence message
    )
{
    rSequence sync = NULL;
    RU8* profileHash = NULL;
    RU32 hashSize = 0;
    rList configurations = NULL;
    rList cloudNotifications = NULL;

    // If it's an internal HBS message we'll process it right away.
    if( rSequence_getSEQUENCE( message, RP_TAGS_NOTIFICATION_SYNC, &sync ) )
    {
        rpal_debug_info( "receiving hbs sync" );
        if( rSequence_getBUFFER( sync, RP_TAGS_HASH, &profileHash, &hashSize ) &&
            CRYPTOLIB_HASH_SIZE == hashSize &&
            rSequence_getLIST( sync, RP_TAGS_HBS_CONFIGURATIONS, &configurations ) )
        {
            if( NULL != ( configurations = rList_duplicate( configurations ) ) )
            {
                if( rMutex_lock( g_hbs_state.mutex ) )
                {
                    rpal_debug_info( "sync has new profile, restarting collectors" );
                    rpal_memory_memcpy( g_hbs_state.currentConfigHash, profileHash, hashSize );

                    // We're going to shut down all collectors, swap the configs and restart them.
                    shutdownCollectors();
                    updateCollectorConfigs( configurations );
                    startCollectors();

                    // Check to see if this has changed the kernel acquisition status.
                    checkKernelAcquisition();

                    rMutex_unlock( g_hbs_state.mutex );
                }

                rList_free( configurations );
            }
        }
        else
        {
            rpal_debug_warning( "hbs sync missing critical component" );
        }
    }
    else if( rSequence_getLIST( message, RP_TAGS_HBS_CLOUD_NOTIFICATIONS, &cloudNotifications ) )
    {
        // If it's a list of notifications we'll pass them on to be verified.
        rpal_debug_info( "received %d cloud notifications", rList_getNumElements( cloudNotifications ) );
        publishCloudNotifications( cloudNotifications );
    }
    else
    {
        rpal_debug_warning( "unknown message received" );
    }
}

RU32
RPAL_THREAD_FUNC
    RpHcpI_mainThread
    (
        rEvent isTimeToStop
    )
{
    RU32 ret = 0;

    rSequence staticConfig = NULL;
    rList tmpConfigurations = NULL;
    RU8* tmpBuffer = NULL;
    RU32 tmpSize = 0;
    rList exfilList = NULL;
    rSequence exfilMessage = NULL;
    rEvent newExfilEvents = NULL;
    RU32 nFrames = 0;

    FORCE_LINK_THAT( HCP_IFACE );

    CryptoLib_init();
    atoms_init();

    if( !getPrivileges() )
    {
        rpal_debug_info( "special privileges not acquired" );
    }

    // This is the event for the collectors, it is different than the
    // hbs proper event so that we can restart the collectors without
    // signaling hbs as a whole.
    if( NULL == ( g_hbs_state.isTimeToStop = rEvent_create( TRUE ) ) )
    {
        return (RU32)-1;
    }

    if( NULL == ( g_hbs_state.mutex = rMutex_create() ) )
    {
        rEvent_free( g_hbs_state.isTimeToStop );
        return (RU32)-1;
    }

    checkKernelAcquisition();

    // Initial boot and we have no profile yet, we'll load a dummy
    // blank profile and use our defaults.
    if( NULL != ( tmpConfigurations = rList_new( RP_TAGS_HCP_MODULES, RPCM_SEQUENCE ) ) )
    {
        updateCollectorConfigs( tmpConfigurations );
        rpal_debug_info( "setting empty profile" );
        rList_free( tmpConfigurations );
    }

    // By default, no collectors are running
    rEvent_set( g_hbs_state.isTimeToStop );

    // We attempt to load some initial config from the serialized
    // rSequence that can be patched in this binary.
    if( NULL != ( staticConfig = getStaticConfig() ) )
    {
        if( rSequence_getBUFFER( staticConfig, RP_TAGS_HBS_ROOT_PUBLIC_KEY, &tmpBuffer, &tmpSize ) )
        {
            hbs_cloud_pub_key = rpal_memory_duplicate( tmpBuffer, tmpSize );
            if( NULL == hbs_cloud_pub_key )
            {
                hbs_cloud_pub_key = hbs_cloud_default_pub_key;
            }
            rpal_debug_info( "loading hbs root public key from static config" );
        }

        if( rSequence_getRU32( staticConfig, RP_TAGS_MAX_QUEUE_SIZE, &g_hbs_state.maxQueueNum ) )
        {
            rpal_debug_info( "loading max queue size from static config" );
        }
        else
        {
            g_hbs_state.maxQueueNum = HBS_EXFIL_QUEUE_MAX_NUM;
        }

        if( rSequence_getRU32( staticConfig, RP_TAGS_MAX_SIZE, &g_hbs_state.maxQueueSize ) )
        {
            rpal_debug_info( "loading max queue num from static config" );
        }
        else
        {
            g_hbs_state.maxQueueSize = HBS_EXFIL_QUEUE_MAX_SIZE;
        }

        rSequence_free( staticConfig );
    }
    else
    {
        hbs_cloud_pub_key = hbs_cloud_default_pub_key;
        g_hbs_state.maxQueueNum = HBS_EXFIL_QUEUE_MAX_NUM;
        g_hbs_state.maxQueueSize = HBS_EXFIL_QUEUE_MAX_SIZE;
    }

    if( !rQueue_create( &g_hbs_state.outQueue, freeExfilEvent, g_hbs_state.maxQueueNum ) )
    {
        rEvent_free( g_hbs_state.isTimeToStop );
        return (RU32)-1;
    }

    newExfilEvents = rQueue_getNewElemEvent( g_hbs_state.outQueue );

    g_hbs_state.isOnlineEvent = rpHcpI_getOnlineEvent();

    // We simply enqueue a message to let the cloud know we're starting
    sendStartupEvent();

    if( !rEvent_wait( isTimeToStop, 0 ) )
    {
        startCollectors();
        notifications_subscribe( RP_TAGS_NOTIFICATION_SELF_TEST,
                                 NULL,
                                 0,
                                 NULL,
                                 runSelfTests );
        notifications_subscribe( RP_TAGS_NOTIFICATION_UPDATE,
                                 NULL,
                                 0,
                                 NULL,
                                 updateCollector );
    }

#ifdef HBS_POWER_ON_SELF_TEST
    // We will do a run through of all POSTs
    {
        rSequence testEvent = NULL;
        rList testConfigs = NULL;
        rSequence testConfig = NULL;
        RU32 i = 0;

        // Introduce a delay to make sure the kernel acquisition module has a chance to load.
        rpal_thread_sleep( MSEC_FROM_SEC( 10 ) );
        checkKernelAcquisition();

        rpal_debug_info( "power on self test begins" );

        if( NULL != ( testEvent = rSequence_new() ) )
        {
            if( NULL != ( testConfigs = rList_new( RP_TAGS_HBS_CONFIGURATION, RPCM_SEQUENCE ) ) )
            {
                for( i = 0; i < ARRAY_N_ELEM( g_hbs_state.collectors ); i++ )
                {
                    if( g_hbs_state.collectors[ i ].isEnabled )
                    {
                        if( NULL != ( testConfig = rSequence_new() ) )
                        {
                            if( !rSequence_addRU32( testConfig, RP_TAGS_HBS_CONFIGURATION_ID, i ) ||
                                !rList_addSEQUENCE( testConfigs, testConfig ) )
                            {
                                rSequence_free( testConfig );
                            }
                        }
                    }
                }

                if( !rSequence_addLIST( testEvent, RP_TAGS_HBS_CONFIGURATIONS, testConfigs ) )
                {
                    rList_free( testConfigs );
                }
            }

            runSelfTests( RP_TAGS_NOTIFICATION_SELF_TEST, testEvent );

            rSequence_free( testEvent );
        }

        rpal_debug_info( "power on self test ends" );
    }
#endif

    // We'll wait for the very first online notification to start syncing.
    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rEvent_wait( g_hbs_state.isOnlineEvent, MSEC_FROM_SEC( 5 ) ) )
        {
            // From the first sync, we'll schedule recurring ones.
            // The collectors are running (so a sync is scheduled), but we want to try
            // to be as timely as possible if/when the cloud becomes online since a lot
            // of the runtime configuration is keyed off the sync.
            issueSync( g_hbs_state.isTimeToStop, NULL );
            break;
        }
    }

    // We've connected to the cloud at least once, did a sync once, let's start normal exfil.
    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rEvent_wait(g_hbs_state.isOnlineEvent, MSEC_FROM_SEC( 1 ) ) &&
            rEvent_wait( newExfilEvents, MSEC_FROM_SEC( 1 ) ) )
        {
            if( NULL != ( exfilList = rList_new( RP_TAGS_MESSAGE, RPCM_SEQUENCE ) ) )
            {
                while( rQueue_remove( g_hbs_state.outQueue, &exfilMessage, NULL, 0 ) )
                {
                    if( !rList_addSEQUENCE( exfilList, exfilMessage ) )
                    {
                        rpal_debug_error( "dropping exfil message" );
                        rSequence_free( exfilMessage );
                    }

                    if( HBS_MAX_OUBOUND_FRAME_SIZE <= rList_getNumElements( exfilList ) )
                    {
                        break;
                    }
                }

                if( rpHcpI_sendHome( exfilList ) )
                {
                    rList_free( exfilList );
                }
                else
                {
                    // Failed to send the data home, so we'll re-queue it.
                    if( g_hbs_state.maxQueueNum < rList_getNumElements( exfilList ) ||
                        g_hbs_state.maxQueueSize < rList_getEstimateSize( exfilList ) )
                    {
                        // We have an overflow of the queues, dropping will occur.
                        rpal_debug_warning( "queue thresholds reached, dropping %d messages", 
                                            rList_getNumElements( exfilList ) );
                        rList_free( exfilList );
                    }
                    else
                    {
                        rpal_debug_info( "transmition failed, re-adding %d messages.", rList_getNumElements( exfilList ) );

                        // We will attempt to re-add the existing messages back in the queue since this failed
                        rList_resetIterator( exfilList );
                        while( rList_getSEQUENCE( exfilList, RP_TAGS_MESSAGE, &exfilMessage ) )
                        {
                            if( !rQueue_add( g_hbs_state.outQueue, exfilMessage, 0 ) )
                            {
                                rSequence_free( exfilMessage );
                            }
                        }
                        rList_shallowFree( exfilList );

                        // We will wait a second to see if whatever condition was preventing the send
                        // will resolve itself before we retry.
                        rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
                    }
                }
            }
        }

        if( !kAcq_isAvailable() &&
            HBS_KACQ_RETRY_N_FRAMES < nFrames++ )
        {
            nFrames = 0;
            checkKernelAcquisition();
        }
    }

    // We issue one last beacon indicating we are stopping
    sendShutdownEvent();

    // Shutdown everything
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_SELF_TEST, NULL, runSelfTests );
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_UPDATE, NULL, updateCollector );
    rMutex_lock( g_hbs_state.mutex );
    shutdownCollectors();

    // Cleanup the last few resources
    rEvent_free( g_hbs_state.isTimeToStop );
    rQueue_free( g_hbs_state.outQueue );

    rMutex_free( g_hbs_state.mutex );

    CryptoLib_deinit();

    if( hbs_cloud_default_pub_key != hbs_cloud_pub_key &&
        NULL != hbs_cloud_pub_key )
    {
        rpal_memory_free( hbs_cloud_pub_key );
        hbs_cloud_pub_key = NULL;
    }

    kAcq_deinit();
    
    atoms_deinit();

    return ret;
}

