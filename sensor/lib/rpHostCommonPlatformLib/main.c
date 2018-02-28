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

#include <rpHostCommonPlatformLib/rpHostCommonPlatformLib.h>
#include "configurations.h"
#include "globalContext.h"
#include "obfuscated.h"
#include <obfuscationLib/obfuscationLib.h>
#include "beacon.h"
#include <rpHostCommonPlatformLib/rTags.h>
#include <librpcm/librpcm.h>
#include "commands.h"
#include "crashHandling.h"
#include "crypto.h"
#include <mbedtls/base64.h>

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <dlfcn.h>
#endif

#define RPAL_FILE_ID    53

rpHCPContext g_hcpContext = { 0 };
rpHCPId g_idTemplate = { { 0 },                                                 // Sensor ID
                         { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },    // Org ID
                         { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },    // Installer ID
                         0,                                                     // Architecture
                         0 };                                                   // Platform

// Large blank buffer to be used to patch configurations post-build
#define _HCP_DEFAULT_STATIC_STORE_SIZE                          (1024 * 50)
#define _HCP_DEFAULT_STATIC_STORE_MAGIC                         { 0xFA, 0x57, 0xF0, 0x0D }
RPRIVATE RU8 g_patchedConfig[ _HCP_DEFAULT_STATIC_STORE_SIZE ] = _HCP_DEFAULT_STATIC_STORE_MAGIC;

//=============================================================================
//  Helpers
//=============================================================================

#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
BOOL
    ctrlHandler
    (
        DWORD type
    )
{
    OBFUSCATIONLIB_DECLARE( store, RP_HCP_CONFIG_CRASH_STORE );
    UNREFERENCED_PARAMETER( type );

    if( CTRL_SHUTDOWN_EVENT == type )
    {
        // This is an emergency shutdown.
        // Trying to do this cleanly is pointless since Windows
        // will kill us very shortly, so let's just clean up
        // the CC so we don't report a pointless "crash".
        OBFUSCATIONLIB_TOGGLE( store );
        rpal_file_delete( (RPWCHAR)store, FALSE );
        OBFUSCATIONLIB_TOGGLE( store );
    }

    // Pass the signal along
    return FALSE;
}
#endif


rSequence
    hcpIdToSeq
    (
        rpHCPId id
    )
{
    rSequence seq = NULL;

    if( NULL != ( seq = rSequence_new() ) )
    {
        if( !rSequence_addBUFFER( seq, RP_TAGS_HCP_SENSOR_ID, id.sensor_id, sizeof( id.sensor_id ) ) ||
            !rSequence_addBUFFER( seq, RP_TAGS_HCP_ORG_ID, id.org_id, sizeof( id.org_id ) ) ||
            !rSequence_addBUFFER( seq, RP_TAGS_HCP_INSTALLER_ID, id.ins_id, sizeof( id.ins_id ) ) ||
            !rSequence_addRU32( seq, RP_TAGS_HCP_ARCHITECTURE, id.architecture ) ||
            !rSequence_addRU32( seq, RP_TAGS_HCP_PLATFORM, id.platform ) )
        {
            DESTROY_AND_NULL( seq, rSequence_free );
        }
    }

    return seq;
}

rpHCPId
    seqToHcpId
    (
        rSequence seq
    )
{
    rpHCPId id = g_idTemplate;
    RPU8 tmpSensorId = NULL;
    RU32 tmpSize = 0;
    RPU8 tmpOrgId = NULL;
    RPU8 tmpInsId = NULL;

    if( NULL != seq )
    {
        if( !rSequence_getBUFFER( seq, RP_TAGS_HCP_SENSOR_ID, &tmpSensorId, &tmpSize ) ||
            sizeof( id.sensor_id ) != tmpSize ||
            !rSequence_getBUFFER( seq, RP_TAGS_HCP_ORG_ID, &tmpOrgId, &tmpSize ) ||
            sizeof( id.org_id ) != tmpSize ||
            !rSequence_getBUFFER( seq, RP_TAGS_HCP_INSTALLER_ID, &tmpInsId, &tmpSize ) ||
            sizeof( id.ins_id ) != tmpSize ||
            !rSequence_getRU32( seq, RP_TAGS_HCP_ARCHITECTURE, &id.architecture ) ||
            !rSequence_getRU32( seq, RP_TAGS_HCP_PLATFORM, &id.platform ) )
        {
            rpal_memory_zero( &id, sizeof( id ) );
        }
        else
        {
            rpal_memory_memcpy( id.sensor_id, tmpSensorId, sizeof( id.sensor_id ) );
            rpal_memory_memcpy( id.org_id, tmpOrgId, sizeof( id.org_id ) );
            rpal_memory_memcpy( id.ins_id, tmpInsId, sizeof( id.ins_id ) );
        }
    }

    return id;
}

RPRIVATE_TESTABLE
RBOOL
    getStoreConfID
    (
        RPNCHAR storePath,
        rpHCPContext* hcpContext
    )
{
    RBOOL isSuccess = FALSE;

    RPU8 storeFile = NULL;
    RU32 storeFileSize = 0;

    rpHCPIdentStore* store = NULL;

    if( NULL == storePath ||
        NULL == hcpContext )
    {
        return FALSE;
    }

    if( rpal_file_read( storePath, &storeFile, &storeFileSize, FALSE ) )
    {
        if( sizeof( rpHCPIdentStore ) <= storeFileSize )
        {
            store = (rpHCPIdentStore*)storeFile;
            if( store->enrollmentTokenSize == storeFileSize - sizeof( rpHCPIdentStore ) )
            {
                isSuccess = TRUE;
                rpal_debug_info( "ident store found" );
                if( NULL != ( hcpContext->enrollmentToken = rpal_memory_alloc( store->enrollmentTokenSize ) ) )
                {
                    rpal_memory_memcpy( hcpContext->enrollmentToken, store->enrollmentToken, store->enrollmentTokenSize );
                    hcpContext->enrollmentTokenSize = store->enrollmentTokenSize;
                }
                hcpContext->currentId = store->agentId;
            }
        }
        else
        {
            rpal_debug_warning( "inconsistent ident store, reseting" );
            rpal_file_delete( storePath, FALSE );
        }

        rpal_memory_free( storeFile );
    }

    // Set some always-correct defaults
    hcpContext->currentId.architecture = RP_HCP_PLATFORM_CURRENT_ARCH;
    hcpContext->currentId.platform = RP_HCP_PLATFORM_CURRENT;

    return isSuccess;
}

RPRIVATE
rSequence
    getStaticConfig
    (

    )
{
    RU8 magic[] = _HCP_DEFAULT_STATIC_STORE_MAGIC;
    rSequence config = NULL;
    RU8 key[] = _HCP_DEFAULT_STATIC_STORE_KEY;

    if( 0 != rpal_memory_memcmp( g_patchedConfig, magic, sizeof( magic ) ) )
    {
        obfuscationLib_toggle( g_patchedConfig, sizeof( g_patchedConfig ), key, sizeof( key ) );

        if( rSequence_deserialise( &config, g_patchedConfig, sizeof( g_patchedConfig ), NULL ) )
        {
            rpal_debug_info( "static store patched, using it as config" );
        }
        else
        {
            rpal_debug_warning( "statis store invalid" );
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
rSequence
    getLocalConfig
    (

    )
{
    rSequence config = NULL;
    RPU8 storeBuffer = NULL;
    RU32 storeBufferSize = 0;
    RU8 key[] = _HCP_DEFAULT_STATIC_STORE_KEY;

    OBFUSCATIONLIB_DECLARE( storePath, RP_HCP_CONFIG_LOCAL_STORE );

    OBFUSCATIONLIB_TOGGLE( storePath );
    if( rpal_file_read( (RPNCHAR)storePath, &storeBuffer, &storeBufferSize, FALSE ) )
    {
        obfuscationLib_toggle( storeBuffer, storeBufferSize, key, sizeof( key ) );
        
        if( rSequence_deserialise( &config, storeBuffer, storeBufferSize, NULL ) )
        {
            rpal_debug_info( "local store loaded, using it as config" );
        }
        else
        {
            rpal_debug_warning( "local store invalid" );
        }

        rpal_memory_free( storeBuffer );
    }
    OBFUSCATIONLIB_TOGGLE( storePath );

    return config;
}

//=============================================================================
//  API
//=============================================================================

RBOOL
    rpHostCommonPlatformLib_launch
    (
        RPNCHAR primaryHomeUrl,
        RPNCHAR secondaryHomeUrl,
        RPNCHAR deploymentBootstrap
    )
{
    RBOOL isInitSuccessful = FALSE;
    rSequence config = NULL;
    RPU8 tmpBuffer = NULL;
    RPCHAR tmpStr = NULL;
    rSequence tmpSeq = NULL;
    
    OBFUSCATIONLIB_DECLARE( storePath, RP_HCP_CONFIG_IDENT_STORE );

    rpal_debug_info( "launching hcp" );

#ifdef RPAL_PLATFORM_WINDOWS
    if( setGlobalCrashHandler() &&
        SetConsoleCtrlHandler( (PHANDLER_ROUTINE)ctrlHandler, TRUE ) )
    {
        rpal_debug_info( "global crash handler set" );
    }
    else
    {
        rpal_debug_warning( "error setting global crash handler" );
    }
#endif

    if( 1 == rInterlocked_increment32( &g_hcpContext.isRunning ) )
    {
        if( rpal_initialize( NULL, RPAL_COMPONENT_HCP ) )
        {
            CryptoLib_init();

            if( NULL == ( g_hcpContext.isCloudOnline = rEvent_create( TRUE ) ) )
            {
                rpal_debug_error( "could not create cloud connection event" );
                return FALSE;
            }

            g_hcpContext.currentId = g_idTemplate;

            // We attempt to load some initial config from the serialized
            // rSequence that can be patched in this binary. Priority is on
            // a local config and then a patched.
            if( NULL != ( config = getLocalConfig() ) ||
                NULL != ( config = getStaticConfig() ) )
            {
                if( !applyConfigStore( config, FALSE ) )
                {
                    rpal_debug_error( "failed to load config" );
                }

                rSequence_free( config );
            }
            else if( NULL != deploymentBootstrap &&
                     0 != rpal_string_strlen( deploymentBootstrap ) )
            {
                RSIZET tmpBufferSize = 0;

                // Ok so we have bootstrap information to begin an enrollment flow.
                if( NULL != ( tmpStr = rpal_string_ntoa( deploymentBootstrap ) ) )
                {
                    mbedtls_base64_decode( NULL,
                                           0,
                                           &tmpBufferSize,
                                           (unsigned char*)tmpStr,
                                           rpal_string_strlenA( tmpStr ) );

                    if( NULL != ( tmpBuffer = rpal_memory_alloc( tmpBufferSize ) ) )
                    {
                        if( 0 == mbedtls_base64_decode( tmpBuffer,
                                                        tmpBufferSize,
                                                        &tmpBufferSize,
                                                        (unsigned char*)tmpStr,
                                                        rpal_string_strlenA( tmpStr ) ) &&
                            rSequence_deserialise( &tmpSeq,
                                                   tmpBuffer,
                                                   (RU32)tmpBufferSize,
                                                   NULL ) )
                        {
                            rpal_debug_info( "deployment bootstrap information parsed" );
                            if( !applyConfigStore( tmpSeq, FALSE ) )
                            {
                                rpal_debug_error( "failed to apply configs from bootstrap" );
                            }

                            rSequence_free( tmpSeq );
                        }
                        else
                        {
                            rpal_debug_error( "deployment bootstrap information failed to parse" );
                        }

                        rpal_memory_free( tmpBuffer );
                        tmpBuffer = NULL;
                    }

                    rpal_memory_free( tmpStr );
                }
            }
            else
            {
                // This is bad, we don't really know where to go or what to do. Let's keep things
                // going in the event this is for debugging.
                rpal_debug_error( "No patched in static config, no local config and no bootstrap information, this is likely an error in configuration!" );
            }

            // Now we will override the defaults (if present) with command
            // line parameters.
            if( NULL != primaryHomeUrl &&
                0 != rpal_string_strlen( primaryHomeUrl ) )
            {
                if( NULL != g_hcpContext.primaryUrl )
                {
                    rpal_memory_free( g_hcpContext.primaryUrl );
                    g_hcpContext.primaryUrl = NULL;
                }
                g_hcpContext.primaryUrl = rpal_string_ntoa( primaryHomeUrl );
            }

            if( NULL != secondaryHomeUrl &&
                0 != rpal_string_strlen( secondaryHomeUrl  ) )
            {
                if( NULL != g_hcpContext.secondaryUrl )
                {
                    rpal_memory_free( g_hcpContext.secondaryUrl );
                    g_hcpContext.secondaryUrl = NULL;
                }
                g_hcpContext.secondaryUrl = rpal_string_ntoa( secondaryHomeUrl );
            }

            g_hcpContext.enrollmentToken = NULL;
            g_hcpContext.enrollmentTokenSize = 0;

            // Load the Identification store where our HCP ID is.
            OBFUSCATIONLIB_TOGGLE( storePath );
            getStoreConfID( (RPNCHAR)storePath, &g_hcpContext );
            OBFUSCATIONLIB_TOGGLE( storePath );

            if( startBeacons() )
            {
                isInitSuccessful = TRUE;
            }
            else
            {
                rpal_debug_warning( "error starting beacons" );
            }

            CryptoLib_deinit();
        }
        else
        {
            rpal_debug_warning( "hcp platform could not init rpal" );
        }
    }
    else
    {
        rInterlocked_decrement32( &g_hcpContext.isRunning );
        rpal_debug_info( "hcp already launched" );
    }

    return isInitSuccessful;
}



RBOOL
    rpHostCommonPlatformLib_stop
    (

    )
{
    if( 0 == rInterlocked_decrement32( &g_hcpContext.isRunning ) )
    {
        stopBeacons();
        stopAllModules();

        rpal_memory_free( g_hcpContext.primaryUrl );
        rpal_memory_free( g_hcpContext.secondaryUrl );

        if( NULL != g_hcpContext.enrollmentToken &&
            0 != g_hcpContext.enrollmentTokenSize )
        {
            rpal_memory_free( g_hcpContext.enrollmentToken );
        }

        freeKeys();

#ifdef RPAL_PLATFORM_WINDOWS
        SetConsoleCtrlHandler( (PHANDLER_ROUTINE)ctrlHandler, FALSE );
#endif

        rEvent_free( g_hcpContext.isCloudOnline );
        g_hcpContext.isCloudOnline = NULL;

        rpal_Context_cleanup();

        rpal_Context_deinitialize();

        // If the default crashContext is still present, remove it since
        // we are shutting down properly. If it's non-default leave it since
        // somehow we may have had a higher order crash we want to keep
        // track of but we are still leaving through our normal code path.
        if( 1 == getCrashContextSize() )
        {
            rpal_debug_info( "clearing default crash context" );
            cleanCrashContext();
        }
    }
    else
    {
        rInterlocked_increment32( &g_hcpContext.isRunning );
    }

    rpal_debug_info( "finished stopping hcp" );

    return TRUE;
}

#ifdef RP_HCP_LOCAL_LOAD
RBOOL
    rpHostCommonPlatformLib_load
    (
        RPNCHAR modulePath,
        RU32 moduleId
    )
{
    RBOOL isSuccess = FALSE;

    RU32 moduleIndex = 0;
    rpal_thread_func pEntry = NULL;
    rpHCPModuleContext* modContext = NULL;
    RPCHAR errorStr = NULL;

    OBFUSCATIONLIB_DECLARE( entrypoint, RP_HCP_CONFIG_MODULE_ENTRY );
    OBFUSCATIONLIB_DECLARE( recvMessage, RP_HCP_CONFIG_MODULE_RECV_MESSAGE );

    if( NULL != modulePath )
    {
        for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
        {
            if( 0 == g_hcpContext.modules[ moduleIndex ].hThread )
            {
                // Found an empty spot
#ifdef RPAL_PLATFORM_WINDOWS
                g_hcpContext.modules[ moduleIndex ].hModule = LoadLibraryW( modulePath );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                g_hcpContext.modules[ moduleIndex ].hModule = dlopen( modulePath, RTLD_NOW | RTLD_LOCAL );
#endif
                if( NULL != g_hcpContext.modules[ moduleIndex ].hModule )
                {
                    OBFUSCATIONLIB_TOGGLE( entrypoint );
#ifdef RPAL_PLATFORM_WINDOWS
                    pEntry = (rpal_thread_func)GetProcAddress( (HMODULE)g_hcpContext.modules[ moduleIndex ].hModule, 
                                                               (RPCHAR)entrypoint );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                    pEntry = (rpal_thread_func)dlsym( g_hcpContext.modules[ moduleIndex ].hModule, (RPCHAR)entrypoint );
#endif
                    OBFUSCATIONLIB_TOGGLE( entrypoint );

                    if( NULL != pEntry )
                    {
                        modContext = &(g_hcpContext.modules[ moduleIndex ].context);

                        modContext->pCurrentId = &(g_hcpContext.currentId);
                        modContext->func_sendHome = doSend;
                        modContext->isTimeToStop = rEvent_create( TRUE );
                        modContext->rpalContext = rpal_Context_get();
                        modContext->isOnlineEvent = g_hcpContext.isCloudOnline;

                        if( NULL != modContext->isTimeToStop )
                        {
                            g_hcpContext.modules[ moduleIndex ].id = (RpHcp_ModuleId)moduleId;
                            g_hcpContext.modules[ moduleIndex ].isTimeToStop  = modContext->isTimeToStop;
                            OBFUSCATIONLIB_TOGGLE( recvMessage );
#ifdef RPAL_PLATFORM_WINDOWS
                            g_hcpContext.modules[ moduleIndex ].func_recvMessage = 
                                    (rpHCPModuleMsgEntry)GetProcAddress( (HMODULE)g_hcpContext.modules[ moduleIndex ].hModule,
                                                                         (RPCHAR)recvMessage );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                            g_hcpContext.modules[ moduleIndex ].func_recvMessage = 
                                    (rpHCPModuleMsgEntry)dlsym( g_hcpContext.modules[ moduleIndex ].hModule, (RPCHAR)recvMessage );
#endif
                            OBFUSCATIONLIB_TOGGLE( recvMessage );
                            g_hcpContext.modules[ moduleIndex ].hThread = rpal_thread_new( pEntry, modContext );

                            if( 0 != g_hcpContext.modules[ moduleIndex ].hThread )
                            {
                                g_hcpContext.modules[ moduleIndex ].isOsLoaded = TRUE;
                                isSuccess = TRUE;
                                rpal_debug_info( "module " RF_STR_N " successfully loaded manually.", modulePath );
                            }
                        }
                    }
                    else
                    {
#ifdef RPAL_PLATFORM_WINDOWS
                        FreeLibrary( (HMODULE)g_hcpContext.modules[ moduleIndex ].hModule );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                        dlclose( g_hcpContext.modules[ moduleIndex ].hModule );
#endif
                        g_hcpContext.modules[ moduleIndex ].hModule = NULL;
                        rpal_debug_error( "Could not manually finding the entry point to a module!" );
                    }
                }
                else
                {
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                    errorStr = dlerror();
#endif
                    rpal_debug_error( "Could not manually load module " RF_STR_N": %X %s", 
                                      modulePath, 
                                      rpal_error_getLast(), 
                                      errorStr );
                }

                break;
            }
        }
    }

    return isSuccess;
}

RBOOL
    rpHostCommonPlatformLib_unload
    (
        RU8 moduleId
    )
{
    RBOOL isSuccess = FALSE;

    RU32 moduleIndex = 0;

    for( moduleIndex = 0; moduleIndex < RP_HCP_CONTEXT_MAX_MODULES; moduleIndex++ )
    {
        if( moduleId == g_hcpContext.modules[ moduleIndex ].id )
        {
            if( rEvent_set( g_hcpContext.modules[ moduleIndex ].isTimeToStop ) &&
                rpal_thread_wait( g_hcpContext.modules[ moduleIndex ].hThread, (30*1000) ) )
            {
                isSuccess = TRUE;
#ifdef RPAL_PLATFORM_WINDOWS
                FreeLibrary( (HMODULE)g_hcpContext.modules[ moduleIndex ].hModule );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                dlclose( g_hcpContext.modules[ moduleIndex ].hModule );
#endif
                rEvent_free( g_hcpContext.modules[ moduleIndex ].context.isTimeToStop );
                rpal_thread_free( g_hcpContext.modules[ moduleIndex ].hThread );
            }

            break;
        }
    }

    return isSuccess;
}
#endif

