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

#include <obfuscationLib/obfuscationLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#pragma warning( disable: 4127 ) // Disabling error on constant expression in condition

//=============================================================================
//  RP HCP Module Requirements
//=============================================================================
#define RPAL_FILE_ID 108
RpHcp_ModuleId g_current_Module_id = RP_HCP_MODULE_ID_KERNEL_ACQ;



//=============================================================================
//  Global Behavior Variables
//=============================================================================
#define HBS_DEFAULT_BEACON_TIMEOUT              (1*60)
#define HBS_DEFAULT_BEACON_TIMEOUT_FUZZ         (1*60)
#define HBS_EXFIL_QUEUE_MAX_NUM                 5000
#define HBS_EXFIL_QUEUE_MAX_SIZE                (1024*1024*10)

// Large blank buffer to be used to patch configurations post-build
#define _HCP_DEFAULT_STATIC_STORE_SIZE                          (1024 * 50)
#define _HCP_DEFAULT_STATIC_STORE_MAGIC                         { 0xFA, 0x57, 0xF0, 0x0D }
static RU8 g_patchedConfig[ _HCP_DEFAULT_STATIC_STORE_SIZE ] = _HCP_DEFAULT_STATIC_STORE_MAGIC;
#define _HCP_DEFAULT_STATIC_STORE_KEY                           { 0xFA, 0x75, 0x01 }

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


//=============================================================================
//  Entry Point
//=============================================================================
RVOID
    RpHcpI_receiveMessage
    (
        rSequence message
    )
{
    UNREFERENCED_PARAMETER( message );
}

static
RBOOL
    tryLoadingKernel
    (
        rEvent isTimeToStop
    )
{
    RBOOL isLoaded = FALSE;

    RU32 error = 0;
    rSequence config = NULL;
    
    if( NULL != ( config = getStaticConfig() ) )
    {
        error = 0;

        rpal_debug_info( "loading kernel acquisition" );

#ifdef RPAL_PLATFORM_MACOSX
        do
        {
            RCHAR tmpPath[] = "/tmp/tmp_hbs_acq.tar.gz";
            RCHAR tmpUntar[] = "tar xzf /tmp/tmp_hbs_acq.tar.gz -C /tmp/; chown -R root:wheel /tmp/tmp_hbs_acq.kext; chmod 500 /tmp/tmp_hbs_acq.kext";
            RCHAR tmpLoad[] = "kextload /tmp/tmp_hbs_acq.kext";
            RCHAR tmpUnload[] = "kextunload /tmp/tmp_hbs_acq.kext";
            RPU8 package = NULL;
            RU32 packageSize = 0;
            RPVOID lastHandler = NULL;
            RU32 nRetries = 0;

            rpal_debug_info( "getting kext from config" );
            if( !rSequence_getBUFFER( config, RP_TAGS_BINARY, &package, &packageSize ) )
            {
                rpal_debug_error( "malformed config" );
                break;
            }

            rpal_debug_info( "writing package to disk" );
            if( !rpal_file_write( tmpPath, package, packageSize, TRUE ) )
            {
                rpal_debug_error( "could not write package to disk" );
                break;
            }

            rpal_debug_info( "unpacking kernel extension" );
            if( 0 != ( error = system( tmpUntar ) ) )
            {
                rpal_debug_error( "could not unpack kernel extension: %d", error );
                break;
            }

            rpal_debug_info( "deleting package from disk" );
            if( !rpal_file_delete( tmpPath, FALSE ) )
            {
                rpal_debug_warning( "error deleting package from disk" );
                // This is not fatal
            }

            rpal_debug_info( "loading kernel extension" );
            if( 0 != ( error = system( tmpLoad ) ) )
            {
                // On OSX the KM stays alive as long as there are clients connected
                // so we may encounter race conditions with other components disconnecting.
                rpal_debug_info( "unloading previous kernel extension if present" );
                for( nRetries = 0; nRetries < 20; nRetries++ )
                {
                    rpal_thread_sleep( 200 );

                    if( 0 == ( error = system( tmpUnload ) ) )
                    {
                        break;
                    }
                }

                if( 0 != ( error = system( tmpLoad ) ) )
                {
                    rpal_debug_error( "could not load kernel extension: %d", error );
                }
            }

            isLoaded = TRUE;

        } while( FALSE );
#elif defined( RPAL_PLATFORM_WINDOWS )
        do
        {
            RWCHAR driverPath[] = _WCH( "%SYSTEMROOT%\\system32\\drivers\\tmp_hbs_acq.sys" );
            RPU8 driverBuffer = NULL;
            RU32 driverBufferSize = 0;
            SC_HANDLE hScControl = NULL;
            RWCHAR driverName[] = _WCH( "HbsAcq" );
            RWCHAR driverRootKey[] = _WCH( "SYSTEM\\CurrentControlSet\\Services\\HbsAcq" );
            SC_HANDLE hService = NULL;
            RPWCHAR absolutePath = NULL;
            HKEY hRootKey = NULL;
            DWORD disp = 0;
            RWCHAR keyInstances[] = _WCH( "Instances" );
            HKEY hInstancesKey = NULL;
            RWCHAR keyDefault[] = _WCH( "DefaultInstance" );
            RWCHAR instanceName[] = _WCH( "HbsAcq" );
            RWCHAR keyDefaultInstance[] = _WCH( "Instances\\HbsAcq" );
            HKEY hInstanceKey = NULL;
            RWCHAR keyAltitude[] = _WCH( "Altitude" );
            RWCHAR altitudeVal[] = _WCH( "328740" );
            RWCHAR keyFlags[] = _WCH( "Flags" );
            DWORD sizeZero = 0;

            if( !rSequence_getBUFFER( config,
                                      RP_TAGS_BINARY,
                                      &driverBuffer,
                                      &driverBufferSize ) )
            {
                rpal_debug_error( "malformed config" );
                break;
            }

            if( !rpal_file_write( driverPath, driverBuffer, driverBufferSize, TRUE ) )
            {
                rpal_debug_error( "could not write driver to disk: 0x%08X", rpal_error_getLast() );
                break;
            }

            if( NULL == ( hScControl = OpenSCManagerW( NULL,
                                                       NULL,
                                                       SC_MANAGER_CREATE_SERVICE ) ) )
            {
                rpal_debug_error( "error opening service manager: 0x%08X", rpal_error_getLast() );
                break;
            }

            if( !rpal_string_expand( driverPath, &absolutePath ) )
            {
                rpal_debug_error( "could not expand driver path" );
                break;
            }

            do
            {
                if( ERROR_SUCCESS == RegCreateKeyExW( HKEY_LOCAL_MACHINE,
                                                      driverRootKey,
                                                      0,
                                                      NULL,
                                                      REG_OPTION_NON_VOLATILE,
                                                      KEY_ALL_ACCESS,
                                                      NULL,
                                                      &hRootKey,
                                                      &disp ) )
                {
                    if( ERROR_SUCCESS == RegCreateKeyExW( hRootKey,
                                                          keyInstances,
                                                          0,
                                                          NULL,
                                                          REG_OPTION_NON_VOLATILE,
                                                          KEY_ALL_ACCESS,
                                                          NULL,
                                                          &hInstancesKey,
                                                          &disp ) )
                    {
                        if( ERROR_SUCCESS == RegSetValueExW( hInstancesKey,
                                                             keyDefault,
                                                             0,
                                                             REG_SZ,
                                                             (BYTE*)instanceName,
                                                             sizeof( instanceName ) ) )
                        {
                            if( ERROR_SUCCESS == RegCreateKeyExW( hRootKey,
                                                                  keyDefaultInstance,
                                                                  0,
                                                                  NULL,
                                                                  REG_OPTION_NON_VOLATILE,
                                                                  KEY_ALL_ACCESS,
                                                                  NULL,
                                                                  &hInstanceKey,
                                                                  &disp ) )
                            {
                                if( ERROR_SUCCESS != RegSetValueExW( hInstanceKey,
                                                                     keyAltitude,
                                                                     0,
                                                                     REG_SZ,
                                                                     (BYTE*)altitudeVal,
                                                                     sizeof( altitudeVal ) ) )
                                {
                                    rpal_debug_error( "could not set altitude: 0x%08X", rpal_error_getLast() );
                                    break;
                                }

                                if( ERROR_SUCCESS != RegSetValueExW( hInstanceKey,
                                                                     keyFlags,
                                                                     0,
                                                                     REG_DWORD,
                                                                     (BYTE*)&sizeZero,
                                                                     sizeof( sizeZero ) ) )
                                {
                                    rpal_debug_error( "could not set flags: 0x%08X", rpal_error_getLast() );
                                    break;
                                }
                            }
                            else
                            {
                                rpal_debug_error( "could not create default instance: 0x%08X", rpal_error_getLast() );
                                break;
                            }
                        }
                        else
                        {
                            rpal_debug_error( "could not create default instance key: 0x%08X", rpal_error_getLast() );
                            break;
                        }
                    }
                    else
                    {
                        rpal_debug_error( "could not create instances key: 0x%08X", rpal_error_getLast() );
                        break;
                    }
                }
                else
                {
                    rpal_debug_error( "could not create driver key: 0x%08X", rpal_error_getLast() );
                    break;
                }
            } while( FALSE );

            if( NULL != hInstanceKey ) RegCloseKey( hInstanceKey );
            if( NULL != hInstancesKey ) RegCloseKey( hInstancesKey );
            if( NULL != hRootKey ) RegCloseKey( hRootKey );

            hService = CreateServiceW( hScControl,
                                       driverName,
                                       driverName,
                                       SERVICE_ALL_ACCESS,
                                       SERVICE_KERNEL_DRIVER,
                                       SERVICE_DEMAND_START,
                                       SERVICE_ERROR_IGNORE,
                                       absolutePath,
                                       NULL, NULL, NULL,
                                       NULL, NULL );

            rpal_memory_free( absolutePath );

            if( NULL == hService )
            {
                rpal_debug_error( "could not create driver entry: 0x%08X", rpal_error_getLast() );
                hService = OpenServiceW( hScControl,
                                         driverName,
                                         SERVICE_ALL_ACCESS );
                if( NULL == hService )
                {
                    CloseServiceHandle( hScControl );
                    rpal_debug_error( "could not open driver entry: 0x%08X",
                                      rpal_error_getLast() );
                    break;
                }
            }

            if( !StartService( hService, 0, NULL ) &&
                ERROR_SERVICE_ALREADY_RUNNING != rpal_error_getLast() )
            {
                rpal_debug_error( "could not start driver: 0x%08X",
                                  rpal_error_getLast() );
            }
            else
            {
                isLoaded = TRUE;
            }

            CloseServiceHandle( hService );
            CloseServiceHandle( hScControl );

        } while( FALSE );
#else
        rpal_debug_warning( "no kernel acquisiton loading available for platform" );
#endif

        rSequence_free( config );
    }
    else
    {
        rpal_debug_warning( "no kernel acquisition package found" );
    }

    if( isLoaded )
    {
        rpal_debug_info( "waiting for exit signal" );
        rEvent_wait( isTimeToStop, RINFINITE );
    }
    else
    {
        rpal_debug_warning( "failed to load, will cleanup any partial install so we can try again" );
    }

    rpal_debug_info( "unloading kernel acquisition" );
#ifdef RPAL_PLATFORM_MACOSX
    do
    {
        RCHAR tmpUnload[] = "kextunload /tmp/tmp_hbs_acq.kext";
        RCHAR tmpDelete[] = "/tmp/tmp_hbs_acq.kext";
        RU32 nRetries = 0;

        // On OSX the KM stays alive as long as there are clients connected
        // so we may encounter race conditions with other components disconnecting.
        for( nRetries = 0; nRetries < 20; nRetries++ )
        {
            rpal_thread_sleep( 200 );

            if( 0 == ( error = system( tmpUnload ) ) )
            {
                break;
            }
        }

        if( 0 != error )
        {
            rpal_debug_error( "could not unload kernel extension: %d", error );
        }
        else
        {
            rpal_debug_info( "deleting kernel extension from disk" );
            if( !rpal_file_delete( tmpDelete, FALSE ) )
            {
                rpal_debug_warning( "error deleting kernel extension from disk" );
                // This is not fatal
            }
        }
    } while( FALSE );
#elif defined( RPAL_PLATFORM_WINDOWS )
    do
    {
        RWCHAR driverPath[] = _WCH( "%SYSTEMROOT%\\system32\\drivers\\tmp_hbs_acq.sys" );
        SC_HANDLE hScControl = NULL;
        RWCHAR driverName[] = _WCH( "HbsAcq" );
        SC_HANDLE hService = NULL;
        SERVICE_STATUS svcStatus = { 0 };

        if( NULL == ( hScControl = OpenSCManagerW( NULL,
                                                   NULL,
                                                   SC_MANAGER_CREATE_SERVICE ) ) )
        {
            rpal_debug_error( "error opening service manager: 0x%08X",
                              rpal_error_getLast() );
        }

        if( NULL != hScControl &&
            NULL == ( hService = OpenServiceW( hScControl,
                                               driverName,
                                               SERVICE_ALL_ACCESS ) ) )
        {
            rpal_debug_error( "error opening service: 0x%08X",
                              rpal_error_getLast() );
            CloseServiceHandle( hScControl );
        }
        else
        {
            if( NULL != hService &&
                !ControlService( hService, SERVICE_CONTROL_STOP, &svcStatus ) )
            {
                rpal_debug_error( "error stopping driver" );
            }

            if( NULL != hService &&
                !DeleteService( hService ) )
            {
                rpal_debug_error( "error deleting driver entry" );
            }

            if( NULL != hService )
            {
                CloseServiceHandle( hService );
            }

            if( NULL != hScControl )
            {
                CloseServiceHandle( hScControl );
            }
        }

        if( !rpal_file_delete( driverPath, FALSE ) )
        {
            rpal_debug_error( "error deleting driver file: 0x%08X",
                              rpal_error_getLast() );
        }
    } while( FALSE );
#else
    rpal_debug_warning( "no kernel acquisiton unloading available for platform" );
#endif

    return isLoaded;
}

RU32
RPAL_THREAD_FUNC
    RpHcpI_mainThread
    (
        rEvent isTimeToStop
    )
{
    RU32 ret = 0;
    RU32 nRetry = 0;

    FORCE_LINK_THAT(HCP_IFACE);

    // Some cases where the installation did not work correctly
    // the first time require a re-install, so we run potentially
    // the kernel installation twice.
    for( nRetry = 0; nRetry < 2; nRetry++ )
    {
        if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            if( tryLoadingKernel( isTimeToStop ) )
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    return ret;
}

