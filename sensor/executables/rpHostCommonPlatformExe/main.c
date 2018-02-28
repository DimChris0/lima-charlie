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
#include <rpHostCommonPlatformLib/rpHostCommonPlatformLib.h>
#include "git_info.h"

#ifdef RPAL_PLATFORM_LINUX
#include <signal.h>
#elif defined( RPAL_PLATFORM_MACOSX )
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif


#ifdef RPAL_PLATFORM_DEBUG
#ifndef HCP_EXE_ENABLE_MANUAL_LOAD
#define HCP_EXE_ENABLE_MANUAL_LOAD
#endif
#endif

RPRIVATE rEvent g_timeToQuit = NULL;
RPRIVATE struct
{
    RU32 nMod;
    RPNCHAR modPath;
} g_manual_loads[ 10 ] = { 0 };



#ifdef RPAL_PLATFORM_WINDOWS
BOOL
    ctrlHandler
    (
        DWORD type
    )
{
    BOOL isHandled = FALSE;

    static RU32 isHasBeenSignaled = 0;
    
    UNREFERENCED_PARAMETER( type );

    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        // We handle all events the same way, cleanly exit
    
        rpal_debug_info( "terminating rpHCP." );
        rpHostCommonPlatformLib_stop();
    
        rEvent_set( g_timeToQuit );
    
        isHandled = TRUE;
    }

    return isHandled;
}

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
void
    ctrlHandler
    (
        int sigNum
    )
{
    static RU32 isHasBeenSignaled = 0;
    
    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        rpal_debug_info( "terminating rpHCP." );
        rpHostCommonPlatformLib_stop();
        rEvent_set( g_timeToQuit );
    }
}
#endif

#ifdef RPAL_PLATFORM_WINDOWS
RBOOL
    isLaunchedInteractively
    (

    )
{
    RBOOL isInteractive = FALSE;
    HANDLE stdHandle = NULL;
    CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };

    if( INVALID_HANDLE_VALUE != ( stdHandle = GetStdHandle( STD_OUTPUT_HANDLE ) ) &&
        GetConsoleScreenBufferInfo( stdHandle, &csbi ) &&
        0 == csbi.dwCursorPosition.X &&
        0 == csbi.dwCursorPosition.Y )
    {
        isInteractive = TRUE;
    }

    return isInteractive;
}
#elif defined( RPAL_PLATFORM_MACOSX )
RBOOL
    isLaunchedInteractively
    (
        RPNCHAR arg0
    )
{
    RBOOL isInteractive = FALSE;

    if( NULL != arg0 &&
        NULL != rpal_string_stristr( arg0, _NC( ".app/" ) ) )
    {
        isInteractive = TRUE;
    }

    return isInteractive;
}
#endif

#ifdef RPAL_PLATFORM_WINDOWS


#define _SERVICE_NAME _WCH( "rphcpsvc" )
#define _SERVICE_NAMEW _WCH( "rphcpsvc" )
#ifdef RPAL_PLATFORM_DEBUG
    #define _SERVICE_IDENT_FILE _NC("%SYSTEMROOT%\\system32\\hcp_debug.dat")
    #define _SERVICE_CONF_FILE _NC("%SYSTEMROOT%\\system32\\hcp_conf_debug.dat")
#else
    #define _SERVICE_IDENT_FILE _NC("%SYSTEMROOT%\\system32\\hcp.dat")
    #define _SERVICE_CONF_FILE _NC("%SYSTEMROOT%\\system32\\hcp_conf.dat")
#endif
static SERVICE_STATUS g_svc_status = { 0 };
static SERVICE_STATUS_HANDLE g_svc_status_handle = NULL;
static RPNCHAR g_svc_primary = NULL;
static RPNCHAR g_svc_secondary = NULL;
static RPNCHAR g_svc_deployment = NULL;

static
RU32
    installService
    (
        RPNCHAR deploymentKey
    )
{
    RU32 ret = 0;
    HMODULE hModule = NULL;
    RWCHAR curPath[ RPAL_MAX_PATH ] = { 0 };
    RWCHAR destPath[] = _WCH( "%SYSTEMROOT%\\system32\\rphcp.exe" );
    RWCHAR svcPath[] = _WCH( "\"%SYSTEMROOT%\\system32\\rphcp.exe\" -w -d " );
    SC_HANDLE hScm = NULL;
    SC_HANDLE hSvc = NULL;
    RWCHAR svcName[] = { _SERVICE_NAMEW };
    RWCHAR svcDisplay[] = { _WCH( "LimaCharlie" ) };
    rString execCmd = NULL;
    SERVICE_FAILURE_ACTIONSW serviceFailureAction = { 0 };
    SC_ACTION failureActions = { 0 };
    SERVICE_DESCRIPTIONW serviceDescription = { 0 };
    RWCHAR svcDesc[] = _WCH( "LimaCharlie endpoint security sensor." );

    rpal_debug_info( "installing service" );

    if( NULL == ( execCmd = rpal_stringbuffer_new( 0, 0 ) ) )
    {
        rpal_debug_error( "failed to allocate exec command buffer" );
        return GetLastError();
    }

    if( !rpal_stringbuffer_add( execCmd, svcPath ) ||
        !rpal_stringbuffer_add( execCmd, deploymentKey ) )
    {
        rpal_stringbuffer_free( execCmd );
        return GetLastError();
    }

    hModule = GetModuleHandleW( NULL );
    if( NULL != hModule )
    {
        if( ARRAY_N_ELEM( curPath ) > GetModuleFileNameW( hModule, curPath, ARRAY_N_ELEM( curPath ) ) )
        {
            if( rpal_file_copy( curPath, destPath ) )
            {
                if( NULL != ( hScm = OpenSCManagerA( NULL, NULL, SC_MANAGER_CREATE_SERVICE ) ) )
                {
                    if( NULL != ( hSvc = CreateServiceW( hScm,
                                                         svcName,
                                                         svcDisplay,
                                                         SERVICE_ALL_ACCESS,
                                                         SERVICE_WIN32_OWN_PROCESS,
                                                         SERVICE_AUTO_START,
                                                         SERVICE_ERROR_NORMAL,
                                                         rpal_stringbuffer_getString( execCmd ),
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         NULL,
                                                         _WCH( "" ) ) ) )
                    {
                        // Reset the failure count after a month of uptime.
                        // On first error, restart the service after 2 seconds.
                        // Never restart after more than 1 error.
                        serviceFailureAction.dwResetPeriod = 60 * 60 * 24 * 30;
                        serviceFailureAction.lpCommand = NULL;
                        serviceFailureAction.lpRebootMsg = NULL;
                        serviceFailureAction.cActions = 1;
                        serviceFailureAction.lpsaActions = &failureActions;
                        failureActions.Type = SC_ACTION_RESTART;
                        failureActions.Delay = 2 * 1000;

                        if( ChangeServiceConfig2W( hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &serviceFailureAction ) )
                        {
                            // Set the service description.
                            serviceDescription.lpDescription = svcDesc;

                            if( ChangeServiceConfig2W( hSvc, SERVICE_CONFIG_DESCRIPTION, &serviceDescription ) )
                            {
                                if( StartService( hSvc, 0, NULL ) )
                                {
                                    // Emitting as error level to make sure it's displayed in release.
                                    rpal_debug_error( "service installed!" );
                                }
                                else
                                {
                                    ret = GetLastError();
                                    rpal_debug_error( "could not start service: %d", ret );
                                }
                            }
                            else
                            {
                                ret = GetLastError();
                                rpal_debug_error( "could not set service description: %d", ret );
                            }
                        }
                        else
                        {
                            ret = GetLastError();
                            rpal_debug_error( "could not set service to restart on first failure: %d", ret );
                        }

                        CloseServiceHandle( hSvc );
                    }
                    else
                    {
                        ret = GetLastError();
                        rpal_debug_error( "could not create service in SCM: %d", ret );
                    }

                    CloseServiceHandle( hScm );
                }
                else
                {
                    ret = GetLastError();
                    rpal_debug_error( "could not open SCM: %d", ret );
                }
            }
            else
            {
                ret = GetLastError();
                rpal_debug_error( "could not move executable to service location: %d", ret );
            }
        }
        else
        {
            ret = GetLastError();
            rpal_debug_error( "could not get current executable path: %d", ret );
        }

        CloseHandle( hModule );
    }
    else
    {
        ret = GetLastError();
        rpal_debug_error( "could not get current executable handle: %d", ret );
    }

    rpal_stringbuffer_free( execCmd );
    
    return ret;
}

static
RU32
    uninstallService
    (
        RBOOL isAlsoClean
    )
{
    RWCHAR destPath[] = _WCH( "%SYSTEMROOT%\\system32\\rphcp.exe" );
    SC_HANDLE hScm = NULL;
    SC_HANDLE hSvc = NULL;
    RWCHAR svcName[] = { _SERVICE_NAMEW };
    RNCHAR identPath[] = { _SERVICE_IDENT_FILE };
    RNCHAR confPath[] = { _SERVICE_CONF_FILE };
    SERVICE_STATUS svcStatus = { 0 };
    RU32 nRetries = 10;
    RBOOL isDeleted = FALSE;

    rpal_debug_info( "uninstalling service" );

    if( NULL != ( hScm = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS ) ) )
    {
        if( NULL != ( hSvc = OpenServiceW( hScm, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE ) ) )
        {
            if( ControlService( hSvc, SERVICE_CONTROL_STOP, &svcStatus ) )
            {
                while( SERVICE_STOPPED != svcStatus.dwCurrentState &&
                       0 != nRetries )
                {
                    rpal_debug_error( "waiting for service to stop..." );
                    rpal_thread_sleep( 1000 );

                    if( !QueryServiceStatus( hSvc, &svcStatus ) )
                    {
                        break;
                    }

                    nRetries--;
                }

                if( 0 == nRetries )
                {
                    rpal_debug_error( "timed out waiting for service to stop, moving on..." );
                }
                else
                {
                    rpal_debug_info( "service stopped" );
                }
            }
            else
            {
                rpal_debug_error( "could not stop service: %d", GetLastError() );
            }

            if( DeleteService( hSvc ) )
            {
                rpal_debug_info( "service deleted" );
            }
            else
            {
                rpal_debug_error( "could not delete service: %d", GetLastError() );
            }

            CloseServiceHandle( hSvc );
        }
        else
        {
            rpal_debug_error( "could not open service: %d", GetLastError() );
        }

        CloseServiceHandle( hScm );
    }
    else
    {
        rpal_debug_error( "could not open SCM: %d", GetLastError() );
    }

    nRetries = 30;
    while( 0 != nRetries )
    {
        nRetries--;

        if( rpal_file_delete( destPath, FALSE ) )
        {
            rpal_debug_info( "service executable deleted" );
            isDeleted = TRUE;
            break;
        }

        rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
    }

    if( !isDeleted )
    {
        rpal_debug_error( "could not delete service executable: %d", GetLastError() );
    }

    if( isAlsoClean )
    {
        if( !rpal_file_delete( identPath, FALSE ) )
        {
            rpal_debug_warning( "failed to delete identity file from disk, not present?" );
        }
        else
        {
            rpal_debug_info( "deleted identity file from disk" );
        }

        if( !rpal_file_delete( confPath, FALSE ) )
        {
            rpal_debug_warning( "failed to delete config file from disk, not present?" );
        }
        else
        {
            rpal_debug_info( "deleted config file from disk" );
        }
    }

    return GetLastError();
}

static
VOID WINAPI 
    SvcCtrlHandler
    (
        DWORD fdwControl
    )
{
    switch( fdwControl )
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:

            if( g_svc_status.dwCurrentState != SERVICE_RUNNING )
                break;

            /*
            * Perform tasks necessary to stop the service here
            */

            g_svc_status.dwControlsAccepted = 0;
            g_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
            g_svc_status.dwWin32ExitCode = 0;
            g_svc_status.dwCheckPoint = 2;

            SetServiceStatus( g_svc_status_handle, &g_svc_status );

            rpal_debug_info( "terminating rpHCP." );
            rpHostCommonPlatformLib_stop();

            rEvent_set( g_timeToQuit );

            break;

        default:
            break;
    }
}

static
VOID WINAPI 
    ServiceMain
    (
        DWORD  dwArgc,
        RPCHAR lpszArgv
    )
{
    RU32 memUsed = 0;
    RWCHAR svcName[] = { _SERVICE_NAME };
    RU32 i = 0;

    UNREFERENCED_PARAMETER( dwArgc );
    UNREFERENCED_PARAMETER( lpszArgv );


    if( NULL == ( g_svc_status_handle = RegisterServiceCtrlHandlerW( svcName, SvcCtrlHandler ) ) )
    {
        return;
    }

    rpal_memory_zero( &g_svc_status, sizeof( g_svc_status ) );
    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCurrentState = SERVICE_START_PENDING;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwServiceSpecificExitCode = 0;
    g_svc_status.dwCheckPoint = 0;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );

    if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
    {
        g_svc_status.dwControlsAccepted = 0;
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        g_svc_status.dwWin32ExitCode = GetLastError();
        g_svc_status.dwCheckPoint = 1;
        SetServiceStatus( g_svc_status_handle, &g_svc_status );
        return;
    }

    rpal_debug_info( "initialising rpHCP." );
    if( !rpHostCommonPlatformLib_launch( g_svc_primary, g_svc_secondary, g_svc_deployment ) )
    {
        rpal_debug_warning( "error launching hcp." );
    }

    for( i = 0; i < ARRAY_N_ELEM( g_manual_loads ); i++ )
    {
        if( NULL != g_manual_loads[ i ].modPath )
        {
            if( 0 != g_manual_loads[ i ].nMod )
            {
#ifdef HCP_EXE_ENABLE_MANUAL_LOAD
                rpHostCommonPlatformLib_load( g_manual_loads[ i ].modPath, g_manual_loads[ i ].nMod );
#endif
            }
            else
            {
                rpal_debug_error( "Mismatched number of -m modulePath and -n moduleId statements provided!" );
            }

            rpal_memory_free( g_manual_loads[ i ].modPath );
            g_manual_loads[ i ].modPath = NULL;
        }
        else
        {
            break;
        }
    }

    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status.dwCurrentState = SERVICE_RUNNING;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwCheckPoint = 1;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );

    rpal_debug_info( "...running, waiting to exit..." );
    rEvent_wait( g_timeToQuit, RINFINITE );
    rEvent_free( g_timeToQuit );

    rpal_debug_info( "...exiting..." );
    rpal_Context_cleanup();

    memUsed = rpal_memory_totalUsed();
    if( 0 != memUsed )
    {
        rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
        //rpal_memory_findMemory();
#ifdef RPAL_FEATURE_MEMORY_ACCOUNTING
        rpal_memory_printDetailedUsage();
#endif
    }

    g_svc_status.dwControlsAccepted = 0;
    g_svc_status.dwCurrentState = SERVICE_STOPPED;
    g_svc_status.dwWin32ExitCode = 0;
    g_svc_status.dwCheckPoint = 3;
    SetServiceStatus( g_svc_status_handle, &g_svc_status );
}

#elif defined( RPAL_PLATFORM_MACOSX )

#define _SERVICE_DESC_FILE  _NC("/Library/LaunchDaemons/com.refractionpoint.rphcp.plist")
#define _SERVICE_NAME       _NC("com.refractionpoint.rphcp")
#define _SERVICE_DIR        _NC("/usr/local/bin/")
#define _SERVICE_FILE       _NC("/usr/local/bin/rphcp")
#define _SERVICE_IDENT_FILE _NC("/usr/local/hcp")
#define _SERVICE_CONF_FILE  _NC("/usr/local/hcp_conf")
#define _SERVICE_LOAD       _NC("launchctl load ") _SERVICE_DESC_FILE
#define _SERVICE_START      _NC("launchctl start ") _SERVICE_NAME
#define _SERVICE_UNLOAD     _NC("launchctl unload ") _SERVICE_DESC_FILE
#define _SERVICE_DESC_1     _NC("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
<plist version=\"1.0\">\
    <dict>\
        <key>Label</key>\
        <string>com.refractionpoint.rphcp</string>\
        <key>ProgramArguments</key>\
        <array>\
            <string>/usr/local/bin/rphcp</string>\
            <string>-d</string>\
            <string>")
#define _SERVICE_DESC_2     _NC("</string>\
        </array>\
        <key>KeepAlive</key>\
        <true/>\
    </dict>\
</plist>\
")

static
RU32
    installService
    (
        RPNCHAR deploymentKey
    )
{
    RU32 res = (RU32)-1;

    RNCHAR currentPath[ RPAL_MAX_PATH ] = {0};
    RU32 currentPathSize = sizeof( currentPath );
    RNCHAR svcDir[] = { _SERVICE_DIR };
    RNCHAR svcPath[] = { _SERVICE_FILE };
    RNCHAR svcDesc1[] = { _SERVICE_DESC_1 };
    RNCHAR svcDesc2[] = { _SERVICE_DESC_2 };
    RNCHAR svcDescPath[] = { _SERVICE_DESC_FILE };
    RBOOL isOnDisk = FALSE;
    RNCHAR svcLoad[] = { _SERVICE_LOAD };
    RNCHAR svcStart[] = { _SERVICE_START };
    rString svcDesc = NULL;

    rpal_debug_info( "installing service" );

    if( NULL == ( svcDesc = rpal_stringbuffer_new( 0, 0 ) ) )
    {
        rpal_debug_error( "failed to allocate exec command buffer" );
        return res;
    }

    if( !rpal_stringbuffer_add( svcDesc, svcDesc1 ) ||
        !rpal_stringbuffer_add( svcDesc, deploymentKey ) ||
        !rpal_stringbuffer_add( svcDesc, svcDesc2 ) )
    {
        rpal_stringbuffer_free( svcDesc );
        return res;
    }

    if( 0 == _NSGetExecutablePath( currentPath, &currentPathSize ) )
    {
        if( rDir_create( svcDir ) )
        {
            chmod( svcDir, S_IRWXU );
        }

        if( rpal_file_copy( currentPath, svcPath ) )
        {
            if( 0 != chmod( svcPath, S_IRWXU ) )
            {
                rpal_debug_warning( "could not set restricted permissions on executable" );
            }

            if( rpal_file_write( svcDescPath, 
                                 rpal_stringbuffer_getString( svcDesc ), 
                                 rpal_string_strlen( rpal_stringbuffer_getString( svcDesc ) ), 
                                 TRUE ) )
            {
                if( 0 != chmod( svcDescPath, S_IRWXU ) )
                {
                    rpal_debug_warning( "could not set restricted permissions on service descriptor" );
                }

                isOnDisk = TRUE;
            }
            else
            {
                rpal_debug_error( "could not write service descriptor" );
            }
        }
        else
        {
            rpal_debug_error( "could not copy executable to service location" );
        }
    }
    else
    {
        rpal_debug_error( "could not get current executable path" );
    }

    if( isOnDisk )
    {
        if( 0 != system( svcLoad ) )
        {
            rpal_debug_warning( "failed to load service, already exists?" );
        }

        if( 0 != system( svcStart ) )
        {
            rpal_debug_warning( "failed to start service, already running?" );
        }
        else
        {
            rpal_debug_info( "successfully installed" );
            res = 0;
        }
    }

    rpal_stringbuffer_free( svcDesc );

    return res;
}

static
RU32
    uninstallService
    (
        RBOOL isAlsoClean
    )
{
    RU32 res = (RU32)-1;

    RNCHAR svcUnload[] = { _SERVICE_UNLOAD };
    RNCHAR svcPath[] = { _SERVICE_FILE };
    RNCHAR identPath[] = { _SERVICE_IDENT_FILE };
    RNCHAR confPath[] = { _SERVICE_CONF_FILE };

    if( 0 != system( svcUnload ) )
    {
        rpal_debug_warning( "failed to unload service, already unloaded?" );
    }

    rpal_thread_sleep( MSEC_FROM_SEC( 5 ) );

    if( !rpal_file_delete( svcPath, FALSE ) )
    {
        rpal_debug_warning( "failed to delete file from disk, not present?" );
    }
    else
    {
        rpal_debug_info( "uninstalled successfully" );
        res = 0;
    }

    if( isAlsoClean )
    {
        if( !rpal_file_delete( identPath, FALSE ) )
        {
            rpal_debug_warning( "failed to delete identity file from disk, not present?" );
            res = (RU32)-1;
        }
        else
        {
            rpal_debug_info( "deleted identity file from disk" );
        }

        if( !rpal_file_delete( confPath, FALSE ) )
        {
            rpal_debug_warning( "failed to delete config file from disk, not present?" );
        }
        else
        {
            rpal_debug_info( "deleted config file from disk" );
        }
    }

    return res;
}

#endif


RPAL_NATIVE_MAIN
{
    RU32 returnValue = 0;
    RNCHAR argFlag = 0;
    RPNCHAR argVal = NULL;
    RPNCHAR primary = NULL;
    RPNCHAR secondary = NULL;
    RPNCHAR deployment = NULL;
    RPNCHAR tmpMod = NULL;
    RU32 tmpModId = 0;
    RU32 i = 0;
    RU32 memUsed = 0;
    RBOOL asService = FALSE;
    RBOOL isArgumentsSpecified = FALSE;

    rpal_opt switches[] = { { _NC( 'h' ), _NC( "help" ), FALSE },
                            { _NC( 'v' ), _NC( "version" ), FALSE },
                            { _NC( 'p' ), _NC( "primary" ), TRUE },
                            { _NC( 's' ), _NC( "secondary" ), TRUE },
                            { _NC( 'm' ), _NC( "manual" ), TRUE },
                            { _NC( 'n' ), _NC( "moduleId" ), TRUE },
                            { _NC( 'd' ), _NC( "deployment" ), TRUE }
#ifdef RPAL_PLATFORM_WINDOWS
                            ,
                            { _NC( 'i' ), _NC( "install" ), TRUE },
                            { _NC( 'r' ), _NC( "uninstall" ), FALSE },
                            { _NC( 'c' ), _NC( "uninstall-clean" ), FALSE },
                            { _NC( 'w' ), _NC( "service" ), FALSE }
#elif defined( RPAL_PLATFORM_MACOSX )
                            ,
                            { _NC( 'i' ), _NC( "install" ), TRUE },
                            { _NC( 'r' ), _NC( "uninstall" ), FALSE },
                            { _NC( 'c' ), _NC( "uninstall-clean" ), FALSE }
#endif
                          };

    if( rpal_initialize( NULL, 0 ) )
    {
        while( (RNCHAR)-1 != ( argFlag = rpal_getopt( argc, argv, switches, &argVal ) ) )
        {
            switch( argFlag )
            {
                case _NC( 'v' ):
                    printf( "VERSION: " RF_U32, GIT_REVISION );
                    return 0;
                    break;
                case _NC( 'p' ):
                    primary = argVal;
                    rpal_debug_info( "Setting primary URL: " RF_STR_N ".", primary );
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 's' ):
                    secondary = argVal;
                    rpal_debug_info( "Setting secondary URL: " RF_STR_N ".", secondary );
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 'm' ):
                    tmpMod = rpal_string_strdup( argVal );
                    rpal_debug_info( "Manually loading module: " RF_STR_N ".", argVal );
                    for( i = 0; i < ARRAY_N_ELEM( g_manual_loads ); i++ )
                    {
                        if( NULL == g_manual_loads[ i ].modPath )
                        {
                            g_manual_loads[ i ].modPath = tmpMod;
                            break;
                        }
                    }
                    if( i >= ARRAY_N_ELEM( g_manual_loads ) )
                    {
                        rpal_debug_error( "Too many manual loads specified, ignoring, max: %d", ARRAY_N_ELEM( g_manual_loads ) );
                    }
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 'n' ):
                    if( rpal_string_stoi( argVal, &tmpModId, TRUE ) )
                    {
                        rpal_debug_info( "Manually loading module id is: %d", tmpModId );
                        for( i = 0; i < ARRAY_N_ELEM( g_manual_loads ); i++ )
                        {
                            if( 0 == g_manual_loads[ i ].nMod )
                            {
                                g_manual_loads[ i ].nMod = tmpModId;
                                break;
                            }
                        }
                        if( i >= ARRAY_N_ELEM( g_manual_loads ) )
                        {
                            rpal_debug_error( "Too many manual loads specified, ignoring, max: %d", ARRAY_N_ELEM( g_manual_loads ) );
                        }
                    }
                    else
                    {
                        rpal_debug_warning( "Module id provided is invalid." );
                    }
                    isArgumentsSpecified = TRUE;
                    break;
                case _NC( 'd' ):
                    deployment = argVal;
                    rpal_debug_info( "Deployment info: " RF_STR_N ".", deployment );
                    isArgumentsSpecified = TRUE;
                    break;
#ifdef RPAL_PLATFORM_WINDOWS
                case _NC( 'i' ):
                    return installService( argVal );
                    break;
                case _NC( 'r' ):
                    return uninstallService( FALSE );
                    break;
                case _NC( 'c' ):
                    return uninstallService( TRUE );
                    break;
                case _NC( 'w' ):
                    asService = TRUE;
                    isArgumentsSpecified = TRUE;
                    break;
#elif defined( RPAL_PLATFORM_MACOSX )
                case _NC( 'i' ):
                    return installService( argVal );
                    break;
                case _NC( 'r' ):
                    return uninstallService( FALSE );
                    break;
                case _NC( 'c' ):
                    return uninstallService( TRUE );
                    break;
#endif
                case _NC( 'h' ):
                default:
                    printf( "Usage: " RF_STR_N " .\n", argv[ 0 ] );
                    printf( "-v: display build version.\n" );
                    printf( "-p <URL>: primary Url used to communicate home.\n" );
                    printf( "-s <URL>: secondary Url used to communicate home if the primary failed.\n" );
                    printf( "-m <FILE_PATH>: a module to be loaded manually, only available in debug builds.\n" );
                    printf( "-n <MODULE_ID>: the module id of a module being manually loaded, only available in debug builds, must match -m modules in order.\n" );
                    printf( "-d <INSTALLATION_KEY>: the deployment key to use to enroll.\n" );
#ifdef RPAL_PLATFORM_WINDOWS
                    printf( "-i <INSTALLATION_KEY>: install executable as a service with deployment key.\n" );
                    printf( "-r: uninstall executable as a service.\n" );
                    printf( "-c: uninstall executable as a service and delete identity files.\n" );
                    printf( "-w: executable is running as a Windows service.\n" );
#elif defined( RPAL_PLATFORM_MACOSX )
                    printf( "-i <INSTALLATION_KEY>: install executable as a service with deployment key.\n" );
                    printf( "-r: uninstall executable as a service.\n" );
                    printf( "-c: uninstall executable as a service and delete identity files.\n" );
#endif
                    printf( "-h: this help.\n" );
                    return 0;
                    break;
            }
        }

#ifdef RPAL_PLATFORM_WINDOWS
        if( asService )
        {
            RWCHAR svcName[] = { _SERVICE_NAME };
            SERVICE_TABLE_ENTRYW DispatchTable[] =
            {
                { NULL, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
                { NULL, NULL }
            };

            DispatchTable[ 0 ].lpServiceName = svcName;

            g_svc_primary = primary;
            g_svc_secondary = secondary;
            g_svc_deployment = deployment;

            if( !StartServiceCtrlDispatcherW( DispatchTable ) )
            {
                return GetLastError();
            }
            else
            {
                return 0;
            }
        }
#endif

#if defined( RPAL_PLATFORM_WINDOWS )
        if( !isArgumentsSpecified &&
            isLaunchedInteractively() )
        {
            rpal_debug_info( "Installing or running requires arguments, see -h." );
            return -1;
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        if( !isArgumentsSpecified &&
            0 != argc &&
            isLaunchedInteractively( argv[ 0 ] ) )
        {
            rpal_debug_info( "Installing or running requires arguments, see -h." );
            return -1;
        }
#endif

        rpal_debug_info( "initialising rpHCP." );
        if( !rpHostCommonPlatformLib_launch( primary, secondary, deployment ) )
        {
            rpal_debug_warning( "error launching hcp." );
        }

        if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
        {
            rpal_debug_error( "error creating quit event." );
            return -1;
        }

#ifdef RPAL_PLATFORM_WINDOWS
        if( !SetConsoleCtrlHandler( (PHANDLER_ROUTINE)ctrlHandler, TRUE ) )
        {
            rpal_debug_error( "error registering control handler function." );
            return -1;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( SIG_ERR == signal( SIGINT, ctrlHandler ) )
        {
            rpal_debug_error( "error setting signal handler" );
            return -1;
        }
#endif
        for( i = 0; i < ARRAY_N_ELEM( g_manual_loads ); i++ )
        {
            if( NULL != g_manual_loads[ i ].modPath )
            {
                if( 0 != g_manual_loads[ i ].nMod )
                {
#ifdef HCP_EXE_ENABLE_MANUAL_LOAD
                    rpHostCommonPlatformLib_load( g_manual_loads[ i ].modPath, g_manual_loads[ i ].nMod );
#endif
                }
                else
                {
                    rpal_debug_error( "Mismatched number of -m modulePath and -n moduleId statements provided!" );
                }
                rpal_memory_free( g_manual_loads[ i ].modPath );
            }
            else
            {
                break;
            }
        }

        rpal_debug_info( "...running, waiting to exit..." );
        rEvent_wait( g_timeToQuit, RINFINITE );
        rEvent_free( g_timeToQuit );
        
        rpal_debug_info( "...exiting..." );
        rpal_Context_cleanup();

        memUsed = rpal_memory_totalUsed();
        if( 0 != memUsed )
        {
            returnValue = 1;

            rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
            //rpal_memory_findMemory();
#ifdef RPAL_FEATURE_MEMORY_ACCOUNTING
            rpal_memory_printDetailedUsage();
#endif
        }
        
        rpal_Context_deinitialize();
    }

    return returnValue;
}
