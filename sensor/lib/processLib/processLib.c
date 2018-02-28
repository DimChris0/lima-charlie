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

#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <libOs/libOs.h>
#include <notificationsLib/notificationsLib.h>

#define RPAL_FILE_ID   44

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#pragma warning( disable: 4306 ) // Disabling error on cast to bigger
#pragma warning( disable: 4127 ) // Disabling error on constant expressions
#define MAX_PEB_PATH_LENGTH        4096

static pfnNtQueryInformationProcess queryInfo = NULL;
static pfnNtQuerySystemInformation querySysInfo = NULL;
static pfnNtQueryObject queryObj = NULL;
static pfnNtQueryInformationFile queryFile = NULL;

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
    #if defined( RPAL_PLATFORM_MACOSX )
        #include <sys/sysctl.h>
        #include <libproc.h>
        #include <launch.h>
        #include <sys/proc_info.h>
        #include <mach/mach_vm.h>
        extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
    #endif
#endif


RBOOL
    processLib_isPidInUse
    (
        RU32 pid
    )
{
    RBOOL isInUse = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hProcess = NULL;
    DWORD exitCode = 0;

    hProcess = OpenProcess( SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pid );
    
    if( ( NULL != hProcess &&
          INVALID_HANDLE_VALUE != hProcess ) ||
        ERROR_INVALID_PARAMETER != GetLastError() )
    {
        if( NULL != hProcess &&
            INVALID_HANDLE_VALUE != hProcess )
        {
            // We got a handle so we can make a secondary check
            if( !GetExitCodeProcess( hProcess, (LPDWORD)&exitCode ) ||
                STILL_ACTIVE == exitCode )
            {
                if( WAIT_TIMEOUT == WaitForSingleObject( hProcess, 0 ) )
                {
                    isInUse = TRUE;
                }
            }

            CloseHandle( hProcess );
        }
        else
        {
            // This is a PID but we don't have access to it so we will
            // assume it exists.
            isInUse = TRUE;
        }
    }
#elif defined( RPAL_PLATFORM_LINUX )
    RCHAR procDir[] = "/proc/%d";
    RCHAR tmpFile[ RPAL_MAX_PATH ] = {0};
    RS32 size = 0;
    rDir hProc = NULL;
        
                
    size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procDir, pid );
    if( size > 0 &&
        size < sizeof( tmpFile ) )
    {
        if( rDir_open( tmpFile, &hProc ) )
        {
            isInUse = TRUE;
            rDir_close( hProc );
        }
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    struct kinfo_proc info = {0};
    size_t size = sizeof( info );

    mib[ 3 ] = pid;

    if( 0 == sysctl( mib, ARRAY_N_ELEM( mib ), &info, &size, NULL, 0 ) && 0 < size )
    {
        if( 0 != size )
        {
            isInUse = TRUE;
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return isInUse;
}

rSequence
    processLib_getProcessInfo
    (
        RU32 processId,
        rSequence bootstrap
    )
{
    rSequence procInfo = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    RWCHAR api_ntdll[] = _WCH("ntdll.dll");
    RCHAR api_queryproc[] = "NtQueryInformationProcess";
    RWCHAR api_psapi[] = _WCH("psapi.dll");
    RCHAR api_getprocmeminfo[] = "GetProcessMemoryInfo";
    RCHAR api_getprocfilenameex[] = "GetProcessImageFileNameW";

    PEB peb = {0};
    PROCESS_BASIC_INFORMATION pbi = {0};
    RTL_USER_PROCESS_PARAMETERS block = {0};
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    SIZE_T dwSize = 0;
    RWCHAR pebPath[ MAX_PEB_PATH_LENGTH ] = { 0 };
    HANDLE hProcSnap = NULL;
    PROCESSENTRY32W procEntry = {0};
    GetProcessMemoryInfo_f getProcMemInfo = NULL;
    GetProcessImageFileName_f getProcFileName = NULL;
    HMODULE hPsApi = NULL;
    PROCESS_MEMORY_COUNTERS memCounters = {0};
    RBOOL isPbiAcquired = FALSE;
    RBOOL isPebAcquired = FALSE;
    RBOOL isUserProcessParamsAcquired = FALSE;
    RBOOL isCommandLineAcquired = FALSE;
    RBOOL isFilePathAcquired = FALSE;
    RBOOL isSecondaryInfoAcquired = FALSE;
    RU32 retryCountDown = 0;
    RU32 i = 0;
    RU32 lastError = 0;
    RU8 tokenOwner[ 256 ] = { 0 };
    RU32 tokenSize = 0;
    RWCHAR ownerName[ 64 ] = { 0 };
    RU32 ownerNameSize = ARRAY_N_ELEM( ownerName );
    RWCHAR ownerDomain[ 64 ] = { 0 };
    RU32 ownerDomainSize = ARRAY_N_ELEM( ownerDomain );
    SID_NAME_USE ownerUse = { 0 };
    RWCHAR fullOwner[ ARRAY_N_ELEM( ownerName ) + ARRAY_N_ELEM( ownerDomain ) ] = { 0 };

    if( NULL == queryInfo )
    {
        // This must be the first call so we will init the import
        queryInfo = (pfnNtQueryInformationProcess)GetProcAddress( LoadLibraryW( api_ntdll ), api_queryproc );
    }

    if( NULL != queryInfo &&
        ( NULL != ( procInfo = bootstrap ) ||
          NULL != ( procInfo = rSequence_new() ) ) )
    {
        pbi.PebBaseAddress = (PPEB)0x7ffdf000;
        pbi.UniqueProcessId = processId;

        hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId );

        if( NULL != hProcess )
        {
            retryCountDown = 5;
            while( 0 != retryCountDown )
            {
                isPbiAcquired = FALSE;
                isPebAcquired = FALSE;

                // We prefer to introspect the process ourselves
                if( STATUS_SUCCESS == queryInfo( hProcess, 
                                                 ProcessBasicInformation, 
                                                 &pbi, 
                                                 sizeof( PROCESS_BASIC_INFORMATION ), 
                                                 (PULONG)&dwSize ) )
                {   
                    isPbiAcquired = TRUE;
                }
                else
                {
                    lastError = GetLastError();
                    rpal_debug_warning( "error querying process basic information: %d", lastError );
                }

                if( isPbiAcquired )
                {
                    if( ReadProcessMemory( hProcess, (LPCVOID)pbi.PebBaseAddress, &peb, sizeof( PEB ), &dwSize ) )
                    {
                        isPebAcquired = TRUE;
                        break;
                    }
                    else
                    {
                        lastError = GetLastError();
                        rpal_debug_warning( "error reading PEB: %d", lastError );
                    }
                }

                retryCountDown--;
                rpal_thread_sleep( 1 );
            }

            if( isPebAcquired )
            {
                rSequence_addPOINTER64( procInfo, RP_TAGS_BASE_ADDRESS, (RU64)peb.ImageBaseAddress );
                rSequence_addRU32( procInfo, RP_TAGS_PROCESS_ID, processId );

                retryCountDown = 5;
                while( 0 != retryCountDown )
                {
                    isUserProcessParamsAcquired = FALSE;
                    isCommandLineAcquired = FALSE;
                    isFilePathAcquired = FALSE;

                    if( ReadProcessMemory( hProcess, peb.ProcessParameters, &block, sizeof( RTL_USER_PROCESS_PARAMETERS ), &dwSize ) )
                    {
                        isUserProcessParamsAcquired = TRUE;
                    }
                    else
                    {
                        lastError = GetLastError();
                        rpal_debug_warning( "error reading process parameters block: %d", lastError );
                    }

                    if( isUserProcessParamsAcquired )
                    {
                        // Attempt to read the command line
                        if( 0 != block.CommandLine.Length && 
                            MAX_PEB_PATH_LENGTH > block.CommandLine.Length )
                        {
                            pebPath[ block.CommandLine.Length / sizeof( RWCHAR ) ] = 0;

                            if( ReadProcessMemory( hProcess, (LPVOID)block.CommandLine.Buffer, &pebPath, block.CommandLine.Length, &dwSize ) )
                            {
                                isCommandLineAcquired = TRUE;
                            }
                            else
                            {
                                lastError = GetLastError();
                                rpal_debug_warning( "error reading command line: %d", lastError );
                            }
                        }
                        else if( 0 == block.CommandLine.Length )
                        {
                            pebPath[ 0 ] = 0;
                            isCommandLineAcquired = TRUE;
                        }
                        else
                        {
                            // Too long, likely a bug, so we will simply not report it.
                        }

                        if( isCommandLineAcquired )
                        {
                            if( 0 != block.CommandLine.Length )
                            {
                                isCommandLineAcquired = FALSE;
                                for( i = 0; i < ( ( block.CommandLine.Length / sizeof( RWCHAR ) ) - 1 ); i++ )
                                {
                                    if( 0 == pebPath[ i ] )
                                    {
                                        pebPath[ i ] = _WCH( ' ' );
                                    }
                                    else
                                    {
                                        // We need at least one non-null character, otherwise it's probably not populated yet.
                                        isCommandLineAcquired = TRUE;
                                    }
                                }
                            }

                            if( isCommandLineAcquired )
                            {
                                rSequence_addSTRINGW( procInfo, RP_TAGS_COMMAND_LINE, pebPath );
                            }
                        }

                        if( !isCommandLineAcquired )
                        {
                            retryCountDown--;
                            rpal_thread_sleep( 1 );
                            continue;
                        }



                        // Attempt to read the path of the executable
                        if( 0 != block.ImagePathName.Length && 
                            MAX_PEB_PATH_LENGTH > block.ImagePathName.Length )
                        {
                            pebPath[ block.ImagePathName.Length / sizeof( RWCHAR ) ] = 0;

                            if( ReadProcessMemory( hProcess, (LPVOID)block.ImagePathName.Buffer, &pebPath, block.ImagePathName.Length, &dwSize ) )
                            {
                                isFilePathAcquired = TRUE;
                            }
                            else
                            {
                                lastError = GetLastError();
                                rpal_debug_warning( "error reading file path: %d", lastError );
                            }
                        }
                        else if( 0 == block.ImagePathName.Length )
                        {
                            pebPath[ 0 ] = 0;
                            isFilePathAcquired = TRUE;
                        }
                        else
                        {
                            // Too long, likely a bug, so we will simply not report it.
                        }

                        if( isFilePathAcquired )
                        {
                            if( 0 != block.ImagePathName.Length )
                            {
                                isFilePathAcquired = FALSE;

                                for( i = 0; i < ( ( block.ImagePathName.Length / sizeof( RWCHAR ) ) - 1 ); i++ )
                                {
                                    if( 0 == pebPath[ i ] )
                                    {
                                        pebPath[ i ] = _WCH( ' ' );
                                    }
                                    else
                                    {
                                        isFilePathAcquired = TRUE;
                                    }
                                }
                            }

                            if( isFilePathAcquired )
                            {
                                rSequence_addSTRINGW( procInfo, RP_TAGS_FILE_PATH, pebPath );
                            }
                        }

                        if( !isFilePathAcquired )
                        {
                            retryCountDown--;
                            rpal_thread_sleep( 1 );
                            continue;
                        }
                    }

                    if( isFilePathAcquired && isCommandLineAcquired )
                    {
                        break;
                    }

                    retryCountDown--;
                    rpal_thread_sleep( 1 );
                    rpal_debug_warning( "missing process information, retrying..." );
                }
            }


            if( INVALID_HANDLE_VALUE != ( hProcSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ) )
            {
                procEntry.dwSize = sizeof( procEntry );

                if( Process32FirstW( hProcSnap, &procEntry ) )
                {
                    do
                    {
                        if( processId == procEntry.th32ProcessID )
                        {
                            rSequence_addRU32( procInfo, RP_TAGS_PARENT_PROCESS_ID, procEntry.th32ParentProcessID );
                            rSequence_addRU32( procInfo, RP_TAGS_THREADS, procEntry.cntThreads );
                            isSecondaryInfoAcquired = TRUE;
                            break;
                        }
                    }
                    while( Process32NextW( hProcSnap, &procEntry ) );
                }

                CloseHandle( hProcSnap );
            }

            
            if( NULL != ( hPsApi = GetModuleHandleW( api_psapi ) ) ||
                NULL != ( hPsApi = LoadLibraryW( api_psapi ) ) )
            {
                if( NULL != ( getProcMemInfo = (GetProcessMemoryInfo_f)GetProcAddress( hPsApi, api_getprocmeminfo ) ) )
                {
                    if( getProcMemInfo( hProcess, &memCounters, sizeof( memCounters ) ) )
                    {
                        rSequence_addRU64( procInfo, RP_TAGS_MEMORY_USAGE, memCounters.WorkingSetSize );
                        isSecondaryInfoAcquired = TRUE;
                    }
                }

                // Ok, we tried to be fancy and got nowhere, let's try to play nice
                if( !isFilePathAcquired )
                {
                    if( NULL != ( getProcFileName = (GetProcessImageFileName_f)GetProcAddress( hPsApi, api_getprocfilenameex ) ) )
                    {
                        if( 0 != getProcFileName( hProcess, pebPath, ARRAY_N_ELEM( pebPath ) ) )
                        {
                            rSequence_addSTRINGW( procInfo, RP_TAGS_FILE_PATH, pebPath );
                            isSecondaryInfoAcquired = TRUE;
                        }
                    }
                }
            }

            // Let's try to get the owner
            if( OpenProcessToken( hProcess, TOKEN_READ, &hToken ) )
            {
                if( GetTokenInformation( hToken, 
                                         TokenOwner, 
                                         (TOKEN_OWNER*)&tokenOwner, 
                                         sizeof( tokenOwner ), 
                                         (PDWORD)&tokenSize ) )
                {
                    if( LookupAccountSidW( NULL,
                                           ((TOKEN_OWNER*)tokenOwner)->Owner,
                                           (LPWSTR)&ownerName,
                                           (LPDWORD)&ownerNameSize,
                                           (LPWSTR)&ownerDomain,
                                           (LPDWORD)&ownerDomainSize,
                                           &ownerUse ) )
                    {
                        // By definition the fullOwner buffer always has enough room if the accounts
                        // query were successful.
                        rpal_string_strcpy( fullOwner, ownerDomain );
                        rpal_string_strcat( fullOwner, _WCH( "\\" ) );
                        rpal_string_strcat( fullOwner, ownerName );
                        rSequence_addSTRINGW( procInfo, RP_TAGS_USER_NAME, fullOwner );
                    }
                }

                CloseHandle( hToken );
            }

            CloseHandle( hProcess );

            if( !isFilePathAcquired && 
                !isCommandLineAcquired && 
                !isSecondaryInfoAcquired && 
                NULL == bootstrap )
            {
                // If we really got NOTHING we'll just clean up to signal to the caller
                rSequence_free( procInfo );
                procInfo = NULL;
            }
            else
            {
                // We won't report a success if all we have is process id since it's dumb
                rSequence_addRU32( procInfo, RP_TAGS_PROCESS_ID, processId );
            }
        }
        else if( NULL == bootstrap )
        {
            rSequence_free( procInfo );
            procInfo = NULL;
        }
    }
#elif defined( RPAL_PLATFORM_LINUX )
    RCHAR procExeDir[] = "/proc/%d/exe";
    RCHAR procStatusDir[] = "/proc/%d/status";
    RCHAR procCmdLineDir[] = "/proc/%d/cmdline";
    RCHAR tmpFile[ RPAL_MAX_PATH ] = {0};
    RPCHAR exeFile = NULL;
    RPCHAR infoFile = NULL;
    RPCHAR info = NULL;
    RPCHAR state = NULL;
    RS32 size = 0;
    
    RCHAR ppidHeader[] = "PPid:";
    RU32 ppid = 0;

    RCHAR vmRssHeader[] = "VmRSS";
    RU32 rss = 0;
    
    RCHAR threadsHeader[] = "Threads:";
    RU32 threads = 0;

    RCHAR nameHeader[] = "Name:";
    RPCHAR name = NULL;

    RCHAR uidHeader[] = "Uid:";
    RU32 uid = (RU32)(-1);
    struct passwd* user_info = NULL;

    RCHAR  preLinkTag[] = ".#prelink#.";
    RPCHAR preLinkIndex = NULL;
    
    RU32 i = 0;
        
    if( NULL != ( procInfo = bootstrap ) ||
        NULL != ( procInfo = rSequence_new() ) )
    {
        rSequence_addRU32( procInfo, RP_TAGS_PROCESS_ID, processId );
        
        size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procStatusDir, processId );
        if( size > 0
            && size < sizeof( tmpFile ) )
        {
            if( rpal_file_read( tmpFile, (RPU8*)&infoFile, &size, FALSE ) )
            {
                info = rpal_string_strtok( infoFile, '\n', &state );
                while( NULL != info )
                {
                    if( 0 == rpal_memory_memcmp( info, ppidHeader, sizeof( ppidHeader ) - sizeof( RCHAR ) ) )
                    {
                        if( rpal_string_stoi( info + sizeof( ppidHeader ), &ppid, TRUE ) )
                        {
                            rSequence_addRU32( procInfo, RP_TAGS_PARENT_PROCESS_ID, ppid );
                        }
                    }
                    else if( 0 == rpal_memory_memcmp( info, threadsHeader, sizeof( threadsHeader ) - sizeof( RCHAR ) ) )
                    {
                        if( rpal_string_stoi( info + sizeof( threadsHeader ), &threads, TRUE ) )
                        {
                            rSequence_addRU32( procInfo, RP_TAGS_THREADS, threads );
                        }
                    }
                    else if( 0 == rpal_memory_memcmp( info, uidHeader, sizeof( uidHeader ) - sizeof( RCHAR ) ) )
                    {
                        // We only care about the "effective" UID for now.
                        for( i = sizeof( uidHeader ); 0 != info[ i ]; i++ )
                        {
                            if( ' ' == info[ i ] || 0x09 == info[ i ] ) // Space or Tab sep
                            {
                                info[ i ] = 0;
                                break;
                            }
                        }
                        
                        if( rpal_string_stoi( info + sizeof( uidHeader ), &uid, TRUE ) )
                        {
                            rSequence_addRU32( procInfo, RP_TAGS_USER_ID, uid );

                            if( NULL != ( user_info = getpwuid( uid ) ) )
                            {
                                if( NULL != user_info->pw_name )
                                {
                                    rSequence_addSTRINGA( procInfo, RP_TAGS_USER_NAME, user_info->pw_name );
                                }
                            }
                        }
                    }
                    else if( 0 == rpal_memory_memcmp( info, nameHeader, sizeof( nameHeader ) - sizeof( RCHAR ) ) )
                    {
                        name = (RPCHAR)info + sizeof( nameHeader );
                    }
                    else if( 0 == rpal_memory_memcmp( info, vmRssHeader, sizeof( vmRssHeader ) - sizeof( RCHAR ) ) )
                    {
                        // Not strict conversion since the line contains a " kB" after.
                        if( rpal_string_stoi( info + sizeof( vmRssHeader ), &rss, FALSE ) )
                        {
                            // The number is always in kB.
                            rSequence_addRU64( procInfo, RP_TAGS_MEMORY_USAGE, rss * 1024 );
                        }
                    }
                                
                    if( 0 != threads && 0 != ppid && (RU32)(-1) != uid && NULL != name )
                    {
                        // We found all that we could look for here
                        break;
                    }
                    
                    info = rpal_string_strtok( NULL, '\n', &state );
                }
                
                rpal_memory_free( infoFile );
            }
        }

        size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procExeDir, processId );
        if( size > 0
            && size < sizeof( tmpFile ) )
        {
            if( rpal_file_getLinkDest( (RPCHAR)tmpFile, &exeFile ) )
            {
                preLinkIndex = rpal_string_strstr( exeFile, preLinkTag );
                if( NULL != preLinkIndex )
                {
                    *preLinkIndex = '\0';
                }

                rSequence_addSTRINGA( procInfo, RP_TAGS_FILE_PATH, exeFile );
                rpal_memory_free( exeFile );
            }
            else if( NULL != name )
            {
                rSequence_addSTRINGA( procInfo, RP_TAGS_FILE_PATH, name );
                name = NULL;
            }
        }
        
        size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procCmdLineDir, processId );
        if( size > 0
            && size < sizeof( tmpFile ) )
        {
            if( rpal_file_read( tmpFile, (RPU8*)&infoFile, &size, FALSE ) )
            {
                RU32 i = 0;
                for( i = 0; i < size - 1; i++ )
                {
                    if( 0 == infoFile[ i ] )
                    {
                        infoFile[ i ] = ' ';
                    }
                }
                
                rSequence_addSTRINGA( procInfo, RP_TAGS_COMMAND_LINE, infoFile );
                
                rpal_memory_free( infoFile );
            }
        }
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    struct kinfo_proc info = {0};
    size_t size = sizeof( info );
    size_t argsize = 0;
    struct passwd* user_info = NULL;
    char* args = NULL;
    char* cmdline = NULL;
    char* exe = NULL;
    int i = 0;
    int nargs = 0;
    rString fullcmdline = NULL;

    mib[ 3 ] = processId;

    procInfo = bootstrap;
    
    if( 0 == sysctl( mib, 4, &info, &size, NULL, 0 ) && 0 < size )
    {
        if( NULL != procInfo ||
            NULL != ( procInfo = rSequence_new() ) )
        {
            rSequence_addRU32( procInfo, RP_TAGS_PROCESS_ID, info.kp_proc.p_pid );
            rSequence_addRU32( procInfo, RP_TAGS_PARENT_PROCESS_ID, info.kp_eproc.e_ppid );

            rSequence_addRU32( procInfo, RP_TAGS_USER_ID, info.kp_eproc.e_ucred.cr_uid );
            if( NULL != ( user_info = getpwuid( info.kp_eproc.e_ucred.cr_uid ) ) )
            {
                if( NULL != user_info->pw_name )
                {
                    rSequence_addSTRINGA( procInfo, RP_TAGS_USER_NAME, user_info->pw_name );
                }
                else
                {
                    rpal_debug_warning( "no username set for uid %d", info.kp_eproc.e_ucred.cr_uid );
                }
            }
            else
            {
                rpal_debug_warning( "could not get user info for uid %d", info.kp_eproc.e_ucred.cr_uid );
            }

            mib[ 1 ] = KERN_ARGMAX;
            size = sizeof( argsize );
            if( 0 == sysctl( mib, 2, &argsize, &size, NULL, 0 ) && 0 < size )
            {
                if( NULL != ( args = rpal_memory_alloc( argsize ) ) )
                {
                    mib[ 1 ] = KERN_PROCARGS2;
                    mib[ 2 ] = processId;
                    size = argsize;
                    if( 0 == sysctl( mib, 3, args, &size, NULL, 0 ) && 0 < size )
                    {
                        nargs = *(int*)args;
                        exe = args + sizeof( int );

                        if( 0 < nargs )
                        {
                            cmdline = exe + rpal_string_strlen( exe ) + 1;

                            if( NULL != ( fullcmdline = rpal_stringbuffer_new( 0, 0 ) ) )
                            {
                                while( i < size )
                                {
                                    if( 0 == cmdline[ i ] )
                                    {
                                        i++;
                                    }
                                    else
                                    {
                                        rpal_stringbuffer_add( fullcmdline, cmdline + i );
                                        i += rpal_string_strlen( cmdline + i );

                                        if( 1 != nargs )
                                        {
                                            rpal_stringbuffer_add( fullcmdline, " " );
                                        }
                                        else
                                        {
                                            break;
                                        }
                                        nargs--;
                                    }
                                }

                                rSequence_addSTRINGA( procInfo,
                                                      RP_TAGS_COMMAND_LINE, 
                                                      rpal_stringbuffer_getString( fullcmdline ) );
                            }

                            rpal_stringbuffer_free( fullcmdline );
                        }

                        args[ size - 1 ] = 0;
                        
                        while( ' ' == *exe )
                        {
                            exe++;
                        }

                        rSequence_addSTRINGA( procInfo, RP_TAGS_FILE_PATH, exe );
                    }

                    rpal_memory_free( args );
                }
            }
        }
    }

    if( processId == processLib_getCurrentPid() )
    {
        struct task_basic_info t_info;
        mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

        if( KERN_SUCCESS == task_info( mach_task_self(),
                                       TASK_BASIC_INFO, (task_info_t)&t_info,
                                       &t_info_count ) )
        {
            rSequence_addRU64( procInfo, RP_TAGS_MEMORY_USAGE, t_info.resident_size );
        }
    }
#else
    rpal_debug_not_implemented();
#endif
    return procInfo;
}

RPNCHAR
    processLib_getCurrentModulePath
    (

    )
{
    RPNCHAR modulePath = NULL;
    rList modules = NULL;
    rSequence module = NULL;
    RU64 baseAddr = 0;
    RU64 memSize = 0;

    if( NULL != ( modules = processLib_getProcessModules( processLib_getCurrentPid() ) ) )
    {
        while( rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
        {
            if( rSequence_getPOINTER64( module, RP_TAGS_BASE_ADDRESS, &baseAddr ) &&
                rSequence_getRU64( module, RP_TAGS_MEMORY_SIZE, &memSize ) &&
                rSequence_getSTRINGN( module, RP_TAGS_FILE_PATH, &modulePath ) )
            {
                if( IS_WITHIN_BOUNDS( processLib_getCurrentModulePath, sizeof( modulePath ), baseAddr, memSize ) )
                {
                    modulePath = rpal_string_strdup( modulePath );
                    break;
                }
                else
                {
                    modulePath = NULL;
                }
            }
        }

        rList_free( modules );
    }

    return modulePath;
}


#ifdef RPAL_PLATFORM_MACOSX
RPRIVATE
RPCHAR
    _getOsxPathForMem
    (
        RU32 processId,
        RU64 baseAddr
    )
{
    RPCHAR path = NULL;
    struct proc_regionwithpathinfo rwpi = { 0 };
    int result = 0;

    result = proc_pidinfo( processId, PROC_PIDREGIONPATHINFO, baseAddr, &rwpi, sizeof( rwpi ) );
    if( 0 != result &&
        rwpi.prp_vip.vip_path[ 0 ] )
    {
        path = rpal_string_strdupA( rwpi.prp_vip.vip_path );
    }

    return path;
}
#endif


rList
    processLib_getProcessModules
    (
        RU32 processId
    )
{
    rList modules = NULL;
    rSequence module = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hSnap = NULL;
    MODULEENTRY32W modEntry = {0};

    while( INVALID_HANDLE_VALUE == ( hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE,
                                                                       processId ) ) &&
           ERROR_BAD_LENGTH == GetLastError() )
    {
        rpal_thread_sleep( 10 );
    }

    if( INVALID_HANDLE_VALUE != hSnap )
    {
        modEntry.dwSize = sizeof( modEntry );

        if( Module32FirstW( hSnap, &modEntry ) )
        {
            if( NULL != ( modules = rList_new( RP_TAGS_DLL, RPCM_SEQUENCE ) ) )
            {
                do
                {
                    if( NULL != ( module = rSequence_new() ) )
                    {
                        rSequence_addRU32( module, RP_TAGS_PROCESS_ID, modEntry.th32ProcessID );
                        rSequence_addPOINTER64( module, RP_TAGS_BASE_ADDRESS, (RU64)modEntry.modBaseAddr );
                        rSequence_addRU64( module, RP_TAGS_MEMORY_SIZE, modEntry.modBaseSize );
                        rSequence_addSTRINGW( module, RP_TAGS_FILE_PATH, modEntry.szExePath );
                        rSequence_addSTRINGW( module, RP_TAGS_MODULE_NAME, modEntry.szModule );

                        if( !rList_addSEQUENCE( modules, module ) )
                        {
                            rSequence_free( module );
                        }
                    }
                }
                while( Module32NextW( hSnap, &modEntry ) );
            }
        }

        CloseHandle( hSnap );
    }
#elif defined( RPAL_PLATFORM_LINUX )
        RCHAR procMapDir[] = "/proc/%d/maps";
        RCHAR tmpFile[ RPAL_MAX_PATH ] = {0};
        RPCHAR infoFile = NULL;
        RPCHAR info = NULL;
        RPCHAR state = NULL;
        RS32 size = 0;
        
        RCHAR entryHeader[] = "%lx-%lx %4s %x %5s %d %512s";
        RU64 addrStart = 0;
        RU64 addrEnd = 0;
        RCHAR permissions[ 5 ] = {0};
        RU32 offset = 0;
        RCHAR device[ 6 ] = {0};
        RU32 inode = 0;
        RCHAR mapPath[ 513 ] = {0};
        RPWCHAR mapPathW = NULL;
        RCHAR execPattern[] = "??x?";
        
        RCHAR curPath[ 513 ] = {0};
        RU64 curEnd = 0;
        RU64 curStart = 0;
        
        size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procMapDir, processId );
        if( size > 0 &&
            size < sizeof( tmpFile ) )
        {
            if( rpal_file_read( tmpFile, (RPU8*)&infoFile, &size, FALSE ) )
            {
                if( NULL != ( modules = rList_new( RP_TAGS_DLL, RPCM_SEQUENCE ) ) )
                {
                    info = rpal_string_strtok( infoFile, '\n', &state );
                    while( NULL != info )
                    {
                        size = rpal_string_sscanf( info, 
                                                   (RPCHAR)entryHeader, 
                                                   &addrStart, 
                                                   &addrEnd, 
                                                   permissions, 
                                                   &offset, 
                                                   device, 
                                                   &inode, 
                                                   mapPath );
                        if( 7 == size &&
                           '[' != mapPath[ 0 ] ) // Ignore if it starts with [ since it means it's not a file
                        {
                            if( ( 0 != curPath[0] ) && 0 != rpal_string_strcmp( mapPath, curPath ) )
                            {
                                if( NULL != module )
                                {
                                    rSequence_addRU64( module, RP_TAGS_MEMORY_SIZE, curEnd - curStart );
                                    
                                    if( !rList_addSEQUENCE( modules, module ) )
                                    {
                                        rSequence_free( module );
                                        module = NULL;
                                    }
                                    
                                    module = NULL;
                                }
                            }

                            if( NULL == module )    
                            {
                                // Ignore modules that are not executable
                                if( rpal_string_match( execPattern, permissions, TRUE ) )
                                {
                                    if( NULL != ( module = rSequence_new() ) )
                                    {
                                        rSequence_addRU32( module, RP_TAGS_PROCESS_ID, processId );
                                        rSequence_addPOINTER64( module, RP_TAGS_BASE_ADDRESS, addrStart );

                                        rSequence_addSTRINGA( module, RP_TAGS_FILE_PATH, mapPath );

                                        rpal_memory_memcpy( curPath, mapPath, sizeof( curPath ) );
                                        curStart = addrStart;
                                        curEnd = addrEnd;
                                    }
                                }
                            }
                            else
                            {
                                curEnd = addrEnd;
                            }
                        }
                        
                        info = rpal_string_strtok( NULL, '\n', &state );
                    }
                    
                    // Process the last module in the list
                    if( NULL != module )
                    {
                        rSequence_addRU64( module, RP_TAGS_MEMORY_SIZE, curEnd - curStart );
                        
                        if( !rList_addSEQUENCE( modules, module ) )
                        {
                            rSequence_free( module );
                        }
                        
                        module = NULL;
                    }
                }
                
                rpal_memory_free( infoFile );
            }
        }
#elif defined( RPAL_PLATFORM_MACOSX )
    RPCHAR tmpPath = NULL;
    rList memMap = NULL;
    rSequence memRegion = NULL;
    RU8 access = 0;
    RU64 baseAddr = 0;

    if( NULL != ( modules = rList_new( RP_TAGS_DLL, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( memMap = processLib_getProcessMemoryMap( processId ) ) )
        {
            while( rList_getSEQUENCE( memMap, RP_TAGS_MEMORY_REGION, &memRegion ) )
            {
                if( rSequence_getRU8( memRegion, RP_TAGS_MEMORY_ACCESS, &access ) &&
                    ( PROCESSLIB_MEM_ACCESS_EXECUTE == access ||
                      PROCESSLIB_MEM_ACCESS_EXECUTE_READ == access ||
                      PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE == access ||
                      PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE == access ||
                      PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE_COPY == access ) &&
                    rSequence_getPOINTER64( memRegion, RP_TAGS_BASE_ADDRESS, &baseAddr ) )
                {
                    // This is an executable region of memory.
                    if( NULL != ( tmpPath = _getOsxPathForMem( processId, baseAddr ) ) )
                    {
                        // Add the path and pid to the region info and report it.
                        rSequence_addRU32( memRegion, RP_TAGS_PROCESS_ID, processId );
                        rSequence_addSTRINGA( memRegion, RP_TAGS_FILE_PATH, tmpPath );

                        rList_addSEQUENCE( modules, rSequence_duplicate( memRegion ) );

                        rpal_memory_free( tmpPath );
                        tmpPath = NULL;
                    }
                }
            }

            rList_free( memMap );
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return modules;
}

processLibProcEntry*
    processLib_getProcessEntries
    (
        RBOOL isBruteForce
    )
{
    processLibProcEntry* procs = NULL;
    processLibProcEntry tmpEntry = {0};
    RU32 nEntries = 0;
        
#ifdef RPAL_PLATFORM_WINDOWS
    DWORD exitCode = 0;
    RU32 processId = 0;
    HANDLE hProcess = NULL;
    
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32W procEntry = {0};
    procEntry.dwSize = sizeof( procEntry );
    
    if( isBruteForce )
    {
        for( processId = 4; processId <= 65536; processId +=  4 )
        {
            hProcess = OpenProcess( SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, processId );
        
            if( ( NULL != hProcess &&
                  INVALID_HANDLE_VALUE != hProcess ) ||
                ERROR_INVALID_PARAMETER != GetLastError() )
            {
                // If we got a handle we can do a second check to make sure
                // the process is still running.
                if( NULL != hProcess &&
                    INVALID_HANDLE_VALUE != hProcess )
                {
                    if( GetExitCodeProcess( hProcess, (LPDWORD)&exitCode ) &&
                        STILL_ACTIVE != exitCode )
                    {
                        CloseHandle( hProcess );
                        continue;
                    }
    
                    if( WAIT_OBJECT_0 == WaitForSingleObject( hProcess, 0 ) )
                    {
                        CloseHandle( hProcess );
                        continue;
                    }
                }
        
                tmpEntry.pid = processId;
        
                nEntries++;
        
                procs = rpal_memory_realloc( procs, ( nEntries + 1 ) * sizeof( processLibProcEntry ) );
                
                if( NULL != procs )
                {
                    procs[ nEntries - 1 ] = tmpEntry;
                    procs[ nEntries ].pid = 0;
                }
        
                rpal_memory_zero( &tmpEntry, sizeof( tmpEntry ) );
        
                if( NULL != hProcess &&
                    INVALID_HANDLE_VALUE != hProcess )
                {
                    CloseHandle( hProcess );
                }
            }
        }
    }
    else
    {
        if( INVALID_HANDLE_VALUE != ( hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ) )
        {
            if( Process32FirstW( hSnapshot, &procEntry ) )
            {
                do
                {
                    if( 0 == procEntry.th32ProcessID )
                    {
                        continue;
                    }
                    
                    nEntries++;
                    
                    if( NULL != ( procs = rpal_memory_realloc( procs, ( nEntries + 1 ) * sizeof( processLibProcEntry ) ) ) )
                    {
                        procs[ nEntries - 1 ].pid = procEntry.th32ProcessID;
                        procs[ nEntries ].pid = 0;
                    }
                }
                while( Process32NextW( hSnapshot, &procEntry ) );
            }

            CloseHandle( hSnapshot );
        }
    }
#elif defined( RPAL_PLATFORM_LINUX )
    RCHAR procDir[] = "/proc/";
    rDir hProcDir = NULL;
    rFileInfo finfo = {0};
    
    // No difference between brute force and API at the moment
        
    if( rDir_open( (RPCHAR)&procDir, &hProcDir ) )
    {
        while( rDir_next( hProcDir, &finfo ) )
        {
            // Look in /proc for directories that are just a number (process IDs)
            if( rpal_string_stoi( (RPCHAR)finfo.fileName, &tmpEntry.pid, TRUE ) &&
                0 != tmpEntry.pid )
            {
                nEntries++;

                procs = rpal_memory_realloc( procs, ( nEntries + 1 ) * sizeof( processLibProcEntry ) );
                if( NULL != procs )
                {
                    procs[ nEntries - 1 ] = tmpEntry;
                    procs[ nEntries ].pid = 0;
                }
        
                rpal_memory_zero( &tmpEntry, sizeof( tmpEntry ) );
            }
        }
        
        rDir_close( hProcDir );
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    struct kinfo_proc* infos = NULL;
    size_t size = 0;
    int ret = 0;
    int i = 0;

    if( isBruteForce )
    {
        // Lots of possible PIDs in OSX: 99999
        for( i = 1; i < 99999; i++ )
        {
            if( processLib_isPidInUse( i ) )
            {
                size++;
        
                procs = rpal_memory_realloc( procs, ( size + 1 ) * sizeof( processLibProcEntry ) );
                
                if( NULL != procs )
                {
                    procs[ size - 1 ].pid = i;
                    procs[ size ].pid = 0;
                }
            }
        }
    }
    else
    {
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
            // Number of procs
            size = size / sizeof( struct kinfo_proc );
            if( NULL != ( procs = rpal_memory_alloc( ( size + 1 ) * sizeof( processLibProcEntry ) ) ) )
            {
                for( i = 0; i < size; i++ )
                {
                    procs[ i ].pid = infos[ i ].kp_proc.p_pid;
                }
    
                procs[ size ].pid = 0;
            }
        }
    
        if( NULL != infos )
        {
            rpal_memory_free( infos );
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return procs;
}


rList
    processLib_getProcessMemoryMap
    (
        RU32 processId
    )
{
    rList map = NULL;
    rSequence loc = NULL;
    RU8 protect = 0;
    RU8 type = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hProcess = NULL;
    MEMORY_BASIC_INFORMATION memInfo = {0};
    RPVOID lastQueried = 0;

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId );

    if( NULL != hProcess )
    {
        if( NULL != ( map = rList_new( RP_TAGS_MEMORY_REGION, RPCM_SEQUENCE ) ) )
        {
            while( TRUE )
            {
                if( 0 == VirtualQueryEx( hProcess, lastQueried, &memInfo, sizeof( MEMORY_BASIC_INFORMATION ) ) )
                {
                    break;
                }
                else if( MEM_COMMIT == memInfo.State )
                {
                    if( NULL != ( loc = rSequence_new() ) )
                    {
                        switch( memInfo.Type )
                        {
                        case MEM_IMAGE:
                            type = PROCESSLIB_MEM_TYPE_IMAGE;
                            break;
                        case MEM_MAPPED:
                            type = PROCESSLIB_MEM_TYPE_MAPPED;
                            break;
                        case MEM_PRIVATE:
                            type = PROCESSLIB_MEM_TYPE_PRIVATE;
                            break;
                        default:
                            type = PROCESSLIB_MEM_TYPE_UNKNOWN;
                            break;
                        }

                        // If PAGE_GUARD is set we report as ACCESS_DENIED.
                        if( IS_FLAG_ENABLED( memInfo.Protect, PAGE_GUARD ) )
                        {
                            memInfo.Protect = 0;
                        }

                        // Ignore values above 0xFF as they're specialized values.
                        DISABLE_FLAG( memInfo.Protect, 0xFFFFFF00 );

                        switch( memInfo.Protect )
                        {
                        case PAGE_EXECUTE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE;
                            break;
                        case PAGE_EXECUTE_READ:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ;
                            break;
                        case PAGE_EXECUTE_READWRITE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE;
                            break;
                        case PAGE_EXECUTE_WRITECOPY:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE_COPY;
                            break;
                        case PAGE_NOACCESS:
                            protect = PROCESSLIB_MEM_ACCESS_NO_ACCESS;
                            break;
                        case PAGE_READONLY:
                            protect = PROCESSLIB_MEM_ACCESS_READ_ONLY;
                            break;
                        case PAGE_READWRITE:
                            protect = PROCESSLIB_MEM_ACCESS_READ_WRITE;
                            break;
                        case PAGE_WRITECOPY:
                            protect = PROCESSLIB_MEM_ACCESS_WRITE_COPY;
                            break;
                        default:
                            protect = PROCESSLIB_MEM_ACCESS_DENIED;
                            break;
                        }

                        if( !rSequence_addRU8( loc, RP_TAGS_MEMORY_TYPE, type ) ||
                            !rSequence_addRU8( loc, RP_TAGS_MEMORY_ACCESS, protect ) ||
                            !rSequence_addPOINTER64( loc, RP_TAGS_BASE_ADDRESS, (RU64)memInfo.BaseAddress ) ||
                            !rSequence_addRU64( loc, RP_TAGS_MEMORY_SIZE, memInfo.RegionSize ) ||
                            !rList_addSEQUENCE( map, loc ) )
                        {
                            rSequence_free( loc );
                            loc = NULL;
                        }
                    }
                }

                lastQueried = (RPVOID)( (RPU8)memInfo.BaseAddress + memInfo.RegionSize );
            }
        }

        CloseHandle( hProcess );
    }
#elif defined( RPAL_PLATFORM_LINUX )
    RCHAR procMapDir[] = "/proc/%d/maps";
    RCHAR tmpFile[ RPAL_MAX_PATH ] = {0};
    RPCHAR infoFile = NULL;
    RPCHAR info = NULL;
    RPCHAR state = NULL;
    RU32 size = 0;

    RCHAR entryHeader[] = "%lx-%lx %4s %x %5s %d %512s";
    RU64 addrStart = 0;
    RU64 addrEnd = 0;
    RCHAR permissions[ 5 ] = {0};
    RU32 offset = 0;
    RCHAR device[ 6 ] = {0};
    RU32 inode = 0;
    RCHAR mapPath[ 513 ] = {0};

    RU32 addrSize = 0;

    size = rpal_string_snprintf( (RPCHAR)&tmpFile, sizeof( tmpFile ), (RPCHAR)&procMapDir, processId );
    if( size > 0
            && size < sizeof( tmpFile ) )
    {
        if( rpal_file_read( tmpFile, (RPU8*)&infoFile, &size, FALSE ) )
        {
            if( NULL != ( map = rList_new( RP_TAGS_MEMORY_REGION, RPCM_SEQUENCE ) ) )
            {
                info = rpal_string_strtok( infoFile, '\n', &state );
                while( NULL != info )
                {
                    size = rpal_string_sscanf( info, (RPCHAR)entryHeader, &addrStart, &addrEnd, permissions, &offset, device, &inode, mapPath );
                    if( 7 == size )
                    {
                        if( NULL == loc )
                        {
                            if( NULL != ( loc = rSequence_new() ) )
                            {
                                if( rpal_string_match( "*p", permissions, TRUE ) )
                                {
                                    type = PROCESSLIB_MEM_TYPE_PRIVATE;
                                }
                                else if( rpal_string_match( "*s", permissions, TRUE ) )
                                {
                                    type = PROCESSLIB_MEM_TYPE_MAPPED;
                                }
                                else
                                {
                                    type = PROCESSLIB_MEM_TYPE_UNKNOWN;
                                }
                                // Map protect permissions
                                if ( rpal_string_match( "--x?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_EXECUTE;
                                }
                                else if ( rpal_string_match( "r-x?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ;
                                }
                                else if ( rpal_string_match( "rwx?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE;
                                }
                                else if ( rpal_string_match( "---?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_NO_ACCESS;
                                }
                                else if ( rpal_string_match( "r--?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_READ_ONLY;
                                }
                                else if ( rpal_string_match( "rw-?", permissions, TRUE ) )
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_READ_WRITE;
                                }
                                else
                                {
                                    protect = PROCESSLIB_MEM_ACCESS_DENIED;
                                }

                                addrSize = addrEnd - addrStart;
                               
                                rSequence_addRU8( loc, RP_TAGS_MEMORY_TYPE, type );
                                rSequence_addRU8( loc, RP_TAGS_MEMORY_ACCESS, protect );
                                rSequence_addPOINTER64( loc, RP_TAGS_BASE_ADDRESS, addrStart );
                                rSequence_addRU64( loc, RP_TAGS_MEMORY_SIZE, addrSize );
                            }
                            if( !rList_addSEQUENCE( map, loc ) )
                            {
                                rSequence_free( loc );
                                loc = NULL;
                            }

                            loc = NULL;
                        }

                    }

                    info = rpal_string_strtok( NULL, '\n', &state );
                }
            }
           
            rpal_memory_free( infoFile );
        }
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    struct proc_regioninfo ri = {0};
    int result = 0;
    uint64_t offset = 0;
    uint64_t prevBase = 0;

    if( NULL != ( map = rList_new( RP_TAGS_MEMORY_REGION, RPCM_SEQUENCE ) ) )
    {
        do 
        {
            result = proc_pidinfo( processId, PROC_PIDREGIONINFO, offset, &ri, sizeof( ri ) );
            if( result == sizeof( ri )) 
            {
                if( NULL != ( loc = rSequence_new() ) )
                {
                    switch( ri.pri_share_mode )
                    {
                        case SM_COW:
                        case SM_SHARED:
                        case SM_TRUESHARED:
                        case SM_SHARED_ALIASED:
                            type = PROCESSLIB_MEM_TYPE_SHARED;
                            break;
                        case SM_PRIVATE:
                        case SM_PRIVATE_ALIASED:
                            type = PROCESSLIB_MEM_TYPE_PRIVATE;
                            break;
                        case SM_EMPTY:
                            type = PROCESSLIB_MEM_TYPE_EMPTY;
                            break;
                        default:
                            type = PROCESSLIB_MEM_TYPE_UNKNOWN;
                            break;
                    }
                    switch( ri.pri_protection )
                    {
                        case VM_PROT_READ:
                            protect = PROCESSLIB_MEM_ACCESS_READ_ONLY;
                            break;
                        case VM_PROT_WRITE:
                            protect = PROCESSLIB_MEM_ACCESS_WRITE_ONLY;
                            break;
                        case VM_PROT_READ|VM_PROT_WRITE:
                            protect = PROCESSLIB_MEM_ACCESS_READ_WRITE;
                            break;
                        case VM_PROT_EXECUTE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE;
                            break;
                        case VM_PROT_READ|VM_PROT_EXECUTE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ;
                            break;
                        case VM_PROT_WRITE|VM_PROT_EXECUTE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE;
                            break;
                        case VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE:
                            protect = PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE;
                            break;
                        default:
                            protect = PROCESSLIB_MEM_ACCESS_NO_ACCESS;
                            break;
                    }
                    rSequence_addRU8( loc, RP_TAGS_MEMORY_TYPE, type );
                    rSequence_addRU8( loc, RP_TAGS_MEMORY_ACCESS, protect );
                    rSequence_addPOINTER64( loc, RP_TAGS_BASE_ADDRESS, ri.pri_address );
                    rSequence_addRU64( loc, RP_TAGS_MEMORY_SIZE, ri.pri_size );
                }
                if( !rList_addSEQUENCE( map, loc ) )
                {
                    rSequence_free( loc );
                    loc = NULL;
                }
                loc = NULL;
            }
            offset = ri.pri_address + ri.pri_size;
        }
        while( result > 0 );
    }
#else
    rpal_debug_not_implemented();
#endif

    return map;
}



RBOOL
    processLib_getProcessMemory
    (
        RU32 processId,
        RPVOID baseAddr,
        RU64 size,
        RPVOID* pBuffer,
        RBOOL isBridgeGaps
    )
{
    RBOOL isSuccess = FALSE;
    RU32 pageSize = 0;
    RPU8 pPageOffset = NULL;
    RPU8 pBufferOffset = NULL;

    if( NULL != pBuffer )
    {
        if( isBridgeGaps )
        {
            pageSize = libOs_getPageSize();
        }

        if( NULL != ( *pBuffer = rpal_memory_alloc( (RU32)size ) ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            HANDLE hProcess = NULL;
            RSIZET sizeRead = 0;

            if( NULL != ( hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                                  FALSE,
                                                  processId ) ) )
            {
                if( ReadProcessMemory( hProcess, baseAddr, *pBuffer, (RU32)size, (SIZE_T*)&sizeRead ) &&
                    sizeRead == size )
                {
                    isSuccess = TRUE;
                }

                if( !isSuccess )
                {
                    if( isBridgeGaps )
                    {
                        isSuccess = TRUE;

                        pPageOffset = baseAddr;
                        pBufferOffset = *pBuffer;
                        while( pPageOffset < ( (RPU8)baseAddr + size ) )
                        {
                            ReadProcessMemory( hProcess,
                                               pPageOffset,
                                               pBufferOffset,
                                               pageSize,
                                               (SIZE_T*)&sizeRead );

                            pPageOffset += pageSize;
                            pBufferOffset += pageSize;
                        }
                    }
                }

                CloseHandle( hProcess );
            }
#elif defined( RPAL_PLATFORM_LINUX )
            RCHAR procMemFile[] = "/proc/%d/mem";
            RCHAR tmpFile[ RPAL_MAX_PATH ] = {0};
            RPWCHAR tmpFileW = NULL;
            rFile memFile = NULL;
            RU32 snpf_size = 0;

            snpf_size = rpal_string_snprintf( (RPCHAR)&tmpFile, 
                                              sizeof( tmpFile ), 
                                              (RPCHAR)&procMemFile, 
                                              processId );
            if( snpf_size > 0
                && snpf_size < sizeof( tmpFile ) )
            {
                if( rFile_open( (RPCHAR)&tmpFile, &memFile, RPAL_FILE_OPEN_READ | RPAL_FILE_OPEN_EXISTING ) )
                {
                    if( rFile_seek( memFile, (RU64)baseAddr, rFileSeek_SET ) )
                    {
                        if( rFile_read( memFile, (RU32)size, *pBuffer ) )
                        {
                            isSuccess = TRUE;
                        }
                    }

                    if( !isSuccess )
                    {
                        if( isBridgeGaps )
                        {
                            isSuccess = TRUE;

                            pPageOffset = baseAddr;
                            pBufferOffset = *pBuffer;
                            while( pPageOffset < ( (RPU8)baseAddr + size ) )
                            {
                                if( rFile_seek( memFile, (RU64)pPageOffset, rFileSeek_SET ) )
                                {
                                    rFile_read( memFile, pageSize, pBufferOffset );
                                }

                                pPageOffset += pageSize;
                                pBufferOffset += pageSize;
                            }
                        }
                    }

                    rFile_close( memFile );
                }
            }
#elif defined( RPAL_PLATFORM_MACOSX )
            kern_return_t kret;
            mach_port_t task;
            unsigned char *rBuffer;
            mach_msg_type_number_t data_cnt;

            kret = task_for_pid( mach_task_self(), processId, &task );
            if ( KERN_SUCCESS == kret )
            {
                kret = mach_vm_read(task, (RU64)baseAddr, size, (vm_offset_t*)&rBuffer, &data_cnt);
                if( KERN_SUCCESS == kret )
                {
                    rpal_memory_memcpy( *pBuffer, rBuffer, size );

                    isSuccess = TRUE;

                    mach_vm_deallocate( task, (mach_vm_address_t)rBuffer, size );
                }

                if( !isSuccess )
                {
                    if( isBridgeGaps )
                    {
                        isSuccess = TRUE;

                        pPageOffset = baseAddr;
                        pBufferOffset = *pBuffer;
                        while( pPageOffset < ( (RPU8)baseAddr + size ) )
                        {
                            kret = mach_vm_read(task, (RU64)pPageOffset, pageSize, (vm_offset_t*)&rBuffer, &data_cnt);

                            pPageOffset += pageSize;
                            pBufferOffset += pageSize;
                        }
                    }
                }
            }
#else
            rpal_debug_not_implemented();
#endif
        }

        if( !isSuccess )
        {
            rpal_memory_free( *pBuffer );
            *pBuffer = NULL;
        }
    }

    return isSuccess;
}

#ifdef RPAL_PLATFORM_WINDOWS
typedef struct
{
    HANDLE _fileHandleToCheck;
    POBJECT_NAME_INFORMATION _fileHandleNameInfo;
    HANDLE hEventDone;
} _fileHandleCheckCtx;

static RU32 RPAL_THREAD_FUNC
    _threadGetWin32HandleName
    (
        _fileHandleCheckCtx* ctx
    )
{
    RU32 size = 0;
    RU32 lastError = 0;
    RPVOID local = NULL;

    while( STATUS_INFO_LENGTH_MISMATCH == ( lastError = queryObj( ctx->_fileHandleToCheck, 
                                                                   ObjectNameInformation, 
                                                                   ctx->_fileHandleNameInfo, 
                                                                   size, 
                                                                   (PULONG)&size ) ) )
    {
        if( NULL == ( ctx->_fileHandleNameInfo = rpal_memory_realloc( ctx->_fileHandleNameInfo, size ) ) )
        {
            break;
        }
    }

    if( NULL != ctx->_fileHandleNameInfo )
    {
        if( STATUS_SUCCESS != lastError ||
            0 == ctx->_fileHandleNameInfo->NameBuffer[ 0 ] ||
            0 == ctx->_fileHandleNameInfo->Name.Length )
        {
            local = ctx->_fileHandleNameInfo;
            ctx->_fileHandleNameInfo = 0;

            rpal_memory_free( local );
        }
    }

    SetEvent( ctx->hEventDone );

    return STATUS_SUCCESS;
}

static POBJECT_NAME_INFORMATION
    getWin32FileInfo
    (
        HANDLE hFile
    )
{
    POBJECT_NAME_INFORMATION info = NULL;
    HANDLE hThread = NULL;
    RBOOL doFreeResources = TRUE;

    _fileHandleCheckCtx ctx = {0};

    ctx._fileHandleToCheck = hFile;
    ctx._fileHandleNameInfo = NULL;
    if( NULL != ( ctx.hEventDone = CreateEvent( NULL, TRUE, FALSE, NULL ) ) )
    {
        if( NULL != ( hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)_threadGetWin32HandleName, &ctx, 0, NULL ) ) )
        {
            if( WAIT_OBJECT_0 == WaitForSingleObject( ctx.hEventDone, 1000 ) )
            {
                info = ctx._fileHandleNameInfo;
                doFreeResources = TRUE;
            }
            else
            {
                // The possibly hanging call takes too long, so we interrupt
                // its execution. We do this by terminating the thread we
                // launched it on. On Windows 7, this works, but it does leak
                // part of the resources the thread allocates itself.
                //
                // 1. Terminate the thread.
                // 2. Wait for it to complete (TerminateThread only
                //    signals termination and returns before the terminated
                //    thread has indeed stopped running).
                // 3. Free the resources of the thread as best as we can.
                //
                rpal_debug_warning( "getHandles - Must terminate helper thread 0x%p.", hThread );
                if( TerminateThread( hThread, STATUS_TIMEOUT ) )
                {
                    // Observation suggests the terminated thread comes back
                    // almost instantly. We still put a long timeout as a
                    // best-effort approach to ensure recuperating resources.
                    // Should that fail, we leave the thread to leak.
                    if( WAIT_OBJECT_0 == WaitForSingleObject( hThread, 60000 ) )
                    {
                        doFreeResources = TRUE;
                    }
                    else
                    {
                        rpal_debug_error( "Leak a thread and an event even after forced termination." );
                        doFreeResources = FALSE;
                    }

                }
                else
                {
                    // Cannot terminate the thread.
                    rpal_debug_warning( "Unable to terminate thread 0x%p -- it leaks.", hThread );
                    doFreeResources = FALSE;
                }
//            	rSequence notif = rSequence_new();
//				doFreeResources = FALSE;
//				if( 
//					notif != NULL &&
//#if defined( RPAL_PLATFORM_32_BIT )
//					rSequence_addPOINTER32( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_HANDLE, (RU32)hThread ) &&
//					//rSequence_addPOINTER32( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_FIBER_PTR, (RU32)ctx._handleCheckFiber ) &&
//					rSequence_addPOINTER32( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_EVENT, (RU32)ctx.hEventDone )
//#else
//					rSequence_addPOINTER64( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_HANDLE, (RU64)hThread ) &&
//					//rSequence_addPOINTER64( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_FIBER_PTR, (RU64)ctx._handleCheckFiber ) &&
//					rSequence_addPOINTER64( notif, RP_TAGS_BLOCKED_WINDOWS_THREAD_EVENT, (RU64)ctx.hEventDone )
//#endif
//					)
//				{
//					notifications_publish( RP_TAGS_NOTIFICATION_BLOCKED_WINDOWS_THREAD, notif );
//				}
            }

            // We close the handle to the thread in all cases: if the thread
            // is still alive, this bears no consequence.
            CloseHandle( hThread );
        }

        if( doFreeResources )
        {
            // The event is freed only if the thread effectively terminated,
            // or did not start in the first place.
            CloseHandle( ctx.hEventDone );
        }
    }

    return info;
}
#endif

rList
    processLib_getHandles
    (
        RU32 processId,
        RBOOL isOnlyReturnNamed,
        RPNCHAR optSubstring
    )
{
    rList handles = NULL;
    rSequence handle = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    RWCHAR api_ntdll[] = _WCH("ntdll.dll");
    RCHAR api_querysysinfo[] = "NtQuerySystemInformation";
    RCHAR api_queryobj[] = "NtQueryObject";
    RCHAR api_queryfile[] = "NtQueryInformationFile";
    RWCHAR strFile[] = _WCH("File");

    HANDLE hSelf = NULL;
    HANDLE hProcess = NULL;
    PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = NULL;
    RU32 size = 0;
    RU32 i = 0;
    HANDLE hDupe = NULL;
    POBJECT_NAME_INFORMATION pObjName = NULL;
    POBJECT_TYPE_INFORMATION pObjType = NULL;
    RU32 lastError = 0;
    RBOOL isBlockable = FALSE;
    RBOOL isFileHackSupported = FALSE;
    RBOOL gotMinInfo = FALSE;
    RU32 tmpSize = 1024;

    if( NULL == querySysInfo )
    {
        // This must be the first call so we will init the import
        querySysInfo = (pfnNtQuerySystemInformation)GetProcAddress( LoadLibraryW( api_ntdll ), api_querysysinfo );
    }

    if( NULL == queryObj )
    {
        // This must be the first call so we will init the import
        queryObj = (pfnNtQueryObject)GetProcAddress( LoadLibraryW( api_ntdll ), api_queryobj );
    }

    if( NULL == queryFile )
    {
        // This must be the first call so we will init the import
        queryFile = (pfnNtQueryInformationFile)GetProcAddress( LoadLibraryW( api_ntdll ), api_queryfile );
    }

    if( OSLIB_VERSION_WINDOWS_2K3 < libOs_getOsVersion() )
    {
        isFileHackSupported = TRUE;
    }

    if( NULL != querySysInfo &&
        NULL != queryObj &&
        NULL != ( hSelf = OpenProcess( PROCESS_DUP_HANDLE, FALSE, GetCurrentProcessId() ) ) )
    {
        if( NULL != ( handles = rList_new( RP_TAGS_HANDLE_INFO, RPCM_SEQUENCE ) ) )
        {
            while( STATUS_INFO_LENGTH_MISMATCH == querySysInfo( SystemHandleInformation, pSysHandleInfo, size, (PULONG)&size ) )
            {
                // On XP the correct size is not actually returned, just 0, so we have to guess and brute force.
                if( 0 == size )
                {
                    size = tmpSize;
                    tmpSize *= 2;
                }

                if( NULL == ( pSysHandleInfo = rpal_memory_realloc( pSysHandleInfo, size ) ) )
                {
                    break;
                }
            }

            if( NULL != pSysHandleInfo )
            {
                for( i = 0; i < pSysHandleInfo->NumberOfHandles; i++ )
                {
                    if( 0 != processId &&
                        pSysHandleInfo->Handles[ i ].UniqueProcessId != processId )
                    {
                        continue;
                    }

                    isBlockable = FALSE;

                    // For now we do this the dumb way, which is to reopen
                    // each process on every handle.
                    if( NULL != ( hProcess = OpenProcess( PROCESS_DUP_HANDLE, 
                                                          FALSE, 
                                                          pSysHandleInfo->Handles[ i ].UniqueProcessId ) ) )
                    {
                        if( DuplicateHandle( hProcess, 
                                             (HANDLE)pSysHandleInfo->Handles[ i ].HandleValue, 
                                             hSelf, 
                                             &hDupe, 
                                             0, 
                                             FALSE, 
                                             DUPLICATE_SAME_ACCESS ) )
                        {
                            if( NULL != ( handle = rSequence_new() ) )
                            {
                                size = 0;
                                pObjType = NULL;
                                gotMinInfo = FALSE;

                                while( STATUS_INFO_LENGTH_MISMATCH == ( lastError = queryObj( hDupe, 
                                                                                              ObjectTypeInformation, 
                                                                                              pObjType, 
                                                                                              size, 
                                                                                              (PULONG)&size ) ) )
                                {
                                    if( NULL == ( pObjType = rpal_memory_realloc( pObjType, size ) ) )
                                    {
                                        break;
                                    }
                                }

                                if( NULL != pObjType )
                                {
                                    rSequence_addSTRINGW( handle, RP_TAGS_HANDLE_TYPE, pObjType->TypeName.Buffer );

                                    if( 0 == rpal_string_strcmp( pObjType->TypeName.Buffer, strFile ) )
                                    {
                                        isBlockable = TRUE;
                                    }

                                    rpal_memory_free( pObjType );
                                }

                                size = 0;
                                pObjName = NULL;
                                if( !isBlockable )
                                {
                                    // The normal supported way
                                    while( STATUS_INFO_LENGTH_MISMATCH == ( lastError = queryObj( hDupe, 
                                                                                                  ObjectNameInformation, 
                                                                                                  pObjName, 
                                                                                                  size, 
                                                                                                  (PULONG)&size ) ) )
                                    {
                                        if( NULL == ( pObjName = rpal_memory_realloc( pObjName, size ) ) )
                                        {
                                            break;
                                        }
                                    }
                                }
                                else if( isFileHackSupported )
                                {
                                    // If the OS supports it, we have a mini hack for handle that could hang
                                    pObjName = getWin32FileInfo( hDupe );
                                }

                                if( NULL != pObjName )
                                {
                                    if( 0 == lastError &&
                                        0 != pObjName->NameBuffer[ 0 ] &&
                                        0 != pObjName->Name.Length )
                                    {
                                        rSequence_addSTRINGW( handle, RP_TAGS_HANDLE_NAME, pObjName->NameBuffer );
                                        gotMinInfo = TRUE;
                                    }
                                }

                                if( ( isOnlyReturnNamed && !gotMinInfo ) || // If only named are requested but we have no name...
                                    ( NULL != optSubstring && ( !gotMinInfo || NULL == rpal_string_strstr( pObjName->NameBuffer, optSubstring ) ) ) ||
                                    // If handles with a name containing a substring was requested and it doesn't fit...
                                    !rSequence_addRU16( handle, RP_TAGS_HANDLE_VALUE, pSysHandleInfo->Handles[ i ].HandleValue ) ||
                                    !rSequence_addRU32( handle, RP_TAGS_PROCESS_ID, pSysHandleInfo->Handles[ i ].UniqueProcessId ) ||
                                    !rList_addSEQUENCE( handles, handle ) )
                                {
                                    rSequence_free( handle );
                                    handle = NULL;
                                }

                                if( NULL != pObjName )
                                {
                                    rpal_memory_free( pObjName );
                                }
                            }

                            CloseHandle( hDupe );
                        }

                        CloseHandle( hProcess );
                    }
                }

                rpal_memory_free( pSysHandleInfo );
            }
        }

        CloseHandle( hSelf );
    }
#elif defined( RPAL_PLATFORM_LINUX )
    rpal_debug_not_implemented();
#endif

    return handles;
}




#ifdef RPAL_PLATFORM_MACOSX
static
void
    iterateJobAttributes
    (
        const launch_data_t data,
        const char* str,
        void* ptr
    )
{
    rSequence svc = (rSequence)ptr;
    RPCHAR attrName = (RPCHAR)str;

    if( NULL != data &&
        NULL != attrName &&
        NULL != svc )
    {
        switch( launch_data_get_type( data ) )
        {
            // For a complet list of attributes :
            // https://developer.apple.com/library/mac/documentation/Darwin/Reference/Manpages/man5/launchd.plist.5.html
            case LAUNCH_DATA_STRING:
                if( 0 == rpal_string_strcmp( attrName, "Program" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_EXECUTABLE, (const RPCHAR)launch_data_get_string( data ) );
                }
                else if( 0 == rpal_string_strcmp( attrName, "Label" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_SVC_NAME, (const RPCHAR)launch_data_get_string( data ) );
                }
                else if( 0 == rpal_string_strcmp( attrName, "ProcessType" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_SVC_TYPE, (const RPCHAR)launch_data_get_string( data ) );
                }
                break;

            case LAUNCH_DATA_ARRAY:
                if( 0 == rpal_string_strcmp( attrName, "ProgramArguments" ) )
                {
                    // Get first argument ( executable path )
                    launch_data_t iterator = launch_data_array_get_index( data, 0 );

                    if( launch_data_get_type( iterator ) == LAUNCH_DATA_STRING )
                    {
                        rSequence_addSTRINGA( svc, RP_TAGS_EXECUTABLE, (const RPCHAR)launch_data_get_string( data ) );
                    }
                }
                break;

            case LAUNCH_DATA_INTEGER:
                if( 0 == rpal_string_strcmp( attrName, "PID" ) )
                {
                    rSequence_addRU64( svc, RP_TAGS_EXECUTABLE, (RU64)launch_data_get_string( data ) );
                }
                break;

            case LAUNCH_DATA_BOOL:
            case LAUNCH_DATA_DICTIONARY:
            case LAUNCH_DATA_FD:
            case LAUNCH_DATA_MACHPORT:
            default:
                // Unused
                break;
        }
    }
}
#endif


#ifdef RPAL_PLATFORM_MACOSX
static
void
    iterateJobs
    (
        const launch_data_t data,
        const char* name,
        void* ptr
    )
{
    rList svcs = (rList)ptr;
    rSequence svc = NULL;

    if( NULL != data &&
        NULL != name )
    {
        if( launch_data_get_type( data ) == LAUNCH_DATA_DICTIONARY &&
            NULL != ( svc = rSequence_new() ) )
        {
            launch_data_dict_iterate( data, iterateJobAttributes, svc );
            if( !rList_addSEQUENCE( svcs, svc ) )
            {
                rSequence_free( svc );
            }
        }
    }
}
#endif


RBOOL 
    processLib_killProcess
    ( 
        RU32 pid 
    )
{
    RBOOL success = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hProc;

    if ( INVALID_HANDLE_VALUE != ( hProc = OpenProcess( PROCESS_TERMINATE, FALSE, pid ) ) )
    {
        success = TerminateProcess( hProc, 0 );

        CloseHandle( hProc );
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    if( 0 != pid )
    {
        if( 0 == kill( pid, SIGKILL ) )
        {
            success = TRUE;
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return success;
}


RU32
    processLib_getCurrentPid
    (

    )
{
    RU32 pid = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    pid = GetCurrentProcessId();
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    pid = getpid();
#else
    rpal_debug_not_implemented();
#endif

    return pid;
}

rList
    processLib_getProcessEnvironment_from
    (
        RU32 pid,
        RU32 from
    )
{
    rList vars = NULL;
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_LINUX
    RCHAR filePathTemplate[] = "//proc//%d//environ";
    RCHAR filePath[ RPAL_MAX_PATH ] = {0};
    RU32  fileSize = 0;
    RPU8  fileContent = NULL;
    RU32  contentSize = 0;
    RU32  contentIt = 0;

    RPCHAR curEnvVar = NULL;

    RU32 patternCount = 0;
    RPCHAR c = 0;
    RPWCHAR tmpVar = NULL;
#elif defined( RPAL_PLATFORM_WINDOWS )
    RWCHAR api_ntdll[] = _WCH("ntdll.dll");
    RCHAR api_queryproc[] = "NtQueryInformationProcess";
    
    PEB peb = {0};
    PROCESS_BASIC_INFORMATION pbi = {0};
    RTL_USER_PROCESS_PARAMETERS block = {0};
    HANDLE hProcess = NULL;
    SIZE_T dwSize = 0;
    RBOOL isPbiAcquired = FALSE;
    RBOOL isPebAcquired = FALSE;
    RBOOL isUserProcessParamsAcquired = FALSE;
    RBOOL isEnvBlockAcquired = FALSE;
    MEMORY_BASIC_INFORMATION memBasicInfo = {0};
    RU32 retryCountDown = 0;
    RU32 lastError = 0;
    RPU8 envSlab = NULL;
    RPWCHAR tmpVar = NULL;
#endif

    if( NULL != ( vars = rList_new_from( RP_TAGS_ENVIRONMENT_VARIABLE, RPCM_STRINGN, from ) ) )
    {
#ifdef RPAL_PLATFORM_LINUX
        fileSize = rpal_string_snprintf( (RPCHAR)&filePath, sizeof( filePath ), (RPCHAR)&filePathTemplate, pid );         
        if( fileSize > 0 && fileSize < sizeof( filePath ) )
        {
            fileSize = rpal_file_getSize( filePath, TRUE );
            if( (RU32)(-1) != fileSize )
            {
                if ( rpal_file_read( (RPCHAR)&filePath, &fileContent, &contentSize, TRUE ) )
                {
                    isSuccess = TRUE;

                    // Make sure we're NULL-terminated in all cases
                    fileContent[ contentSize - 1 ] = 0;

                    // Iterate the env variables
                    curEnvVar = (RPCHAR)fileContent;
                    while( contentIt < contentSize )
                    {
                        // Security check to validate that we are between bounds
                        // and that we are reading a string
                        while( fileContent[ contentIt ] != '\0' )
                        {
                            contentIt++;
                            if( contentIt >= contentSize )
                            {
                                curEnvVar = NULL;
                                break;
                            }
                        }
                        contentIt++;

                        if( NULL != curEnvVar )
                        {
                            rList_addSTRINGA( vars, curEnvVar );

                            curEnvVar = (RPCHAR)fileContent + contentIt;
                        }
                    }

                    rpal_memory_free( fileContent );
                    curEnvVar = NULL;
                }
            }
        }
#elif defined( RPAL_PLATFORM_WINDOWS )
    

    if( NULL == queryInfo )
    {
        // This must be the first call so we will init the import
        queryInfo = (pfnNtQueryInformationProcess)GetProcAddress( LoadLibraryW( api_ntdll ), api_queryproc );
    }

    if( NULL != queryInfo )
    {
        pbi.PebBaseAddress = (PPEB)0x7ffdf000;
        pbi.UniqueProcessId = pid;

        hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );

        if( NULL != hProcess )
        {
            retryCountDown = 5;
            while( 0 != retryCountDown )
            {
                isPbiAcquired = FALSE;
                isPebAcquired = FALSE;

                // We prefer to introspect the process ourselves
                if( STATUS_SUCCESS == queryInfo( hProcess, 
                                                 ProcessBasicInformation, 
                                                 &pbi, 
                                                 sizeof( PROCESS_BASIC_INFORMATION ), 
                                                 (PULONG)&dwSize ) )
                {   
                    isPbiAcquired = TRUE;
                }
                else
                {
                    lastError = GetLastError();
                    rpal_debug_warning( "error querying process basic information: %d", lastError );
                }

                if( isPbiAcquired )
                {
                    if( ReadProcessMemory( hProcess, (LPCVOID)pbi.PebBaseAddress, &peb, sizeof( PEB ), &dwSize ) )
                    {
                        isPebAcquired = TRUE;
                        break;
                    }
                    else
                    {
                        lastError = GetLastError();
                        rpal_debug_warning( "error reading PEB: %d", lastError );
                    }
                }

                retryCountDown--;
                rpal_thread_sleep( 1 );
            }

            if( isPebAcquired )
            {
                retryCountDown = 5;
                while( 0 != retryCountDown )
                {
                    isUserProcessParamsAcquired = FALSE;

                    if( ReadProcessMemory( hProcess, peb.ProcessParameters, &block, sizeof( RTL_USER_PROCESS_PARAMETERS ), &dwSize ) )
                    {
                        isUserProcessParamsAcquired = TRUE;
                    }
                    else
                    {
                        lastError = GetLastError();
                        rpal_debug_warning( "error reading process parameters block: %d", lastError );
                    }

                    if( isUserProcessParamsAcquired )
                    {
                        isEnvBlockAcquired = FALSE;

                        if( 0 != VirtualQueryEx( hProcess, block.Environment, &memBasicInfo, sizeof( memBasicInfo ) ) )
                        {
                            if( NULL != ( envSlab = rpal_memory_alloc( memBasicInfo.RegionSize + ( 2 * sizeof( RWCHAR ) ) ) ) )
                            {
                                if( ReadProcessMemory( hProcess, 
                                                       block.Environment, 
                                                       envSlab, 
                                                       memBasicInfo.RegionSize - (RSIZET)( (RPU8)block.Environment - (RPU8)memBasicInfo.BaseAddress ), 
                                                       &dwSize ) )
                                {
                                    isEnvBlockAcquired = TRUE;

                                    // Cap the block for safey
                                    rpal_memory_zero( envSlab + memBasicInfo.RegionSize, 2 * sizeof( RWCHAR ) );

                                    tmpVar = (RPWCHAR)envSlab;

                                    while( (RPU8)tmpVar < ( envSlab + memBasicInfo.RegionSize ) )
                                    {
                                        if( 0 != *tmpVar )
                                        {
                                            // Start of a valid string
                                            rList_addSTRINGW( vars, tmpVar );
                                            tmpVar += rpal_string_strlen( tmpVar );
                                        }
                                        else if( 0 == *( tmpVar + 1 ) )
                                        {
                                            // Two null-chars indicates end of environment
                                            break;
                                        }
                                        else
                                        {
                                            // Single null indicates end of current var
                                            tmpVar++;
                                        }
                                    }

                                    isSuccess = TRUE;
                                }

                                rpal_memory_free( envSlab );
                            }
                        }
                    }

                    if( isEnvBlockAcquired )
                    {
                        break;
                    }

                    retryCountDown--;
                    rpal_thread_sleep( 1 );
                    rpal_debug_warning( "missing process information, retrying..." );
                }
            }

            CloseHandle( hProcess );
        }
        else
        {
            lastError = GetLastError();
            rpal_debug_warning( "could not open process for introspection: %d", lastError );
        }
    }
#else
    rpal_debug_not_implemented();
#endif

        if( !isSuccess )
        {
            rList_free( vars );
            vars = NULL;
        }
    }

    return vars;
}

// NOT THREAD SAFE because of the Sym functions.
// BE VERY CARFUL REQUESTING SYMBOLS WITH TRACE
// AS THERE ARE SOME MEMORY LEAKS IN THE MS CODE
rList
    processLib_getStackTrace
    (
        RU32 pid,
        RU32 tid,
        RBOOL isWithSymbolNames
    )
{
    rList frames = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    __declspec( align( 16 ) ) CONTEXT context = {0};
    STACKFRAME64* pStacks = NULL;
    STACKFRAME64 lastStack = { 0 };
    RU32 nPreAllocFrames = 10;
    RBOOL isSnapshotDone = FALSE;
    RU32 nFrames = 0;
    PIMAGEHLP_SYMBOL64 pSymbol = NULL;
    RU32 symbolSize = sizeof( IMAGEHLP_SYMBOL64 ) + ( RPAL_MAX_PATH * sizeof( TCHAR ) );

    RWCHAR importLib[] = { _NC( "DbgHelp.dll" ) };
    RCHAR import1[] = { "SymInitialize" };
    RCHAR import2[] = { "StackWalk64" };
    RCHAR import3[] = { "SymGetSymFromAddr64" };
    RCHAR import4[] = { "SymFunctionTableAccess64" };
    RCHAR import5[] = { "SymGetModuleBase64" };
    RCHAR import6[] = { "UnDecorateSymbolName" };
    RCHAR import7[] = { "SymSetOptions" };
    RCHAR import8[] = { "SymCleanup" };

    HINSTANCE hDbgHelp = NULL;
    StackWalk64_f fpStackWalk64 = NULL;
    SymGetSymFromAddr64_f fpSymGetSymFromAddr64 = NULL;
    SymInitialize_f fpSymInitialize = NULL;
    UndecorateSymbolName_f fpUndecorateSymbolName = NULL;
    SymFunctionTableAccess64_f fpSymFunctionTableAccess64 = NULL;
    SymGetModuleBase64_f fpSymGetModuleBase64 = NULL;
    SymSetOptions_f fpSymSetOptions = NULL;
    SymCleanup_f fpSymCleanup = NULL;

    RU32 fr = 0;
    RU64 displacement = 0;
    rSequence frame = NULL;
    RCHAR symbolName[ 0x100 ] = {0};

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
    hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, tid );
    
    if ( NULL != hProcess &&
         NULL != hThread &&
         ( NULL != ( hDbgHelp = GetModuleHandleW( importLib ) ) ||
           NULL != ( hDbgHelp = LoadLibraryW( importLib ) ) ) &&
         ( NULL != ( fpSymInitialize = (SymInitialize_f)GetProcAddress( hDbgHelp, import1 ) ) ) &&
         ( NULL != ( fpStackWalk64 = (StackWalk64_f)GetProcAddress( hDbgHelp, import2 ) ) ) &&
         ( NULL != ( fpSymGetSymFromAddr64 = (SymGetSymFromAddr64_f)GetProcAddress( hDbgHelp, import3 ) ) ) &&
         ( NULL != ( fpSymFunctionTableAccess64 = (SymFunctionTableAccess64_f)GetProcAddress( hDbgHelp, import4 ) ) ) &&
         ( NULL != ( fpSymGetModuleBase64 = (SymGetModuleBase64_f)GetProcAddress( hDbgHelp, import5 ) ) ) &&
         ( NULL != ( fpUndecorateSymbolName = (UndecorateSymbolName_f)GetProcAddress( hDbgHelp, import6 ) ) ) &&
         ( NULL != ( fpSymSetOptions = (SymSetOptions_f)GetProcAddress( hDbgHelp, import7 ) ) ) &&
         ( NULL != ( fpSymCleanup = (SymCleanup_f)GetProcAddress( hDbgHelp, import8 ) ) ) )
    {
        rpal_memory_zero( &context, sizeof( context ) );
        context.ContextFlags = CONTEXT_FULL;

        fpSymInitialize( hProcess, NULL, TRUE );
        fpSymSetOptions( SYMOPT_DEFERRED_LOADS |
                         SYMOPT_FAIL_CRITICAL_ERRORS |
                         SYMOPT_NO_PROMPTS );

        if( NULL != ( pStacks = rpal_memory_alloc( sizeof( *pStacks ) * nPreAllocFrames ) ) &&
            SuspendThread( hThread ) >= 0 )
        {
            if( GetThreadContext( hThread, &context ) )
            {
#ifndef RPAL_PLATFORM_WINDOWS_64
                lastStack.AddrPC.Offset = context.Eip;
                lastStack.AddrPC.Mode = AddrModeFlat;
                lastStack.AddrStack.Offset = context.Esp;
                lastStack.AddrStack.Mode = AddrModeFlat;
                lastStack.AddrFrame.Offset = context.Ebp;
                lastStack.AddrFrame.Mode = AddrModeFlat;
#else
                lastStack.AddrPC.Offset = context.Rip;
                lastStack.AddrPC.Mode = AddrModeFlat;
                lastStack.AddrStack.Offset = context.Rsp;
                lastStack.AddrStack.Mode = AddrModeFlat;
                lastStack.AddrFrame.Offset = context.Rbp;
                lastStack.AddrFrame.Mode = AddrModeFlat;
#endif

                isSnapshotDone = TRUE;

                for( fr = 0;; fr++ )
                {
                    if( nPreAllocFrames >= ( fr + 1 ) ||
                        NULL != ( pStacks = rpal_memory_reAlloc( pStacks, sizeof( *pStacks ) * ( fr + 1 ) ) ) )
                    {
#ifndef RPAL_PLATFORM_WINDOWS_64

                        if( !fpStackWalk64( IMAGE_FILE_MACHINE_I386,
                                            hProcess,
                                            hThread,
                                            &lastStack,
                                            &context,
                                            NULL,
                                            isWithSymbolNames ? fpSymFunctionTableAccess64 : NULL,
                                            isWithSymbolNames ? fpSymGetModuleBase64 : NULL,
                                            NULL ) )
                        {
                            break;
                        }
#else

                        if( !fpStackWalk64( IMAGE_FILE_MACHINE_AMD64,
                                            hProcess,
                                            hThread,
                                            &lastStack,
                                            &context,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL ) )
                        {
                            break;
                        }
#endif
                        if( 0 == lastStack.AddrPC.Offset )
                        {
                            break;
                        }

                        pStacks[ fr ] = lastStack;
                    }
                }

                nFrames = fr;
            }
            else
            {
                rpal_debug_warning( "Unable to get context of thread %u of process %u -- last error %u.", tid, pid, GetLastError() );
            }

            ResumeThread( hThread );
        }
        else
        {
            rpal_debug_warning( "Unable to suspend thread %u of process %u -- last error %u.", tid, pid, GetLastError() );
        }

        if( isSnapshotDone )
        {
            if( NULL != ( pSymbol = (PIMAGEHLP_SYMBOL64)rpal_memory_alloc( symbolSize ) ) )
            {
                if( NULL != ( frames = rList_new( RP_TAGS_STACK_TRACE_FRAME, RPCM_SEQUENCE ) ) )
                {
                    for( fr = 0; fr < nFrames; fr++ )
                    {
                        if( NULL == ( frame = rSequence_new() ) )
                        {
                            break;
                        }

                        if( isWithSymbolNames )
                        {
                            rpal_memory_zero( pSymbol, symbolSize );
                            pSymbol->SizeOfStruct = symbolSize;
                            pSymbol->MaxNameLength = RPAL_MAX_PATH;

                            if( fpSymGetSymFromAddr64( hProcess,
                                                       (ULONG64)pStacks[ fr ].AddrPC.Offset,
                                                       &displacement,
                                                       pSymbol ) )
                            {
                                if( 0 < fpUndecorateSymbolName( pSymbol->Name,
                                                                (PSTR)symbolName,
                                                                sizeof( symbolName ),
                                                                UNDNAME_COMPLETE ) )
                                {
                                    rSequence_addSTRINGA( frame, 
                                                          RP_TAGS_STACK_TRACE_FRAME_SYM_NAME, 
                                                          symbolName );
                                }
                                else
                                {
                                    rSequence_addSTRINGA( frame, 
                                                          RP_TAGS_STACK_TRACE_FRAME_SYM_NAME, 
                                                          pSymbol->Name );
                                }
                            }
                        }

                        rSequence_addRU64( frame, 
                                           RP_TAGS_STACK_TRACE_FRAME_PC, 
                                           (ULONG64)pStacks[ fr ].AddrPC.Offset );
                        rSequence_addRU64( frame, 
                                           RP_TAGS_STACK_TRACE_FRAME_SP, 
                                           (ULONG64)pStacks[ fr ].AddrStack.Offset );
                        rSequence_addRU64( frame, 
                                           RP_TAGS_STACK_TRACE_FRAME_FP, 
                                           (ULONG64)pStacks[ fr ].AddrFrame.Offset );

                        if( !rList_addSEQUENCE( frames, frame ) )
                        {
                            rSequence_free( frame );
                        }
                    }
                }

                rpal_memory_free( pSymbol );
            }
        }

        fpSymCleanup( hProcess );
    }

    if( NULL != pStacks )
    {
        rpal_memory_free( pStacks );
    }

    if( NULL != hThread )
    {
        CloseHandle( hThread );
    }

    if( NULL != hProcess )
    {
        CloseHandle( hProcess );
    }
#else
    rpal_debug_not_implemented();
#endif

    return frames;
}

// NOT THREAD SAFE because of the Sym functions.
// BE VERY CARFUL REQUESTING SYMBOLS WITH TRACE
// AS THERE ARE SOME MEMORY LEAKS IN THE MS CODE
RVOID
    processLib_decorateStackTrace
    (
        RU32 pid,
        rList stackTrace
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    RU64 displacement = 0;
    rSequence frame = NULL;
    RCHAR symbolName[ 0x100 ] = { 0 };
    RU64 offset = 0;
    PIMAGEHLP_SYMBOL64 pSymbol = NULL;
    RU32 symbolSize = sizeof( IMAGEHLP_SYMBOL64 ) + ( RPAL_MAX_PATH * sizeof( TCHAR ) );
    HANDLE hProcess = 0;

    RCHAR importLib[] = { "DbgHelp.dll" };
    RCHAR import1[] = { "SymInitialize" };
    RCHAR import2[] = { "StackWalk64" };
    RCHAR import3[] = { "SymGetSymFromAddr64" };
    RCHAR import4[] = { "SymFunctionTableAccess64" };
    RCHAR import5[] = { "SymGetModuleBase64" };
    RCHAR import6[] = { "UnDecorateSymbolName" };
    RCHAR import7[] = { "SymCleanup" };

    HINSTANCE hDbgHelp = NULL;
    StackWalk64_f fpStackWalk64 = NULL;
    SymGetSymFromAddr64_f fpSymGetSymFromAddr64 = NULL;
    SymInitialize_f fpSymInitialize = NULL;
    UndecorateSymbolName_f fpUndecorateSymbolName = NULL;
    SymFunctionTableAccess64_f fpSymFunctionTableAccess64 = NULL;
    SymGetModuleBase64_f fpSymGetModuleBase64 = NULL;
    SymCleanup_f fpSymCleanup = NULL;

    if( rpal_memory_isValid( stackTrace ) )
    {
        if( ( NULL != ( hDbgHelp = GetModuleHandleA( importLib ) ) ||
              NULL != ( hDbgHelp = LoadLibraryA( importLib ) ) ) &&
            ( NULL != ( fpSymInitialize = (SymInitialize_f)GetProcAddress( hDbgHelp, import1 ) ) ) &&
            ( NULL != ( fpStackWalk64 = (StackWalk64_f)GetProcAddress( hDbgHelp, import2 ) ) ) &&
            ( NULL != ( fpSymGetSymFromAddr64 = (SymGetSymFromAddr64_f)GetProcAddress( hDbgHelp, import3 ) ) ) &&
            ( NULL != ( fpSymFunctionTableAccess64 = (SymFunctionTableAccess64_f)GetProcAddress( hDbgHelp, import4 ) ) ) &&
            ( NULL != ( fpSymGetModuleBase64 = (SymGetModuleBase64_f)GetProcAddress( hDbgHelp, import5 ) ) ) &&
            ( NULL != ( fpUndecorateSymbolName = (UndecorateSymbolName_f)GetProcAddress( hDbgHelp, import6 ) ) ) &&
            ( NULL != ( fpSymCleanup = (SymCleanup_f)GetProcAddress( hDbgHelp, import7 ) ) ) )
        {
            if( NULL != ( hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid ) ) )
            {
                fpSymInitialize( hProcess, NULL, TRUE );

                if( NULL != ( pSymbol = (PIMAGEHLP_SYMBOL64)rpal_memory_alloc( symbolSize ) ) )
                {
                    while( rList_getSEQUENCE( stackTrace, RP_TAGS_STACK_TRACE_FRAME, &frame ) )
                    {
                        if( rSequence_getRU64( frame, RP_TAGS_STACK_TRACE_FRAME_PC, &offset ) )
                        {
                            rpal_memory_zero( pSymbol, symbolSize );
                            pSymbol->SizeOfStruct = symbolSize;
                            pSymbol->MaxNameLength = RPAL_MAX_PATH;

                            if( fpSymGetSymFromAddr64( hProcess,
                                                       (ULONG64)offset,
                                                       &displacement,
                                                       pSymbol ) )
                            {
                                if( 0 < fpUndecorateSymbolName( pSymbol->Name,
                                                                (PSTR)symbolName,
                                                                sizeof( symbolName ),
                                                                UNDNAME_COMPLETE ) )
                                {
                                    rpal_debug_info( "FOUND %s", symbolName );
                                    rSequence_addSTRINGA( frame,
                                                          RP_TAGS_STACK_TRACE_FRAME_SYM_NAME,
                                                          symbolName );
                                }
                                else
                                {
                                    rpal_debug_info( "FOUND %s", symbolName );
                                    rSequence_addSTRINGA( frame,
                                                          RP_TAGS_STACK_TRACE_FRAME_SYM_NAME,
                                                          pSymbol->Name );
                                }
                            }
                        }
                    }

                    rpal_memory_free( pSymbol );
                }

                fpSymCleanup( hProcess );
                CloseHandle( hProcess );
            }
        }
    }
#endif
}

rList
    processLib_getThreads
    (
        RU32 pid
    )
{
    rList threads = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hProcSnap = NULL;
    THREADENTRY32 threadInfo = {0};

    if( NULL != ( threads = rList_new( RP_TAGS_THREAD_ID, RPCM_RU32 ) ) )
    {
        if( INVALID_HANDLE_VALUE != ( hProcSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) ) )
        {
            threadInfo.dwSize = sizeof( threadInfo );

            if( Thread32First( hProcSnap, &threadInfo ) )
            {
                do
                {
                    if( threadInfo.th32OwnerProcessID == pid )
                    {
                        rList_addRU32( threads, threadInfo.th32ThreadID );
                    }
                }
                while( Thread32Next( hProcSnap, &threadInfo ) );
            }

            CloseHandle( hProcSnap );
        }
        else
        {
            rList_free( threads );
            threads = NULL;
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return threads;
}

RU32
    processLib_getCurrentThreadId
    (

    )
{
    RU32 threadId = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    threadId = GetCurrentThreadId();
#else
    rpal_debug_not_implemented();
#endif

    return threadId;
}


RBOOL
    processLib_suspendProcess
    (
        RU32 pid
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    rList threads = NULL;
    RU32 tid = 0;
    RU32 lastSuspended = 0;

    if( NULL != ( threads = processLib_getThreads( pid ) ) )
    {
        isSuccess = TRUE;

        while( rList_getRU32( threads, RP_TAGS_THREAD_ID, &tid ) )
        {
            if( !processLib_suspendThread( pid, tid ) )
            {
                isSuccess = FALSE;
            }

            lastSuspended = tid;
        }

        if( !isSuccess )
        {
            rList_resetIterator( threads );

            while( rList_getRU32( threads, RP_TAGS_THREAD_ID, &tid ) )
            {
                processLib_resumeThread( pid, tid );

                if( tid == lastSuspended )
                {
                    break;
                }
            }
        }

        rList_free( threads );
    }
#else
    if( 0 == kill( pid, SIGSTOP ) )
    {
        isSuccess = TRUE;
    }
#endif

    return isSuccess;
}

RBOOL
    processLib_suspendThread
    (
        RU32 pid,
        rThreadID tid
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hThread = NULL;
    UNREFERENCED_PARAMETER( pid );

    if( NULL != ( hThread = OpenThread( THREAD_SUSPEND_RESUME, FALSE, tid ) ) )
    {
        if( ( -1 ) != SuspendThread( hThread ) )
        {
            isSuccess = TRUE;
        }

        CloseHandle( hThread );
    }
#else
    UNREFERENCED_PARAMETER( pid );
    UNREFERENCED_PARAMETER( tid );
    rpal_debug_not_implemented();
#endif

    return isSuccess;
}

RBOOL
    processLib_resumeProcess
    (
        RU32 pid
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    rList threads = NULL;
    RU32 tid = 0;

    if( NULL != ( threads = processLib_getThreads( pid ) ) )
    {
        isSuccess = TRUE;

        while( rList_getRU32( threads, RP_TAGS_THREAD_ID, &tid ) )
        {
            if( !processLib_resumeThread( pid, tid ) )
            {
                isSuccess = FALSE;
            }
        }

        rList_free( threads );
    }
#else
    if( 0 == kill( pid, SIGCONT ) )
    {
        isSuccess = TRUE;
    }
#endif

    return isSuccess;
}

RBOOL
    processLib_resumeThread
    (
        RU32 pid,
        rThreadID tid
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hThread = NULL;
    UNREFERENCED_PARAMETER( pid );

    if( NULL != ( hThread = OpenThread( THREAD_SUSPEND_RESUME, FALSE, tid ) ) )
    {
        if( ( -1 ) != ResumeThread( hThread ) )
        {
            isSuccess = TRUE;
        }

        CloseHandle( hThread );
    }
#else
    UNREFERENCED_PARAMETER( pid );
    UNREFERENCED_PARAMETER( tid );
#endif

    return isSuccess;
}