#define RPAL_FILE_ID 9999

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <processLib/processLib.h>

#pragma warning( push )
#pragma warning(disable:4201)
#pragma warning(disable:4324)
#include <yara.h>
#pragma warning( pop )

#ifdef RPAL_PLATFORM_LINUX
#include <signal.h>
#endif

/*
 * Simple Yara scanner proof of concept. Scans files and UserMode memory
 * related to currently running processes and modules.
 */

rEvent g_timeToQuit = NULL;

typedef struct
{
    RU32 pid;
    RU64 regionBase;
    RU64 regionSize;
    RPCHAR path;
} YaraMatchContext;

typedef struct
{
    RU64 base;
    RU64 size;
} _MemRange;

typedef struct
{
    RU32 nFiles;
    RU64 nFileBytes;
    RU64 nMemBytes;
} ScanStats;

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

        rpal_debug_info( "terminating." );
        rEvent_set( g_timeToQuit );

        isHandled = TRUE;
    }

    return isHandled;
}


static 
RBOOL 
    SetPrivilege
    (
        HANDLE hToken, 
        RPNCHAR lpszPrivilege, 
        BOOL bEnablePrivilege
    )
{
    LUID luid;
    RBOOL bRet = FALSE;

    if( LookupPrivilegeValueW( NULL, lpszPrivilege, &luid ) )
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

static
RBOOL
    Get_Privilege
    (
        RPNCHAR privName
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
            if( SetPrivilege( hToken, privName, TRUE ) )
            {
                isSuccess = TRUE;
            }

            CloseHandle( hToken );
        }
    }

    return isSuccess;
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
        rpal_debug_info( "terminating." );
        rEvent_set( g_timeToQuit );
    }
}
#endif

RVOID
    printUsage
    (

    )
{
    printf( "Usage: -f compiledYaraRules [ -d ] [ -m ]\n" );
    printf( "\t compiledYaraRules: the rules, in a compiled (yarac) form to scan for\n" );
    printf( "-m: scan memory\n" );
    printf( "-d: scan disk\n" );
}

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
    RU32 toRead = (RU32)( count * size );

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
    RU32 toWrite = (RU32)( count * size );

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

    if( CALLBACK_MSG_RULE_MATCHING == message &&
        NULL != message_data &&
        NULL != user_data )
    {
        printf( "MATCH: " RF_STR_A " @ " RF_U32 " base " RF_PTR " size " RF_X32 "\n", 
                (char*)rule->identifier, 
                context->pid, 
                NUMBER_TO_PTR( context->regionBase ), 
                (RU32)context->regionSize );
    }

    return CALLBACK_CONTINUE;
}

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

    if( CALLBACK_MSG_RULE_MATCHING == message &&
        NULL != message_data &&
        NULL != user_data )
    {
        printf( "MATCH: " RF_STR_A " @ " RF_STR_A "\n",
                (char*)rule->identifier,
                context->path );
    }

    return CALLBACK_CONTINUE;
}

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

RVOID
    scanFile
    (
        ScanStats* stats,
        RPNCHAR path,
        rBloom fileCache,
        YR_RULES* rules
    )
{
    RU32 scanError = 0;
    RU32 size = 0;
    YaraMatchContext matchContext = { 0 };

#ifdef RNATIVE_IS_WIDE
    matchContext.path = rpal_string_wtoa( path );
#else
    matchContext.path = rpal_string_strdup( path );
#endif
    
    if( rpal_bloom_addIfNew( fileCache, matchContext.path, rpal_string_strlenA( matchContext.path ) ) )
    {
        size = rpal_file_getSizeA( matchContext.path, FALSE );

        if( 0 != size && ( 1024 * 1024 * 50 ) >= size )
        {
            if( ERROR_SUCCESS != ( scanError = yr_rules_scan_file( rules,
                                                                   matchContext.path,
                                                                   SCAN_FLAGS_FAST_MODE,
                                                                   _yaraFileMatchCallback,
                                                                   &matchContext, 60 ) ) )
            {
                rpal_debug_warning( "Error while scanning file " RF_STR_A ": " RF_X32, matchContext.path, scanError );
            }

            stats->nFiles++;
            stats->nFileBytes += size;
        }
        else
        {
            rpal_debug_warning( "Not scanning file " RF_STR_A ", too big or zero: " RF_U32, matchContext.path, size );
        }
    }

    rpal_memory_free( matchContext.path );
}

RVOID
    scanMem
    (
        ScanStats* stats,
        RU32 pid,
        RPVOID base,
        RU64 size,
        YR_RULES* rules
    )
{
    RPU8 buffer = NULL;
    RU32 scanError = 0;
    YaraMatchContext matchContext = { 0 };

    if( processLib_getProcessMemory( pid, base, size, (RPVOID*)&buffer, TRUE ) )
    {
        matchContext.pid = pid;
        matchContext.regionBase = PTR_TO_INT64( base );
        matchContext.regionSize = size;
        if( ERROR_SUCCESS != ( scanError = yr_rules_scan_mem( rules,
                                                              buffer,
                                                              (size_t)size,
                                                              SCAN_FLAGS_FAST_MODE |
                                                              SCAN_FLAGS_PROCESS_MEMORY,
                                                              _yaraMemMatchCallback,
                                                              &matchContext, 60 ) ) )
        {
            rpal_debug_warning( "Error while scanning mem: " RF_X32, scanError );
        }

        stats->nMemBytes += size;

        rpal_memory_free( buffer );
    }
    else
    {
        rpal_debug_warning( "Failed to get memory range " RF_U32 " - " RF_PTR " : " RF_X64 " (" RF_U32 ").", pid, base, size, rpal_error_getLast() );
    }
}

RVOID
    scanProcess
    (
        ScanStats* stats,
        RU32 pid,
        YR_RULES* rules,
        rBloom fileCache,
        RBOOL isWithDisk,
        RBOOL isWithMem
    )
{
    rSequence processInfo = NULL;
    RPNCHAR path = NULL;
    rList modules = NULL;
    rSequence moduleInfo = NULL;
    RPNCHAR modulePath = NULL;
    rList memoryMap = NULL;
    rSequence memoryInfo = NULL;
    RPVOID memBase = NULL;
    RU64 memSize = 0;
    RU8 memAccess = 0;

    if( isWithDisk &&
        NULL != ( processInfo = processLib_getProcessInfo( pid, NULL ) ) )
    {
        if( rSequence_getSTRINGN( processInfo, RP_TAGS_FILE_PATH, &path ) )
        {
            scanFile( stats, path, fileCache, rules );
        }
        else
        {
            rpal_debug_warning( "Failed to get process path." );
        }

        rSequence_free( processInfo );
    }
    else if( isWithDisk )
    {
        rpal_debug_warning( "Failed to get process info: " RF_X32 ".", rpal_error_getLast() );
    }

    if( isWithDisk &&
        NULL != ( modules = processLib_getProcessModules( pid ) ) )
    {
        while( rList_getSEQUENCE( modules, RP_TAGS_DLL, &moduleInfo ) )
        {
            if( rSequence_getSTRINGN( moduleInfo, RP_TAGS_FILE_PATH, &modulePath ) )
            {
                scanFile( stats, modulePath, fileCache, rules );
            }
            else
            {
                rpal_debug_warning( "Could not get module path." );
            }
        }

        rList_free( modules );
    }
    else if( isWithDisk )
    {
        rpal_debug_warning( "Could not get process modules: " RF_X32 ".", rpal_error_getLast() );
    }

    if( isWithMem &&
        NULL != ( memoryMap = processLib_getProcessMemoryMap( pid ) ) )
    {
        while( rList_getSEQUENCE( memoryMap, RP_TAGS_MEMORY_REGION, &memoryInfo ) )
        {
            if( rSequence_getPOINTER64( memoryInfo, RP_TAGS_BASE_ADDRESS, (RU64*)&memBase ) &&
                rSequence_getRU64( memoryInfo, RP_TAGS_MEMORY_SIZE, &memSize ) &&
                rSequence_getRU8( memoryInfo, RP_TAGS_MEMORY_ACCESS, &memAccess ) &&
                PROCESSLIB_MEM_ACCESS_NO_ACCESS != memAccess &&
                PROCESSLIB_MEM_ACCESS_DENIED != memAccess )
            {
                scanMem( stats, pid, memBase, memSize, rules );
            }
            else
            {
                isWithDisk = isWithDisk;
            }
        }

        rList_free( memoryMap );
    }
    else if( isWithMem )
    {
        rpal_debug_warning( "Could not get memory map: " RF_X32 ".", rpal_error_getLast() );
    }
}

RPAL_NATIVE_MAIN
{
    RU32 memUsed = 0;
    RNCHAR argFlag = 0;
    RPNCHAR argVal = NULL;

    rpal_opt switches[] = { { _NC( 'f' ), _NC( "yaracfile" ), TRUE },
                            { _NC( 'm' ), _NC( "memory" ), FALSE },
                            { _NC( 'd' ), _NC( "disk" ), FALSE } };

    // Execution Environment
    RPNCHAR compiledYaraFile = NULL;
    RBOOL isScanMemory = FALSE;
    RBOOL isScanDisk = FALSE;
    RPU8 ruleFile = NULL;
    RU32 ruleFileSize = 0;
    YR_RULES* rules = NULL;

    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    RU32 thisProcessId = 0;
    rBloom fileCache = NULL;
    ScanStats stats = { 0 };

    RTIME startTime = 0;

    rpal_debug_info( "initializing..." );
    if( rpal_initialize( NULL, 0 ) )
    {
        // Initialize boilerplate runtime.
#ifdef RPAL_PLATFORM_WINDOWS
        RNCHAR strSeDebug[] = _NC( "SeDebugPrivilege" );
        if( !Get_Privilege( strSeDebug ) )
        {
            rpal_debug_error( "could not get debug privilege, are we running as admin?" );
            return -1;
        }
#endif

        startTime = rpal_time_getLocal();

        if( 0 != yr_initialize() )
        {
            rpal_debug_error( "Failed to init Yara." );
            return -1;
        }

        if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
        {
            rpal_debug_critical( "Failed to create timeToQuit event." );
            return -1;
        }

        if( NULL == ( fileCache = rpal_bloom_create( 10000, 0.000001 ) ) )
        {
            rpal_debug_critical( "Failed to create file chache." );
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

        // Parse arguments on the type of simulation requested.
        while( (RNCHAR)(-1) != ( argFlag = rpal_getopt( argc, argv, switches, &argVal ) ) )
        {
            switch( argFlag )
            {
                case _NC( 'f' ):
                    compiledYaraFile = argVal;
                    break;
                case _NC( 'm' ):
                    isScanMemory = TRUE;
                    break;
                case _NC( 'd' ):
                    isScanDisk = TRUE;
                    break;
                default:
                    printUsage();
                    return -1;
            }
        }

        if( NULL == compiledYaraFile )
        {
            printUsage();
            return -1;
        }

        rpal_debug_info( "Loading yarac file." );
        if( !rpal_file_read( compiledYaraFile, &ruleFile, &ruleFileSize, FALSE ) )
        {
            rpal_debug_info( "Error loading rule file." );
            return -1;
        }

        rpal_debug_info( "loading yarac rules" );
        if( NULL == ( rules = loadYaraRules( ruleFile, ruleFileSize ) ) )
        {
            rpal_debug_error( "Error loading rules." );
            return -1;
        }

        rpal_memory_free( ruleFile );

        rpal_debug_info( "Listing processes." );
        if( NULL == ( processes = processLib_getProcessEntries( FALSE ) ) )
        {
            rpal_debug_error( "Could not get process list." );
        }

        rpal_debug_info( "Starting scan." );
        thisProcessId = processLib_getCurrentPid();
        curProc = processes;
        for( curProc = processes; 0 != curProc->pid; curProc++ )
        {
            if( thisProcessId == curProc->pid ) continue;
            if( rEvent_wait( g_timeToQuit, 0 ) ) break;
            rpal_debug_info( "Scanning process id " RF_U32, curProc->pid );
            scanProcess( &stats, curProc->pid, rules, fileCache, isScanDisk, isScanMemory );
        }

        rpal_memory_free( processes );

        yr_rules_destroy( rules );

        yr_finalize();
        
        //rEvent_wait( g_timeToQuit, RINFINITE );
        rEvent_free( g_timeToQuit );

        rpal_bloom_destroy( fileCache );

        printf( "Finished scan in " RF_U32 " seconds: " RF_U32 " files, " RF_U64 " bytes from files, " RF_U64 " memory bytes scanned.\n", 
                (RU32)( rpal_time_getLocal() - startTime ),
                stats.nFiles, stats.nFileBytes, stats.nMemBytes );

        rpal_debug_info( "...exiting..." );
        rpal_Context_cleanup();

#ifdef RPAL_PLATFORM_DEBUG
        memUsed = rpal_memory_totalUsed();
        if( 0 != memUsed )
        {
            rpal_debug_critical( "Memory leak: " RF_U32 " bytes.\n", memUsed );
            rpal_memory_findMemory();
        }
#else
        UNREFERENCED_PARAMETER( memUsed );
#endif
        
        rpal_Context_deinitialize();
    }
    else
    {
        rpal_debug_error( "error initializing rpal." );
    }

    return 0;
}
