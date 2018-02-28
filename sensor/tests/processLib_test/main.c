#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <Basic.h>


#ifdef RPAL_PLATFORM_WINDOWS
static RBOOL 
    SetPrivilege
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

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
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


static RBOOL
    Get_Privilege
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
            if( SetPrivilege( hToken, privName, TRUE ) )
            {
                isSuccess = TRUE;
            }
            
            CloseHandle( hToken );
        }
    }

    return isSuccess;
}
#endif

void 
    test_memoryLeaks
    (
        void
    )
{
    RU32 memUsed = 0;

    rpal_Context_cleanup();

    memUsed = rpal_memory_totalUsed();

    CU_ASSERT_EQUAL( memUsed, 0 );

    if( 0 != memUsed )
    {
        rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
        printf( "\nMemory leak: %d bytes.\n", memUsed );

        rpal_memory_findMemory();
    }
}

void 
    test_procEntries
    (
        void
    )
{
    processLibProcEntry* entries = NULL;
    RU32 entryIndex = 0;
    RU32 nEntries = 0;

    entries = processLib_getProcessEntries( TRUE );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( entries, NULL );

    while( 0 != entries[ entryIndex ].pid )
    {
        nEntries++;

        entryIndex++;
    }

    CU_ASSERT_TRUE( 5 < nEntries );

    rpal_memory_free( entries );
	
	entries = processLib_getProcessEntries( FALSE );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( entries, NULL );

    while( 0 != entries[ entryIndex ].pid )
    {
        nEntries++;

        entryIndex++;
    }

    CU_ASSERT_TRUE( 5 < nEntries );

    rpal_memory_free( entries );
}

void 
    test_processInfo
    (
        void
    )
{
    RU32 tmpPid = 0;
    rSequence proc = NULL;
    RPNCHAR path = NULL;
    RU64 mem = 0;
    
    tmpPid = processLib_getCurrentPid();
    CU_ASSERT_NOT_EQUAL_FATAL( tmpPid, 0 );

    proc = processLib_getProcessInfo( tmpPid, NULL );

    CU_ASSERT_PTR_NOT_EQUAL( proc, NULL );

    CU_ASSERT_TRUE( rSequence_getSTRINGN( proc, RP_TAGS_FILE_PATH, &path ) );

#ifdef RPAL_PLATFORM_LINUX
    // Only Linux can report UID info from processLib.
    {
        RU32 uid = 0;
        RPCHAR userName = NULL;

        CU_ASSERT_TRUE( rSequence_getRU32( proc, RP_TAGS_USER_ID, &uid ) );
        CU_ASSERT_TRUE( rSequence_getSTRINGA( proc, RP_TAGS_USER_NAME, &userName ) );
    }
#endif

    CU_ASSERT_PTR_NOT_EQUAL( path, NULL );
    CU_ASSERT_NOT_EQUAL( rpal_string_strlen( path ), 0 );

    CU_ASSERT_TRUE( rSequence_getRU64( proc, RP_TAGS_MEMORY_USAGE, &mem ) );
    rpal_debug_print( "current process mem: " RF_U64, mem );
    CU_ASSERT_NOT_EQUAL( mem, 0 );

    rSequence_free( proc );
}

void 
    test_modules
    (
        void
    )
{
    RU32 tmpPid = 0;
    rList mods = NULL;
    rSequence mod = NULL;
    RPNCHAR path = NULL;

    tmpPid = processLib_getCurrentPid();
    CU_ASSERT_NOT_EQUAL_FATAL( tmpPid, 0 );

    mods = processLib_getProcessModules( tmpPid );

    CU_ASSERT_PTR_NOT_EQUAL( mods, NULL );

    CU_ASSERT_TRUE( rList_getSEQUENCE( mods, RP_TAGS_DLL, &mod ) );

    CU_ASSERT_TRUE( rSequence_getSTRINGN( mod, RP_TAGS_FILE_PATH, &path ) );

    CU_ASSERT_PTR_NOT_EQUAL( path, NULL );
    CU_ASSERT_NOT_EQUAL( rpal_string_strlen( path ), 0 );

    rSequence_free( mods );
}

void 
    test_memmap
    (
        void
    )
{
    RU32 tmpPid = 0;
    rList regions = NULL;
    rSequence region = NULL;
    RU32 nRegions = 0;
    
    RU8 type = 0;
    RU8 protect = 0;
    RU64 ptr = 0;
    RU64 size = 0;

    tmpPid = processLib_getCurrentPid();
    CU_ASSERT_NOT_EQUAL_FATAL( tmpPid, 0 );

    regions = processLib_getProcessMemoryMap( tmpPid );

    CU_ASSERT_PTR_NOT_EQUAL( regions, NULL );

    while( rList_getSEQUENCE( regions, RP_TAGS_MEMORY_REGION, &region ) )
    {
        CU_ASSERT_TRUE( rSequence_getRU8( region, RP_TAGS_MEMORY_TYPE, &type ) );
        CU_ASSERT_TRUE( rSequence_getRU8( region, RP_TAGS_MEMORY_ACCESS, &protect ) );
        CU_ASSERT_TRUE( rSequence_getPOINTER64( region, RP_TAGS_BASE_ADDRESS, &ptr ) );
        CU_ASSERT_TRUE( rSequence_getRU64( region, RP_TAGS_MEMORY_SIZE, &size ) );
        nRegions++;
    }

    CU_ASSERT_TRUE( 2 < nRegions ); 

    rSequence_free( regions );
}

void
    test_currentModule
    (
        void
    )
{
    RPNCHAR path = NULL;
    
    path = processLib_getCurrentModulePath();
    CU_ASSERT_NOT_EQUAL( path, NULL );
    CU_ASSERT_NOT_EQUAL( rpal_string_strstr( path, _NC( "processLib_test" ) ), NULL );

    rpal_memory_free( path );
}

void 
    test_handles
    (
        void
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    rList handles = NULL;
    rSequence handle = NULL;
    RU32 nHandles = 0;
    RU32 nNamedHandles = 0;
    RPNCHAR handleName = NULL;
    processLibProcEntry* tmpProcesses = NULL;
    RU32 i = 0;

    // Look for a process to analyze.
    if( NULL != ( tmpProcesses = processLib_getProcessEntries( FALSE ) ) )
    {
        while( 0 != tmpProcesses[ i ].pid )
        {
            nHandles = 0;
            nNamedHandles = 0;

            if( NULL != ( handles = processLib_getHandles( tmpProcesses[ i ].pid, FALSE, NULL ) ) )
            {
                while( rList_getSEQUENCE( handles, RP_TAGS_HANDLE_INFO, &handle ) )
                {
                    nHandles++;
                }

                rList_free( handles );
            }

            if( 0 != nHandles )
            {
                if( NULL != ( handles = processLib_getHandles( tmpProcesses[ i ].pid, TRUE, NULL ) ) )
                {
                    while( rList_getSEQUENCE( handles, RP_TAGS_HANDLE_INFO, &handle ) )
                    {
                        nNamedHandles++;

                        CU_ASSERT_TRUE( rSequence_getSTRINGN( handle, RP_TAGS_HANDLE_NAME, &handleName ) );
                        CU_ASSERT_TRUE( 0 != rpal_string_strlen( handleName ) );
                    }

                    rList_free( handles );
                }

                CU_ASSERT_TRUE( 10 < nHandles );
                CU_ASSERT_TRUE( nNamedHandles < nHandles );
                break;
            }

            i++;
        }

        rpal_memory_free( tmpProcesses );
    }

    CU_ASSERT_TRUE( 0 != nHandles );
    CU_ASSERT_TRUE( 0 != nNamedHandles );
#else
    CU_ASSERT_EQUAL( processLib_getHandles( 0, FALSE, NULL ), NULL );
#endif
}

int
    main
    (
        int argc,
        char* argv[]
    )
{
    int ret = -1;

    CU_pSuite suite = NULL;
    CU_ErrorCode error = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    RCHAR strSeDebug[] = "SeDebugPrivilege";
    Get_Privilege( strSeDebug );
#endif
    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    if( rpal_initialize( NULL, 1 ) )
    {
        if( CUE_SUCCESS == ( error = CU_initialize_registry() ) )
        {
            if( NULL != ( suite = CU_add_suite( "processLib", NULL, NULL ) ) )
            {
                if( NULL == CU_add_test( suite, "procEntries", test_procEntries ) ||
                    NULL == CU_add_test( suite, "processInfo", test_processInfo ) ||
                    NULL == CU_add_test( suite, "modules", test_modules ) ||
                    NULL == CU_add_test( suite, "memmap", test_memmap ) ||
                    NULL == CU_add_test( suite, "currentModule", test_currentModule ) ||
                    NULL == CU_add_test( suite, "handles", test_handles ) ||
                    NULL == CU_add_test( suite, "memoryLeaks", test_memoryLeaks ) )
                {
                    rpal_debug_error( "%s", CU_get_error_msg() );
                }
                else
                {
                    CU_basic_run_tests();
                    ret = CU_get_number_of_failures();
                }
            }

            CU_cleanup_registry();
        }
        else
        {
            rpal_debug_error( "could not init cunit: %d", error );
        }

        rpal_Context_deinitialize();
    }
    else
    {
        printf( "error initializing rpal" );
    }

    return ret;
}

