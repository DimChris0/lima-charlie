#include <rpal/rpal.h>
#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <cryptoLib/cryptoLib.h>
#include <Basic.h>

#define RPAL_FILE_ID      86

#ifdef RPAL_PLATFORM_WINDOWS
// Some private definitions for libOS RPRIVATE_TESTABLE functions we want to test.
RPRIVATE_TESTABLE
RBOOL
    _processRegValue
    (
        DWORD type,
        RPWCHAR path,
        RPWCHAR keyName,
        RPU8 value,
        DWORD size,
        rList listEntries
    );
#endif


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

void test_init( void )
{
    CU_ASSERT_TRUE( CryptoLib_init() );
}

void test_deinit( void )
{
    CryptoLib_deinit();
}

void test_memoryLeaks( void )
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
	parseSignature
	( 
	    rSequence signature  
	)
{
	RPNCHAR strBuffer = NULL;
	RPNCHAR wStrBuffer = NULL;
	RU32   signatureStatus = 0;
	RU32   byteBufferSize = 0;
	RU8*   byteBuffer = NULL;

	CU_ASSERT_TRUE( rSequence_getSTRINGN( signature, RP_TAGS_FILE_PATH, &wStrBuffer ) );
	CU_ASSERT_TRUE( rSequence_getRU32( signature, RP_TAGS_CERT_CHAIN_STATUS, &signatureStatus ) );
	if( rSequence_getSTRINGN( signature, RP_TAGS_CERT_ISSUER, &strBuffer ) )
	{
		CU_ASSERT_TRUE( 0 < rpal_string_strsize( strBuffer ) );
	}
		
	if( rSequence_getSTRINGN( signature, RP_TAGS_CERT_SUBJECT, &strBuffer ) )
	{
		CU_ASSERT_TRUE( 0 < rpal_string_strsize( strBuffer ) );
	}
	
	if( rSequence_getBUFFER( signature, RP_TAGS_CERT_BUFFER, &byteBuffer, &byteBufferSize ) )
	{
		CU_ASSERT_TRUE( 0 < byteBufferSize );
		CU_ASSERT_PTR_NOT_EQUAL_FATAL( byteBuffer, NULL );
	}
}


void
	test_signCheck
	(
	    void
	)
{
#ifdef RPAL_PLATFORM_WINDOWS
    rList filePaths = NULL;
	RPWCHAR filePath = NULL;
	rSequence fileSignature = NULL;
	RU32 operationFlags = OSLIB_SIGNCHECK_NO_NETWORK | OSLIB_SIGNCHECK_CHAIN_VERIFICATION | OSLIB_SIGNCHECK_INCLUDE_RAW_CERT;
	RBOOL isSigned = FALSE;
	RBOOL isVerified_local = FALSE;
	RBOOL isVerified_global = FALSE;

	filePaths = rList_new( RP_TAGS_FILE_PATH, RPCM_STRINGW );
	CU_ASSERT_PTR_NOT_EQUAL_FATAL( filePaths, NULL );

	// Windows signed file
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\Taskmgr.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\Program Files\\Internet Explorer\\iexplore.exe" ) );

	// Catalogs files
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\explorer.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\calc.exe" ) );
	rList_addSTRINGW( filePaths, _WCH( "C:\\WINDOWS\\system32\\cmd.exe" ) );

    while( rList_getSTRINGW( filePaths, RP_TAGS_FILE_PATH, &filePath ) )
	{
		if( libOs_getSignature( filePath, &fileSignature, operationFlags, &isSigned, &isVerified_local, &isVerified_global ) )
		{
			CU_ASSERT_PTR_NOT_EQUAL_FATAL( fileSignature, NULL );

			if ( isSigned )
			{
				parseSignature( fileSignature );
			}

			rSequence_free( fileSignature );
			fileSignature = NULL;
		}
	}
    rList_free( filePaths );
#endif
}


void
    test_services
    (
        void
    )
{
    rList svcs = NULL;
    rSequence svc = NULL;
    RPNCHAR svcName = NULL;

    svcs = libOs_getServices( TRUE );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( svcs, NULL );

    CU_ASSERT_TRUE( rList_getSEQUENCE( svcs, RP_TAGS_SVC, &svc ) );

    CU_ASSERT_TRUE( rSequence_getSTRINGN( svc, RP_TAGS_SVC_NAME, &svcName ) );

    CU_ASSERT_PTR_NOT_EQUAL( svcName, NULL );

    CU_ASSERT_NOT_EQUAL( rpal_string_strlen( svcName ), 0 );

    rSequence_free( svcs );
}

void
    test_autoruns
    (
        void
    )
{
    rList autoruns = NULL;

    autoruns = libOs_getAutoruns( TRUE );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( autoruns, NULL );

    // For now no validation since it will have to be very platform specific.
    // Just make sure it runs ok on the platform as a base case.
#if defined( RPAL_PLATFORM_WINDOWS ) || defined( RPAL_PLATFORM_MACOSX )
    CU_ASSERT_NOT_EQUAL( rList_getNumElements( autoruns ), 0 );
#endif

    rSequence_free( autoruns );
}

void
    test_registry
    (
        void
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    struct
    {
        DWORD type;
        RPWCHAR path;
        RPWCHAR keyName;
        RPWCHAR value;
        DWORD size;
        RBOOL isSuccess;
        RU32 nResults;
    } regTests[] = {
        { 0, NULL, NULL, NULL, 0, FALSE, 0 },
        { REG_SZ, _WCH( "dummy1" ), 
          _WCH( "dummy2" ), 
          (RPWCHAR)" \0\0", 
          1, 
          TRUE, 
          1 },
        { REG_SZ, 
          _WCH( "dummy1" ), 
          _WCH( "dummy2" ),
          _WCH( "dummyVal\0" ), 
          sizeof( _WCH( "dummyVal" ) ), 
          TRUE, 
          1 },
        { REG_SZ, 
          _WCH( "dummy1" ), 
          _WCH( "dummy2" ), 
          _WCH( "dummyVal,another,finally\0" ), 
          sizeof( _WCH( "dummyVal,another,finally" ) ), 
          TRUE, 
          3 },
        { REG_SZ, 
          _WCH( "dummy1" ), 
          _WCH( "dummy2" ), 
          _WCH( "dum\0myVal\0" ), 
          sizeof( _WCH( "dum\0myVal" ) ), 
          TRUE, 
          1 },
        { REG_MULTI_SZ, 
          _WCH( "dummy1" ), 
          _WCH( "dummy2" ), 
          _WCH( "dummyVal\0another\x00yup\0finally\0\0\0" ), 
          sizeof( _WCH( "dummyVal\0another\0yup\0finally\0\0" ) ), 
          TRUE, 
          4 },
    };
    rList autoruns = NULL;
    RU32 i = 0;
    RBOOL isTmpSuccess = FALSE;
    RU32 nTmpResults = 0;

    RPU8 garbage = NULL;
    RU32 garbageMaxSize = 100;
    RU32 garbageSize = 0;
    RU32 garbageLoops = 100;
    
    for( i = 0; i < ARRAY_N_ELEM( regTests ); i++ )
    {
        autoruns = rList_new( 1, RPCM_SEQUENCE );
        CU_ASSERT_NOT_EQUAL_FATAL( autoruns, NULL );

        isTmpSuccess = _processRegValue( regTests[ i ].type, 
                                         regTests[ i ].path, 
                                         regTests[ i ].keyName, 
                                         (RPU8)regTests[ i ].value, 
                                         regTests[ i ].size, 
                                         autoruns );
        CU_ASSERT_EQUAL( isTmpSuccess, regTests[ i ].isSuccess );
        nTmpResults = rList_getNumElements( autoruns );
        CU_ASSERT_EQUAL( nTmpResults, regTests[ i ].nResults );

        rSequence_free( autoruns );
    }

    // Fuzz
    for( garbageLoops = garbageLoops; 0 != garbageLoops; garbageLoops-- )
    {
        autoruns = rList_new( 1, RPCM_SEQUENCE );
        CU_ASSERT_NOT_EQUAL_FATAL( autoruns, NULL );

        garbageSize = ( rpal_rand() % garbageMaxSize ) + 128;
        garbage = rpal_memory_alloc( garbageSize );
        CU_ASSERT_NOT_EQUAL_FATAL( garbage, NULL );
        CU_ASSERT_TRUE( CryptoLib_genRandomBytes( garbage, garbageSize ) );

        // At this point we're just doing a bit of fuzzing looking for any crash.
        _processRegValue( REG_SZ, _WCH( "DUMMY" ), _WCH( "DUMMY2" ), garbage, garbageSize - ( sizeof( RWCHAR ) * 2 ), autoruns );

        rpal_memory_free( garbage );
        rSequence_free( autoruns );
    }
#endif
}

void
    test_version
    (
        void
    )
{
    rSequence info = NULL;
    RPCHAR stringA = NULL;
    RU32 num32 = 0;
    RBOOL isOneFound = FALSE;

    info = libOs_getOsVersionEx();
    CU_ASSERT_NOT_EQUAL_FATAL( info, NULL );

    if( rSequence_getRU32( info, RP_TAGS_VERSION_MAJOR, &num32 ) )
    {
        isOneFound = TRUE;
        rpal_debug_info( "MAJOR NUM32: %d", num32 );
    }

    if( rSequence_getRU32( info, RP_TAGS_VERSION_MINOR, &num32 ) )
    {
        isOneFound = TRUE;
        rpal_debug_info( "MINOR NUM32: %d", num32 );
    }

    if( rSequence_getSTRINGA( info, RP_TAGS_VERSION_MAJOR, &stringA ) )
    {
        isOneFound = TRUE;
        rpal_debug_info( "MAJOR STR: %s", stringA );
    }

    if( rSequence_getSTRINGA( info, RP_TAGS_VERSION_MINOR, &stringA ) )
    {
        isOneFound = TRUE;
        rpal_debug_info( "MINOR STR: %s", stringA );
    }

    CU_ASSERT_TRUE( isOneFound );

    rSequence_free( info );
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
            if( NULL != ( suite = CU_add_suite( "libOs", NULL, NULL ) ) )
            {
                if( NULL == CU_add_test( suite, "initialize", test_init ) ||
                    NULL == CU_add_test( suite, "signCheck", test_signCheck ) ||
                    NULL == CU_add_test( suite, "services", test_services ) ||
                    NULL == CU_add_test( suite, "autoruns", test_autoruns ) ||
                    NULL == CU_add_test( suite, "registry", test_registry ) ||
                    NULL == CU_add_test( suite, "version", test_version ) ||
                    NULL == CU_add_test( suite, "deinitialize", test_deinit ) ||
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

