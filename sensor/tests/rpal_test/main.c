#include <rpal/rpal.h>
#include <Basic.h>

#define RPAL_FILE_ID   96
#define _TEST_MAJOR_1   6

void test_memoryLeaks(void)
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

void test_strings(void)
{
    RNCHAR tmpString[] = _NC( "C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE" );
    CU_ASSERT_EQUAL( rpal_string_strlen( tmpString ), ARRAY_N_ELEM( tmpString ) - 1 );
}

void test_events(void)
{
    rEvent evt = NULL;
    evt = rEvent_create( TRUE );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( evt, NULL );

    CU_ASSERT_FALSE( rEvent_wait( evt, 0 ) );
    CU_ASSERT_TRUE( rEvent_set( evt ) );
    // Manual reset so it should still be up
    CU_ASSERT_TRUE( rEvent_wait( evt, 0 ) );
    CU_ASSERT_TRUE( rEvent_wait( evt, 0 ) );
    CU_ASSERT_TRUE( rEvent_unset( evt ) );
    CU_ASSERT_FALSE( rEvent_wait( evt, 0 ) );

    rEvent_free( evt );
    
    evt = rEvent_create( FALSE );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( evt, NULL );
    
    CU_ASSERT_FALSE( rEvent_wait( evt, 0 ) );
    CU_ASSERT_TRUE( rEvent_set( evt ) );
    // Auto reset so it should still be down
    CU_ASSERT_TRUE( rEvent_wait( evt, 0 ) );
    CU_ASSERT_FALSE( rEvent_wait( evt, 0 ) );
    
    CU_ASSERT_TRUE( rEvent_set( evt ) );
    CU_ASSERT_TRUE( rEvent_unset( evt ) );
    CU_ASSERT_FALSE( rEvent_wait( evt, 0 ) );
    
    rEvent_free( evt );
}

void test_handleManager(void)
{
    RU32 dummy1 = 42;
    RU32* test = NULL;
    rHandle hDummy1 = RPAL_HANDLE_INIT;
    RBOOL isDestroyed = FALSE;
    
    hDummy1 = rpal_handleManager_create( _TEST_MAJOR_1, (RU32)RPAL_HANDLE_INVALID, &dummy1, NULL );

    CU_ASSERT_NOT_EQUAL_FATAL( hDummy1.h, RPAL_HANDLE_INVALID );

    CU_ASSERT_TRUE_FATAL( rpal_handleManager_open( hDummy1, (RPVOID*)&test ) );

    CU_ASSERT_EQUAL( *test, dummy1 );

    CU_ASSERT_TRUE( rpal_handleManager_close( hDummy1, &isDestroyed ) );
    CU_ASSERT_FALSE_FATAL( isDestroyed );
    CU_ASSERT_TRUE( rpal_handleManager_close( hDummy1, &isDestroyed ) );
    CU_ASSERT_TRUE_FATAL( isDestroyed );
    
}

void test_blob(void)
{
    rBlob blob = NULL;
    RU8 refBuff[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    RU8 trimBuff1[] = { 0x01, 0x02, 0x07 };
    RU8 trimBuff2[] = { 0x02, 0x07 };
    RU8 trimBuff3[] = { 0x02 };
    RPU8 tmpBuff = NULL;

    blob = rpal_blob_create( 0, 10 );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( blob, NULL );

    CU_ASSERT_TRUE( rpal_blob_add( blob, refBuff, sizeof( refBuff ) ) );

    tmpBuff = rpal_blob_getBuffer( blob );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( tmpBuff, NULL );

    CU_ASSERT_EQUAL( rpal_memory_memcmp( tmpBuff, rpal_blob_getBuffer( blob ), sizeof( refBuff ) ), 0 );

    CU_ASSERT_TRUE( rpal_blob_remove( blob, 2, 4 ) );
    CU_ASSERT_EQUAL( rpal_memory_memcmp( trimBuff1, rpal_blob_getBuffer( blob ), sizeof( trimBuff1 ) ), 0 );

    CU_ASSERT_TRUE( rpal_blob_remove( blob, 0, 1 ) );
    CU_ASSERT_EQUAL( rpal_memory_memcmp( trimBuff2, rpal_blob_getBuffer( blob ), sizeof( trimBuff2 ) ), 0 );

    CU_ASSERT_TRUE( rpal_blob_remove( blob, 1, 1 ) );
    CU_ASSERT_EQUAL( rpal_memory_memcmp( trimBuff3, rpal_blob_getBuffer( blob ), sizeof( trimBuff3 ) ), 0 );

    CU_ASSERT_FALSE( rpal_blob_remove( blob, 2, 2 ) );

    rpal_blob_free( blob );
}

RBOOL
    _dummyStackFree
    (
        RPU32 pRu32
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pRu32 )
    {
        *pRu32 = 0;
        isSuccess = TRUE;
    }

    return isSuccess;
}

void test_stack(void)
{
    rStack stack = NULL;
    RU32 val1 = 1;
    RU32 val2 = 42;
    RU32 val3 = 666;
    RU32 val4 = 70000;
    RU32 test = 0;

    stack = rStack_new( sizeof( RU32 ) );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( stack, NULL );


    CU_ASSERT_TRUE( rStack_push( stack, &val1 ) );
    CU_ASSERT_TRUE( rStack_push( stack, &val2 ) );
    CU_ASSERT_TRUE( rStack_push( stack, &val3 ) );

    CU_ASSERT_FALSE( rStack_isEmpty( stack ) );

    CU_ASSERT_TRUE( rStack_pop( stack, &test ) );
    CU_ASSERT_EQUAL( test, val3 );

    CU_ASSERT_TRUE( rStack_push( stack, &val4 ) );

    CU_ASSERT_TRUE( rStack_pop( stack, &test ) );
    CU_ASSERT_EQUAL( test, val4 );
    CU_ASSERT_TRUE( rStack_pop( stack, &test ) );
    CU_ASSERT_EQUAL( test, val2 );
    CU_ASSERT_TRUE( rStack_pop( stack, &test ) );
    CU_ASSERT_EQUAL( test, val1 );

    CU_ASSERT_FALSE( rStack_pop( stack, &test ) );
    CU_ASSERT_TRUE( rStack_isEmpty( stack ) );

    CU_ASSERT_TRUE( rStack_free( stack, (rStack_freeFunc)_dummyStackFree ) );
}

void test_queue(void)
{
    rQueue q = NULL;

    RU32 i1 = 1;
    RU32 i2 = 2;
    RU32 i3 = 3;
    RU32 i4 = 4;
    RU32 i5 = 5;

    RU32* pI = 0;
    RU32 iSize = 0;

    CU_ASSERT_TRUE( rQueue_create( &q, NULL, 3 ) );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( q, NULL );

    CU_ASSERT_TRUE( rQueue_add( q, &i1, sizeof( i1 ) ) );
    CU_ASSERT_TRUE( rQueue_add( q, &i2, sizeof( i2 ) ) );
    CU_ASSERT_TRUE( rQueue_add( q, &i3, sizeof( i3 ) ) );
    CU_ASSERT_FALSE( rQueue_addEx( q, &i4, sizeof( i4 ), FALSE ) );
    CU_ASSERT_TRUE( rQueue_add( q, &i5, sizeof( i5 ) ) );

    CU_ASSERT_TRUE( rQueue_remove( q, (RPVOID*)&pI, &iSize, (10*1000) ) );
    CU_ASSERT_EQUAL( *pI, i2 );
    CU_ASSERT_EQUAL( iSize, sizeof( RU32 ) );

    CU_ASSERT_TRUE( rQueue_remove( q, (RPVOID*)&pI, &iSize, (10*1000) ) );
    CU_ASSERT_EQUAL( *pI, i3 );
    CU_ASSERT_EQUAL( iSize, sizeof( RU32 ) );

    CU_ASSERT_TRUE( rQueue_remove( q, (RPVOID*)&pI, &iSize, (10*1000) ) );
    CU_ASSERT_EQUAL( *pI, i5 );
    CU_ASSERT_EQUAL( iSize, sizeof( RU32 ) );

    CU_ASSERT_TRUE( rQueue_isEmpty( q ) );
    CU_ASSERT_FALSE( rQueue_isFull( q ) );

    CU_ASSERT_FALSE( rQueue_remove( q, (RPVOID*)&pI, &iSize, 10 ) );

    rQueue_free( q );
}

void test_circularbuffer(void)
{
    rCircularBuffer cb = NULL;

    RU32 i1 = 1;
    RU32 i2 = 2;
    RU32 i3 = 3;
    RU32 i4 = 4;
    RU32 i5 = 5;

    cb = rpal_circularbuffer_new( 3, sizeof( RU32 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( cb, NULL );

    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_last( cb ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 0 ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 2 ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 3 ), NULL );

    CU_ASSERT_TRUE( rpal_circularbuffer_add( cb, &i1 ) );

    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 0 ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 1 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_last( cb ), NULL );

    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 0 ), 1 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_last( cb ), 1 );

    CU_ASSERT_TRUE( rpal_circularbuffer_add( cb, &i2 ) );

    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 0 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 1 ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 2 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_last( cb ), NULL );

    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 0 ), 1 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 1 ), 2 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_last( cb ), 2 );

    CU_ASSERT_TRUE( rpal_circularbuffer_add( cb, &i3 ) );
    CU_ASSERT_TRUE( rpal_circularbuffer_add( cb, &i4 ) );
    CU_ASSERT_TRUE( rpal_circularbuffer_add( cb, &i5 ) );

    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 0 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 1 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_get( cb, 2 ), NULL );
    CU_ASSERT_PTR_EQUAL( rpal_circularbuffer_get( cb, 3 ), NULL );
    CU_ASSERT_PTR_NOT_EQUAL( rpal_circularbuffer_last( cb ), NULL );

    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 0 ), 4 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 1 ), 5 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_get( cb, 2 ), 3 );
    CU_ASSERT_EQUAL( *(RU32*)rpal_circularbuffer_last( cb ), 5 );

    rpal_circularbuffer_free( cb );
}

void test_strtok(void)
{
    RNCHAR testStr[] = { _NC( "/this/is/a/test/path" ) };
    RNCHAR token = _NC( '/' );
    RPNCHAR state = NULL;
    RPNCHAR tmp = NULL;

    tmp = rpal_string_strtok( testStr, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "" ) ), 0 );

    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "this" ) ), 0 );
    
    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "is" ) ), 0 );
    
    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "a" ) ), 0 );
    
    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "test" ) ), 0 );
    
    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_NOT_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( tmp, _NC( "path" ) ), 0 );

    
    tmp = rpal_string_strtok( NULL, token, &state );
    CU_ASSERT_PTR_EQUAL( tmp, NULL );

    CU_ASSERT_EQUAL( rpal_string_strcmp( testStr, _NC("/this/is/a/test/path") ), 0 );
}

void test_strmatch(void)
{
    RPNCHAR pattern1 = _NC("this?complex*pattern?");
    RPNCHAR pattern2 = _NC( "this?complex*pattern+" );
    RPNCHAR pattern3 = _NC( "this?complex+pattern*" );
    RPNCHAR pattern4 = _NC( "this\\?escaped\\pattern" );

    RPNCHAR test1 = _NC( "thiscomplexpattern" );
    RPNCHAR test2 = _NC( "this1complex1234pattern" );
    RPNCHAR test3 = _NC( "this2complex123456pattern1" );
    RPNCHAR test4 = _NC( "this2complex123456pattern123" );
    RPNCHAR test5 = _NC( "this1complexpattern" );

    RPNCHAR test6 = _NC( "this?escaped\\pattern" );
    RPNCHAR test7 = _NC( "this1escapedpattern" );

    CU_ASSERT_FALSE( rpal_string_match( pattern1, test1, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern1, test2, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern1, test3, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern1, test4, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern1, test5, TRUE ) );

    CU_ASSERT_FALSE( rpal_string_match( pattern2, test1, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern2, test2, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern2, test3, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern2, test4, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern2, test5, TRUE ) );

    CU_ASSERT_FALSE( rpal_string_match( pattern3, test1, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern3, test2, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern3, test3, TRUE ) );
    CU_ASSERT_TRUE( rpal_string_match( pattern3, test4, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern3, test5, TRUE ) );

    CU_ASSERT_TRUE( rpal_string_match( pattern4, test6, TRUE ) );
    CU_ASSERT_FALSE( rpal_string_match( pattern4, test7, TRUE ) );
}

void test_dir(void)
{
    rDir hDir = NULL;
    rFileInfo info = {0};

    CU_ASSERT_TRUE( rDir_open( _NC( "./" ), &hDir ) );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( hDir, NULL );

    while( rDir_next( hDir, &info ) )
    {
        CU_ASSERT_NOT_EQUAL( info.filePath[ 0 ], 0 );
        CU_ASSERT_PTR_NOT_EQUAL( info.fileName, NULL );
        if( !IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) )
        {
            CU_ASSERT_NOT_EQUAL( info.size, 0 );
        }
    }
    
    rDir_close( hDir );
}

void test_crawler(void)
{
    rDirCrawl hCrawl = NULL;
    rFileInfo info = {0};
#ifdef RPAL_PLATFORM_WINDOWS
    RPWCHAR fileArr[] = { _WCH("*.dll"), _WCH("*.exe"), NULL };
    hCrawl = rpal_file_crawlStart( _WCH("C:\\test\\"), fileArr, 2 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPNCHAR fileArr[] = { _NC("*.pub"), _NC("*.txt"), NULL };
    hCrawl = rpal_file_crawlStart( _NC("/home/server/"), fileArr, 2 );
#endif
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( hCrawl, NULL );
    
    while( rpal_file_crawlNextFile( hCrawl, &info ) )
    {
        rpal_debug_info( "FILE" );
        printf( RF_STR_A "\n", info.filePath );
    }
    
    rpal_file_crawlStop( hCrawl );
}


void test_file(void)
{
    rFile hFile = NULL;
    rFileInfo fileInfo = { 0 };
    RWCHAR testBuff[] = _WCH("testing...");
    RWCHAR outBuff[ ARRAY_N_ELEM( testBuff ) ] = {0};
    RPNCHAR testDir = _NC( "./tmp_test_dir" );
    RPNCHAR testFile = _NC( "./tmp_test_dir/testFile.dat" );

    CU_ASSERT_TRUE( rDir_create( testDir ) );
    CU_ASSERT_TRUE( rpal_file_getInfo( testDir, &fileInfo ) );
    CU_ASSERT_TRUE( IS_FLAG_ENABLED( fileInfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) );

    CU_ASSERT_TRUE_FATAL( rFile_open( testFile, &hFile, RPAL_FILE_OPEN_ALWAYS | RPAL_FILE_OPEN_WRITE ) );
    CU_ASSERT_TRUE( rFile_write( hFile, sizeof( testBuff ), &testBuff ) );
    rFile_close( hFile );

    CU_ASSERT_TRUE( rpal_file_getInfo( testFile, &fileInfo ) );
    CU_ASSERT_TRUE( !IS_FLAG_ENABLED( fileInfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) );

    CU_ASSERT_TRUE_FATAL( rFile_open( testFile, &hFile, RPAL_FILE_OPEN_EXISTING | RPAL_FILE_OPEN_READ ) );
    CU_ASSERT_TRUE( rFile_read( hFile, sizeof( outBuff ), &outBuff ) );
    rFile_close( hFile );
    CU_ASSERT_EQUAL( rpal_memory_memcmp( testBuff, outBuff, sizeof( testBuff ) ), 0 );

    CU_ASSERT_TRUE( rpal_file_delete( testFile, FALSE ) );
    CU_ASSERT_FALSE( rpal_file_getInfo( testFile, &fileInfo ) );

    CU_ASSERT_TRUE_FATAL( rFile_open( testFile, &hFile, RPAL_FILE_OPEN_ALWAYS | RPAL_FILE_OPEN_WRITE ) );
    CU_ASSERT_TRUE( rFile_write( hFile, sizeof( testBuff ), &testBuff ) );
    rFile_close( hFile );

    CU_ASSERT_TRUE( rpal_file_getInfo( testFile, &fileInfo ) );
    CU_ASSERT_TRUE( !IS_FLAG_ENABLED( fileInfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) );

    CU_ASSERT_TRUE( rpal_file_delete( testDir, FALSE ) );
    CU_ASSERT_FALSE( rpal_file_getInfo( testFile, &fileInfo ) );
}


void test_bloom( void )
{
    rBloom b = NULL;

    RU32 i1 = 1;
    RU32 i2 = 2;
    RU32 i3 = 3;
    RU32 i4 = 4;

    RPVOID buff = NULL;
    RU32 size = 0;

    b = rpal_bloom_create( 100, 0.001 );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( b, NULL );

    CU_ASSERT_TRUE( rpal_bloom_add( b, &i1, sizeof( i1 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i1, sizeof( i1 ) ) );

    CU_ASSERT_TRUE( rpal_bloom_add( b, &i2, sizeof( i2 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i2, sizeof( i2 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i1, sizeof( i1 ) ) );

    CU_ASSERT_FALSE( rpal_bloom_present( b, &i3, sizeof( i3 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_addIfNew( b, &i3, sizeof( i3 ) ) );
    CU_ASSERT_FALSE( rpal_bloom_addIfNew( b, &i3, sizeof( i3 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i3, sizeof( i3 ) ) );

    CU_ASSERT_TRUE( rpal_bloom_serialize( b, (RPU8*)&buff, &size ) );
    rpal_bloom_destroy( b );
    b = rpal_bloom_deserialize( buff, size );
    rpal_memory_free( buff );
    CU_ASSERT_PTR_NOT_EQUAL_FATAL( b, NULL );

    CU_ASSERT_TRUE( rpal_bloom_present( b, &i1, sizeof( i1 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i2, sizeof( i2 ) ) );
    CU_ASSERT_TRUE( rpal_bloom_present( b, &i3, sizeof( i3 ) ) );
    CU_ASSERT_FALSE( rpal_bloom_present( b, &i4, sizeof( i4 ) ) );
    
    rpal_bloom_destroy( b );
}


RU32 g_tp_total_test_res = 0;
RU32 g_tp_total_scheduled_test_res = 0;

RPU32
    tp_test
    (
        rEvent stopEvt,
        RPU32 pNum
    )
{
    UNREFERENCED_PARAMETER( stopEvt );
    g_tp_total_test_res++;
    return pNum;
}

RPU32
    tp_testLong
    (
        rEvent stopEvt,
        RPU32 pNum
    )
{
    UNREFERENCED_PARAMETER( stopEvt );
    rpal_thread_sleep( MSEC_FROM_SEC( 5 ) );
    g_tp_total_test_res++;
    return pNum;
}

RPU32
    tp_testScheduleOnce
    (
        rEvent stopEvt,
        RPU32 pNum
    )
{
    UNREFERENCED_PARAMETER( stopEvt );
    g_tp_total_scheduled_test_res++;
    return pNum;
}


RPU32
    tp_testSchedule
    (
        rEvent stopEvt,
        RPU32 pNum
    )
{
    UNREFERENCED_PARAMETER( stopEvt );
    g_tp_total_scheduled_test_res++;
    return pNum;
}

void test_threadpool(void)
{
    rThreadPool pool = NULL;

    RU32 n1 = 1;
    RU32 n2 = 2;
    RU32 n3 = 3;
    RU32 n4 = 4;
    RU32 n5 = 5;
    RU32 n6 = 6;
    RU32 n7 = 7;

    pool = rThreadPool_create( 3, 10, 60 );

    CU_ASSERT_PTR_NOT_EQUAL_FATAL( pool, NULL );

    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_testLong, &n1 ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );

    CU_ASSERT_FALSE( rThreadPool_isIdle( pool ) );

    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n1 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n2 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n3 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n4 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n5 ) );

    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n1 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n2 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n3 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n4 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n5 ) );

    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n1 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n2 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n3 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n4 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n5 ) );

    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n1 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n2 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n3 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n4 ) );
    CU_ASSERT_TRUE( rThreadPool_task( pool, (rpal_thread_pool_func)tp_test, &n5 ) );

    rpal_thread_sleep( MSEC_FROM_SEC( 10 ) );

    CU_ASSERT_TRUE( rThreadPool_isIdle( pool ) );

    rThreadPool_scheduleOneTime( pool, 
                                 rpal_time_getGlobal() + 2 ,
                                 (rpal_thread_pool_func)tp_testScheduleOnce, 
                                 &n6 );
    rThreadPool_scheduleRecurring( pool, 2,(rpal_thread_pool_func)tp_testSchedule, &n7, TRUE );

    rpal_thread_sleep( MSEC_FROM_SEC( 5 ) );

    rThreadPool_destroy( pool, TRUE );

    CU_ASSERT_EQUAL( g_tp_total_test_res, 21 );
    CU_ASSERT_TRUE( g_tp_total_scheduled_test_res >= 3 || g_tp_total_scheduled_test_res  <= 4 );
}


void test_sortsearch( void )
{
    RU32 toSort[] = { 2, 6, 7, 8, 32, 10, 14, 64, 99, 100 };
    RU32 sorted[] = { 2, 6, 7, 8, 10, 14, 32, 64, 99, 100 };
    RU32 repeated[] = { 2, 6, 7, 8, 10, 10, 14, 32, 64, 99, 100 };
    RU32 toFind = 7;
    RU32 toFind2 = 10;
    RU32 toFind3 = 14;
    RU32 toFindRel = 9;
    RU32 toFindRel2 = 3;
    RU32 toFindRel3 = 98;
    RU32 toFindRel4 = 150;
    RU32 toFindRel5 = 0;
    RU32 i = 0;

    CU_ASSERT_TRUE( rpal_sort_array( toSort, 
                                     ARRAY_N_ELEM( toSort ), 
                                     sizeof( RU32 ), 
                                     (rpal_ordering_func)rpal_order_RU32 ) );

    for( i = 0; i < ARRAY_N_ELEM( toSort ); i++ )
    {
        CU_ASSERT_EQUAL( toSort[ i ], sorted[ i ] );
    }

    CU_ASSERT_TRUE( rpal_sort_array( repeated,
                                     ARRAY_N_ELEM( repeated ),
                                     sizeof( RU32 ),
                                     (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( 2, rpal_binsearch_array( repeated,
                                              ARRAY_N_ELEM( repeated ),
                                              sizeof( RU32 ),
                                              &toFind,
                                              (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( 5, rpal_binsearch_array( repeated,
                                              ARRAY_N_ELEM( repeated ),
                                              sizeof( RU32 ),
                                              &toFind2,
                                              (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( 6, rpal_binsearch_array( repeated,
                                              ARRAY_N_ELEM( repeated ),
                                              sizeof( RU32 ),
                                              &toFind3,
                                              (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( 2, rpal_binsearch_array( toSort, 
                                              ARRAY_N_ELEM( toSort ), 
                                              sizeof( RU32 ), 
                                              &toFind, 
                                              (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( -1, rpal_binsearch_array( toSort,
                                               ARRAY_N_ELEM( toSort ),
                                               sizeof( RU32 ),
                                               &toFindRel,
                                               (rpal_ordering_func)rpal_order_RU32 ) );

    CU_ASSERT_EQUAL( 2, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFind,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      TRUE ) );

    CU_ASSERT_EQUAL( 2, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFind,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      FALSE ) );

    CU_ASSERT_EQUAL( 3, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      TRUE ) );

    CU_ASSERT_EQUAL( 4, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      FALSE ) );
    CU_ASSERT_EQUAL( 0, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel2,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      TRUE ) );

    CU_ASSERT_EQUAL( 1, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel2,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      FALSE ) );

    CU_ASSERT_EQUAL( 7, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel3,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      TRUE ) );

    CU_ASSERT_EQUAL( 8, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel3,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      FALSE ) );

    CU_ASSERT_EQUAL( 9, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel4,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      TRUE ) );

    CU_ASSERT_EQUAL( -1, rpal_binsearch_array_closest( toSort,
                                                       ARRAY_N_ELEM( toSort ),
                                                       sizeof( RU32 ),
                                                       &toFindRel4,
                                                       (rpal_ordering_func)rpal_order_RU32,
                                                       FALSE ) );

    CU_ASSERT_EQUAL( -1, rpal_binsearch_array_closest( toSort,
                                                       ARRAY_N_ELEM( toSort ),
                                                       sizeof( RU32 ),
                                                       &toFindRel5,
                                                       (rpal_ordering_func)rpal_order_RU32,
                                                       TRUE ) );

    CU_ASSERT_EQUAL( 0, rpal_binsearch_array_closest( toSort,
                                                      ARRAY_N_ELEM( toSort ),
                                                      sizeof( RU32 ),
                                                      &toFindRel5,
                                                      (rpal_ordering_func)rpal_order_RU32,
                                                      FALSE ) );
}

RS32
    _cmp_number
    (
        RU32* nCur,
        RU32* nNew
    )
{
    return *nCur - *nNew;
}

void test_btree( void )
{
    rBTree tree = NULL;

    RU32 n0 = 0;
    RU32 n1 = 1;
    RU32 n2 = 2;
    RU32 n3 = 3;
    RU32 n4 = 4;
    RU32 res = 0;

    tree = rpal_btree_create( sizeof( RU32 ), (rpal_btree_comp_f)_cmp_number, NULL );
    CU_ASSERT_NOT_EQUAL( tree, NULL );

    CU_ASSERT_TRUE( rpal_btree_isEmpty( tree, FALSE ) );
    CU_ASSERT_EQUAL( rpal_btree_getSize( tree, FALSE ), 0 );

    // Accessors on empty tree
    CU_ASSERT_FALSE( rpal_btree_search( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    CU_ASSERT_FALSE( rpal_btree_remove( tree, &n1, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_maximum( tree, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_minimum( tree, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_next( tree, &n1, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_after( tree, &n1, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n1, &res, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_optimize( tree, FALSE ) );
    CU_ASSERT_FALSE( rpal_btree_update( tree, &n1, &n1, FALSE ) );

    CU_ASSERT_TRUE( rpal_btree_add( tree, &n1, FALSE ) );

    CU_ASSERT_FALSE( rpal_btree_isEmpty( tree, FALSE ) );
    CU_ASSERT_EQUAL( rpal_btree_getSize( tree, FALSE ), 1 );

    // One item
    CU_ASSERT_TRUE( rpal_btree_search( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_maximum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_minimum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_next( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_next( tree, NULL, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_next( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;

    CU_ASSERT_FALSE( rpal_btree_after( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_after( tree, &n0, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_after( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n0, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_optimize( tree, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_update( tree, &n1, &n2, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_minimum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 2 );
    res = 0;

    CU_ASSERT_FALSE( rpal_btree_remove( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_isEmpty( tree, FALSE ) );
    CU_ASSERT_NOT_EQUAL( rpal_btree_getSize( tree, FALSE ), 0 );
    CU_ASSERT_TRUE( rpal_btree_remove( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 2 );
    res = 0;

    CU_ASSERT_TRUE( rpal_btree_isEmpty( tree, FALSE ) );
    CU_ASSERT_EQUAL( rpal_btree_getSize( tree, FALSE ), 0 );

    CU_ASSERT_TRUE( rpal_btree_add( tree, &n1, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_add( tree, &n3, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_add( tree, &n4, FALSE ) );

    CU_ASSERT_FALSE( rpal_btree_isEmpty( tree, FALSE ) );
    CU_ASSERT_EQUAL( rpal_btree_getSize( tree, FALSE ), 3 );

    // Multi items
    CU_ASSERT_FALSE( rpal_btree_search( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_search( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_maximum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 4 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_minimum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_next( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 3 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_next( tree, NULL, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_next( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_next( tree, &n3, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 4 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_next( tree, &n4, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;

    CU_ASSERT_TRUE( rpal_btree_after( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 3 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_after( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 3 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_after( tree, &n4, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n1, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n2, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_FALSE( rpal_btree_previous( tree, &n0, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 0 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_previous( tree, &n3, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 1 );
    res = 0;
    CU_ASSERT_TRUE( rpal_btree_optimize( tree, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_update( tree, &n4, &n3, FALSE ) );
    CU_ASSERT_TRUE( rpal_btree_maximum( tree, &res, FALSE ) );
    CU_ASSERT_EQUAL( res, 3 );
    res = 0;

    rpal_btree_destroy( tree, FALSE );
}

void test_dirwatch( void )
{
    rDirWatch dw = NULL;
    RPNCHAR tmpPath = NULL;
    RU32 action = 0;
    RU8 dummy[ 4 ] = { 0 };
#ifdef RPAL_PLATFORM_WINDOWS
    RPNCHAR root1 = _NC( "%TEMP%\\_test_1" );
    RPNCHAR root2 = _NC( "%TEMP%\\_test_1\\_test_2" );
    RPNCHAR tmpFile = _NC( "%TEMP%\\_test_1\\_test_2\\_test_file" );
    RPNCHAR tmpFileNew = _NC( "%TEMP%\\_test_1\\_test_2\\_test_file_post" );
    RPNCHAR tmpFileName = _NC( "_test_2\\_test_file" );
    RPNCHAR tmpFileNameNew = _NC( "_test_2\\_test_file_post" );
#else
    RPNCHAR root1 = _NC( "/tmp/_test_1" );
    RPNCHAR root2 = _NC( "/tmp/_test_1/_test_2" );
    RPNCHAR tmpFile = _NC( "/tmp/_test_1/_test_2/_test_file" );
    RPNCHAR tmpFileNew = _NC( "/tmp/_test_1/_test_2/_test_file_post" );
    RPNCHAR tmpFileName = _NC( "_test_2/_test_file" );
    RPNCHAR tmpFileNameNew = _NC( "_test_2/_test_file_post" );
#endif
    RPNCHAR tmpDir = _NC( "_test_2" );

    RBOOL isFile1Added = FALSE;
    RBOOL isFile1Modified = FALSE;
    RBOOL isDirModified = FALSE;
    RBOOL isNewFile = FALSE;
    RBOOL isOldFile = FALSE;
    RU32 i = 0;

    rpal_file_delete( root1, FALSE );
    rDir_create( root1 );
    rDir_create( root2 );

    dw = rDirWatch_new( root1, RPAL_DIR_WATCH_CHANGE_ALL, TRUE );
    CU_ASSERT_NOT_EQUAL( dw, NULL );

    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    //=========================================================================
    // Write a new file.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_write( tmpFile, dummy, sizeof( dummy ), TRUE ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

    for( i = 0; i < 2; i++ )
    {
        CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
        if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_ADDED  == action )
        {
            isFile1Added = TRUE;
        }
        else if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
                 RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            isFile1Modified = TRUE;
        }
#ifdef RPAL_PLATFORM_WINDOWS
        else if( 0 == rpal_string_strcmp( tmpDir, tmpPath ) &&
                 RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            // Some versions of Windows seem to report a change to the dir.
            i--;
        }
#endif
        else
        {
            rpal_debug_info( ":: " RF_STR_N " == " RF_U32, tmpPath, action );
            CU_ASSERT_TRUE( FALSE );
        }
    }
    CU_ASSERT_TRUE( isFile1Added );
    CU_ASSERT_TRUE( isFile1Modified );
    isFile1Modified = FALSE;
    isFile1Added = FALSE;
    isDirModified = FALSE;

    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    //=========================================================================
    // Write on existing file.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_write( tmpFile, dummy, sizeof( dummy ), TRUE ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

#ifdef RPAL_PLATFORM_WINDOWS
    for( i = 0; i < 2; i++ )
    {
        CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
        if( 0 == rpal_string_strcmp( tmpDir, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            isDirModified = TRUE;
        }
        else if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
                 RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            isFile1Modified = TRUE;
        }
        else
        {
            rpal_debug_info( ":: " RF_STR_N " == " RF_U32, tmpPath, action );
            CU_ASSERT_TRUE( FALSE );
        }
    }
    // Not all versions of Windows will report the directory modified.
    // CU_ASSERT_TRUE( isDirModified );

    CU_ASSERT_TRUE( isFile1Modified );
#else
    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_MODIFIED, action );
#endif

    isFile1Modified = FALSE;
    isFile1Added = FALSE;
    isDirModified = FALSE;

    //=========================================================================
    // Move existing file.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_move( tmpFile, tmpFileNew ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

    for( i = 0; i < 2; i++ )
    {
        CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
        if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_RENAMED_OLD == action )
        {
            isOldFile = TRUE;
        }
        else if( 0 == rpal_string_strcmp( tmpFileNameNew, tmpPath ) &&
                RPAL_DIR_WATCH_ACTION_RENAMED_NEW == action )
        {
            isNewFile = TRUE;
        }
#ifdef RPAL_PLATFORM_WINDOWS
        else if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            // Some versions of Windows report the old file modified.
            i--;
        }
#endif
        else
        {
            rpal_debug_info( ":: " RF_STR_N " == " RF_U32, tmpPath, action );
            CU_ASSERT_TRUE( FALSE );
        }
    }
    CU_ASSERT_TRUE( isOldFile );
    CU_ASSERT_TRUE( isNewFile );

    //=========================================================================
    // Delete a file.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_delete( tmpFileNew, FALSE ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

#ifdef RPAL_PLATFORM_WINDOWS
    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpDir, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_MODIFIED, action );
    
    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpFileNameNew, tmpPath ) );
    // Some versions of Windows will have an additional modifed here.
    if( RPAL_DIR_WATCH_ACTION_MODIFIED == action )
    {
        CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
        CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpFileNameNew, tmpPath ) );
        CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_REMOVED, action );
    }
    else
    {
        CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_REMOVED, action );
    }
#else
    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpFileNameNew, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_REMOVED, action );
#endif

    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    //=========================================================================
    // Delete subdir.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_delete( root2, FALSE ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

#ifdef RPAL_PLATFORM_WINDOWS
    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpDir, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_MODIFIED, action );
#endif

    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpDir, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_REMOVED, action );
    
    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    //=========================================================================
    // Create subdir.
    //=========================================================================
    CU_ASSERT_TRUE( rDir_create( root2 ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

    CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
    CU_ASSERT_TRUE( 0 == rpal_string_strcmp( tmpDir, tmpPath ) );
    CU_ASSERT_EQUAL( RPAL_DIR_WATCH_ACTION_ADDED, action );

    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    //=========================================================================
    // Create new file to make sure it gets picked up.
    //=========================================================================
    CU_ASSERT_TRUE( rpal_file_write( tmpFile, dummy, sizeof( dummy ), TRUE ) );
    rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );

    for( i = 0; i < 2; i++ )
    {
        CU_ASSERT_TRUE( rDirWatch_next( dw, 0, &tmpPath, &action ) );
        if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_ADDED == action )
        {
            isFile1Added = TRUE;
        }
        else if( 0 == rpal_string_strcmp( tmpFileName, tmpPath ) &&
            RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            isFile1Modified = TRUE;
        }
#ifdef RPAL_PLATFORM_WINDOWS
        // Some versions of Windows have a directory modify here.
        else if( 0 == rpal_string_strcmp( tmpDir, tmpPath ) &&
                 RPAL_DIR_WATCH_ACTION_MODIFIED == action )
        {
            i--;
        }
#endif
        else
        {
            rpal_debug_info( ":: " RF_STR_N " == " RF_U32, tmpPath, action );
            CU_ASSERT_TRUE( FALSE );
        }
    }
    CU_ASSERT_TRUE( isFile1Added );
    CU_ASSERT_TRUE( isFile1Modified );
    isFile1Modified = FALSE;
    isFile1Added = FALSE;
    isDirModified = FALSE;

    CU_ASSERT_FALSE( rDirWatch_next( dw, 0, &tmpPath, &action ) );

    rDirWatch_free( dw );
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

    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    if( rpal_initialize( NULL, 1 ) )
    {
        if( CUE_SUCCESS == ( error = CU_initialize_registry() ) )
        {
            if( NULL != ( suite = CU_add_suite( "rpal", NULL, NULL ) ) )
            {
                if( NULL == CU_add_test( suite, "events", test_events ) ||
                    NULL == CU_add_test(suite, "dirwatch", test_dirwatch) ||
                    NULL == CU_add_test( suite, "handleManager", test_handleManager ) ||
                    NULL == CU_add_test( suite, "strings", test_strings ) ||
                    NULL == CU_add_test( suite, "blob", test_blob ) ||
                    NULL == CU_add_test( suite, "stack", test_stack ) ||
                    NULL == CU_add_test( suite, "queue", test_queue ) ||
                    NULL == CU_add_test( suite, "circularbuffer", test_circularbuffer ) ||
                    NULL == CU_add_test( suite, "strtok", test_strtok ) ||
                    NULL == CU_add_test( suite, "strmatch", test_strmatch ) ||
                    NULL == CU_add_test( suite, "dir", test_dir ) ||
                    NULL == CU_add_test( suite, "crawl", test_crawler ) ||
                    NULL == CU_add_test( suite, "file", test_file ) ||
                    NULL == CU_add_test( suite, "bloom", test_bloom ) ||
                    NULL == CU_add_test( suite, "btree", test_btree ) ||
                    NULL == CU_add_test( suite, "threadpool", test_threadpool ) ||
                    NULL == CU_add_test( suite, "sortsearch", test_sortsearch ) ||
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

