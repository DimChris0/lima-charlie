#include <rpal/rpal.h>
#include <obsLib/obsLib.h>
#include <Basic.h>

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

void test_CreateAndDestroy(void)
{
    HObs hObs = NULL;

    hObs = obsLib_new( 0, 0 );

    CU_ASSERT_TRUE_FATAL( rpal_memory_isValid( hObs ) );

    obsLib_free( hObs );
}

void test_addPattern(void)
{
    HObs hObs = NULL;
    RU8 pattern[] = { 0x01, 0x02, 0x03, 0x04 };
    RU32 context = 0;

    hObs = obsLib_new( 0, 0 );

    CU_ASSERT_TRUE_FATAL( rpal_memory_isValid( hObs ) );

    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern, sizeof( pattern ), &context ) );

    obsLib_free( hObs );
}

void test_singlePattern(void)
{
    HObs hObs = NULL;
    RU8 pattern[] = { 0x01, 0x02, 0x03, 0x04 };
    RU8 buffer1[] = { 0x02, 0x04, 0xFF, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    RU8 buffer2[] = { 0x02, 0x04, 0xFF, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xEE, 0x6F };
    RU8 buffer3[] = { 0x02, 0x04, 0xFF, 0xEF, 0x01, 0x02, 0x01, 0x04, 0xEE, 0x6F };
    RU8 buffer4[] = { 0x02, 0x04, 0xFF, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xEE, 0x6F, 0x01, 0x02, 0x03, 0x04 };
    RU32 context = 0;
    RPVOID hitCtx = NULL;
    RU8* hitLoc = NULL;

    hObs = obsLib_new( 0, 0 );

    CU_ASSERT_TRUE_FATAL( rpal_memory_isValid( hObs ) );

    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern, sizeof( pattern ), &context ) );

    // 1 pattern found end of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer1, sizeof( buffer1 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context );
    CU_ASSERT_EQUAL( hitLoc, buffer1 + sizeof( buffer1 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 1 pattern found middle of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer2, sizeof( buffer2 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context );
    CU_ASSERT_EQUAL( hitLoc, buffer2 + sizeof( buffer2 ) - 6 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 0 pattern found
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer3, sizeof( buffer3 ) ) );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 2 pattern found end and middle of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer4, sizeof( buffer4 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context );
    CU_ASSERT_EQUAL( hitLoc, buffer4 + sizeof( buffer4 ) - 10 );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context );
    CU_ASSERT_EQUAL( hitLoc, buffer4 + sizeof( buffer4 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    obsLib_free( hObs );
}

void test_multiPattern(void)
{
    HObs hObs = NULL;
    RU8 pattern1[] = { 0x01, 0x02, 0x03, 0x04 };
    RU8 pattern2[] = { 0x01, 0x02, 0x03, 0x06 };
    RU8 pattern3[] = { 0x01, 0x02, 0x06, 0x04 };
    RU8 pattern4[] = { 0xEF, 0x02, 0x03, 0x04 };
    RU8 buffer1[] = { 0x02, 0x04, 0xFF, 0xEF, 
                      0x01, 0x02, 0x03, 0x04 };
    RU8 buffer2[] = { 0x02, 0x04, 0xFF, 0xEF,
                      0x01, 0x02, 0x03, 0x04, 0xEE, 0x6F };
    RU8 buffer3[] = { 0x02, 0x04, 0xFF, 0xEF,
                      0x01, 0x02, 0x01, 0x04, 0xEE, 0x6F };
    RU8 buffer4[] = { 0x02, 0x04, 0xFF, 0xEF, 0x01, 
                      0x02, 0x03, 0x04, 0xEE, 0x6F,
                      0x01, 0x02, 0x03, 0x04 };
    RU8 buffer5[] = { 0x02, 0x04, 0xFF, 0xEF, 
                      0x02, 0x03, 0x04, 0x04, 
                      0xEE, 0x6F, 0x01, 0x02, 0x03, 0x04 };
    RU8 buffer6[] = { 0x02, 0x04, 0xFF, 0xEF,
                      0x02, 0x03, 0x04, 0x04, 
                      0xEE, 0x6F, 0x01, 0x02, 
                      0x03, 0x04, 0x01, 0x02, 0x06, 0x04 };
    RU32 context1 = 0;
    RU32 context2 = 0;
    RU32 context3 = 0;
    RU32 context4 = 0;
    RPVOID hitCtx = NULL;
    RU8* hitLoc = NULL;

    hObs = obsLib_new( 0, 0 );

    CU_ASSERT_TRUE_FATAL( rpal_memory_isValid( hObs ) );

    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern1, sizeof( pattern1 ), &context1 ) );
    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern2, sizeof( pattern2 ), &context2 ) );
    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern3, sizeof( pattern3 ), &context3 ) );
    CU_ASSERT_TRUE_FATAL( obsLib_addPattern( hObs, (RPU8)&pattern4, sizeof( pattern4 ), &context4 ) );

    // 1 pattern found end of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer1, sizeof( buffer1 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer1 + sizeof( buffer1 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 1 pattern found middle of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer2, sizeof( buffer2 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer2 + sizeof( buffer2 ) - 6 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 0 pattern found
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer3, sizeof( buffer3 ) ) );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // 2 pattern found end and middle of buffer
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer4, sizeof( buffer4 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer4 + sizeof( buffer4 ) - 10 );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer4 + sizeof( buffer4 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // Multi 1
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer5, sizeof( buffer5 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context4 );
    CU_ASSERT_EQUAL( hitLoc, buffer5 + 3 );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer5 + sizeof( buffer5 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    // Multi 2
    CU_ASSERT_TRUE_FATAL( obsLib_setTargetBuffer( hObs, buffer6, sizeof( buffer6 ) ) );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context4 );
    CU_ASSERT_EQUAL( hitLoc, buffer6 + 3 );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context1 );
    CU_ASSERT_EQUAL( hitLoc, buffer6 + sizeof( buffer6 ) - 8 );
    CU_ASSERT_TRUE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );
    CU_ASSERT_EQUAL( hitCtx, &context3 );
    CU_ASSERT_EQUAL( hitLoc, buffer6 + sizeof( buffer6 ) - 4 );
    CU_ASSERT_FALSE( obsLib_nextHit( hObs, &hitCtx, (RPVOID*)&hitLoc ) );

    obsLib_free( hObs );
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
            if( NULL != ( suite = CU_add_suite( "obsLib", NULL, NULL ) ) )
            {
                if( NULL == CU_add_test( suite, "createAndDestroy", test_CreateAndDestroy ) ||
                    NULL == CU_add_test( suite, "addPattern", test_addPattern ) ||
                    NULL == CU_add_test( suite, "singlePattern", test_singlePattern ) ||
                    NULL == CU_add_test( suite, "multiPattern", test_multiPattern ) ||
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

            if( 0 != rpal_memory_totalUsed() )
            {
                ret = -1;
            }
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

