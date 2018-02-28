#include <rpal/rpal.h>
#include <processLib/processLib.h>
#include <MemoryModule/MemoryModule.h>

#ifdef RPAL_PLATFORM_LINUX
#include <signal.h>
#endif

#if defined(RPAL_PLATFORM_MACOSX) || defined(RPAL_PLATFORM_LINUX)
#include <dlfcn.h>
#include <sys/mman.h>
#endif

/*
 * This executable simulates a few different types of memory loading to be used to
 * test detection capabilities like Yara memory scanning.
 */

rEvent g_timeToQuit = NULL;

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
    printf( "Usage: -m method -t target\n" );
    printf( "-m method: the loading method to use, one of\n" );
    printf( "\t1: simple loading, no mapping, not executable, INERT CODE\n" );
    printf( "\t2: simple loading, no mapping, executable, INERT CODET\n" );
    printf( "\t3: OS loading, mapped, executable, LIVE CODE WARNING!\n" );
    printf( "\t4: manual loading, mapped, executable, LIVE CODE WARNING!\n" );
    printf( "-t target: the target file to load in memory\n" );
}

RPAL_NATIVE_MAIN
{
    RU32 memUsed = 0;
    RNCHAR argFlag = 0;
    RPNCHAR argVal = NULL;

    rpal_opt switches[] = { { _NC( 't' ), _NC( "target" ), TRUE },
                            { _NC( 'm' ), _NC( "method" ), TRUE } };

    // Execution Environment
    RPNCHAR target = NULL;
    RU32 method = 0;

    // Method-specific variables.
    RPU8 loadedBuffer = NULL;
    RU32 loadedSize = 0;
    RU32 protect = 0;
    RU32 oldProtect = 0;
    HMEMORYMODULE hMemoryLib = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hLib = NULL;
#else
    RPVOID hLib = NULL;
    RPVOID mapping = NULL;
#endif
    rpal_debug_info( "initializing..." );
    if( rpal_initialize( NULL, 0 ) )
    {
        // Initialize boilerplate runtime.
        if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
        {
            rpal_debug_critical( "Failed to create timeToQuit event." );
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
        while( -1 != ( argFlag = rpal_getopt( argc, argv, switches, &argVal ) ) )
        {
            switch( argFlag )
            {
                case 't':
                    target = argVal;
                    break;
                case 'm':
                    if( rpal_string_stoi( argVal, &method, TRUE ) )
                    {
                        break;
                    }
                default:
                    printUsage();
                    return -1;
            }
        }

        if( 0 == method ||
            NULL == target )
        {
            printUsage();
            return -1;
        }

        // Execute the loading as requested.
        switch( method )
        {
            // Method 1: simple load in memory of a buffer, no mapping, not executable.
            case 1:
            case 2:
                if( !rpal_file_read( target, &loadedBuffer, &loadedSize, FALSE ) )
                {
                    rpal_debug_error( "Failed to load target file in buffer." );
                }
                else if( 2 == method )
                {
#ifdef RPAL_PLATFORM_WINDOWS
                    protect = PAGE_EXECUTE_READWRITE;
                    oldProtect = 0;
                    if( !VirtualProtect( loadedBuffer, loadedSize, protect, (PDWORD)&oldProtect ) )
                    {
                        rpal_debug_warning( "Failed to make memory executable." );
                    }
#else
                    mapping = mmap( NULL, 
                        loadedSize, 
                        PROT_EXEC | PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        0, 0 );
                    if( NULL != mapping )
                    {
                        rpal_memory_memcpy( mapping, loadedBuffer, loadedSize );
                    }
                    else
                    {
                        rpal_debug_error( "Failed to create executable mapping." );
                    }

                    rpal_memory_free( loadedBuffer );
                    loadedBuffer = NULL;
#endif
                }
                break;
            case 3:
#ifdef RPAL_PLATFORM_WINDOWS
                hLib = LoadLibraryW( target );
                if( NULL == hLib || INVALID_HANDLE_VALUE == hLib )
                {
                    rpal_debug_error( "Failed to load library: %d", GetLastError() );
                }
#else
                if( NULL == ( hLib = dlopen( target, RTLD_NOW | RTLD_LOCAL ) ) )
                {
                    rpal_debug_error( "Failed to load library." );
                }
                if( NULL != mapping )
                {
                    munmap( mapping, loadedSize );
                }
#endif
                break;
            case 4:
                if( !rpal_file_read( target, &loadedBuffer, &loadedSize, FALSE ) )
                {
                    rpal_debug_error( "Failed to read target file." );
                }
                else
                {
                    if( NULL == ( hMemoryLib = MemoryLoadLibrary( loadedBuffer, loadedSize ) ) )
                    {
                        rpal_debug_error( "Could not load library manually in memory." );
                    }

                    rpal_memory_free( loadedBuffer );
                    loadedBuffer = NULL;
                }
                break;
        }

        rpal_debug_info( "Loading complete, waiting for signal to exit." );
        rEvent_wait( g_timeToQuit, RINFINITE );
        rEvent_free( g_timeToQuit );

        // Cleanup whatever is left in memory.
        rpal_memory_free( loadedBuffer );
        MemoryFreeLibrary( hMemoryLib );
#ifdef RPAL_PLATFORM_WINDOWS
        if( NULL != hLib && INVALID_HANDLE_VALUE != hLib )
        {
            FreeLibrary( hLib );
        }
#else
        if( NULL != hLib ) dlclose( hLib );
#endif

        rpal_debug_info( "...exiting..." );
        rpal_Context_cleanup();

#ifdef RPAL_PLATFORM_DEBUG
        memUsed = rpal_memory_totalUsed();
        if( 0 != memUsed )
        {
            rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
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
