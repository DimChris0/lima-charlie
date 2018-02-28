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

#include <rpal_time.h>
#include <rpal_synchronization.h>
#include <time.h>

#if defined( RPAL_PLATFORM_MACOSX )
    #include <mach/mach_time.h>
    #include <sys/time.h>
    #include <mach/clock_types.h>
    #include <mach/mach_host.h>
    #include <mach/clock.h>
    #include <sys/sysctl.h>
#elif defined( RPAL_PLATFORM_LINUX )
    #include <unistd.h>
    #include <sys/time.h>
    #include <ctype.h>
#elif defined( RPAL_PLATFORM_WINDOWS)
    #define FILETIME2ULARGE( uli, ft )  (uli).u.LowPart = (ft).dwLowDateTime, (uli).u.HighPart = (ft).dwHighDateTime
#endif

// This resource is not protected from multi-threading
// To do so would be the *right* thing, but a hassle
// for now. Since the impact of a race condition should
// be trivial, no protection for now...
static RU64 g_rpal_time_globalOffset = 0;

RU64
    rpal_time_getLocal
    (

    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    return _time64( NULL );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    return time( NULL );
#endif
}

RPRIVATE
RU32
    _getNumCpus
    (

    )
{
    static RU32 nCores = 0;

    if( 0 != nCores )
    {
        return nCores;
    }
    {
#ifdef RPAL_PLATFORM_WINDOWS
        SYSTEM_INFO sysinfo = { 0 };
        GetSystemInfo( &sysinfo );
        nCores = sysinfo.dwNumberOfProcessors;
#elif defined( RPAL_PLATFORM_MACOSX )
        int mib[ 4 ] = { CTL_HW, HW_AVAILCPU, 0, 0 };
        size_t len = sizeof( nCores );
        sysctl( mib, 2, &nCores, &len, NULL, 0 );
        if( nCores < 1 )
        {
            mib[ 1 ] = HW_NCPU;
            sysctl( mib, 2, &nCores, &len, NULL, 0 );

            if( nCores < 1 )
            {
                nCores = 1;
            }
        }
#elif defined( RPAL_PLATFORM_LINUX )
        nCores = sysconf( _SC_NPROCESSORS_ONLN );
#else
        rpal_debug_not_implemented();
#endif
    }

    return nCores;
}

RBOOL
    rpal_time_getCPU
    (
        RU64* cpuTime
    )
{
#if defined( RPAL_PLATFORM_WINDOWS )
    static GetSystemTimes_f gst = NULL;
    RBOOL isSuccess = FALSE;
    FILETIME ftUser = { 0 };
    FILETIME ftKernel = { 0 };
    FILETIME ftIdle = { 0 };
    RCHAR getSystemTime[] = "GetSystemTimes";
    ULARGE_INTEGER uUser = { 0 };
    ULARGE_INTEGER uKernel = { 0 };
    ULARGE_INTEGER uIdle = { 0 };

    if( NULL == cpuTime )
    {
        return FALSE;
    }

    if( NULL == gst )
    {
        gst = (GetSystemTimes_f)GetProcAddress( GetModuleHandleW( _WCH( "kernel32.dll" ) ),
            getSystemTime );
        if( NULL == gst )
        {
            rpal_debug_error( "Cannot get the address to GetSystemTimes -- error code %u.", GetLastError() );
            isSuccess = FALSE;
        }
    }

    if( NULL != gst &&
        gst( &ftIdle, &ftKernel, &ftUser ) )
    {
        FILETIME2ULARGE( uUser, ftUser );
        FILETIME2ULARGE( uKernel, ftKernel );
        FILETIME2ULARGE( uIdle, ftIdle );

        *cpuTime = ( uUser.QuadPart + uKernel.QuadPart + uIdle.QuadPart ) / NSEC_100_PER_USEC;

        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_error( "Unable to get system times -- error code %u.", GetLastError() );
        isSuccess = FALSE;
    }

    return isSuccess;
#elif defined( RPAL_PLATFORM_LINUX )
    static RU64 user_hz = 0;
    FILE* proc_stat = NULL;
    RCHAR line[ 256 ] = { 0 };
    RCHAR* saveptr = NULL;
    RCHAR* tok = NULL;
    RPCHAR unused = NULL;

    if( 0 == user_hz )
    {
        long tmp = sysconf( _SC_CLK_TCK );
        if( tmp < 0 )
        {
            rpal_debug_error( "Cannot find the proc clock tick size -- error code %u.", errno );
            return FALSE;
        }
        user_hz = (RU64)tmp;
    }
    if( NULL == cpuTime )
    {
        return TRUE;
    }

    if( NULL != ( proc_stat = fopen( "/proc/stat", "r" ) ) )
    {
        rpal_memory_zero( line, sizeof( line ) );

        while( !feof( proc_stat ) )
        {
            unused = fgets( line, sizeof( line ), proc_stat );
            if( line == strstr( line, "cpu " ) )
            {
                saveptr = NULL;
                tok = strtok_r( line, " ", &saveptr );
                *cpuTime = 0;

                while( NULL != tok )
                {
                    if( isdigit( tok[ 0 ] ) )
                    {
                        *cpuTime += (RU64)atol( tok );
                    }
                    tok = strtok_r( NULL, " ", &saveptr );
                }

                /* user_hz = clock ticks per second; we want time in microseconds. */
                *cpuTime = ( *cpuTime * 1000000 ) / user_hz;
                break;
            }
        }
        fclose( proc_stat );
    }
    else
    {
        rpal_debug_error( "Cannot open /proc/stat -- error code %u.", errno );
    }

    return *cpuTime > 0;
#elif defined( RPAL_PLATFORM_MACOSX )
    static clock_serv_t cclock;
    static RBOOL isInitialized = FALSE;
    mach_timespec_t mts;
    if( !isInitialized )
    {
        host_get_clock_service( mach_host_self(), SYSTEM_CLOCK, &cclock );
        isInitialized = TRUE;
    }

    clock_get_time( cclock, &mts );

    if( NULL != cpuTime )
    {
        *cpuTime = USEC_FROM_NSEC( mts.tv_nsec ) + USEC_FROM_SEC( mts.tv_sec );
    }

    return TRUE;
#else
    rpal_debug_not_implemented();
#endif
}

RPAL_DEFINE_API
( 
RU64, 
    rpal_time_getGlobal, 
)
{
    RU64 time = 0;
    
    time = rpal_time_getLocal() + g_rpal_time_globalOffset;

    return time;
}


RPAL_DEFINE_API
( 
RU64, 
    rpal_time_setGlobalOffset,
        RU64 offset
)
{
    RU64 oldOffset = 0;

    oldOffset = g_rpal_time_globalOffset;

    g_rpal_time_globalOffset = offset;

    return oldOffset;
}


RPAL_DEFINE_API
(
RU64,
    rpal_time_getGlobalFromLocal,
        RU64 localTs
)
{
    return localTs + g_rpal_time_globalOffset;
}

RU64
    rpal_time_getGlobalPreciseTime
    (

    )
{
    static volatile RU64 lastLocalTime = 0;
    static RU64 lastCPUTime = 0;
    RU64 tmpTime = 0;
    RU64 cpuTime = 0;
    RU64 cpuDelta = 0;
    RU64 timeDelta = 0;
    RU64 ts = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    FILETIME ft = { 0 };
    GetSystemTimeAsFileTime( &ft );
    ts = MS_FILETIME_TO_MSEC_EPOCH( (RU64)ft.dwLowDateTime + ( (RU64)ft.dwHighDateTime << 32 ) );
#else
    struct timeval tv = { 0 };
    gettimeofday( &tv, NULL );
    ts = MSEC_FROM_SEC((RU64)tv.tv_sec) + MSEC_FROM_USEC( (RU64)tv.tv_usec );
#endif

#ifdef RPAL_PLATFORM_64_BIT
    // We get an atomic version of the time and set the current one to be thread safe for the hibernation detection.
    tmpTime = rInterlocked_set64( &lastLocalTime, ts );
#else
    // We do not have true atomic exchange for 64 bit ints on 32 bit so we'll do best effort.
    tmpTime = lastLocalTime;
    lastLocalTime = ts;
#endif

    timeDelta = DELTA_OF( tmpTime, ts );
    if( MSEC_FROM_SEC( 10 ) < timeDelta )
    {
        if( 0 != lastLocalTime &&
            rpal_time_getCPU( &cpuTime ) )
        {
            if( 0 != lastCPUTime )
            {
                // The CPU Time can overflow.
                cpuDelta = MIN_OF( lastCPUTime - cpuTime, cpuTime - lastCPUTime );
                cpuDelta = MSEC_FROM_USEC( cpuDelta );
                cpuDelta /= _getNumCpus();
                
                // We only really care about wall clock time being greater than CPU to indicate
                // some form of hybernation.
                if( timeDelta > cpuDelta &&
                    MSEC_FROM_SEC( 10 ) < timeDelta - cpuDelta )
                {
                    rpal_debug_info( "Delta check: dtime = " RF_U64 " dcpu = " RF_U64, timeDelta, cpuDelta );
                    rpal_time_setGlobalOffset( 0 );
                    rpal_debug_info( "detected external clock sync, resetting global offset" );
                }
            }

            lastCPUTime = cpuTime;
        }
    }
    else
    {
        // It was not time to refresh so we will put back the previous value of last check.
        lastLocalTime = tmpTime;
    }

    ts += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

    return ts;
}

RBOOL
    rpal_timer_init_interval
    (
        rpal_timer* timer,
        RU64 intervalSec,
        RBOOL isRandomStartTime
    )
{
    RBOOL isSuccess = FALSE;

    RU64 curTime = rpal_time_getGlobal();

    if( NULL != timer )
    {
        timer->isAbsolute = FALSE;
        timer->isReady = FALSE;

        if( isRandomStartTime )
        {
            timer->nextTime = ( rpal_rand() % intervalSec ) + curTime;
        }
        else
        {
            timer->nextTime = curTime + intervalSec;
        }

        timer->timeValue = intervalSec;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    rpal_timer_init_onetime
    (
        rpal_timer* timer,
        RU64 timeStamp
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != timer )
    {
        timer->isAbsolute = TRUE;
        timer->isReady = FALSE;
        timer->nextTime = timeStamp;
        timer->timeValue = timeStamp;
        isSuccess = TRUE;
    }

    return isSuccess;
}


RU64
    rpal_timer_nextWait
    (
        rpal_timer* timers[]
    )
{
    RU64 i = 0;
    
    RU64 minTime = (RU64)(-1);
    RU64 curTime = rpal_time_getGlobal();

    if( NULL != timers )
    {
        while( NULL != timers[ i ] )
        {
            if( 0 != timers[ i ]->nextTime &&
                minTime > timers[ i ]->nextTime )
            {
                minTime = timers[ i ]->nextTime;
            }

            i++;
        }

        if( (RU64)(-1) != minTime )
        {
            if( curTime <= minTime )
            {
                minTime = minTime - curTime;
            }
            else
            {
                minTime = 0;
            }
        }
    }

    return minTime;
}

RU32
    rpal_timer_update
    (
        rpal_timer* timers[]
    )
{
    RU64 i = 0;
    RU64 curTime = rpal_time_getGlobal();

    RU32 nReady = FALSE;

    if( NULL != timers )
    {
        while( NULL != timers[ i ] )
        {
            if( 0 != timers[ i ]->nextTime &&
                curTime >= timers[ i ]->nextTime )
            {
                // Ready
                nReady++;

                if( timers[ i ]->isAbsolute )
                {
                    timers[ i ]->nextTime = 0;
                }
                else
                {
                    timers[ i ]->nextTime = curTime + timers[ i ]->timeValue;
                }

                timers[ i ]->isReady = TRUE;
            }
            else
            {
                timers[ i ]->isReady = FALSE;
            }

            i++;
        }
    }

    return nReady;
}

RU32
    rpal_time_getMilliSeconds
    (

    )
{
    RU32 t = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    t = GetTickCount();
#elif defined( RPAL_PLATFORM_LINUX )
    struct timespec abs_time;
    clock_gettime( CLOCK_REALTIME, &abs_time );
    t = ( abs_time.tv_sec * 1000 ) + ( abs_time.tv_nsec / 1000000 );
#elif defined( RPAL_PLATFORM_MACOSX )
    const int64_t kOneMillion = 1000 * 1000;
    static mach_timebase_info_data_t s_timebase_info;
    
    if ( s_timebase_info.denom == 0 )
    {
        (void) mach_timebase_info( &s_timebase_info );
    }
    
    // mach_absolute_time() returns billionth of seconds,
    // so divide by one million to get milliseconds
    t = (RU32)( ( mach_absolute_time() * s_timebase_info.numer ) / ( kOneMillion * s_timebase_info.denom ) );
#endif
    return t;
}

RU64
    rpal_time_elapsedMilliSeconds
    (
        RU32 start
    )
{
    RU64 total = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    RU32 now = 0;
    now = GetTickCount();

    if( start <= now )
    {
        total = now - start;
    }
    else
    {
        // Overflow
        total = ( 0xFFFFFFFF - start ) + now;
    }
#elif defined( RPAL_PLATFORM_LINUX )
    struct timespec abs_time;
    RU32 t = 0;
    clock_gettime( CLOCK_REALTIME, &abs_time );
    t = ( abs_time.tv_sec * 1000 ) + ( abs_time.tv_nsec / 1000000 );
    total = t - start;
#elif defined( RPAL_PLATFORM_MACOSX )
    RU32 t = 0;
    const int64_t kOneMillion = 1000 * 1000;
    static mach_timebase_info_data_t s_timebase_info;
    
    if ( s_timebase_info.denom == 0 )
    {
        (void) mach_timebase_info( &s_timebase_info );
    }
    
    // mach_absolute_time() returns billionth of seconds,
    // so divide by one million to get milliseconds
    t = (RU32)( ( mach_absolute_time() * s_timebase_info.numer ) / ( kOneMillion * s_timebase_info.denom ) );
    total = t - start;
#endif
    return total;
}

#ifdef RPAL_PLATFORM_WINDOWS
RU64 
    rpal_winFileTimeToMsTs
    (
        FILETIME ft
    )
{
    return MS_FILETIME_TO_MSEC_EPOCH( (RU64)ft.dwLowDateTime + ( (RU64)ft.dwHighDateTime << 32 ) );
}
#endif

RBOOL
    rpal_time_hires_timestamp_metadata_init
    (
        rpal_hires_timestamp_metadata* metadata
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    LARGE_INTEGER freq;

    metadata->ticks_per_second = 0ull;
    
    if ( QueryPerformanceFrequency( &freq ) )
    {
        metadata->ticks_per_second = freq.QuadPart;
        isSuccess = TRUE;
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    isSuccess = TRUE;
#endif

    return isSuccess;
}


RU64
    rpal_time_get_hires_timestamp
    (
        rpal_hires_timestamp_metadata* metadata
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    LARGE_INTEGER timestamp_ticks;

    if ( metadata->ticks_per_second == 0ull )
    {
        return 0ull;
    }

    if ( !QueryPerformanceCounter( &timestamp_ticks ) )
    {
        return 0ull;
    }
    return ( timestamp_ticks.QuadPart * 1000000ull ) / metadata->ticks_per_second;

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )

    struct timeval tv = { 0 };
    if ( 0 != gettimeofday( &tv, NULL ) )
    {
        return 0ull;
    }
    return ( ( RU64 )tv.tv_sec ) * 1000000ull + ( ( RU64 )tv.tv_usec );

#endif
}
