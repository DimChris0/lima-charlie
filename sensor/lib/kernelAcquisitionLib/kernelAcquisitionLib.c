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

#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define RPAL_FILE_ID   105

rMutex g_km_mutex = NULL;
#define KERNEL_ACQUISITION_TIMEOUT      5

#ifdef RPAL_PLATFORM_MACOSX
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <mach/mach_types.h>
    #include <sys/errno.h>
    #include <sys/kern_control.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
    #include <sys/sys_domain.h>

    static int g_km_socket = (-1);
#elif defined( RPAL_PLATFORM_WINDOWS )
    #define LOCAL_COMMS_NAME    _WCH("\\\\.\\") ## ACQUISITION_COMMS_NAME
    static HANDLE g_km_handle = INVALID_HANDLE_VALUE;
#endif

static RBOOL g_is_available = FALSE;

static RBOOL g_platform_availability[ KERNEL_ACQ_NUM_OPS ] = {
#ifdef RPAL_PLATFORM_MACOSX
    TRUE, // KERNEL_ACQ_OP_PING
    TRUE, // KERNEL_ACQ_OP_GET_NEW_PROCESSES
    TRUE, // KERNEL_ACQ_OP_GET_NEW_FILE_IO
    FALSE, // KERNEL_ACQ_OP_NEW_MODULE
    TRUE, // KERNEL_ACQ_OP_NEW_NETWORK
    TRUE, // KERNEL_ACQ_OP_DNS
    TRUE, // KERNEL_ACQ_OP_SEGREGATE_NETWORK
    TRUE, // KERNEL_ACQ_OP_REJOIN_NETWORK
#elif defined( RPAL_PLATFORM_WINDOWS )
    TRUE, // KERNEL_ACQ_OP_PING
    TRUE, // KERNEL_ACQ_OP_GET_NEW_PROCESSES
    TRUE, // KERNEL_ACQ_OP_GET_NEW_FILE_IO
    TRUE, // KERNEL_ACQ_OP_NEW_MODULE
    TRUE, // KERNEL_ACQ_OP_NEW_NETWORK
    TRUE, // KERNEL_ACQ_OP_DNS
    TRUE, // KERNEL_ACQ_OP_SEGREGATE_NETWORK
    TRUE, // KERNEL_ACQ_OP_REJOIN_NETWORK
#endif
};

RPRIVATE
RBOOL
    _kAcq_init
    (
        RBOOL isLock
    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_MACOSX
    int result = 0;
    struct ctl_info info = { 0 };
    struct sockaddr_ctl addr = { 0 };
    if( ( -1 ) == g_km_socket )
    {
        g_is_available = FALSE;

        if( !isLock ||
            NULL != ( g_km_mutex = rMutex_create() ) )
        {
            if( ( -1 ) != ( g_km_socket = socket( PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL ) ) )
            {
                strncpy( info.ctl_name, ACQUISITION_COMMS_NAME, sizeof( info.ctl_name ) );
                if( 0 == ioctl( g_km_socket, CTLIOCGINFO, &info ) )
                {
                    addr.sc_id = info.ctl_id;
                    addr.sc_unit = 0;
                    addr.sc_len = sizeof( struct sockaddr_ctl );
                    addr.sc_family = AF_SYSTEM;
                    addr.ss_sysaddr = AF_SYS_CONTROL;
                    if( 0 == ( result = connect( g_km_socket, ( struct sockaddr * )&addr, sizeof( addr ) ) ) )
                    {
                        g_is_available = TRUE;
                        isSuccess = TRUE;
                    }
                }

                if( !isSuccess )
                {
                    close( g_km_socket );
                    g_km_socket = ( -1 );
                }
            }

            if( !isSuccess &&
                isLock )
            {
                rMutex_free( g_km_mutex );
                g_km_mutex = NULL;
            }
        }
    }
    else
    {
        isSuccess = TRUE;
    }
#elif defined( RPAL_PLATFORM_WINDOWS )
    if( INVALID_HANDLE_VALUE == g_km_handle )
    {
        g_is_available = FALSE;

        if( !isLock ||
            NULL != ( g_km_mutex = rMutex_create() ) )
        {
            if( INVALID_HANDLE_VALUE != ( g_km_handle = CreateFileW( LOCAL_COMMS_NAME,
                                                                     GENERIC_READ,
                                                                     0,
                                                                     NULL,
                                                                     OPEN_EXISTING,
                                                                     FILE_ATTRIBUTE_NORMAL,
                                                                     NULL ) ) )
            {
                g_is_available = TRUE;
                isSuccess = TRUE;
            }
            else if( isLock )
            {
                rMutex_free( g_km_mutex );
                g_km_mutex = NULL;
            }
        }
    }
    else
    {
        g_is_available = TRUE;
        isSuccess = TRUE;
    }
#endif

    return isSuccess;
}

RBOOL
    kAcq_init
    (

    )
{
    return _kAcq_init( TRUE );
}

RPRIVATE
RBOOL
    _kAcq_deinit
    (
        RBOOL isLock
    )
{
    RBOOL isSuccess = FALSE;


    if( !isLock ||
        rMutex_lock( g_km_mutex ) )
    {
        g_is_available = FALSE;

#ifdef RPAL_PLATFORM_MACOSX
        if( ( -1 ) != g_km_socket )
        {
            close( g_km_socket );
            g_km_socket = ( -1 );
            isSuccess = TRUE;
        }
#elif defined( RPAL_PLATFORM_WINDOWS )
        if( INVALID_HANDLE_VALUE != g_km_handle )
        {
            CloseHandle( g_km_handle );
            g_km_handle = INVALID_HANDLE_VALUE;
        }
#endif
        if( isLock )
        {
            rMutex_free( g_km_mutex );
            g_km_mutex = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_deinit
    (

    )
{
    return _kAcq_deinit( TRUE );
}

RPRIVATE
RU32
    _krnlSendReceive
    (
        RU32 op,
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32 resultSize,
        RU32* pSizeUsed
    )
{
    RU32 error = (RU32)(-1);
    RU32 nRetries = 1;

    // Check whether this particular function is available on
    // this platform via kernel.
    if( op >= KERNEL_ACQ_NUM_OPS ||
        !g_platform_availability[ op ] )
    {
        return error;
    }

    if( rMutex_lock( g_km_mutex ) )
    {
        while( 0 != nRetries )
        {
#ifdef RPAL_PLATFORM_MACOSX
            KernelAcqCommand cmd = { 0 };
            cmd.pArgs = pArgs;
            cmd.argsSize = argsSize;
            cmd.pResult = pResult;
            cmd.resultSize = resultSize;
            cmd.pSizeUsed = pSizeUsed;
            fd_set readset = { 0 };
            struct timeval timeout = { 0 };
            int waitVal = 0;

            if( 0 != ( error = setsockopt( g_km_socket, SYSPROTO_CONTROL, op, &cmd, sizeof( cmd ) ) ) )
            {
                error = errno;
            }
#elif defined( RPAL_PLATFORM_WINDOWS )
            RU32 ioBufferSize = sizeof( KernelAcqCommand ) + argsSize;
            RPU8 ioBuffer = NULL;
            KernelAcqCommand* pCmd = NULL;

            if( NULL != ( ioBuffer = rpal_memory_alloc( ioBufferSize ) ) )
            {
                pCmd = (KernelAcqCommand*)ioBuffer;
                pCmd->op = op;
                pCmd->dataOffset = sizeof( KernelAcqCommand );
                pCmd->argsSize = argsSize;
                if( NULL != pArgs && 0 != argsSize )
                {
                    rpal_memory_memcpy( pCmd->data, pArgs, argsSize );
                }

                if( DeviceIoControl( g_km_handle,
                                     (DWORD)IOCTL_EXCHANGE_DATA,
                                     ioBuffer,
                                     ioBufferSize,
                                     pResult,
                                     resultSize,
                                     (LPDWORD)pSizeUsed,
                                     NULL ) )
                {
                    error = 0;
                }
                else
                {
                    error = rpal_error_getLast();
                }

                rpal_memory_free( ioBuffer );
            }
            else
            {
                error = RPAL_ERROR_NOT_ENOUGH_MEMORY;
            }
#else
            UNREFERENCED_PARAMETER( op );
            UNREFERENCED_PARAMETER( pArgs );
            UNREFERENCED_PARAMETER( argsSize );
            UNREFERENCED_PARAMETER( pResult );
            UNREFERENCED_PARAMETER( resultSize );
            UNREFERENCED_PARAMETER( pSizeUsed );
            break;
#endif

            // Success, return in.
            if( 0 == error )
            {
                break;
            }

            // Looks like we had a failure, this may be a sign from the kernel
            // that it must unload, so we'll give it a chance and toggle our
            // connection.
            _kAcq_deinit( FALSE );
            if( !_kAcq_init( FALSE ) )
            {
                break;
            }
            nRetries--;
        }
        rMutex_unlock( g_km_mutex );
    }

    if( 0 != error )
    {
        rpal_debug_warning( "kernel error: %d", error );
    }

    return error;
}

RBOOL
    kAcq_ping
    (

    )
{
    RBOOL isAvailable = FALSE;
    RU32 error = 0;

    RU32 challenge = ACQUISITION_COMMS_CHALLENGE;
    RU32 response = 0;

    RU32 respSize = 0;

    if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_PING, 
                                         (RPU8)&challenge, 
                                         sizeof( challenge ),
                                         (RPU8)&response,
                                         sizeof( response ),
                                         &respSize ) ) &&
        sizeof( RU32 ) == respSize )
    {
        if( ACQUISITION_COMMS_RESPONSE == response )
        {
            isAvailable = TRUE;
            g_is_available = TRUE;
        }
        else
        {
            g_is_available = FALSE;
        }
    }
    else
    {
        g_is_available = FALSE;
    }

    return isAvailable;
}

RBOOL
    kAcq_isAvailable
    (

    )
{
    return g_is_available;
}

RBOOL
    kAcq_getNewProcesses
    (
        KernelAcqProcess* entries,
        RU32* nEntries
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    RU32 respSize = 0;

    if( NULL != entries &&
        NULL != nEntries &&
        0 != *nEntries )
    {
        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_GET_NEW_PROCESSES,
                                             NULL,
                                             0,
                                             (RPU8)entries,
                                             *nEntries * sizeof( *entries ),
                                             &respSize ) ) )
        {
            *nEntries = respSize / sizeof( *entries );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_getNewFileIo
    (
        KernelAcqFileIo* entries,
        RU32* nEntries
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    RU32 respSize = 0;

    if( NULL != entries &&
        NULL != nEntries &&
        0 != *nEntries )
    {
        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_GET_NEW_FILE_IO,
                                             NULL,
                                             0,
                                             (RPU8)entries,
                                             *nEntries * sizeof( *entries ),
                                             &respSize ) ) )
        {
            *nEntries = respSize / sizeof( *entries );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_getNewModules
    (
        KernelAcqModule* entries,
        RU32* nEntries
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    RU32 respSize = 0;

    if( NULL != entries &&
        NULL != nEntries &&
        0 != *nEntries )
    {
        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_MODULE_LOAD,
                                             NULL,
                                             0,
                                             (RPU8)entries,
                                             *nEntries * sizeof( *entries ),
                                             &respSize ) ) )
        {
            *nEntries = respSize / sizeof( *entries );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_getNewConnections
    (
        KernelAcqNetwork* entries,
        RU32* nEntries
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    RU32 respSize = 0;

    if( NULL != entries &&
        NULL != nEntries &&
        0 != *nEntries )
    {
        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_NETWORK_CONN,
                                             NULL,
                                             0,
                                             (RPU8)entries,
                                             *nEntries * sizeof( *entries ),
                                             &respSize ) ) )
        {
            *nEntries = respSize / sizeof( *entries );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_getNewDnsPackets
    (
        KernelAcqDnsPacket* packets,
        RU32* totalSize
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    RU32 respSize = 0;

    if( NULL != packets &&
        NULL != totalSize &&
        0 != *totalSize )
    {
        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_DNS,
                                             NULL,
                                             0,
                                             (RPU8)packets,
                                             *totalSize,
                                             &respSize ) ) )
        {
            *totalSize = respSize;
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    kAcq_segregateNetwork
    (
        
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;

    if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_SEGRAGATE,
                                         NULL,
                                         0,
                                         NULL,
                                         0,
                                         NULL ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    kAcq_rejoinNetwork
    (

    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;

    if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_REJOIN,
                                         NULL,
                                         0,
                                         NULL,
                                         0,
                                         NULL ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}
