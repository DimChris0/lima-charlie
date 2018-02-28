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

#include "collectors.h"
#include "helpers.h"
#include <kernelAcquisitionLib/common.h>

#ifndef _NUM_BUFFERED_PROCESSES
    #define _NUM_BUFFERED_PROCESSES 200
#endif

static KSPIN_LOCK g_collector_1_mutex = { 0 };
static KernelAcqProcess g_processes[ _NUM_BUFFERED_PROCESSES ] = { 0 };
static RU32 g_nextProcess = 0;

RBOOL
    task_get_new_processes
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    RU32 toCopy = 0;

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        KeAcquireInStackQueuedSpinLock( &g_collector_1_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( KernelAcqProcess );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextProcess ? g_nextProcess : toCopy );

            *resultSize = toCopy * sizeof( KernelAcqProcess );
            memcpy( pResult, g_processes, *resultSize );

            g_nextProcess -= toCopy;
            memmove( g_processes, g_processes + toCopy, g_nextProcess );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

static VOID
    CreateProcessNotifyEx
    (
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( Process );

    KeAcquireInStackQueuedSpinLock( &g_collector_1_mutex, &hMutex );

    
    // We're only interested in starts for now, a non-NULL CreateInfo indicates this.
    if( NULL != CreateInfo )
    {
        g_processes[ g_nextProcess ].pid = (RU32)ProcessId;
        g_processes[ g_nextProcess ].ppid = (RU32)PsGetCurrentProcessId();
        g_processes[ g_nextProcess ].ts = rpal_time_getLocal();
        g_processes[ g_nextProcess ].uid = KERNEL_ACQ_NO_USER_ID;

        copyUnicodeStringToBuffer( CreateInfo->ImageFileName, 
                                   g_processes[ g_nextProcess ].path );

        copyUnicodeStringToBuffer( CreateInfo->CommandLine,
                                   g_processes[ g_nextProcess ].cmdline );

        g_nextProcess++;
        if( g_nextProcess == _NUM_BUFFERED_PROCESSES )
        {
            g_nextProcess = 0;
        }
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

RBOOL
    collector_1_initialize
    (
        PDRIVER_OBJECT driverObject,
        PDEVICE_OBJECT deviceObject
    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( driverObject );
    UNREFERENCED_PARAMETER( deviceObject );

#ifndef _DISABLE_COLLECTOR_1
    KeInitializeSpinLock( &g_collector_1_mutex );

    status = PsSetCreateProcessNotifyRoutineEx( CreateProcessNotifyEx, FALSE );

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to initialize: 0x%08X", status );
    }
#else
    isSuccess = TRUE;
#endif

    return isSuccess;
}

RBOOL
    collector_1_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

#ifndef _DISABLE_COLLECTOR_1
    status = PsSetCreateProcessNotifyRoutineEx( CreateProcessNotifyEx, TRUE );

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to deinitialize: 0x%08X", status );
    }
#else
    isSuccess = TRUE;
#endif

    return isSuccess;
}
