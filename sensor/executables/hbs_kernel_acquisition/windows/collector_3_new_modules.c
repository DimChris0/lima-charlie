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

#ifndef _NUM_BUFFERED_MODULES
    #define _NUM_BUFFERED_MODULES 200
#endif

static KSPIN_LOCK g_collector_3_mutex = { 0 };
static KernelAcqModule g_modules[ _NUM_BUFFERED_MODULES ] = { 0 };
static RU32 g_nextModule = 0;

RBOOL
    task_get_new_module_loads
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
        KeAcquireInStackQueuedSpinLock( &g_collector_3_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( KernelAcqModule );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextModule ? g_nextModule : toCopy );

            *resultSize = toCopy * sizeof( KernelAcqModule );
            memcpy( pResult, g_modules, *resultSize );

            g_nextModule -= toCopy;
            memmove( g_modules, g_modules + toCopy, g_nextModule );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

static VOID
    LoadImageNotify
    (
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo
    )
{
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    KeAcquireInStackQueuedSpinLock( &g_collector_3_mutex, &hMutex );


    // We're only interested in starts for now, a non-NULL CreateInfo indicates this.
    g_modules[ g_nextModule ].pid = (RU32)ProcessId;
    g_modules[ g_nextModule ].ts = rpal_time_getLocal();

    if( NULL != FullImageName )
    {
        copyUnicodeStringToBuffer( FullImageName, g_modules[ g_nextModule ].path );
    }

    if( NULL != ImageInfo )
    {
        g_modules[ g_nextModule ].baseAddress = ImageInfo->ImageBase;
        g_modules[ g_nextModule ].imageSize= ImageInfo->ImageSize;
    }
    
    g_nextModule++;
    if( g_nextModule == _NUM_BUFFERED_MODULES )
    {
        g_nextModule = 0;
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

RBOOL
    collector_3_initialize
    (
        PDRIVER_OBJECT driverObject,
        PDEVICE_OBJECT deviceObject
    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( driverObject );
    UNREFERENCED_PARAMETER( deviceObject );

#ifndef _DISABLE_COLLECTOR_3
    KeInitializeSpinLock( &g_collector_3_mutex );

    status = PsSetLoadImageNotifyRoutine( LoadImageNotify );

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
    collector_3_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
   
#ifndef _DISABLE_COLLECTOR_3
    status = PsRemoveLoadImageNotifyRoutine( LoadImageNotify );

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
