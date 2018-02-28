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

#include <ntifs.h>
#include <wdmsec.h>
#include <rpal/rpal_datatypes.h>
#include <kernelAcquisitionLib/common.h>
#include "collectors.h"

#define RPAL_PLATFORM_DEBUG

DRIVER_INITIALIZE           DriverEntry;
DRIVER_UNLOAD               DriverUnload;
__drv_dispatchType( IRP_MJ_CREATE );
DRIVER_DISPATCH DispatchCreate;
__drv_dispatchType( IRP_MJ_CLOSE );
DRIVER_DISPATCH DispatchClose;
__drv_dispatchType( IRP_MJ_DEVICE_CONTROL );
DRIVER_DISPATCH DispatchControl;


#ifdef RPAL_PLATFORM_DEBUG
    #define ACCESS_SDDL     SDDL_DEVOBJ_SYS_ALL_ADM_ALL
#else
    #define ACCESS_SDDL     SDDL_DEVOBJ_SYS_ALL
#endif

#define DEVICE_NAME         _WCH("\\Device\\") ## ACQUISITION_COMMS_NAME
#define DEVICE_UM_NAME      _WCH("\\DosDevices\\") ## ACQUISITION_COMMS_NAME

#pragma warning(disable: 4276)

#define _COLLECTOR_INIT(cId) { collector_ ## cId ## _initialize, collector_ ## cId ## _deinitialize }
#define _COLLECTOR_DISABLED(cId) { NULL, NULL }

typedef struct
{
    RBOOL( *initializer )( PDRIVER_OBJECT driverObject, PDEVICE_OBJECT deviceObject );
    RBOOL( *deinitializer )( );
} CollectorContext;

static KSPIN_LOCK g_connection_mutex = { 0 };
static RBOOL g_is_connected = FALSE;
RU32 g_owner_pid = 0;

//=========================================================================
//  Built-in Tasks
//=========================================================================
static
RBOOL
    task_ping
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pArgs &&
        sizeof( RU32 ) == argsSize &&
        NULL != pResult &&
        NULL != resultSize &&
        sizeof( RU32 ) == *resultSize &&
        ACQUISITION_COMMS_CHALLENGE == *(RU32*)pArgs )
    {
        *(RU32*)pResult = ACQUISITION_COMMS_RESPONSE;
        *resultSize = sizeof( RU32 );
        
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Invalid challenge: %p:%d / %p:%d",
                           pArgs,
                           argsSize,
                           pResult,
                           *resultSize );
    }

    return isSuccess;
}

//=========================================================================
//  Dispatcher
//=========================================================================
static CollectorContext g_collectors[] = { _COLLECTOR_INIT( 1 ),
                                           _COLLECTOR_INIT( 2 ),
                                           _COLLECTOR_INIT( 3 ),
                                           _COLLECTOR_INIT( 4 ) };
static collector_task g_tasks[ KERNEL_ACQ_NUM_OPS  ] = { task_ping,
                                                         task_get_new_processes,
                                                         task_get_new_files,
                                                         task_get_new_module_loads,
                                                         task_get_new_network,
                                                         task_get_new_dns,
                                                         task_segregate_network,
                                                         task_rejoin_network };


NTSTATUS
    UserModeDispatcher
    (
        RU32 op,
        RU32 argsSize,
        RU32* pSizeUsed,
        RPU8 pArgs,
        RPU8 ioBuffer
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    RBOOL isSuccess = FALSE;

    if( NULL != ioBuffer &&
        NULL != pSizeUsed )
    {
        if( op >= ARRAY_N_ELEM( g_tasks ) ||
            NULL == g_tasks[ op ] )
        {
            status = STATUS_INVALID_PARAMETER;
        }

        isSuccess = g_tasks[ op ]( pArgs, argsSize, ioBuffer, pSizeUsed );

        if( !isSuccess )
        {
            status = STATUS_UNSUCCESSFUL;
        }
    }

    return status;
}

//=========================================================================
//  Kernel / User Comms
//=========================================================================
NTSTATUS
    DispatchClose
    (
        PDEVICE_OBJECT DeviceObject,
        PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( Irp );

    UNREFERENCED_PARAMETER( DeviceObject );

    if( NULL == irpStack ||
        IRP_MJ_CLOSE != irpStack->MajorFunction )
    {
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        KeAcquireInStackQueuedSpinLock( &g_connection_mutex, &hMutex );
        if( g_is_connected )
        {
            g_is_connected = FALSE;
            g_owner_pid = 0;
        }
        else
        {
            rpal_debug_kernel( "Close called but device not connected!" );
        }
        KeReleaseInStackQueuedSpinLock( &hMutex );
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return status;
}

NTSTATUS
    DispatchCreate
    (
        PDEVICE_OBJECT DeviceObject,
        PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( Irp );
    
    UNREFERENCED_PARAMETER( DeviceObject );

    if( NULL == irpStack ||
        IRP_MJ_CREATE != irpStack->MajorFunction )
    {
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        KeAcquireInStackQueuedSpinLock( &g_connection_mutex, &hMutex );
        
        if( g_is_connected )
        {
            status = STATUS_DEVICE_BUSY;
        }
        else
        {
            g_owner_pid = IoGetRequestorProcessId( Irp );
            rpal_debug_kernel( "connected to %d", g_owner_pid );
            g_is_connected = TRUE;
        }
        KeReleaseInStackQueuedSpinLock( &hMutex );
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return status;
}

NTSTATUS
    DispatchControl
    (
        PDEVICE_OBJECT DeviceObject,
        PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    
    PIO_STACK_LOCATION irpStack = NULL;

    RU32 controlCode = 0;
    RU32 inputLength = 0;
    KernelAcqCommand* cmd = NULL;
    RU32 outputLength = 0;
    RPU8 ioBuffer = NULL;
    
    UNREFERENCED_PARAMETER( DeviceObject );

    irpStack = IoGetCurrentIrpStackLocation( Irp );

    if( NULL == irpStack ||
        IRP_MJ_DEVICE_CONTROL != irpStack->MajorFunction )
    {
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        Irp->IoStatus.Information = 0;

        controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
        inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        cmd = (KernelAcqCommand*)Irp->AssociatedIrp.SystemBuffer;
        ioBuffer = Irp->AssociatedIrp.SystemBuffer;
        outputLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

        if( NULL != cmd &&
            sizeof( KernelAcqCommand ) <= inputLength &&
            inputLength >= cmd->dataOffset )
        {
            status = UserModeDispatcher( cmd->op,
                                         inputLength - cmd->dataOffset,
                                         &outputLength,
                                         cmd->data,
                                         ioBuffer );

            if( NT_SUCCESS( status ) )
            {
                Irp->IoStatus.Information = outputLength;
            }
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return status;
}

//=========================================================================
//  Entry Points
//=========================================================================
VOID
    DriverUnload
    (
        PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING winDeviceName = { 0 };

    RU32 i = 0;

    RtlInitUnicodeString( &winDeviceName, DEVICE_UM_NAME );

    for( i = 0; i < ARRAY_N_ELEM( g_collectors ); i++ )
    {
        if( NULL == g_collectors[ i ].deinitializer ) continue;

        if( !g_collectors[ i ].deinitializer() )
        {
            rpal_debug_kernel( "Failed to deinitialize collector %d.", i + 1 );
        }
    }

    IoDeleteSymbolicLink( &winDeviceName );
    IoDeleteDevice( DriverObject->DeviceObject );
}

NTSTATUS
    DriverEntry
    (
        PDRIVER_OBJECT  DriverObject, 
        PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING ntDeviceName = { 0 };
    UNICODE_STRING winDeviceName = { 0 };
    PDEVICE_OBJECT device = NULL;

    RS32 i = 0;

    UNREFERENCED_PARAMETER( RegistryPath );

    RtlInitUnicodeString( &ntDeviceName, DEVICE_NAME );
    RtlInitUnicodeString( &winDeviceName, DEVICE_UM_NAME );

    status = IoCreateDeviceSecure( DriverObject,
                                   0,
                                   &ntDeviceName,
                                   FILE_DEVICE_TRANSPORT,
                                   FILE_DEVICE_SECURE_OPEN,
                                   FALSE,
                                   &ACCESS_SDDL,
                                   NULL,
                                   &device );
    
    if( !NT_SUCCESS( status ) )
    {
        return status;
    }

    DriverObject->MajorFunction[ IRP_MJ_CREATE ] = DispatchCreate;
    DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = DispatchClose;
    DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = DispatchControl;
    DriverObject->DriverUnload = DriverUnload;

    status = IoCreateSymbolicLink( &winDeviceName, &ntDeviceName );

    if( !NT_SUCCESS( status ) )
    {
        IoDeleteDevice( DriverObject->DeviceObject );
        return status;
    }

    for( i = 0; i < ARRAY_N_ELEM( g_collectors ); i++ )
    {
        if( NULL == g_collectors[ i ].initializer ) continue;

        if( !g_collectors[ i ].initializer( DriverObject, DriverObject->DeviceObject ) )
        {
            rpal_debug_kernel( "Failed to initialize collector %d.", i + 1 );
            status = STATUS_FAILED_DRIVER_ENTRY;
            break;
        }
    }

    if( !NT_SUCCESS( status ) )
    {
        for( i = i - 1; i >= 0; i-- )
        {
            if( NULL == g_collectors[ i ].deinitializer ) continue;

            g_collectors[ i ].deinitializer();
        }

        IoDeleteSymbolicLink( &winDeviceName );
        IoDeleteDevice( DriverObject->DeviceObject );
    }

    return status;
}
