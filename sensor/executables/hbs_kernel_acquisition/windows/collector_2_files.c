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
#include <fltKernel.h>

#ifndef _NUM_BUFFERED_FILES
    #define _NUM_BUFFERED_FILES 200
#endif

// Missing from older versions of the DDK
#define FileDispositionInformationEx 64

static KSPIN_LOCK g_collector_2_mutex = { 0 };
static KernelAcqFileIo g_files[ _NUM_BUFFERED_FILES ] = { 0 };
static RU32 g_nextFile = 0;
static PFLT_FILTER g_filter = NULL;

typedef struct
{
    RBOOL isDelete;
    RBOOL isNew;
    RBOOL isChanged;
    RBOOL isRead;
    RU32 lastWritePid;
    RU32 lastReadPid;
} _fileContext;

static
_fileContext*
    _getOrSetContext
    (
        PFLT_CALLBACK_DATA Data
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    _fileContext* context = NULL;
    _fileContext* oldContext = NULL;

    status = FltGetFileContext( Data->Iopb->TargetInstance,
                                Data->Iopb->TargetFileObject,
                                &context );

    if( STATUS_NOT_FOUND == status )
    {
        status = FltAllocateContext( g_filter,
                                     FLT_FILE_CONTEXT,
                                     sizeof( _fileContext ),
                                     NonPagedPool,
                                     (PFLT_CONTEXT*)&context );
        
        if( STATUS_SUCCESS == status )
        {
            context->isNew = FALSE;
            context->isDelete = FALSE;
            context->isChanged = FALSE;
            context->isRead = FALSE;
            context->lastWritePid = 0;
            context->lastReadPid = 0;

            status = FltSetFileContext( Data->Iopb->TargetInstance,
                                        Data->Iopb->TargetFileObject,
                                        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                        context,
                                        &oldContext );

            if( STATUS_FLT_CONTEXT_ALREADY_DEFINED == status )
            {
                FltReleaseContext( (PFLT_CONTEXT)context );
                context = oldContext;
            }
            else if( STATUS_SUCCESS != status )
            {
                FltReleaseContext( (PFLT_CONTEXT)context );
                context = NULL;
            }
        }
    }

    if( NULL_CONTEXT == context )
    {
        context = NULL;
    }

    return context;
}

static
FLT_PREOP_CALLBACK_STATUS
    FileCreateFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if( UserMode != Data->RequestorMode )
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileCreateFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    PFLT_FILE_NAME_INFORMATION fileInfo = NULL;
    RU32 pid = 0;
    RU64 ts = 0;
    RU32 createOptions = 0;
    RU32 createDispositions = 0;
    _fileContext* context = NULL;
    
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    // We only care about user mode for now.
    if( UserMode != Data->RequestorMode ||
        STATUS_SUCCESS != Data->IoStatus.Status )
    {
        return status;
    }

    if( FILE_CREATED == Data->IoStatus.Information )
    {
        pid = (RU32)FltGetRequestorProcessId( Data );
        ts = rpal_time_getLocal();
        
        if( !NT_SUCCESS( FltGetFileNameInformation( Data,
                                                    FLT_FILE_NAME_NORMALIZED |
                                                    FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                    &fileInfo ) ) )
        {
            rpal_debug_kernel( "Failed to get file name info" );
            fileInfo = NULL;
        }
        else
        {
            //rpal_debug_kernel( "NEW: %wZ", fileInfo->Name );
        }

        if( NULL != ( context = _getOrSetContext( Data ) ) )
        {
            context->isNew = TRUE;
            FltReleaseContext( (PFLT_CONTEXT)context );
        }

        KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

        g_files[ g_nextFile ].pid = pid;
        g_files[ g_nextFile ].ts = ts;
        g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;
        g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_ADDED;

        if( NULL != fileInfo )
        {
            copyUnicodeStringToBuffer( &fileInfo->Name,
                                       g_files[ g_nextFile ].path );

            FltReleaseFileNameInformation( fileInfo );
        }

        g_nextFile++;
        if( g_nextFile == _NUM_BUFFERED_FILES )
        {
            g_nextFile = 0;
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );
    }

    createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    createDispositions = ( Data->Iopb->Parameters.Create.Options & 0xFF000000 ) >> 24;

    if( IS_FLAG_ENABLED( createOptions, FILE_DELETE_ON_CLOSE ) )
    {
        if( NULL != ( context = _getOrSetContext( Data ) ) )
        {
            context->isDelete = TRUE;
            FltReleaseContext( (PFLT_CONTEXT)context );
        }
    }

    return status;
}

static
FLT_PREOP_CALLBACK_STATUS
    FileSetInfoFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PFLT_FILE_NAME_INFORMATION fileInfoSrc = NULL;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if( FileRenameInformation == Data->Iopb->Parameters.SetFileInformation.FileInformationClass )
    {
        // For a move, we keep the original path before the move
        if( NT_SUCCESS( FltGetFileNameInformation( Data,
                                                   FLT_FILE_NAME_NORMALIZED |
                                                   FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                   &fileInfoSrc ) ) )
        {
            status = FLT_PREOP_SYNCHRONIZE;
            *CompletionContext = fileInfoSrc;
        }
    }
    else if( FileDispositionInformation == Data->Iopb->Parameters.SetFileInformation.FileInformationClass ||
             FileDispositionInformationEx == Data->Iopb->Parameters.SetFileInformation.FileInformationClass )
    {
        status = FLT_PREOP_SYNCHRONIZE;
    }

    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileSetInfoFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    PFLT_FILE_NAME_INFORMATION fileInfoSrc = NULL;
    PFLT_FILE_NAME_INFORMATION fileInfoDst = NULL;
    RU32 pid = 0;
    RU64 ts = 0;
    RU32 createOptions = 0;
    RU32 createDispositions = 0;
    PFILE_RENAME_INFORMATION renameInfo = NULL;
    _fileContext* context = NULL;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    // We only care about user mode for now.
    if( UserMode != Data->RequestorMode ||
        STATUS_SUCCESS != Data->IoStatus.Status )
    {
        return status;
    }

    if( FileRenameInformation == Data->Iopb->Parameters.SetFileInformation.FileInformationClass )
    {
        if( NULL != ( fileInfoSrc = (PFLT_FILE_NAME_INFORMATION)CompletionContext ) )
        {
            //rpal_debug_kernel( "MOVE OLD: %wZ", fileInfoSrc->Name );
        }
        else
        {
            rpal_debug_kernel( "Failed to get src file name info" );
        }

        renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if( !NT_SUCCESS( FltGetDestinationFileNameInformation( FltObjects->Instance,
                                                               FltObjects->FileObject,
                                                               renameInfo->RootDirectory,
                                                               renameInfo->FileName,
                                                               renameInfo->FileNameLength,
                                                               FLT_FILE_NAME_NORMALIZED |
                                                               FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                               &fileInfoDst ) ) )
        {
            rpal_debug_kernel( "Failed to get dst file name info" );
        }
        else
        {
            //rpal_debug_kernel( "MOVE TO: %wZ", fileInfoDst->Name );
        }

        pid = (RU32)FltGetRequestorProcessId( Data );
        ts = rpal_time_getLocal();

        createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
        createDispositions = ( Data->Iopb->Parameters.Create.Options & 0xFF000000 ) >> 24;

        KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

        g_files[ g_nextFile ].pid = pid;
        g_files[ g_nextFile ].ts = ts;
        g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;

        // For compability with the user mode API we report file moves
        // as two different operations.

        // First we report the old file name.
        g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_RENAME_OLD;

        if( NULL != fileInfoSrc )
        {
            copyUnicodeStringToBuffer( &fileInfoSrc->Name,
                                       g_files[ g_nextFile ].path );

            FltReleaseFileNameInformation( fileInfoSrc );
        }

        g_nextFile++;
        if( g_nextFile == _NUM_BUFFERED_FILES )
        {
            g_nextFile = 0;
        }

        // Now report the new file name.
        g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_RENAME_NEW;

        if( NULL != fileInfoDst )
        {
            copyUnicodeStringToBuffer( &fileInfoDst->Name,
                                       g_files[ g_nextFile ].path );

            FltReleaseFileNameInformation( fileInfoDst );
        }

        g_nextFile++;
        if( g_nextFile == _NUM_BUFFERED_FILES )
        {
            g_nextFile = 0;
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );
    }
    else if( FileDispositionInformationEx == Data->Iopb->Parameters.SetFileInformation.FileInformationClass ||
             ( FileDispositionInformation == Data->Iopb->Parameters.SetFileInformation.FileInformationClass &&
               ( (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer )->DeleteFile ) )
    {
        if( NULL != ( context = _getOrSetContext( Data ) ) )
        {
            context->isDelete = TRUE;

            FltReleaseContext( (PFLT_CONTEXT)context );
        }
    }

    return status;
}


static
FLT_PREOP_CALLBACK_STATUS
    FileCleanupFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    _fileContext* context = NULL;
    PFLT_FILE_NAME_INFORMATION fileInfo = NULL;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if( NT_SUCCESS( FltGetFileContext( Data->Iopb->TargetInstance,
                                       Data->Iopb->TargetFileObject,
                                       &context ) ) )
    {
        if( context->isDelete )
        {
            status = FLT_PREOP_SYNCHRONIZE;

            if( !NT_SUCCESS( FltGetFileNameInformation( Data,
                                                        FLT_FILE_NAME_NORMALIZED |
                                                        FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                        &fileInfo ) ) )
            {
                fileInfo = NULL;
            }

            *CompletionContext = fileInfo;
        }

        FltReleaseContext( (PFLT_CONTEXT)context );
    }


    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileCleanupFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    PFLT_FILE_NAME_INFORMATION fileInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
    FILE_STANDARD_INFORMATION fileStdInfo = { 0 };
    RU32 pid = 0;
    RU64 ts = 0;
    _fileContext* context = NULL;
    
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    if( NT_SUCCESS( FltGetFileContext( Data->Iopb->TargetInstance,
                                       Data->Iopb->TargetFileObject,
                                       &context ) ) )
    {
        if( STATUS_SUCCESS == Data->IoStatus.Status )
        {
            if( context->isDelete &&
                STATUS_FILE_DELETED == FltQueryInformationFile( Data->Iopb->TargetInstance,
                                                                Data->Iopb->TargetFileObject,
                                                                &fileStdInfo,
                                                                sizeof( fileStdInfo ),
                                                                FileStandardInformation,
                                                                NULL ) )
            {
                if( NULL == fileInfo )
                {
                    rpal_debug_kernel( "Failed to get file name info" );
                }
                else
                {
                    //rpal_debug_kernel( "DEL: %wZ", fileInfo->Name );
                }

                pid = (RU32)FltGetRequestorProcessId( Data );
                ts = rpal_time_getLocal();

                KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

                g_files[ g_nextFile ].pid = pid;
                g_files[ g_nextFile ].ts = ts;
                g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;
                g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_REMOVED;

                if( NULL != fileInfo )
                {
                    copyUnicodeStringToBuffer( &fileInfo->Name,
                                               g_files[ g_nextFile ].path );
                }

                g_nextFile++;
                if( g_nextFile == _NUM_BUFFERED_FILES )
                {
                    g_nextFile = 0;
                }

                KeReleaseInStackQueuedSpinLock( &hMutex );
            }
        }

        FltReleaseContext( context );
        FltDeleteFileContext( Data->Iopb->TargetInstance,
                              Data->Iopb->TargetFileObject,
                              NULL );
    }

    if( NULL != fileInfo )
    {
        FltReleaseFileNameInformation( fileInfo );
    }

    return status;
}


static
FLT_PREOP_CALLBACK_STATUS
    FileWriteFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SYNCHRONIZE;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if( UserMode != Data->RequestorMode )
    {
        status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileWriteFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
    _fileContext* context = NULL;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    PFLT_FILE_NAME_INFORMATION fileInfo = NULL;
    RU32 pid = 0;
    RU64 ts = 0;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    // We only care about user mode for now.
    if( UserMode != Data->RequestorMode ||
        STATUS_SUCCESS != Data->IoStatus.Status )
    {
        return status;
    }

    if( NULL != ( context = _getOrSetContext( Data ) ) )
    {
        pid = (RU32)FltGetRequestorProcessId( Data );

        if( 0 != pid &&
            ( !context->isChanged ||
              context->lastWritePid != pid ) &&
            !context->isNew )
        {
            context->isChanged = TRUE;
            context->lastWritePid = pid;

            if( !NT_SUCCESS( FltGetFileNameInformation( Data,
                                                        FLT_FILE_NAME_NORMALIZED |
                                                        FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                        &fileInfo ) ) )
            {
                rpal_debug_kernel( "Failed to get file name info" );
                fileInfo = NULL;
            }
            else
            {
                //rpal_debug_kernel( "WRITE: %d %wZ", pid, fileInfo->Name );

                if( 0 == pid )
                {
                    pid = (RU32)FltGetRequestorProcessId( Data );
                }
                ts = rpal_time_getLocal();

                KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

                g_files[ g_nextFile ].pid = pid;
                g_files[ g_nextFile ].ts = ts;
                g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;
                g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_MODIFIED;

                if( NULL != fileInfo )
                {
                    copyUnicodeStringToBuffer( &fileInfo->Name,
                                               g_files[ g_nextFile ].path );

                    FltReleaseFileNameInformation( fileInfo );
                }

                g_nextFile++;
                if( g_nextFile == _NUM_BUFFERED_FILES )
                {
                    g_nextFile = 0;
                }

                KeReleaseInStackQueuedSpinLock( &hMutex );
            }
        }

        FltReleaseContext( (PFLT_CONTEXT)context );
    }

    return status;
}


static
FLT_PREOP_CALLBACK_STATUS
    FileReadFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SYNCHRONIZE;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if( UserMode != Data->RequestorMode )
    {
        status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileReadFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
    _fileContext* context = NULL;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    PFLT_FILE_NAME_INFORMATION fileInfo = NULL;
    RU32 pid = 0;
    RU64 ts = 0;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    // We only care about user mode for now.
    if( UserMode != Data->RequestorMode ||
        STATUS_SUCCESS != Data->IoStatus.Status )
    {
        return status;
    }

    if( NULL != ( context = _getOrSetContext( Data ) ) )
    {
        pid = (RU32)FltGetRequestorProcessId( Data );

        if( 0 != pid &&
            ( !context->isRead ||
              context->lastReadPid != pid ) &&
            !context->isNew )
        {
            context->isRead = TRUE;
            context->lastReadPid = pid;

            if( !NT_SUCCESS( FltGetFileNameInformation( Data,
                                                        FLT_FILE_NAME_NORMALIZED |
                                                        FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                        &fileInfo ) ) )
            {
                rpal_debug_kernel( "Failed to get file name info" );
                fileInfo = NULL;
            }
            else
            {
                //rpal_debug_kernel( "READ: %d %wZ", pid, fileInfo->Name );

                if( 0 == pid )
                {
                    pid = (RU32)FltGetRequestorProcessId( Data );
                }
                ts = rpal_time_getLocal();

                KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

                g_files[ g_nextFile ].pid = pid;
                g_files[ g_nextFile ].ts = ts;
                g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;
                g_files[ g_nextFile ].action = KERNEL_ACQ_FILE_ACTION_READ;

                if( NULL != fileInfo )
                {
                    copyUnicodeStringToBuffer( &fileInfo->Name,
                                               g_files[ g_nextFile ].path );

                    FltReleaseFileNameInformation( fileInfo );
                }

                g_nextFile++;
                if( g_nextFile == _NUM_BUFFERED_FILES )
                {
                    g_nextFile = 0;
                }

                KeReleaseInStackQueuedSpinLock( &hMutex );
            }
        }

        FltReleaseContext( (PFLT_CONTEXT)context );
    }

    return status;
}

static
NTSTATUS
    FileFilterUnload
    (
        FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );
    FltUnregisterFilter( g_filter );
    return STATUS_SUCCESS;
}

static
NTSTATUS
    FileFilterQueryTeardown
    (
        PCFLT_RELATED_OBJECTS FltObjects,
        FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    return STATUS_SUCCESS;
}

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg("INIT")
#pragma const_seg("INIT")
#endif

const FLT_OPERATION_REGISTRATION g_filterCallbacks[] = {
    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO |
          FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      FileCreateFilterPreCallback,
      FileCreateFilterPostCallback },
    { IRP_MJ_SET_INFORMATION,
      FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO |
          FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      FileSetInfoFilterPreCallback,
      FileSetInfoFilterPostCallback },
    { IRP_MJ_CLEANUP,
      FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO |
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      FileCleanupFilterPreCallback,
      FileCleanupFilterPostCallback },
    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO |
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      FileWriteFilterPreCallback,
      FileWriteFilterPostCallback },
    { IRP_MJ_READ,
      FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO |
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      FileReadFilterPreCallback,
      FileReadFilterPostCallback },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION g_filterContexts[] = {
    { FLT_FILE_CONTEXT,
      0,
      NULL,
      sizeof( _fileContext ),
      'hbsa',
      NULL,
      NULL,
      NULL },
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION g_filterRegistration = 
{
    sizeof( FLT_REGISTRATION ),             //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    0,                                      //  Flags
    g_filterContexts,                       //  Context
    g_filterCallbacks,                      //  Operation callbacks
    FileFilterUnload,                       //  FilterUnload
    NULL,                                   //  InstanceSetup
    FileFilterQueryTeardown,                //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete
    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg()
#pragma const_seg()
#endif

RBOOL
    task_get_new_files
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
        KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( KernelAcqFileIo );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextFile ? g_nextFile : toCopy );

            *resultSize = toCopy * sizeof( KernelAcqFileIo );
            memcpy( pResult, g_files, *resultSize );

            g_nextFile -= toCopy;
            memmove( g_files, g_files + toCopy, g_nextFile );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_2_initialize
    (
        PDRIVER_OBJECT driverObject,
        PDEVICE_OBJECT deviceObject
    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( deviceObject );

#ifndef _DISABLE_COLLECTOR_2
    KeInitializeSpinLock( &g_collector_2_mutex );

    status = FltRegisterFilter( driverObject, &g_filterRegistration, &g_filter );

    if( NT_SUCCESS( status ) )
    {
        status = FltStartFiltering( g_filter );
        if( NT_SUCCESS( status ) )
        {
            isSuccess = TRUE;
        }
        else
        {
            rpal_debug_kernel( "Failed to start: 0x%08X", status );
            FltUnregisterFilter( g_filter );
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to initialize: 0x%08X", status );
    }
#else
    UNREFERENCED_PARAMETER( driverObject );
    isSuccess = TRUE;
#endif

    return isSuccess;
}

RBOOL
    collector_2_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

#ifndef _DISABLE_COLLECTOR_2
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
