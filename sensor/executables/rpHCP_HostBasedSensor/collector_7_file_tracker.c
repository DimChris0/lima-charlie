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

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <kernelAcquisitionLib/common.h>

#define RPAL_FILE_ID          67

RPRIVATE RBOOL g_is_create_enabled = TRUE;
RPRIVATE RBOOL g_is_delete_enabled = TRUE;
RPRIVATE RBOOL g_is_modified_enabled = TRUE;
RPRIVATE RBOOL g_is_read_enabled = TRUE;

RPRIVATE
RBOOL
    _assemble_full_name
    (
        RPNCHAR out,
        RU32 outSize,
        RPNCHAR root,
        RPNCHAR file
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != out &&
        0 != outSize &&
        NULL != root &&
        NULL != file )
    {
        rpal_memory_zero( out, outSize );
        rpal_string_strcat( out, root );

        if( outSize > ( rpal_string_strlen( out ) + rpal_string_strlen( file ) ) * sizeof( RNCHAR ) )
        {
            rpal_string_strcat( out, file );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RPRIVATE
RPVOID
    processUmFileChanges
    (
        rEvent isTimeToStop
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    RNCHAR rootEnv[] = _WCH( "%SYSTEMDRIVE%\\" );
    RNCHAR fullName[ 1024 ] = { 0 };
    rDirWatch watch = NULL;
    RPNCHAR root = NULL;
    RPNCHAR fileName = NULL;
    RU32 apiAction = 0;
    rpcm_tag event = RP_TAGS_INVALID;
    rSequence notif = 0;
    RU64 curTime = 0;

    RU32 mask = 0;

    if( g_is_create_enabled ) mask |= RPAL_DIR_WATCH_CHANGE_CREATION;
    if( g_is_delete_enabled ) mask |= RPAL_DIR_WATCH_CHANGE_FILE_NAME;
    if( g_is_modified_enabled ) mask |= RPAL_DIR_WATCH_CHANGE_LAST_WRITE;

    if( rpal_string_expand( (RPNCHAR)&rootEnv, &root ) &&
        NULL != ( watch = rDirWatch_new( root, mask, TRUE ) ) )
    {
        while( rpal_memory_isValid( isTimeToStop ) &&
               !rEvent_wait( isTimeToStop, 0 ) &&
               !kAcq_isAvailable() )
        {
            event = RP_TAGS_INVALID;

            if( rDirWatch_next( watch, 100, &fileName, &apiAction ) &&
                ( RPAL_DIR_WATCH_ACTION_ADDED == apiAction ||
                  RPAL_DIR_WATCH_ACTION_REMOVED == apiAction ||
                  RPAL_DIR_WATCH_ACTION_MODIFIED == apiAction ) )
            {
                curTime = rpal_time_getGlobalPreciseTime();

                if( _assemble_full_name( fullName, sizeof( fullName ), root, fileName ) )
                {
                    if( NULL != ( notif = rSequence_new() ) )
                    {
                        if( RPAL_DIR_WATCH_ACTION_ADDED == apiAction )
                        {
                            event = RP_TAGS_NOTIFICATION_FILE_CREATE;
                        }
                        else if( RPAL_DIR_WATCH_ACTION_REMOVED == apiAction )
                        {
                            event = RP_TAGS_NOTIFICATION_FILE_DELETE;
                        }
                        else if( RPAL_DIR_WATCH_ACTION_MODIFIED == apiAction )
                        {
                            event = RP_TAGS_NOTIFICATION_FILE_MODIFIED;
                        }

                        if( rSequence_addSTRINGN( notif, RP_TAGS_FILE_PATH, (RPNCHAR)&fullName ) &&
                            hbs_timestampEvent( notif, curTime ) )
                        {
                            hbs_publish( event, notif );
                        }

                        rSequence_free( notif );
                    }
                }
            }
        }

        rDirWatch_free( watch );
    }

    rpal_memory_free( root );
#else
    // There is currently no efficient way to track file changes from UM on
    // Linux and OSX so we just wait for termination or for kernel to become available.
    while( !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) &&
           !kAcq_isAvailable() )
    {

    }
#endif

    return NULL;
}


RPRIVATE
RPVOID
    processKmFileChanges
    (
        rEvent isTimeToStop
    )
{
    rpcm_tag event = RP_TAGS_INVALID;
    rSequence notif = 0;
    RU32 nScratch = 0;
    RU32 prev_nScratch = 0;
    KernelAcqFileIo new_from_kernel[ 200 ] = { 0 };
    KernelAcqFileIo prev_from_kernel[ 200 ] = { 0 };
    RU32 i = 0;
    Atom parentAtom = { 0 };
    RPNCHAR cleanPath = NULL;
    RPNCHAR actualPath = NULL;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 1000 ) )
    {
        nScratch = ARRAY_N_ELEM( new_from_kernel );
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        if( !kAcq_getNewFileIo( new_from_kernel, &nScratch ) )
        {
            rpal_debug_warning( "kernel acquisition for new file io failed" );
            break;
        }

        for( i = 0; i < prev_nScratch; i++ )
        {
            prev_from_kernel[ i ].ts += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

            if( KERNEL_ACQ_FILE_ACTION_ADDED == prev_from_kernel[ i ].action &&
                g_is_create_enabled )
            {
                event = RP_TAGS_NOTIFICATION_FILE_CREATE;
            }
            else if( KERNEL_ACQ_FILE_ACTION_REMOVED == prev_from_kernel[ i ].action &&
                     g_is_delete_enabled )
            {
                event = RP_TAGS_NOTIFICATION_FILE_DELETE;
            }
            else if( KERNEL_ACQ_FILE_ACTION_MODIFIED == prev_from_kernel[ i ].action &&
                     g_is_modified_enabled )
            {
                event = RP_TAGS_NOTIFICATION_FILE_MODIFIED;
            }
            else if( KERNEL_ACQ_FILE_ACTION_READ == prev_from_kernel[ i ].action &&
                     g_is_read_enabled )
            {
                event = RP_TAGS_NOTIFICATION_FILE_READ;
            }
            else
            {
                continue;
            }

            if( NULL != ( notif = rSequence_new() ) )
            {
                parentAtom.key.process.pid = prev_from_kernel[ i ].pid;
                parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                if( atoms_query( &parentAtom, prev_from_kernel[ i ].ts ) )
                {
                    HbsSetParentAtom( notif, parentAtom.id );
                }

                actualPath = prev_from_kernel[ i ].path;

                if( NULL != ( cleanPath = rpal_file_clean( prev_from_kernel[ i ].path ) ) )
                {
                    actualPath = cleanPath;
                }

                if( rSequence_addSTRINGN( notif, RP_TAGS_FILE_PATH, actualPath ) &&
                    rSequence_addRU32( notif, RP_TAGS_PROCESS_ID, prev_from_kernel[ i ].pid ) &&
                    hbs_timestampEvent( notif, prev_from_kernel[ i ].ts ) )
                {
                    hbs_publish( event, notif );
                }

                rpal_memory_free( cleanPath );

                rSequence_free( notif );
            }
        }

        rpal_memory_memcpy( prev_from_kernel, new_from_kernel, sizeof( prev_from_kernel ) );
        prev_nScratch = nScratch;
    }

    return NULL;
}

RPRIVATE
RPVOID
    processFileChanges
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            // We first attempt to get new fileio through
            // the kernel mode acquisition driver
            rpal_debug_info( "running kernel acquisition fileio notification" );
            processKmFileChanges( isTimeToStop );
        }
        // If the kernel mode fails, or is not available, try
        // to revert to user mode
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition fileio notification" );
            processUmFileChanges( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_7_events[] = { RP_TAGS_NOTIFICATION_FILE_CREATE,
                                  RP_TAGS_NOTIFICATION_FILE_DELETE,
                                  RP_TAGS_NOTIFICATION_FILE_MODIFIED,
                                  RP_TAGS_NOTIFICATION_FILE_READ,
                                  0};

RBOOL
    collector_7_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    rList disabledList = NULL;
    RU32 tagDisabled = 0;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rSequence_getLIST( config, RP_TAGS_IS_DISABLED, &disabledList ) )
        {
            while( rList_getRU32( disabledList, RP_TAGS_IS_DISABLED, &tagDisabled ) )
            {
                if( RP_TAGS_NOTIFICATION_FILE_CREATE == tagDisabled )
                {
                    g_is_create_enabled = FALSE;
                }
                else if( RP_TAGS_NOTIFICATION_FILE_DELETE == tagDisabled )
                {
                    g_is_delete_enabled = FALSE;
                }
                else if( RP_TAGS_NOTIFICATION_FILE_MODIFIED == tagDisabled )
                {
                    g_is_modified_enabled = FALSE;
                }
                else if( RP_TAGS_NOTIFICATION_FILE_READ == tagDisabled )
                {
                    g_is_read_enabled = FALSE;
                }
            }
        }

        if( rThreadPool_task( hbsState->hThreadPool, processFileChanges, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_7_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_7_update
    (
        HbsState* hbsState,
        rSequence update
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( update );

    return isSuccess;
}

//=============================================================================
//  Collector Testing
//=============================================================================
HBS_TEST_SUITE( 7 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}