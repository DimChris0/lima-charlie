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
#include <obsLib/obsLib.h>

#define  RPAL_FILE_ID           110


typedef struct
{
    RU8 atomId[ HBS_ATOM_ID_SIZE ];
    RU64 extBitMask;
    RPNCHAR processPath;

} ProcExtInfo;

RPRIVATE rBTree g_procContexts = NULL;
RPRIVATE rMutex g_mutex = NULL;
RPRIVATE HObs g_extensions = NULL;

RPRIVATE
RS32
    _cmpContext
    (
        ProcExtInfo* ctx1,
        ProcExtInfo* ctx2
    )
{
    RS32 ret = 0;

    if( NULL != ctx1 &&
        NULL != ctx2 )
    {
        ret = rpal_memory_memcmp( ctx1->atomId, ctx2->atomId, sizeof( ctx1->atomId ) );
    }

    return ret;
}

RPRIVATE
RVOID
    _freeContext
    (
        ProcExtInfo* ctx
    )
{
    if( rpal_memory_isValid( ctx ) )
    {
        rpal_memory_free( ctx->processPath );
    }
}

RPRIVATE
RBOOL
    _addPattern
    (
        HObs matcher,
        RPNCHAR pattern,
        RBOOL isSuffix,
        RPVOID context
    )
{
    RBOOL isSuccess = FALSE;
    RBOOL isCaseInsensitive = FALSE;
    RPNCHAR tmpN = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    // On Windows files and paths are not case sensitive.
    isCaseInsensitive = TRUE;
#endif
    if( rpal_string_expand( pattern, &tmpN ) )
    {
        obsLib_addStringPatternN( matcher, tmpN, isSuffix, isCaseInsensitive, context );
        rpal_memory_free( tmpN );
    }
    return isSuccess;
}

RPRIVATE
RBOOL
    checkFileType
    (
        RPU8 atomId,
        RU8 patternId,
        RPNCHAR newProcessPath,
        RPNCHAR* pReportPath
    )
{
    RBOOL isShouldReport = FALSE;

    ProcExtInfo tmpCtx = { 0 };
    RBOOL isAlreadyThere = TRUE;

    if( NULL != atomId )
    {
        if( !rpal_btree_search( g_procContexts, atomId, &tmpCtx, TRUE ) )
        {
            rpal_memory_memcpy( tmpCtx.atomId, atomId, sizeof( tmpCtx.atomId ) );
            isAlreadyThere = FALSE;
        }

        if( NULL != newProcessPath )
        {
            tmpCtx.processPath = rpal_string_strdup( newProcessPath );
        }

        if( !isAlreadyThere )
        {
            rpal_btree_add( g_procContexts, &tmpCtx, TRUE );
        }

        if( patternId <= sizeof( RU64 ) * 8 &&
            !IS_FLAG_ENABLED( tmpCtx.extBitMask, (RU64)1 << patternId ) )
        {
            isShouldReport = TRUE;
            if( NULL != pReportPath )
            {
                *pReportPath = tmpCtx.processPath;
            }
            ENABLE_FLAG( tmpCtx.extBitMask, (RU64)1 << patternId );

            if( !rpal_btree_update( g_procContexts, atomId, &tmpCtx, TRUE ) )
            {
                // Something went wrong so we will not report to avoid spam.
                isShouldReport = FALSE;
            }
        }
    }

    return isShouldReport;
}

RPRIVATE
RVOID
    processNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR path = NULL;
    RPU8 atomId = NULL;

    UNREFERENCED_PARAMETER( notifType );

    if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &path ) &&
        HbsGetThisAtom( event, &atomId ) )
    {
        if( rMutex_lock( g_mutex ) )
        {
            checkFileType( atomId, (RU8)-1, path, NULL );

            rMutex_unlock( g_mutex );
        }
    }
}

RPRIVATE
RVOID
    processTerminateProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    ProcExtInfo tmpCtx = { 0 };

    UNREFERENCED_PARAMETER( notifType );

    if( rMutex_lock( g_mutex ) )
    {
        if( HbsGetParentAtom( event, &atomId ) )
        {
            if( rpal_btree_remove( g_procContexts, atomId, &tmpCtx, TRUE ) )
            {
                rpal_memory_free( tmpCtx.processPath );
            }
        }

        rMutex_unlock( g_mutex );
    }
}

RPRIVATE
RVOID
    processFileIo
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR path = NULL;
    RPVOID patternCtx = 0;
    RU8 patternId = 0;
    RPU8 atomId = NULL;
    RU32 pid = 0;
    rSequence newEvent = NULL;
    RPNCHAR processPath = NULL;

    UNREFERENCED_PARAMETER( notifType );

    if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &path ) &&
        HbsGetParentAtom( event, &atomId ) &&
        rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
    {
        if( rMutex_lock( g_mutex ) )
        {
            obsLib_resetSearchState( g_extensions );
            if( obsLib_setTargetBuffer( g_extensions,
                                        path,
                                        rpal_string_strsize( path ) ) )
            {
                while( obsLib_nextHit( g_extensions, &patternCtx, NULL ) )
                {
                    patternId = (RU8)PTR_TO_NUMBER( patternCtx );

                    if( checkFileType( atomId, patternId, NULL, &processPath ) )
                    {
                        rpal_debug_info( "process " RF_U32 " observed file io " RF_U64, 
                                            pid, patternId + 1 );

                        if( NULL != ( newEvent = rSequence_new() ) )
                        {
                            HbsSetParentAtom( newEvent, atomId );
                            rSequence_addRU32( newEvent, RP_TAGS_PROCESS_ID, pid );
                            rSequence_addRU8( newEvent, RP_TAGS_RULE_NAME, patternId + 1 );
                            rSequence_addSTRINGN( newEvent, RP_TAGS_FILE_PATH, processPath );

                            hbs_publish( RP_TAGS_NOTIFICATION_FILE_TYPE_ACCESSED, newEvent );
                            rSequence_free( newEvent );
                        }
                    }
                }
            }

            rMutex_unlock( g_mutex );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_22_events[] = { RP_TAGS_NOTIFICATION_FILE_TYPE_ACCESSED,
                                   0 };

RBOOL
    collector_22_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    rList patterns = NULL;
    rSequence pattern = NULL;
    RPCHAR strA = NULL;
    RPWCHAR strW = NULL;
    RPNCHAR tmpN = NULL;
    RU8 patternId = 0;

    if( NULL != hbsState &&
        NULL != ( g_extensions = obsLib_new( 0, 0 ) ) )
    {
        if( rSequence_getLIST( config, RP_TAGS_PATTERNS, &patterns ) )
        {
            while( rList_getSEQUENCE( patterns, RP_TAGS_RULE, &pattern ) )
            {
                if( rSequence_getRU8( pattern, RP_TAGS_RULE_NAME, &patternId ) )
                {
                    if( 64 < patternId || 0 == patternId )
                    {
                        rpal_debug_critical( "rule id must be below 64 and 1-based." );
                        continue;
                    }

                    // Base the pattern id to 0
                    patternId--;

                    if( rSequence_getSTRINGA( pattern, RP_TAGS_EXTENSION, &strA ) &&
                        NULL != ( tmpN = rpal_string_aton( strA ) ) )
                    {
                        _addPattern( g_extensions, tmpN, TRUE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGW( pattern, RP_TAGS_EXTENSION, &strW ) &&
                        NULL != ( tmpN = rpal_string_wton( strW ) ) )
                    {
                        _addPattern( g_extensions, tmpN, TRUE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGA( pattern, RP_TAGS_STRING_PATTERN, &strA ) &&
                        NULL != ( tmpN = rpal_string_aton( strA ) ) )
                    {
                        _addPattern( g_extensions, tmpN, FALSE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGW( pattern, RP_TAGS_STRING_PATTERN, &strW ) &&
                        NULL != ( tmpN = rpal_string_wton( strW ) ) )
                    {
                        _addPattern( g_extensions, tmpN, FALSE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }
                }
            }

            if( NULL != ( g_mutex = rMutex_create() ) &&
                NULL != ( g_procContexts = rpal_btree_create( sizeof( ProcExtInfo ), 
                                                              (rpal_btree_comp_f)_cmpContext, 
                                                              (rpal_btree_free_f)_freeContext ) ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, processNewProcesses ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_EXISTING_PROCESS, NULL, 0, NULL, processNewProcesses ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, 0, NULL, processTerminateProcesses ) )
            {
                isSuccess = TRUE;
            }
        }
        else
        {
            // If no file type list was provided we're still good to go.
            isSuccess = TRUE;
        }
    }

    if( !isSuccess )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXISTING_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, processTerminateProcesses );
        obsLib_free( g_extensions );
        g_extensions = NULL;
        rpal_btree_destroy( g_procContexts, TRUE );
        g_procContexts = NULL;
        rMutex_free( g_mutex );
        g_mutex = NULL;
    }

    return isSuccess;
}

RBOOL
    collector_22_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXISTING_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, processTerminateProcesses );
        obsLib_free( g_extensions );
        g_extensions = NULL;
        rpal_btree_destroy( g_procContexts, TRUE );
        g_procContexts = NULL;
        rMutex_free( g_mutex );
        g_mutex = NULL;

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_22_update
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
HBS_TEST_SUITE( 22 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}