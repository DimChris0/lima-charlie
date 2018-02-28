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


#define RPAL_FILE_ID                  64

RPRIVATE
RBOOL
    _getAsNativeString
    (
        rSequence seq,
        rpcm_tag tag,
        RPNCHAR* pStr
    )
{
    RBOOL isFound = FALSE;
    RPCHAR tmpA = NULL;
    RPWCHAR tmpW = NULL;

    if( NULL != seq &&
        RPCM_INVALID_TAG != tag &&
        NULL != pStr )
    {
        if( rSequence_getSTRINGA( seq, tag, &tmpA ) )
        {
            *pStr = rpal_string_aton( tmpA );
            isFound = TRUE;
        }
        else if( rSequence_getSTRINGW( seq, tag, &tmpW ) )
        {
            *pStr = rpal_string_wton( tmpW );
            isFound = TRUE;
        }
    }

    return isFound;
}

RPRIVATE
RBOOL
    enhanceFileInfo
    (
        rSequence info
    )
{
    RBOOL isEnhanced = FALSE;

    RPNCHAR filePath = NULL;
    rFileInfo finfo = { 0 };

    if( NULL != info )
    {
        if( _getAsNativeString( info, RP_TAGS_FILE_PATH, &filePath ) )
        {
            if( rpal_file_getInfo( filePath, &finfo ) )
            {
                rSequence_unTaintRead( info );
                if( rSequence_addTIMESTAMP( info, RP_TAGS_ACCESS_TIME, finfo.lastAccessTime ) &&
                    rSequence_addTIMESTAMP( info, RP_TAGS_CREATION_TIME, finfo.creationTime ) &&
                    rSequence_addTIMESTAMP( info, RP_TAGS_MODIFICATION_TIME, finfo.modificationTime ) &&
                    rSequence_addRU64( info, RP_TAGS_FILE_SIZE, finfo.size ) &&
                    rSequence_addRU32( info, RP_TAGS_ATTRIBUTES, finfo.attributes ) )
                {
                    isEnhanced = TRUE;
                }
            }
            else
            {
                rSequence_addRU32( info, RP_TAGS_ERROR, rpal_error_getLast() );
            }

            rpal_memory_free( filePath );
        }
        else
        {
            rSequence_addRU32( info, RP_TAGS_ERROR, RPAL_ERROR_INVALID_NAME );
        }
    }

    return isEnhanced;
}

RPRIVATE
RVOID
    file_get
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPNCHAR filePath = NULL;
    RU8 flag = 0;
    RBOOL isAvoidTimeStamps = TRUE;
    RPU8 fileBuffer = NULL;
    RU32 fileSize = 0;
    RU32 maxSize = 0;
    RBOOL isRetrieve = TRUE;
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( _getAsNativeString( event, RP_TAGS_FILE_PATH, &filePath ) )
        {
            rSequence_unTaintRead( event );

            if( rSequence_getRU8( event, RP_TAGS_AVOID_TIMESTAMPS, &flag ) )
            {
                isAvoidTimeStamps = ( 1 == flag ) ? TRUE : FALSE;
            }

            fileSize = rpal_file_getSize( filePath, isAvoidTimeStamps );
            rSequence_addRU32( event, RP_TAGS_FILE_SIZE, fileSize );

            if( rSequence_getRU32( event, RP_TAGS_MAX_SIZE, &maxSize ) &&
                maxSize < fileSize )
            {
                isRetrieve = FALSE;
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_FILE_TOO_LARGE );
            }

            if( isRetrieve )
            {
                if( rpal_file_read( filePath, &fileBuffer, &fileSize, isAvoidTimeStamps ) )
                {
                    rSequence_addBUFFER( event, RP_TAGS_FILE_CONTENT, fileBuffer, fileSize );
                    rpal_memory_free( fileBuffer );
                }
                else
                {
                    rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
                }
            }

            rpal_memory_free( filePath );
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_NOT_ENOUGH_MEMORY );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_FILE_GET_REP, event );
    }
}

RPRIVATE
RVOID
    file_del
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPNCHAR filePath = NULL;
    RU8 flag = 0;
    RBOOL isSafeDelete = FALSE;
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( _getAsNativeString( event, RP_TAGS_FILE_PATH, &filePath ) )
        {
            rSequence_unTaintRead( event );

            if( rSequence_getRU8( event, RP_TAGS_SAFE_DELETE, &flag ) )
            {
                isSafeDelete = ( 1 == flag ) ? TRUE : FALSE;
            }

            if( !rpal_file_delete( filePath, isSafeDelete ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }

            rpal_memory_free( filePath );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_FILE_DEL_REP, event );
    }
}

RPRIVATE
RVOID
    file_mov
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPNCHAR filePathFrom = NULL;
    RPNCHAR filePathTo = NULL;
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( _getAsNativeString( event, RP_TAGS_SOURCE, &filePathFrom ) &&
            _getAsNativeString( event, RP_TAGS_DESTINATION, &filePathTo ) )
        {
            if( !rpal_file_move( filePathFrom, filePathTo ) )
            {
                rSequence_unTaintRead( event );
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }

        rpal_memory_free( filePathFrom );
        rpal_memory_free( filePathTo );

        rSequence_unTaintRead( event );
        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_FILE_MOV_REP, event );
    }
}

RPRIVATE
RVOID
    file_hash
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPNCHAR filePath = NULL;
    CryptoLib_Hash hash = { 0 };
    RU8 flag = 0;
    RBOOL isAvoidTimeStamps = TRUE;
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( _getAsNativeString( event, RP_TAGS_FILE_PATH, &filePath ) )
        {
            if( rSequence_getRU8( event, RP_TAGS_AVOID_TIMESTAMPS, &flag ) )
            {
                isAvoidTimeStamps = ( 1 == flag ) ? TRUE : FALSE;
            }

            rSequence_unTaintRead( event );

            if( !CryptoLib_hashFile( filePath, &hash, isAvoidTimeStamps ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
            else
            {
                rSequence_addBUFFER( event, RP_TAGS_HASH, (RPU8)&hash, sizeof( hash ) );
            }
            
            rpal_memory_free( filePath );
        }

        

        rSequence_unTaintRead( event );
        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_FILE_HASH_REP, event );
    }
}

RPRIVATE
RVOID
    file_info
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        enhanceFileInfo( event );

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_FILE_INFO_REP, event );
    }
}

RPRIVATE
RVOID
    dir_list
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RPNCHAR filePath = NULL;
    RPNCHAR fileSpec[] = { NULL, NULL };
    rDirCrawl hDir = NULL;
    rFileInfo finfo = { 0 };
    rList entries = NULL;
    rSequence dirEntry = NULL;
    RU32 depth = 0;
    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( _getAsNativeString( event, RP_TAGS_DIRECTORY_PATH, &filePath ) &&
            _getAsNativeString( event, RP_TAGS_FILE_PATH, &fileSpec[ 0 ] ) )
        {
            rSequence_unTaintRead( event );

            // dir depth is optional, but if provided, use it
            rSequence_getRU32( event, RP_TAGS_DIRECTORY_LIST_DEPTH, &depth );

            if( NULL != ( hDir = rpal_file_crawlStart( filePath, fileSpec, depth ) ) )
            {
                if( NULL != ( entries = rList_new( RP_TAGS_DIRECTORY_LIST, RPCM_SEQUENCE ) ) )
                {
                    rSequence_unTaintRead( event );

                    while( rpal_file_crawlNextFile( hDir, &finfo ) && NULL != ( dirEntry = rSequence_new() ) )
                    {
                        if( rSequence_addSTRINGN( dirEntry, RP_TAGS_FILE_NAME, finfo.fileName ) &&
                            rSequence_addTIMESTAMP( dirEntry, RP_TAGS_ACCESS_TIME, finfo.lastAccessTime ) &&
                            rSequence_addTIMESTAMP( dirEntry, RP_TAGS_CREATION_TIME, finfo.creationTime ) &&
                            rSequence_addTIMESTAMP( dirEntry, RP_TAGS_MODIFICATION_TIME, finfo.modificationTime ) &&
                            rSequence_addRU64( dirEntry, RP_TAGS_FILE_SIZE, finfo.size ) &&
                            rSequence_addRU32( dirEntry, RP_TAGS_ATTRIBUTES, finfo.attributes ) )
                        {
                            if( !rList_addSEQUENCE( entries, dirEntry ) )
                            {
                                rSequence_free( dirEntry );
                            }
                        }
                    }

                    if( !rSequence_addLIST( event, RP_TAGS_DIRECTORY_LIST, entries ) )
                    {
                        rList_free( entries );
                    }
                }

                rpal_file_crawlStop( hDir );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_INVALID_NAME );
        }

        rpal_memory_free( filePath );
        rpal_memory_free( fileSpec[ 0 ] );

        rSequence_unTaintRead( event );
        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_DIR_LIST_REP, event );
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_9_events[] = { RP_TAGS_NOTIFICATION_FILE_GET_REP,
                                  RP_TAGS_NOTIFICATION_FILE_DEL_REP,
                                  RP_TAGS_NOTIFICATION_FILE_MOV_REP,
                                  RP_TAGS_NOTIFICATION_FILE_HASH_REP,
                                  RP_TAGS_NOTIFICATION_FILE_INFO_REP,
                                  RP_TAGS_NOTIFICATION_DIR_LIST_REP,
                                  0 };

RBOOL
    collector_9_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_GET_REQ, NULL, 0, NULL, file_get ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_DEL_REQ, NULL, 0, NULL, file_del ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_MOV_REQ, NULL, 0, NULL, file_mov ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_HASH_REQ, NULL, 0, NULL, file_hash ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_INFO_REQ, NULL, 0, NULL, file_info ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_DIR_LIST_REQ, NULL, 0, NULL, dir_list ) )
        {
            isSuccess = TRUE;
        }
        else
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_GET_REQ, NULL, file_get );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DEL_REQ, NULL, file_del );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MOV_REQ, NULL, file_mov );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_HASH_REQ, NULL, file_hash );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_INFO_REQ, NULL, file_info );
        }
    }

    return isSuccess;
}

RBOOL
    collector_9_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_GET_REQ, NULL, file_get );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DEL_REQ, NULL, file_del );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MOV_REQ, NULL, file_mov );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_HASH_REQ, NULL, file_hash );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_INFO_REQ, NULL, file_info );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_DIR_LIST_REQ, NULL, dir_list );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_9_update
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
HBS_TEST_SUITE( 9 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}