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
#include <cryptoLib/cryptoLib.h>
#include <libOs/libOs.h>

#define RPAL_FILE_ID 109

RPRIVATE rMutex g_mutex = NULL;
RPRIVATE rVector g_users = NULL;

RPRIVATE
RS32
    _cmpUserName
    (
        RPNCHAR* user1,
        RPNCHAR* user2
    )
{
    RS32 ret = 0;

    if( NULL != user1 &&
        NULL != user2 &&
        NULL != *user1 &&
        NULL != *user2 )
    {
        ret = rpal_string_strcmp( *user1, *user2 );
    }

    return ret;
}


RPRIVATE
RVOID
    processNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPNCHAR nameN = NULL;
    rSequence newNotif = NULL;
    RPNCHAR tmpName = NULL;
    RPU8 tmpParent = NULL;
    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGN( event, RP_TAGS_USER_NAME, &nameN ) )
        {
            if( rMutex_lock( g_mutex ) )
            {
                if( (RU32)-1 == rpal_binsearch_array( g_users->elements, 
                                                      g_users->nElements, 
                                                      sizeof( g_users->elements[ 0 ] ), 
                                                      &nameN, 
                                                      (rpal_ordering_func)_cmpUserName ) )
                {
                    // Have not seen this user before.
                    if( NULL != ( newNotif = rSequence_new() ) )
                    {
                        hbs_markAsRelated( event, newNotif );
                        rSequence_addSTRINGN( newNotif, RP_TAGS_USER_NAME, nameN );
                        if( HbsGetThisAtom( event, &tmpParent ) )
                        {
                            HbsSetParentAtom( newNotif, tmpParent );
                        }
                        hbs_publish( RP_TAGS_NOTIFICATION_USER_OBSERVED, newNotif );

                        rSequence_free( newNotif );
                    }

                    if( NULL != ( tmpName = rpal_string_strdup( nameN ) ) )
                    {
                        if( !rpal_vector_add( g_users, tmpName ) )
                        {
                            rpal_memory_free( tmpName );
                        }

                        rpal_sort_array( g_users->elements, 
                                         g_users->nElements, 
                                         sizeof( g_users->elements[ 0 ] ), 
                                         (rpal_ordering_func)_cmpUserName );
                    }
                }

                rMutex_unlock( g_mutex );
            }
        }
    }
}



//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_21_events[] = { RP_TAGS_NOTIFICATION_USER_OBSERVED,
                                   0 };

RBOOL
    collector_21_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( NULL != ( g_mutex = rMutex_create() ) )
        {
            if( NULL != ( g_users = rpal_vector_new() ) )
            {
                isSuccess = FALSE;

                if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, processNewProcesses ) )
                {
                    isSuccess = TRUE;
                }
                else
                {
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );

                    rpal_vector_free( g_users );
                    g_users = NULL;
                    rMutex_free( g_mutex );
                    g_mutex = NULL;
                }
            }
            else
            {
                rMutex_free( g_mutex );
                g_mutex = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_21_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses ) )
        {
            isSuccess = TRUE;
        }

        for( i = 0; i < g_users->nElements; i++ )
        {
            rpal_memory_free( g_users->elements[ i ] );
        }

        rpal_vector_free( g_users );
        g_users = NULL;

        rMutex_free( g_mutex );
        g_mutex = NULL;
    }

    return isSuccess;
}

RBOOL
    collector_21_update
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
HBS_TEST_SUITE( 21 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}