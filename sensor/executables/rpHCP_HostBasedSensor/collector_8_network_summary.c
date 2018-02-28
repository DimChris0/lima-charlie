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

#define  RPAL_FILE_ID           68

#define SUMMARY_N_NET_CONNECTIONS   (10)


typedef struct
{
    RU32 pid;
    RBOOL hasBeenSummarized;
    rSequence proc;
    rList net;

} _NetActivity;

RPRIVATE rBTree netState = NULL;

RPRIVATE rQueue netQueue = NULL;
RPRIVATE rQueue execQueue = NULL;
RPRIVATE rQueue termQueue = NULL;

RPRIVATE
RVOID
    _freePid
    (
        _NetActivity* p
    )
{
    if( NULL != p )
    {
        rSequence_free( p->proc );
        rList_free( p->net );
        p->proc = NULL;
        p->net = NULL;
    }
}

RPRIVATE
RS32
    _isPid
    (
        _NetActivity* p1,
        _NetActivity* p2
    )
{
    RS32 ret = 0;

    if( NULL != p1 &&
        NULL != p2 )
    {
        ret = p1->pid - p2->pid;
    }

    return ret;
}

RPRIVATE
RVOID
    _freeEvt
    (
        rSequence evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rSequence_free( evt );
}


RPRIVATE
RBOOL
    _summarize
    (
        _NetActivity* pActivity
    )
{
    RBOOL isSuccess = FALSE;
    Atom parentAtom = { 0 };
    rSequence wrapper = NULL;

    if( NULL != pActivity )
    {
        if( NULL != pActivity->net &&
            0 != rList_getNumElements( pActivity->net ) )
        {
            if( NULL == pActivity->proc )
            {
                if( NULL != ( pActivity->proc = rSequence_new() ) )
                {
                    rSequence_addRU32( pActivity->proc, RP_TAGS_PROCESS_ID, pActivity->pid );
                }
            }

            if( NULL != pActivity->proc )
            {
                if( rSequence_addLIST( pActivity->proc, RP_TAGS_NETWORK_ACTIVITY, pActivity->net ) )
                {
                    if( NULL != ( wrapper = rSequence_new() ) )
                    {
                        if( rSequence_addSEQUENCE( wrapper, RP_TAGS_PROCESS, pActivity->proc ) )
                        {
                            parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                            parentAtom.key.process.pid = pActivity->pid;
                            // Query the last value since summaries are on process death.
                            if( atoms_query( &parentAtom, 0 ) )
                            {
                                HbsSetParentAtom( wrapper, parentAtom.id );
                            }

                            hbs_timestampEvent( wrapper, 0 );
                            hbs_publish( RP_TAGS_NOTIFICATION_NETWORK_SUMMARY, wrapper );
                        }

                        rSequence_shallowFree( wrapper );
                    }

                    pActivity->net = NULL;
                }
            }
        }

        rSequence_free( pActivity->proc );
        rList_free( pActivity->net );

        rpal_memory_zero( pActivity, sizeof( *pActivity ) );
    }

    return isSuccess;
}


RPRIVATE
RPVOID
    summarizeNetwork
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence netEvt = NULL;
    rSequence execEvt = NULL;
    rSequence termEvt = NULL;

    RU32 netPid = 0;
    RU32 execPid = 0;
    RU32 termPid = 0;

    _NetActivity activity = { 0 };

    RBOOL isNewEventProcessed = FALSE;

    UNREFERENCED_PARAMETER( ctx );

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( !isNewEventProcessed )
        {
            rpal_thread_sleep( 1000 );
        }
        else
        {
            isNewEventProcessed = FALSE;
        }

        while( rpal_memory_isValid( isTimeToStop ) &&
               !rEvent_wait( isTimeToStop, 0 ) &&
               rQueue_remove( execQueue, &execEvt, NULL, 0 ) )
        {
            // This is a process starting up
            if( rSequence_getRU32( execEvt, RP_TAGS_PROCESS_ID, &execPid ) )
            {
                // If we already had an entry for it in the state
                // we assume we somehow missed the termination event (although unlikely)
                // so we reset it
                if( !rpal_btree_remove( netState, &execPid, &activity, TRUE ) )
                {
                    rpal_memory_zero( &activity, sizeof( activity ) );
                    activity.pid = execPid;
                }

                if( NULL != activity.proc ||
                    NULL != activity.net )
                {
                    // If it had previous data, free it
                    _freePid( &activity );
                }

                activity.hasBeenSummarized = FALSE;
                activity.proc = execEvt;

                if( rpal_btree_add( netState, &activity, TRUE ) )
                {
                    isNewEventProcessed = TRUE;
                }
                else
                {
                    _freePid( &activity );
                }
            }
            else
            {
                rSequence_free( execEvt );
            }
        }

        while( rpal_memory_isValid( isTimeToStop ) &&
              !rEvent_wait( isTimeToStop, 0 ) &&
              rQueue_remove( netQueue, &netEvt, NULL, 0 ) )
        {
            if( rSequence_getRU32( netEvt, RP_TAGS_PROCESS_ID, &netPid ) )
            {
                if( !rpal_btree_remove( netState, &netPid, &activity, TRUE ) )
                {
                    // We don't have a record of the process starting.
                    // There is a potential race condition and ignoring
                    // the net event opens a blind spot but for now it greatly
                    // simplifies the code. Just trying to avoid managed memory leaks.
                    rSequence_free( netEvt );
                }
                else
                {
                    if( !activity.hasBeenSummarized )
                    {
                        if( NULL == activity.net )
                        {
                            activity.net = rList_new( RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION, RPCM_SEQUENCE );
                        }

                        if( !rList_addSEQUENCE( activity.net, netEvt ) )
                        {
                            rSequence_free( netEvt );
                        }

                        if( SUMMARY_N_NET_CONNECTIONS <= rList_getNumElements( activity.net ) )
                        {
                            rpal_debug_info( "process reached max summary size, publish" );
                            _summarize( &activity );
                            activity.pid = netPid;
                            activity.hasBeenSummarized = TRUE;
                        }
                    }
                    else
                    {
                        rSequence_free( netEvt );
                    }

                    if( rpal_btree_add( netState, &activity, TRUE ) )
                    {
                        isNewEventProcessed = TRUE;
                    }
                    else
                    {
                        _freePid( &activity );
                    }
                }
            }
            else
            {
                rSequence_free( netEvt );
            }
        }
        while( rpal_memory_isValid( isTimeToStop ) &&
               !rEvent_wait( isTimeToStop, 0 ) &&
               rQueue_remove( termQueue, &termEvt, NULL, 0 ) )
        {
            if( rSequence_getRU32( termEvt, RP_TAGS_PROCESS_ID, &termPid ) )
            {
                if( rpal_btree_remove( netState, &termPid, &activity, TRUE ) )
                {
                    rpal_debug_info( "process terminating, cleanup" );
                    _summarize( &activity );
                }
            }

            rSequence_free( termEvt );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_8_events[] = { RP_TAGS_NOTIFICATION_NETWORK_SUMMARY,
                                  0 };

RBOOL
    collector_8_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( NULL != ( netState = rpal_btree_create( sizeof( _NetActivity ), (rpal_btree_comp_f)_isPid, (rpal_btree_free_f)_freePid ) ) &&
            rQueue_create( &netQueue, _freeEvt, 100 ) &&
            rQueue_create( &execQueue, _freeEvt, 100 ) &&
            rQueue_create( &termQueue, _freeEvt, 100 ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION, NULL, 0, netQueue, NULL ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION, NULL, 0, netQueue, NULL ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, execQueue, NULL ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, 0, termQueue, NULL ) &&
            rThreadPool_task( hbsState->hThreadPool, summarizeNetwork, NULL ) )
        {
            isSuccess = TRUE;
        }
        else
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION, netQueue, NULL );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION, netQueue, NULL );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, execQueue, NULL );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, termQueue, NULL );
            rQueue_free( netQueue );
            rQueue_free( execQueue );
            rQueue_free( termQueue );
            rpal_btree_destroy( netState, TRUE );
        }
    }

    return isSuccess;
}

RBOOL
    collector_8_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION, netQueue, NULL );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION, netQueue, NULL );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, execQueue, NULL );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, termQueue, NULL );
        rQueue_free( netQueue );
        rQueue_free( execQueue );
        rQueue_free( termQueue );
        rpal_btree_destroy( netState, TRUE );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_8_update
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
HBS_TEST_SUITE( 8 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}