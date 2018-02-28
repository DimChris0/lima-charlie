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

#define RPAL_FILE_ID       94

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <networkLib/networkLib.h>

#define _HISTORY_MAX_LENGTH     (1000)
#define _HISTORY_MAX_SIZE       (1024*1024*5)

typedef struct
{
    rpcm_tag* pElems;
    RU32 nElem;
    rMutex mutex;
} _EventList;

typedef struct
{
    RU8 atomId[ HBS_ATOM_ID_SIZE ];
    RU32 iEvent;
} _AtomEvent;

RPRIVATE HbsState* g_state = NULL;

RPRIVATE _EventList g_exfil_profile = { 0 };
RPRIVATE _EventList g_exfil_adhoc = { 0 };

RPRIVATE RU32 g_cur_size = 0;
RPRIVATE rSequence g_history[ _HISTORY_MAX_LENGTH ] = { 0 };
RPRIVATE RU32 g_history_head = 0;
RPRIVATE rMutex g_history_mutex = NULL;

RPRIVATE
RS32
    _cmpAtom
    (
        _AtomEvent* e1,
        _AtomEvent* e2
    )
{
    if( NULL != e1 &&
        NULL != e2 )
    {
        return rpal_memory_memcmp( e1->atomId, e2->atomId, sizeof( e1->atomId ) );
    }

    return 0;
}

RPRIVATE
rpcm_tag
    _getEventName
    (
        rSequence event
    )
{
    rpcm_tag tag = RPCM_INVALID_TAG;

    rSequence_getElement( event, &tag, NULL, NULL, NULL );

    return tag;
}

RPRIVATE
RBOOL
    _initEventList
    (
        _EventList* pList
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( NULL != ( pList->mutex = rMutex_create() ) )
        {
            pList->pElems = NULL;
            pList->nElem = 0;
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _deinitEventList
    (
        _EventList* pList
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( rpal_memory_isValid( pList->mutex ) )
        {
            rMutex_free( pList->mutex );
            pList->mutex = NULL;
        }

        if( rpal_memory_isValid( pList->pElems ) )
        {
            rpal_memory_free( pList->pElems );
            pList->pElems = NULL;
        }

        pList->nElem = 0;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _addEventId
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;
    RPVOID original = NULL;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            pList->nElem++;
            original = pList->pElems;
            pList->pElems = rpal_memory_reAlloc( pList->pElems, pList->nElem * sizeof( *( pList->pElems ) ) );
            if( rpal_memory_isValid( pList->pElems ) )
            {
                pList->pElems[ pList->nElem - 1 ] = eventId;
                isSuccess = TRUE;
            }
            else
            {
                pList->pElems = original;
                pList->nElem--;
            }

            rpal_sort_array( pList->pElems, 
                             pList->nElem, 
                             sizeof( *( pList->pElems ) ), 
                             (rpal_ordering_func)rpal_order_RU32 );

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _removeEventId
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
    RPVOID original = NULL;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            if( (RU32)( -1 ) != ( i = rpal_binsearch_array( pList->pElems, 
                                                            pList->nElem, 
                                                            sizeof( *( pList->pElems ) ), 
                                                            &eventId,
                                                            (rpal_ordering_func)rpal_order_RU32 ) ) )
            {
                rpal_memory_memmove( &( pList->pElems[ i ] ), 
                                     &( pList->pElems[ i + 1 ] ), 
                                     ( pList->nElem - i - 1 ) * sizeof( *( pList->pElems ) ) );
                pList->nElem--;
                original = pList->pElems;
                pList->pElems = rpal_memory_realloc( pList->pElems,
                                                     pList->nElem * sizeof( *( pList->pElems ) ) );
                if( rpal_memory_isValid( pList->pElems ) )
                {
                    rpal_sort_array( pList->pElems, 
                                     pList->nElem, 
                                     sizeof( *( pList->pElems ) ), 
                                     (rpal_ordering_func)rpal_order_RU32 );
                    isSuccess = TRUE;
                }
                else
                {
                    pList->nElem++;
                    pList->pElems = original;
                }
            }

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _isEventIn
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            if( (RU32)( -1 ) != rpal_binsearch_array( pList->pElems,
                                                      pList->nElem,
                                                      sizeof( *( pList->pElems ) ),
                                                      &eventId,
                                                      (rpal_ordering_func)rpal_order_RU32 ) )
            {
                isSuccess = TRUE;
            }

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

RPRIVATE
RVOID
    recordEvent
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 i = 0;
    rSequence tmpNotif = NULL;
    rSequence wrapper = NULL;

    if( rpal_memory_isValid( notif ) )
    {
        if( rMutex_lock( g_history_mutex ) )
        {
            if( g_history_head >= ARRAY_N_ELEM( g_history ) )
            {
                g_history_head = 0;
            }

            if( NULL != g_history[ g_history_head ] )
            {
                g_cur_size -= rSequence_getEstimateSize( g_history[ g_history_head ] );

                rSequence_free( g_history[ g_history_head ] );
                g_history[ g_history_head ] = NULL;
            }

            if( NULL != ( tmpNotif = rSequence_duplicate( notif ) ) )
            {
                if( NULL != ( wrapper = rSequence_new() ) )
                {
                    if( rSequence_addSEQUENCE( wrapper, notifId, tmpNotif ) )
                    {
                        g_history[ g_history_head ] = wrapper;
                        g_cur_size += rSequence_getEstimateSize( wrapper );

                        i = g_history_head + 1;
                        while( _HISTORY_MAX_SIZE < g_cur_size )
                        {
                            if( i >= ARRAY_N_ELEM( g_history ) )
                            {
                                i = 0;
                            }

                            g_cur_size -= rSequence_getEstimateSize( g_history[ i ] );

                            rSequence_free( g_history[ i ] );
                            g_history[ i ] = NULL;
                            i++;
                        }

                        g_history_head++;
                    }
                    else
                    {
                        rSequence_free( wrapper );
                        rSequence_free( tmpNotif );
                    }
                }
                else
                {
                    rSequence_free( tmpNotif );
                }
            }

            if( ( 1024 * 1024 * 10 ) < g_cur_size )
            {
                rpal_debug_info( "History size: +%d = %d KB", notifId, ( g_cur_size / 1024 ) );
            }

            rMutex_unlock( g_history_mutex );
        }
    }
}

RPRIVATE
RVOID
    exfilFunc
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    rSequence wrapper = NULL;
    rSequence tmpNotif = NULL;

    if( rpal_memory_isValid( notif ) &&
        NULL != g_state &&
        !rEvent_wait( g_state->isTimeToStop, 0 ) )
    {
        if( _isEventIn( &g_exfil_profile, notifId ) ||
            _isEventIn( &g_exfil_adhoc, notifId ) )
        {
            if( NULL != ( wrapper = rSequence_new() ) )
            {
                if( NULL != ( tmpNotif = rSequence_duplicate( notif ) ) )
                {
                    if( rSequence_addSEQUENCE( wrapper, notifId, tmpNotif ) )
                    {
                        if( !rQueue_add( g_state->outQueue, wrapper, 0 ) )
                        {
                            rSequence_free( wrapper );
                        }
                    }
                    else
                    {
                        rSequence_free( wrapper );
                        rSequence_free( tmpNotif );
                    }
                }
                else
                {
                    rSequence_free( wrapper );
                }
            }
        }
        else
        {
            recordEvent( notifId, notif );
        }
    }
}

RPRIVATE
RVOID
    dumpHistory
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 i = 0;
    rSequence tmp = NULL;
    RU32 tmpSize = 0;
    RPU8 parentAtom = NULL;
    RPU8 thisAtom = NULL;
    RPU8 targetAtom = NULL;
    rpcm_tag ofType = 0;
    rBTree matchingEvents = NULL;
    _AtomEvent tmpEntry = { 0 };
    RBOOL isMatch = TRUE;
    rSequence tmpEvent = NULL;
    UNREFERENCED_PARAMETER( notifId );

    rSequence_getRU32( notif, RP_TAGS_HBS_NOTIFICATION_ID, &ofType );
    HbsGetThisAtom( notif, &thisAtom );
    HbsGetParentAtom( notif, &parentAtom );

    if( rMutex_lock( g_history_mutex ) )
    {
        if( !rEvent_wait( g_state->isTimeToStop, 0 ) )
        {
            if( NULL == parentAtom )
            {
                // No filtering at all, fast.
                for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
                {
                    if( rpal_memory_isValid( g_history[ i ] ) )
                    {
                        if( ( NULL == thisAtom ||
                            ( rSequence_getSEQUENCE( g_history[ i ], RPCM_INVALID_TAG, &tmpEvent ) &&
                              rSequence_getBUFFER( tmpEvent, RP_TAGS_HBS_THIS_ATOM, &targetAtom, &tmpSize ) &&
                              0 == rpal_memory_memcmp( thisAtom, targetAtom, HBS_ATOM_ID_SIZE ) ) ) &&
                            ( 0 == ofType ||
                              ofType == _getEventName( g_history[ i ] ) ) )
                        {
                            if( NULL != ( tmp = rSequence_duplicate( g_history[ i ] ) ) )
                            {
                                hbs_markAsRelated( notif, tmp );

                                if( !rQueue_add( g_state->outQueue, tmp, 0 ) )
                                {
                                    rSequence_free( tmp );
                                }
                                else
                                {
                                    g_cur_size -= rSequence_getEstimateSize( g_history[ i ] );

                                    rSequence_free( g_history[ i ] );
                                    g_history[ i ] = NULL;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                // Filters need to be applied, this is more involved.
                if( NULL != ( matchingEvents = rpal_btree_create( sizeof( _AtomEvent ), 
                                                                  (rpal_btree_comp_f)_cmpAtom, 
                                                                  NULL ) ) )
                {
                    // First we populate an index of seed matching events.
                    for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
                    {
                        if( rpal_memory_isValid( g_history[ i ] ) &&
                            rSequence_getSEQUENCE( g_history[ i ], RPCM_INVALID_TAG, &tmpEvent ) &&
                            rSequence_getBUFFER( tmpEvent, RP_TAGS_HBS_PARENT_ATOM, &targetAtom, &tmpSize ) )
                        {
                            // If this matches the filters, also add to the other tree.
                            if( NULL != parentAtom &&
                                0 == rpal_memory_memcmp( targetAtom, parentAtom, HBS_ATOM_ID_SIZE ) )
                            {
                                rpal_memory_memcpy( tmpEntry.atomId, targetAtom, sizeof( tmpEntry.atomId ) );
                                tmpEntry.iEvent = i;
                                rpal_btree_add( matchingEvents, &tmpEntry, TRUE );
                            }
                        }
                    }

                    // Next we go through events until no more match.
                    if( 0 != rpal_btree_getSize( matchingEvents, TRUE ) )
                    {
                        while( isMatch )
                        {
                            isMatch = FALSE;

                            for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
                            {
                                if( rpal_memory_isValid( g_history[ i ] ) &&
                                    rSequence_getSEQUENCE( g_history[ i ], RPCM_INVALID_TAG, &tmpEvent ) &&
                                    rSequence_getBUFFER( tmpEvent, RP_TAGS_HBS_PARENT_ATOM, &targetAtom, &tmpSize ) )
                                {
                                    if( rpal_btree_search( matchingEvents, targetAtom, NULL, TRUE ) )
                                    {
                                        rpal_memory_memcpy( tmpEntry.atomId, targetAtom, sizeof( tmpEntry.atomId ) );
                                        tmpEntry.iEvent = i;
                                        if( rpal_btree_add( matchingEvents, &tmpEntry, TRUE ) )
                                        {
                                            isMatch = TRUE;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Finally we report all the matches.
                    if( rpal_btree_minimum( matchingEvents, &tmpEntry, TRUE ) )
                    {
                        do
                        {
                            if( ( NULL == thisAtom ||
                                ( rSequence_getSEQUENCE( g_history[ tmpEntry.iEvent ], RPCM_INVALID_TAG, &tmpEvent ) &&
                                  rSequence_getBUFFER( tmpEvent, RP_TAGS_HBS_THIS_ATOM, &targetAtom, &tmpSize ) &&
                                    0 == rpal_memory_memcmp( thisAtom, targetAtom, HBS_ATOM_ID_SIZE ) ) ) &&
                                ( 0 == ofType ||
                                  ofType == _getEventName( g_history[ tmpEntry.iEvent ] ) ) )
                            {
                                if( NULL != ( tmp = rSequence_duplicate( g_history[ tmpEntry.iEvent ] ) ) )
                                {
                                    hbs_markAsRelated( notif, tmp );

                                    if( !rQueue_add( g_state->outQueue, tmp, 0 ) )
                                    {
                                        rSequence_free( tmp );
                                    }
                                    else
                                    {
                                        g_cur_size -= rSequence_getEstimateSize( g_history[ tmpEntry.iEvent ] );

                                        rSequence_free( g_history[ tmpEntry.iEvent ] );
                                        g_history[ tmpEntry.iEvent ] = NULL;
                                    }
                                }
                            }
                        }
                        while( rpal_btree_next( matchingEvents, &tmpEntry, &tmpEntry, TRUE ) );
                    }

                    rpal_btree_destroy( matchingEvents, TRUE );
                }
            }
        }

        rMutex_unlock( g_history_mutex );
    }

    hbs_sendCompletionEvent( notif, 
                             RP_TAGS_NOTIFICATION_HISTORY_DUMP_REP, 
                             RPAL_ERROR_SUCCESS, 
                             NULL );
}

RPRIVATE
RVOID
    segregateNetwork
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 errorCode = RPAL_ERROR_SUCCESS;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( notifId );
    UNREFERENCED_PARAMETER( notif );

    // Since we may be getting segregated as soon as we get online, let's give
    // a chance to the kernel acquisition driver to get loaded if possible.
    for( i = 0; i < 3; i++ )
    {
        if( kAcq_isAvailable() )
        {
            break;
        }

        rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
    }

    if( kAcq_isAvailable() )
    {
        if( !kAcq_segregateNetwork() )
        {
            rpal_debug_error( "failed to segregate network" );
            errorCode = RPAL_ERROR_NOT_SUPPORTED;
        }
        else
        {
            rpal_debug_info( "network segregation successful" );
        }
    }
    else
    {
        rpal_debug_error( "network segregation not possible, no kernel presence" );
        errorCode = RPAL_ERROR_OPEN_FAILED;
    }

    hbs_sendCompletionEvent( notif, RP_TAGS_NOTIFICATION_RECEIPT, errorCode, NULL );
}

RPRIVATE
RVOID
    rejoinNetwork
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 errorCode = RPAL_ERROR_SUCCESS;

    UNREFERENCED_PARAMETER( notifId );
    UNREFERENCED_PARAMETER( notif );

    if( kAcq_isAvailable() )
    {
        if( !kAcq_rejoinNetwork() )
        {
            rpal_debug_error( "failed to rejoin network" );
            errorCode = RPAL_ERROR_NOT_SUPPORTED;
        }
        else
        {
            rpal_debug_info( "network rejoined" );
        }
    }
    else
    {
        errorCode = RPAL_ERROR_OPEN_FAILED;
    }

    hbs_sendCompletionEvent( notif, RP_TAGS_NOTIFICATION_RECEIPT, errorCode, NULL );
}

RPRIVATE
RPVOID
    stopExfilCb
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rpcm_tag* exfilStub = (rpcm_tag*)ctx;

    UNREFERENCED_PARAMETER( isTimeToStop );

    if( rpal_memory_isValid( exfilStub ) )
    {
        if( _removeEventId( &g_exfil_adhoc, *exfilStub ) )
        {
            rpal_debug_info( "removing adhoc exfil (expired): %d", *exfilStub );
        }

        rpal_memory_free( exfilStub );
    }

    return NULL;
}

RPRIVATE
RVOID
    add_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;
    RTIME expire = 0;
    rpcm_tag* exfilStub = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _addEventId( &g_exfil_adhoc, eventId ) )
            {
                rpal_debug_info( "adding adhoc exfil: %d", eventId );

                if( rSequence_getTIMESTAMP( event, RP_TAGS_EXPIRY, &expire ) )
                {
                    if( NULL != ( exfilStub = rpal_memory_alloc( sizeof( *exfilStub ) ) ) )
                    {
                        *exfilStub = eventId;
                        if( !rThreadPool_scheduleOneTime( g_state->hThreadPool, 
                                                          expire, 
                                                          stopExfilCb, 
                                                          exfilStub ) )
                        {
                            rpal_memory_free( exfilStub );
                        }
                        else
                        {
                            rpal_debug_info( "adding callback for expiry on new adhoc exfil" );
                        }
                    }
                }
            }
        }
    }
}


RPRIVATE
RVOID
    del_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _removeEventId( &g_exfil_adhoc, eventId ) )
            {
                rpal_debug_info( "removing adhoc exfil: %d", eventId );
            }
        }
    }
}


RPRIVATE
RVOID
    get_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList events = NULL;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rMutex_lock( g_exfil_adhoc.mutex ) )
        {
            if( NULL != ( events = rList_new( RP_TAGS_HBS_NOTIFICATION_ID, RPCM_RU32 ) ) )
            {
                if( rpal_memory_isValid( g_exfil_adhoc.pElems ) )
                {
                    for( i = 0; i < g_exfil_adhoc.nElem; i++ )
                    {
                        rList_addRU32( events, g_exfil_adhoc.pElems[ i ] );
                    }
                }

                if( !rSequence_addLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, events ) )
                {
                    rList_free( events );
                    events = NULL;
                }

                notifications_publish( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP, event );
            }

            rMutex_unlock( g_exfil_adhoc.mutex );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_0_events[] = { RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP,
                                  RP_TAGS_NOTIFICATION_HISTORY_DUMP_REP,
                                  RP_TAGS_NOTIFICATION_RECEIPT,
                                  0 };

RBOOL
    collector_0_init
    ( 
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    rList subscribed = NULL;
    rpcm_tag notifId = 0;
    RU32 i = 0;
    RU32 j = 0;

    if( NULL != hbsState )
    {
        if( NULL != ( g_history_mutex = rMutex_create() ) &&
            _initEventList( &g_exfil_profile ) &&
            _initEventList( &g_exfil_adhoc ) )
        {
            isSuccess = TRUE;
            g_state = hbsState;

            rpal_memory_zero( g_history, sizeof( g_history ) );
            g_cur_size = 0;
            g_history_head = 0;

            if( notifications_subscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         add_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         del_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         get_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, 
                                         NULL, 
                                         0, 
                                         NULL, 
                                         dumpHistory ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_SEGREGATE_NETWORK,
                                         NULL,
                                         0,
                                         NULL,
                                         segregateNetwork ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_REJOIN_NETWORK,
                                         NULL,
                                         0,
                                         NULL,
                                         rejoinNetwork ) )
            {
                // First we register for all the external events of all the collectors.
                // We will triage as they come in.
                for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
                {
                    j = 0;

                    while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                    {
                        if( !notifications_subscribe( g_state->collectors[ i ].externalEvents[ j ],
                                                      NULL, 0, NULL, exfilFunc ) )
                        {
                            rpal_debug_error( "error subscribing to event %d for exfil management",
                                              g_state->collectors[ i ].externalEvents[ j ] );
                            isSuccess = FALSE;
                        }

                        j++;
                    }
                }

                // Next we assemble the list of events for profile exfil.
                if( rpal_memory_isValid( config ) &&
                    rSequence_getLIST( config, RP_TAGS_HBS_LIST_NOTIFICATIONS, &subscribed ) )
                {
                    while( rList_getRU32( subscribed, RP_TAGS_HBS_NOTIFICATION_ID, &notifId ) )
                    {
                        if( !_addEventId( &g_exfil_profile, notifId ) )
                        {
                            isSuccess = FALSE;
                        }
                    }
                }
            }
        }

        if( !isSuccess )
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, NULL, add_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, NULL, del_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, NULL, get_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, NULL, dumpHistory );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_SEGREGATE_NETWORK, NULL, segregateNetwork );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_REJOIN_NETWORK, NULL, rejoinNetwork );

            for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
            {
                j = 0;

                while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                {
                    notifications_unsubscribe( g_state->collectors[ i ].externalEvents[ j ], 
                                               NULL, exfilFunc );

                    j++;
                }
            }

            rMutex_free( g_history_mutex );
            g_history_mutex = NULL;
            _deinitEventList( &g_exfil_profile );
            _deinitEventList( &g_exfil_adhoc );
        }
    }

    return isSuccess;
}

RBOOL 
    collector_0_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    RU32 i = 0;
    RU32 j = 0;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rMutex_lock( g_history_mutex ) )
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, NULL, add_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, NULL, del_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, NULL, get_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, NULL, dumpHistory );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_SEGREGATE_NETWORK, NULL, segregateNetwork );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_REJOIN_NETWORK, NULL, rejoinNetwork );

            for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
            {
                j = 0;

                while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                {
                    notifications_unsubscribe( g_state->collectors[ i ].externalEvents[ j ],
                                               NULL, 
                                               exfilFunc );

                    j++;
                }
            }

            for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
            {
                if( rpal_memory_isValid( g_history[ i ] ) )
                {
                    rSequence_free( g_history[ i ] );
                    g_history[ i ] = NULL;
                }
            }

            g_cur_size = 0;
            g_history_head = 0;

            rMutex_free( g_history_mutex );
            g_history_mutex = NULL;
            _deinitEventList( &g_exfil_profile );
            _deinitEventList( &g_exfil_adhoc );
        }
    }

    return isSuccess;
}

RBOOL
    collector_0_update
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
HBS_DECLARE_TEST( adhocExfil  )
{
    RU32 eventId = 0;
    rQueue q = NULL;
    RU32 tmpSize = 0;
    rSequence event = NULL;
    rList events = NULL;

    if( HBS_ASSERT_TRUE( rQueue_create( &q, rSequence_freeWithSize, 0 ) ) &&
        HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP, NULL, 0, q, NULL ) ) &&
        HBS_ASSERT_TRUE( NULL != ( g_state = rpal_memory_alloc(sizeof( *g_state ) ) ) ) &&
        HBS_ASSERT_TRUE( NULL != ( g_state->hThreadPool = rThreadPool_create( 1, 5, 10 ) ) ) &&
        HBS_ASSERT_TRUE( rQueue_create( &g_state->outQueue, rSequence_freeWithSize, 0 ) ) )
    {
        HBS_ASSERT_TRUE( _initEventList( &g_exfil_adhoc ) );

        // Add 3 valid exfil events
        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 42 );
        add_exfil( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 100 );
        add_exfil( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 200 );
        add_exfil( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Check we get the 3 back
        event = rSequence_new();
        get_exfil( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( q, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );
        if( HBS_ASSERT_TRUE( rQueue_remove( q, &event, &tmpSize, 0 ) ) )
        {
            HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, &events ) );
            HBS_ASSERT_TRUE( 3 == rList_getNumElements( events ) );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 42 == eventId );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 100 == eventId );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 200 == eventId );
            rSequence_free( event );
        }

        // Remove 1 of the exfil events
        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 100 );
        del_exfil( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Make sure only that one was removed
        event = rSequence_new();
        get_exfil( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( q, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );
        if( HBS_ASSERT_TRUE( rQueue_remove( q, &event, &tmpSize, 0 ) ) )
        {
            HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, &events ) );
            HBS_ASSERT_TRUE( 2 == rList_getNumElements( events ) );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 42 == eventId );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 200 == eventId );
            rSequence_free( event );
        }

        // Remove all exfil events
        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 200 );
        del_exfil( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 42 );
        del_exfil( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Should now be empty
        event = rSequence_new();
        get_exfil( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( q, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );
        if( HBS_ASSERT_TRUE( rQueue_remove( q, &event, &tmpSize, 0 ) ) )
        {
            HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, &events ) );
            HBS_ASSERT_TRUE( 0 == rList_getNumElements( events ) );
            rSequence_free( event );
        }

        // Add an exfil event with an expiry
        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 66 );
        rSequence_addTIMESTAMP( event, RP_TAGS_EXPIRY, rpal_time_getGlobal() + 2 );
        add_exfil( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Make sure that event is there
        event = rSequence_new();
        get_exfil( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( q, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );
        if( HBS_ASSERT_TRUE( rQueue_remove( q, &event, &tmpSize, 0 ) ) )
        {
            HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, &events ) );
            HBS_ASSERT_TRUE( 1 == rList_getNumElements( events ) );
            HBS_ASSERT_TRUE( rList_getRU32( events, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) );
            HBS_ASSERT_TRUE( 66 == eventId );
            rSequence_free( event );
        }

        // Wait for a bit for it to expire
        rpal_thread_sleep( MSEC_FROM_SEC( 3 ) );

        event = rSequence_new();
        get_exfil( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Make sure it has been removed
        HBS_ASSERT_TRUE( rQueue_getSize( q, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );
        if( HBS_ASSERT_TRUE( rQueue_remove( q, &event, &tmpSize, 0 ) ) )
        {
            HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, &events ) );
            HBS_ASSERT_TRUE( 0 == rList_getNumElements( events ) );
            rSequence_free( event );
        }

        // Simulate an event occuring
        event = rSequence_new();
        exfilFunc( 42, event );
        rSequence_free( event );

        // Make sure it is not exfiled
        HBS_ASSERT_TRUE( rQueue_getSize( g_state->outQueue, &tmpSize ) );
        HBS_ASSERT_TRUE( 0 == tmpSize );

        // Add an event to exfil
        event = rSequence_new();
        rSequence_addRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, 42 );
        add_exfil( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, event );
        rSequence_free( event );

        // Simulate the event occuring again
        event = rSequence_new();
        exfilFunc( 42, event );
        rSequence_free( event );

        // Make sure it is recorded this time
        HBS_ASSERT_TRUE( rQueue_getSize( g_state->outQueue, &tmpSize ) );
        HBS_ASSERT_TRUE( 1 == tmpSize );

        HBS_ASSERT_TRUE( _deinitEventList( &g_exfil_adhoc ) );
    }

    if( NULL != g_state )
    {
        rThreadPool_destroy( g_state->hThreadPool, TRUE );
        rQueue_free( g_state->outQueue );
        rpal_memory_free( g_state );
        g_state = NULL;
    }
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP, q, NULL );
    rQueue_free( q );
}

HBS_DECLARE_TEST( history )
{
    rSequence evt = NULL;
    rSequence tmpEvt1 = NULL;
    rSequence tmpEvt2 = NULL;
    RU32 evtType = 1;
    RU32 i = 0;
    RPU8 buffer = NULL;
    RU32 tmpSize = 0;

    g_history_mutex = rMutex_create();
    if( HBS_ASSERT_TRUE( NULL != g_history_mutex ) )
    {
        // Test recordEvent
        recordEvent( evtType, NULL );
        HBS_ASSERT_TRUE( 0 == g_history_head );
        HBS_ASSERT_TRUE( NULL == g_history[ 0 ] );

        // Record a simple event
        evt = rSequence_new();
        recordEvent( evtType, evt );
        rSequence_free( evt );

        HBS_ASSERT_TRUE( 1 == g_history_head );
        HBS_ASSERT_TRUE( rSequence_getSEQUENCE( g_history[ 0 ], evtType, &tmpEvt1 ) );

        // Record a second one
        evt = rSequence_new();
        recordEvent( evtType, evt );
        rSequence_free( evt );

        HBS_ASSERT_TRUE( 2 == g_history_head );
        HBS_ASSERT_TRUE( rSequence_getSEQUENCE( g_history[ 1 ], evtType, &tmpEvt1 ) );

        // Wrap around the max number of events in history
        tmpEvt1 = g_history[ 0 ];
        tmpEvt2 = g_history[ 1 ];
        for( i = 0; i < ARRAY_N_ELEM( g_history ) - 1; i++ )
        {
            evt = rSequence_new();
            recordEvent( evtType, evt );
            rSequence_free( evt );
        }
        HBS_ASSERT_TRUE( 1 == g_history_head );
        HBS_ASSERT_TRUE( tmpEvt2 == g_history[ 1 ] );

        // Overflow the max size of history
        evt = rSequence_new();
        buffer = rpal_memory_alloc( 1024 * 1024 );
        rSequence_addBUFFER( evt, evtType, buffer, 1024 * 1024 );
        rpal_memory_free( buffer );
        for( i = 0; i < ( _HISTORY_MAX_SIZE / ( 1024 * 1024 ) ) + 2; i++ )
        {
            recordEvent( evtType, evt );
        }
        rSequence_free( evt );
        HBS_ASSERT_TRUE( _HISTORY_MAX_SIZE > g_cur_size );

        // Cleanup
        for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
        {
            rSequence_free( g_history[ i ] );
            g_history[ i ] = NULL;
        }
        g_history_head = 0;
        g_cur_size = 0;

        // Dump the history
        if( HBS_ASSERT_TRUE( NULL != ( g_state = rpal_memory_alloc( sizeof( *g_state ) ) ) ) &&
            HBS_ASSERT_TRUE( rQueue_create( &g_state->outQueue, rSequence_freeWithSize, 0 ) ) )
        {
            // Add three elements
            evt = rSequence_new();
            recordEvent( evtType, evt );
            recordEvent( evtType, evt );
            recordEvent( evtType, evt );

            HBS_ASSERT_TRUE( 3 == g_history_head );

            // Straight dump (no filter)
            dumpHistory( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, evt );
            rSequence_free( evt );

            HBS_ASSERT_TRUE( rQueue_getSize( g_state->outQueue, &tmpSize ) );
            HBS_ASSERT_TRUE( 3 == tmpSize );
        }

        // Cleanup
        for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
        {
            rSequence_free( g_history[ i ] );
            g_history[ i ] = NULL;
        }
        g_history_head = 0;
        g_cur_size = 0;

        if( NULL != g_state )
        {
            rQueue_free( g_state->outQueue );
            rpal_memory_free( g_state );
            g_state = NULL;
        }

        rMutex_free( g_history_mutex );
        g_history_mutex = NULL;
    }
}

HBS_TEST_SUITE( 0 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        HBS_RUN_TEST( adhocExfil );
        HBS_RUN_TEST( history );

        isSuccess = TRUE;
    }

    return isSuccess;
}