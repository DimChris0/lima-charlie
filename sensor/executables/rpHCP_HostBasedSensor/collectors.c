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
#include <rpHostCommonPlatformLib/rTags.h>
#include <libOs/libOs.h>
#include <notificationsLib/notificationsLib.h>

#define RPAL_FILE_ID        103

typedef struct
{
    rCollection col;
    RU32 sizeInBuffer;
    RU32 nMaxElements;
    RU32 maxTotalSize;

} _HbsRingBuffer;

typedef struct
{
    rBTree events;
    RU32 nMilliSeconds;
    rEvent newElemEvent;
    rMutex mutex;
    RTIME oldestItem;
} _HbsDelayBuffer;

RBOOL
    hbs_markAsRelated
    (
        rSequence parent,
        rSequence toMark
    )
{
    RBOOL isSuccess = FALSE;
    RPCHAR invId = NULL;

    if( rpal_memory_isValid( parent ) &&
        rpal_memory_isValid( toMark ) )
    {
        isSuccess = TRUE;

        if( rSequence_getSTRINGA( parent, RP_TAGS_HBS_INVESTIGATION_ID, &invId ) )
        {
            isSuccess = FALSE;
            if( rSequence_addSTRINGA( toMark, RP_TAGS_HBS_INVESTIGATION_ID, invId ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    hbs_timestampEvent
    (
        rSequence event,
        RTIME optOriginal
    )
{
    RBOOL isTimestamped = FALSE;
    RTIME ts = 0;

    if( NULL != event )
    {
        if( 0 != optOriginal )
        {
            ts = optOriginal;
        }
        else
        {
            ts = rpal_time_getGlobalPreciseTime();
        }

        isTimestamped = rSequence_addTIMESTAMP( event, RP_TAGS_TIMESTAMP, ts );
    }

    return isTimestamped;
}

RBOOL
    hbs_whenCpuBelow
    (
        RU8 percent,
        RTIME timeoutSeconds,
        rEvent abortEvent
    )
{
    RBOOL isCpuIdle = FALSE;

    RTIME end = rpal_time_getLocal() + timeoutSeconds;

    do
    {
        if( libOs_getCpuUsage() <= percent )
        {
            isCpuIdle = TRUE;
            break;
        }

        if( NULL == abortEvent )
        {
            rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
        }
        else
        {
            if( rEvent_wait( abortEvent, MSEC_FROM_SEC( 1 ) ) )
            {
                break;
            }
        }
    } 
    while( end > rpal_time_getLocal() );

    return isCpuIdle;
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

HbsRingBuffer
    HbsRingBuffer_new
    (
        RU32 nMaxElements,
        RU32 maxTotalSize
    )
{
    _HbsRingBuffer* hrb = NULL;

    if( NULL != ( hrb = rpal_memory_alloc( sizeof( _HbsRingBuffer ) ) ) )
    {
        if( rpal_collection_create( &hrb->col, _freeEvt ) )
        {
            hrb->sizeInBuffer = 0;
            hrb->nMaxElements = nMaxElements;
            hrb->maxTotalSize = maxTotalSize;
        }
        else
        {
            rpal_memory_free( hrb );
            hrb = NULL;
        }
    }

    return (HbsRingBuffer)hrb;
}

RVOID
    HbsRingBuffer_free
    (
        HbsRingBuffer hrb
    )
{
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;
    
    if( rpal_memory_isValid( pHrb ) )
    {
        if( NULL != pHrb->col )
        {
            rpal_collection_free( pHrb->col );
        }

        rpal_memory_free( pHrb );
    }
}

RBOOL
    HbsRingBuffer_add
    (
        HbsRingBuffer hrb,
        rSequence elem
    )
{
    RBOOL isAdded = FALSE;
    RBOOL isReadyToAdd = FALSE;
    RU32 elemSize = 0;
    rSequence toDelete = NULL;
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;

    if( rpal_memory_isValid( hrb ) &&
        rpal_memory_isValid( elem ) )
    {
        elemSize = rSequence_getEstimateSize( elem );

        isReadyToAdd = TRUE;

        while( ( 0 != pHrb->maxTotalSize &&
                 elemSize + pHrb->sizeInBuffer > pHrb->maxTotalSize ) ||
               ( 0 != pHrb->nMaxElements &&
                 rpal_collection_getSize( pHrb->col ) + 1 > pHrb->nMaxElements ) )
        {
            if( rpal_collection_remove( pHrb->col, &toDelete, NULL, NULL, NULL ) )
            {
                rSequence_free( toDelete );
            }
            else
            {
                isReadyToAdd = FALSE;
                break;
            }
        }

        if( isReadyToAdd &&
            rpal_collection_add( pHrb->col, elem, sizeof( elem ) ) )
        {
            isAdded = TRUE;
            pHrb->sizeInBuffer += rSequence_getEstimateSize( elem );
        }
    }

    return isAdded;
}

typedef struct
{
    RBOOL( *compareFunction )( rSequence seq, RPVOID ref );
    RPVOID ref;
    rSequence last;

} _ShimCompareContext;

RPRIVATE
RBOOL
    _shimCompareFunction
    (
        rSequence seq,
        RU32 dummySize,
        _ShimCompareContext* ctx
    )
{
    RBOOL ret = FALSE;
    UNREFERENCED_PARAMETER( dummySize );

    if( NULL != seq &&
        NULL != ctx )
    {
        // If the out value of the find contained a non-null
        // pointer we use it as an iterator marker and will
        // only report hits we find AFTER we've seen the marker.
        // This means that a new call to find should always
        // use NULL as an initial value in the pFound but also
        // that if you use it as an iterator you cannot remove
        // the last found value in between calls.
        if( NULL != ctx->last )
        {
            if( ctx->last == seq )
            {
                ctx->last = NULL;
            }
        }
        else
        {
            ret = ctx->compareFunction( seq, ctx->ref );
        }
    }

    return ret;
}

RBOOL
    HbsRingBuffer_find
    (
        HbsRingBuffer hrb,
        RBOOL( *compareFunction )( rSequence seq, RPVOID ref ),
        RPVOID ref,
        rSequence* pFound
    )
{
    RBOOL isFound = FALSE;
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;
    _ShimCompareContext ctx = { 0 };

    if( rpal_memory_isValid( hrb ) &&
        NULL != compareFunction &&
        NULL != pFound )
    {
        ctx.compareFunction = compareFunction;
        ctx.ref = ref;

        if( NULL != *pFound )
        {
            ctx.last = *pFound;
        }

        if( rpal_collection_get( pHrb->col, pFound, NULL, (collection_compare_func)_shimCompareFunction, &ctx ) )
        {
            isFound = TRUE;
        }
    }

    return isFound;
}

RBOOL
    hbs_sendCompletionEvent
    (
        rSequence originalRequest,
        rpcm_tag eventType,
        RU32 errorCode,
        RPCHAR errorMessage
    )
{
    RBOOL isSuccess = FALSE;

    rSequence event = NULL;
    RPU8 pAtomId = NULL;

    if( NULL != ( event = rSequence_new() ) )
    {
        if( rSequence_addRU32( event, RP_TAGS_ERROR, errorCode ) &&
            ( NULL == errorMessage || rSequence_addSTRINGA( event, RP_TAGS_ERROR_MESSAGE, errorMessage ) ) )
        {
            hbs_markAsRelated( originalRequest, event );
            HbsGetThisAtom( originalRequest, &pAtomId );
            HbsSetParentAtom( event, pAtomId );
            hbs_timestampEvent( event, 0 );
            isSuccess = notifications_publish( eventType, event );
        }

        rSequence_free( event );
    }

    return isSuccess;
}

RBOOL
    hbs_publish
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RBOOL isSuccess = FALSE;
    RPU8 pAtomId = NULL;
    Atom atom = { 0 };
    RU32 atomSize = 0;
    RTIME ts = 0;

    if( NULL != event )
    {
        // We will add a one-off atom for free if it's not there.
        // But if you need a registered atom you will need to generate it and 
        // add it yourself.
        if( !rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &pAtomId, &atomSize ) )
        {
            atoms_getOneTime( &atom );
            rSequence_addBUFFER( event, RP_TAGS_HBS_THIS_ATOM, atom.id, sizeof( atom.id ) );
        }

        if( !rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &ts ) )
        {
            hbs_timestampEvent( event, 0 );
        }

        isSuccess = notifications_publish( eventType, event );

        rSequence_unTaintRead( event );
    }

    return isSuccess;
}

typedef struct
{
    rpcm_tag type;
    RTIME ts;
    rSequence event;
} _EventStub;

RPRIVATE
RS32
    _cmpEventTimes
    (
        _EventStub* evt1,
        _EventStub* evt2
    )
{
    RS32 ret = 0;
    RTIME t1 = 0;
    RTIME t2 = 0;

    if( NULL != evt1 &&
        NULL != evt2 )
    {
        t1 = evt1->ts;
        t2 = evt2->ts;

        // First key is the time and the pointer value is the tie breaker.
        if( t1 > t2 )
        {
            ret = 1;
        }
        else if( t2 > t1 )
        {
            ret = -1;
        }
        else if( evt1->event > evt2->event )
        {
            ret = 1;
        }
        else if( evt2->event > evt1->event )
        {
            ret = -1;
        }
        else
        {
            ret = 0;
        }
    }

    return ret;
}

RPRIVATE
RVOID
    _freeStub
    (
        _EventStub* evt
    )
{
    if( NULL != evt )
    {
        rSequence_free( evt->event );
    }
}

HbsDelayBuffer
    HbsDelayBuffer_new
    (
        RU32 nMilliSeconds
    )
{
    _HbsDelayBuffer* hdb = NULL;

    if( NULL != ( hdb = rpal_memory_alloc( sizeof( *hdb ) ) ) )
    {
        hdb->nMilliSeconds = nMilliSeconds;
        hdb->oldestItem = (RTIME)(-1);
        if( NULL == ( hdb->events = rpal_btree_create( sizeof( _EventStub ),
                                                       (rpal_btree_comp_f)_cmpEventTimes,
                                                       (rpal_btree_free_f)_freeStub ) ) ||
            NULL == ( hdb->newElemEvent = rEvent_create( FALSE ) ) ||
            NULL == ( hdb->mutex = rMutex_create() ) )
        {
            rEvent_free( hdb->newElemEvent );
            rMutex_free( hdb->mutex );
            rpal_btree_destroy( hdb->events, FALSE );
            rpal_memory_free( hdb );
            hdb = NULL;
        }
    }

    return hdb;
}

RBOOL
    HbsDelayBuffer_add
    (
        HbsDelayBuffer hdb,
        rpcm_tag eventType,
        rSequence event
    )
{
    RBOOL isAdded = FALSE;
    _HbsDelayBuffer* pHdb = (_HbsDelayBuffer*)hdb;
    RTIME newTime = 0;
    _EventStub stub = { 0 };

    if( NULL != pHdb )
    {
        if( rMutex_lock( pHdb->mutex ) )
        {
            stub.event = event;
            stub.type = eventType;

            if( rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &newTime ) )
            {
                stub.ts = newTime;

                if( rpal_btree_add( pHdb->events, &stub, FALSE ) )
                {
                    if( newTime < pHdb->oldestItem )
                    {
                        pHdb->oldestItem = newTime;
                        rEvent_set( pHdb->newElemEvent );
                    }

                    isAdded = TRUE;
                }
            }
            rMutex_unlock( pHdb->mutex );
        }
    }

    return isAdded;
}

RVOID
    HbsDelayBuffer_free
    (
        HbsDelayBuffer hdb
    )
{
    _HbsDelayBuffer* pHdb = (_HbsDelayBuffer*)hdb;

    if( NULL != pHdb )
    {
        rMutex_lock( pHdb->mutex );
        rEvent_free( pHdb->newElemEvent );
        rMutex_free( pHdb->mutex );
        rpal_btree_destroy( pHdb->events, TRUE );
        rpal_memory_free( pHdb );
    }
}

RBOOL
    HbsDelayBuffer_remove
    (
        HbsDelayBuffer hdb,
        rSequence* pEvent,
        rpcm_tag* pEventType,
        RU32 milliSecTimeout
    )
{
    RBOOL isSuccess = FALSE;
    _HbsDelayBuffer* pHdb = (_HbsDelayBuffer*)hdb;
    RTIME curTime = 0;
    RTIME endWait = 0;
    RTIME toWait = 0;
    RBOOL isItemReady = FALSE;
    _EventStub stub = { 0 };

    if( NULL != pHdb &&
        NULL != pEvent &&
        NULL != pEventType )
    {
        if( rMutex_lock( pHdb->mutex ) )
        {
            curTime = rpal_time_getGlobalPreciseTime();
            endWait = curTime + milliSecTimeout;

            do
            {
                if( (RTIME)( -1 ) != pHdb->oldestItem )
                {
                    if( pHdb->oldestItem + pHdb->nMilliSeconds <= curTime )
                    {
                        isItemReady = TRUE;
                        break;
                    }

                    if( endWait <= curTime )
                    {
                        break;
                    }

                    toWait = MIN_OF( ( pHdb->oldestItem + pHdb->nMilliSeconds ) - curTime, endWait - curTime );
                }
                else if( endWait <= curTime )
                {
                    break;
                }
                else
                {
                    toWait = milliSecTimeout;
                }

                rMutex_unlock( pHdb->mutex );

                // We add a sanity check for max timeout here since in some rare cases
                // (mainly related to running both a Cloud and a sensor in VMs on a laptop
                // going in hibernation) we could end up with wild values.
                if( !rEvent_wait( pHdb->newElemEvent, (RU32)MIN_OF( toWait, milliSecTimeout ) ) )
                {
                    isItemReady = TRUE;
                }

                rMutex_lock( pHdb->mutex );

                curTime = rpal_time_getGlobalPreciseTime();

            } while( !isItemReady );

            if( isItemReady )
            {
                if( rpal_btree_minimum( pHdb->events, &stub, TRUE ) &&
                    curTime >= stub.ts + pHdb->nMilliSeconds &&
                    rpal_btree_remove( pHdb->events, &stub, &stub, TRUE ) )
                {
                    *pEvent = stub.event;
                    *pEventType = stub.type;

                    if( rpal_btree_minimum( pHdb->events, &stub, TRUE ) )
                    {
                        pHdb->oldestItem = stub.ts;
                    }
                    else
                    {
                        pHdb->oldestItem = (RTIME)(-1);
                    }

                    isSuccess = TRUE;
                }
            }

            rMutex_unlock( pHdb->mutex );
        }
    }

    return isSuccess;
}


RBOOL
    HbsSetThisAtom
    (
        rSequence msg,
        RU8 atomId[ HBS_ATOM_ID_SIZE ]
    )
{
    RBOOL isSuccess = FALSE;

    if( rSequence_addBUFFER( msg, RP_TAGS_HBS_THIS_ATOM, atomId, HBS_ATOM_ID_SIZE ) ||
        ( rSequence_removeElement( msg, RP_TAGS_HBS_THIS_ATOM, RPCM_BUFFER ) &&
          rSequence_addBUFFER( msg, RP_TAGS_HBS_THIS_ATOM, atomId, HBS_ATOM_ID_SIZE ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    HbsSetParentAtom
    (
        rSequence msg,
        RU8 atomId[ HBS_ATOM_ID_SIZE ]
    )
{
    RBOOL isSuccess = FALSE;

    if( rSequence_addBUFFER( msg, RP_TAGS_HBS_PARENT_ATOM, atomId, HBS_ATOM_ID_SIZE ) ||
        ( rSequence_removeElement( msg, RP_TAGS_HBS_PARENT_ATOM, RPCM_BUFFER ) &&
          rSequence_addBUFFER( msg, RP_TAGS_HBS_PARENT_ATOM, atomId, HBS_ATOM_ID_SIZE ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    HbsGetThisAtom
    (
        rSequence msg,
        RPU8* pAtomId
    )
{
    RBOOL isSuccess = FALSE;
    RU32 size = 0;

    if( rSequence_getBUFFER( msg, RP_TAGS_HBS_THIS_ATOM, pAtomId, &size ) )
    {
        if( HBS_ATOM_ID_SIZE == size )
        {
            isSuccess = TRUE;
        }
        else if( NULL != pAtomId )
        {
            *pAtomId = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    HbsGetParentAtom
    (
        rSequence msg,
        RPU8* pAtomId
    )
{
    RBOOL isSuccess = FALSE;
    RU32 size = 0;

    if( rSequence_getBUFFER( msg, RP_TAGS_HBS_PARENT_ATOM, pAtomId, &size ) )
    {
        if( HBS_ATOM_ID_SIZE == size )
        {
            isSuccess = TRUE;
        }
        else if( NULL != pAtomId )
        {
            *pAtomId = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    HbsAssert
    (
        SelfTestContext* ctx,
        RU32 fileId,
        RU32 lineId,
        RBOOL value,
        rSequence mtd
    )
{
    RBOOL isOk = FALSE;
    rSequence notif = NULL;
    RU8 atomId[ HBS_ATOM_ID_SIZE ] = { 0 };

    if( NULL != ctx )
    {
        isOk = value;
        ctx->nTests++;

        if( !value )
        {
            ctx->nFailures++;

            rpal_debug_warning( "TEST FAILURE in file %d at line %d.", fileId, lineId );

            if( NULL != ( notif = rSequence_new() ) )
            {
                if( rpal_memory_isValid( mtd ) &&
                    !rSequence_addSEQUENCEdup( notif, RP_TAGS_HCP_CRASH_CONTEXT, mtd ) )
                {
                    rpal_debug_error( "failed to attach crash context to test failure." );
                }

                if( !rSequence_addRU32( notif, RP_TAGS_HCP_FILE_ID, fileId ) ||
                    !rSequence_addRU32( notif, RP_TAGS_HCP_LINE_NUMBER, lineId ) )
                {
                    rpal_debug_error( "failed to add basic test data for failure." );
                }

                hbs_markAsRelated( ctx->originalTestRequest, notif );
                HbsGetThisAtom( ctx->originalTestRequest, (RPU8*)&atomId );
                HbsSetParentAtom( notif, atomId );

                hbs_publish( RP_TAGS_NOTIFICATION_SELF_TEST_RESULT, notif );

                rSequence_free( notif );
            }
        }
    }

    return isOk;
}
