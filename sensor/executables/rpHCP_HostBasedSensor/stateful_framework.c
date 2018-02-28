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

#include "stateful_framework.h"
#include <rpal/rpal.h>
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include "collectors.h"

#define RPAL_FILE_ID        107

//=============================================================================
//  BOILERPLATE
//=============================================================================
RPRIVATE
RVOID
    _freeEvent
    (
        StatefulEvent* event,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    if( rpal_memory_isValid( event ) )
    {
        rSequence_free( event->data );
        event->data = NULL;
        rpal_memory_free( event );
    }
}

RPRIVATE
RBOOL
    _reportEvents
    (
        StatefulMachine* machine
    )
{
    RBOOL isSuccess = FALSE;

    rSequence wrapper = NULL;
    rList events = NULL;
    rSequence event = NULL;
    RU32 i = 0;

    if( NULL != machine )
    {
        if( NULL != ( wrapper = rSequence_new() ) )
        {
            if( NULL != ( events = rList_new( RP_TAGS_EVENT, RPCM_SEQUENCE ) ) )
            {
                for( i = 0; i < machine->history->nElements; i++ )
                {
                    event = ( (StatefulEvent*)machine->history->elements[ i ] )->data;
                    rList_addSEQUENCE( events, rSequence_duplicate( event ) );
                }

                if( !rSequence_addLIST( wrapper, RP_TAGS_EVENTS, events ) )
                {
                    rList_free( events );
                }
                else
                {
                    hbs_timestampEvent( wrapper, 0 );
                    isSuccess = hbs_publish( machine->desc->reportEventType, wrapper );
                }
            }

            rSequence_free( wrapper );
        }
    }

    return isSuccess;
}

RPRIVATE
StatefulMachine*
    _newMachineFrom
    (
        StatefulMachineDescriptor* desc
    )
{
    StatefulMachine* machine = NULL;

    if( NULL != desc )
    {
        if( NULL != ( machine = rpal_memory_alloc( sizeof( *machine ) ) ) )
        {
            machine->desc = desc;
            machine->currentState = 0;
            if( NULL == ( machine->history = rpal_vector_new() ) )
            {
                rpal_memory_free( machine );
                machine = NULL;
            }
        }
    }

    return machine;
}

StatefulEvent*
    SMEvent_new
    (
        rpcm_tag eventType,
        rSequence data
    )
{
    StatefulEvent* event = NULL;

    rSequence wrapper = NULL;

    if( NULL != data )
    {
        if( NULL != ( wrapper = rSequence_new() ) )
        {
            if( NULL != ( event = rpal_memory_alloc( sizeof( *event ) ) ) )
            {
                if( NULL != ( event->ref = rRefCount_create( (rRefCount_freeFunc)_freeEvent, event, sizeof( *event ) ) ) )
                {
                    if( rSequence_addSEQUENCE( wrapper, eventType, data ) )
                    {
                        event->data = wrapper;
                        event->eventType = eventType;
                        rSequence_getTIMESTAMP( data, RP_TAGS_TIMESTAMP, &event->ts );
                    }
                    else
                    {
                        rSequence_free( wrapper );
                    }
                }
                else
                {
                    rpal_memory_free( event );
                    event = NULL;
                    rSequence_free( wrapper );
                }
            }
            else
            {
                rSequence_free( wrapper );
            }
        }
    }

    return event;
}

StatefulMachine*
    SMPrime
    (
        StatefulMachineDescriptor* desc,
        StatefulEvent* event
    )
{
    StatefulMachine* machine = NULL;
    StatefulState* currentState = NULL;
    RU32 i = 0;

    if( NULL != desc )
    {
        // When evaluating a possible new machine, we use state 0's transitions
        // to determine if it should be created. If one matches (not going to state 0), we create a new machine.
        currentState = (StatefulState*)( desc->states[ 0 ] );
        for( i = 0; i < currentState->nTransitions; i++ )
        {
            if( ( 0 == currentState->transitions[ i ].eventTypeOnly ||
                  event->eventType == currentState->transitions[ i ].eventTypeOnly ) &&
                0 != currentState->transitions[ i ].destState &&
                ( NULL == currentState->transitions[ i ].transition || 
                  currentState->transitions[ i ].transition( machine, 
                                                             event, 
                                                             currentState->transitions[ i ].parameters ) ) )
            {
                if( NULL != ( machine = _newMachineFrom( desc ) ) )
                {
                    // This is a match
                    if( currentState->transitions[ i ].isRecordEventOnMatch )
                    {
                        // We need to record this event as part of the history
                        if( rRefCount_acquire( event->ref ) )
                        {
                            if( !rpal_vector_add( machine->history, event ) )
                            {
                                rRefCount_release( event->ref, NULL );
                            }
                        }
                    }
                    if( currentState->transitions[ i ].isReportOnMatch )
                    {
                        // Report the current vector history
                        _reportEvents( machine );
                    }

                    machine->currentState = currentState->transitions[ i ].destState;
                }

                break;
            }
        }
    }

    return machine;
}

RBOOL
    SMUpdate
    (
        StatefulMachine*  machine,
        StatefulEvent* event
    )
{
    RBOOL isStayAlive = TRUE;

    RU32 i = 0;
    StatefulState* currentState = NULL;

    if( NULL != machine && 
        NULL != machine->desc )
    {
        if( machine->currentState < machine->desc->nStates )
        {
            currentState = (StatefulState*)( machine->desc->states[ machine->currentState ] );
            for( i = 0; i < currentState->nTransitions; i++ )
            {
                if( ( 0 == currentState->transitions[ i ].eventTypeOnly || 
                      event->eventType == currentState->transitions[ i ].eventTypeOnly ) &&
                    ( NULL == currentState->transitions[ i ].transition ||
                      currentState->transitions[ i ].transition( machine, 
                                                                 event, 
                                                                 currentState->transitions[ i ].parameters ) ) )
                {
                    // This is a match
                    if( currentState->transitions[ i ].isRecordEventOnMatch )
                    {
                        // We need to record this event as part of the history
                        if( rRefCount_acquire( event->ref ) )
                        {
                            if( !rpal_vector_add( machine->history, event ) )
                            {
                                rRefCount_release( event->ref, NULL );
                            }
                        }

                        //rpal_debug_info( "SM recorded event" );
                    }
                    if( currentState->transitions[ i ].isReportOnMatch )
                    {
                        // Report the current vector history
                        _reportEvents( machine );
                        rpal_debug_info( "SM generated event" );
                    }

                    if( 0 == currentState->transitions[ i ].destState ||
                        ( currentState->transitions[ i ].isFinishOnEmptySet &&
                          0 == machine->history->nElements ) )
                    {
                        // State 0 is a special state, it is the initial and terminal state
                        isStayAlive = FALSE;
                        //rpal_debug_info( "SM now finishing from %d by transition %d.", machine->currentState, i );
                    }
                    else
                    {
                        //rpal_debug_info( "SM moving from state %d to state %d by transition %d.", machine->currentState, currentState->transitions[ i ].destState, i );
                        machine->currentState = currentState->transitions[ i ].destState;
                    }

                    break;
                }
            }
        }
    }

    return isStayAlive;
}

RVOID
    SMFreeMachine
    (
        StatefulMachine* machine
    )
{
    RU32 i = 0;
    StatefulEvent* tmpEvent = NULL;
    
    if( NULL != machine )
    {
        for( i = 0; i < machine->history->nElements; i++ )
        {
            tmpEvent = machine->history->elements[ i ];
            rRefCount_release( tmpEvent->ref, NULL );
        }

        rpal_vector_free( machine->history );
        rpal_memory_free( machine );
    }
}


RPRIVATE
RBOOL
    _isTimeMatch
    (
        RTIME newEvent,
        RTIME oldEvent,
        RTIME withinAtLeast,
        RTIME withinAtMost
    )
{
    RBOOL isMatch = FALSE;

    RTIME delta = 0;

    if( 0 != newEvent &&
        0 != oldEvent )
    {
        if( newEvent >= oldEvent )
        {
            delta = newEvent - oldEvent;
        }
        else
        {
            delta = oldEvent - newEvent;
        }
        if( ( 0 == withinAtLeast || withinAtLeast <= delta ) &&
            ( 0 == withinAtMost || withinAtMost >= delta ) )
        {
            isMatch = TRUE;
        }
    }

    return isMatch;
}

RPRIVATE
RBOOL
    _isPatternMatch
    (
        rpcm_elem_record* elemToCheck,
        rpcm_elem_record* elemRef
    )
{
    RBOOL isMatch = FALSE;

    if( NULL != elemToCheck &&
        NULL != elemRef &&
        ( 0 == elemToCheck->tag ||
          0 == elemRef->tag ||
          elemToCheck->tag == elemRef->tag ) )
    {
        if( RPCM_STRINGA == elemToCheck->type &&
            RPCM_STRINGA == elemRef->type )
        {
            isMatch = rpal_string_matchA( elemRef->value, elemToCheck->value, FALSE );
        }
        else if( RPCM_STRINGW == elemToCheck->type &&
                 RPCM_STRINGW == elemRef->type )
        {
            isMatch = rpal_string_matchW( elemRef->value, elemToCheck->value, FALSE );
        }
    }

    return isMatch;
}


//=============================================================================
//  TRANSITIONS
//=============================================================================
RBOOL
    tr_match
    (
        StatefulMachine* machine,
        StatefulEvent* event,
        tr_match_params* parameters
    )
{
    RBOOL isMatch = FALSE;

    rStack elems1 = NULL;
    rStack elems2 = NULL;
    rpcm_elem_record elem1 = { 0 };
    rpcm_elem_record elem2 = { 0 };
    RU32 i = 0;
    RU32 j = 0;
    RU32 k = 0;
    StatefulEvent* tmpEvent = NULL;
    rRefCount tmpRef = NULL;

    if( NULL != event &&
        NULL != parameters )
    {
        if( NULL != parameters->newPathMatch )
        {
            if( NULL != ( elems1 = rpcm_fetchAllV( event->data,
                                                   parameters->matchType,
                                                   parameters->newPathMatch ) ) )
            {
                for( i = 0; i < rStack_getSize( elems1 ); i++ )
                {
                    if( !rStack_atIndex( elems1, i, &elem1 ) )
                    {
                        break;
                    }

                    if( NULL != machine &&
                        NULL != parameters->histPathMatch )
                    {
                        // We are matching between a historic value and a path in the
                        // current event match.
                        for( j = 0; j < machine->history->nElements; j++ )
                        {
                            tmpEvent = machine->history->elements[ j ];
                            if( NULL != ( elems2 = rpcm_fetchAllV( tmpEvent->data,
                                                                   parameters->matchType,
                                                                   parameters->histPathMatch ) ) )
                            {
                                for( k = 0; k < rStack_getSize( elems2 ); k++ )
                                {
                                    if( rStack_atIndex( elems2, k, &elem2 ) )
                                    {
                                        isMatch = rpcm_isElemEqual( parameters->matchType,
                                                                    elem1.value,
                                                                    elem1.size,
                                                                    elem2.value,
                                                                    elem2.size );
                                        /*
                                        if( 4 == elem1.size )
                                        {
                                            rpal_debug_info( "SM CMP %d %d %d", *(RU32*)elem1.value, *(RU32*)elem2.value, isMatch );
                                        }
                                        */
                                        if( isMatch )
                                        {
                                            if( 0 != parameters->withinAtLeast ||
                                                0 != parameters->withinAtMost )
                                            {
                                                isMatch = _isTimeMatch( event->ts,
                                                                        tmpEvent->ts,
                                                                        parameters->withinAtLeast,
                                                                        parameters->withinAtMost );
                                            }

                                            if( isMatch )
                                            {
                                                break;
                                            }
                                        }
                                    }

                                    if( isMatch )
                                    {
                                        break;
                                    }
                                }

                                rStack_free( elems2, NULL );
                            }

                            if( isMatch &&
                                parameters->isRemoveMatching )
                            {
                                tmpRef = tmpEvent->ref;
                                if( rpal_vector_remove( machine->history, j ) )
                                {
                                    j--;
                                    rRefCount_release( tmpRef, NULL );
                                }
                            }

                            if( isMatch ||
                                parameters->isMatchFirstEventOnly )
                            {
                                break;
                            }
                        }
                    }
                    else
                    {
                        // We are matching between a path in the current event match and
                        // a user-provided value.
                        elem2 = parameters->newMatchValue;
                        if( !parameters->isMatchPattern )
                        {
                            isMatch = rpcm_isElemEqual( parameters->matchType,
                                                        elem1.value,
                                                        elem1.size,
                                                        elem2.value,
                                                        elem2.size );
                        }
                        else
                        {
                            isMatch = _isPatternMatch( &elem1, &elem2 );
                        }
                        
                        if( isMatch )
                        {
                            if( NULL != machine &&
                                0 != machine->history->nElements &&
                                ( 0 != parameters->withinAtLeast ||
                                  0 != parameters->withinAtMost ) )
                            {
                                for( j = 0; j < machine->history->nElements; j++ )
                                {
                                    tmpEvent = machine->history->elements[ j ];
                                    
                                    isMatch = _isTimeMatch( event->ts,
                                                            tmpEvent->ts,
                                                            parameters->withinAtLeast,
                                                            parameters->withinAtMost );

                                    if( isMatch )
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if( isMatch )
                    {
                        break;
                    }
                }

                rStack_free( elems1, NULL );
            }
        }
        else if( NULL != machine &&
                 0 != machine->history->nElements )
        {
            // This is a pure time match, not content.

            for( i = 0; i < machine->history->nElements; i++ )
            {
                tmpEvent = machine->history->elements[ i ];
                isMatch = _isTimeMatch( event->ts,
                                        tmpEvent->ts,
                                        parameters->withinAtLeast,
                                        parameters->withinAtMost );
                if( isMatch )
                {
                    break;
                }

                if( isMatch &&
                    parameters->isRemoveMatching )
                {
                    tmpRef = tmpEvent->ref;
                    if( rpal_vector_remove( machine->history, i ) )
                    {
                        i--;
                        rRefCount_release( tmpRef, NULL );
                    }
                }

                if( parameters->isMatchFirstEventOnly )
                {
                    break;
                }
            }
        }
        else
        {
            isMatch = TRUE;
        }
    }

    isMatch = parameters->isInvertMatch ? !isMatch : isMatch;

    return isMatch;
}

RBOOL
    tr_and_match
    (
        StatefulMachine* machine,
        StatefulEvent* event,
        tr_and_match_params* parameters
    )
{
    RBOOL isMatch = FALSE;

    RU32 i = 0;

    if( NULL != machine &&
        NULL != event &&
        NULL != parameters )
    {
        isMatch = TRUE;

        for( i = 0; i < ARRAY_N_ELEM( parameters->params ); i++ )
        {
            if( !tr_match( machine, event, &(parameters->params[ i ]) ) )
            {
                isMatch = FALSE;
                break;
            }
        }
    }

    return isMatch;
}