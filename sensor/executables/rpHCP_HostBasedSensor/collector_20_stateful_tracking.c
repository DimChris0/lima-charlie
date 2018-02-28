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
#include "stateful_framework.h"
#include "stateful_events.h"

#define RPAL_FILE_ID       106

RPRIVATE rQueue g_events = NULL;
RPRIVATE rVector g_liveMachines = NULL;

RPRIVATE StatefulMachineDescriptor* g_statefulMachines[] =
{
    // Need to set various platform recon categories
    //ENABLED_STATEFUL( 0 ),
    DISABLED_STATEFUL( 0 ),
    // Need more timely module notifications on other platforms for this to be relevant
    //ENABLED_WINDOWS_STATEFUL( 1 ),
    DISABLED_STATEFUL( 1 ),
    // Need to categorize document software on other platforms
    //ENABLED_WINDOWS_STATEFUL( 2 )
    DISABLED_STATEFUL( 2 )
};

// For now this is a hardcoded list of events, TODO: make it dynamic based on info from FSMs.
RPRIVATE rpcm_tag g_eventsOfInterest[] = { RP_TAGS_NOTIFICATION_NEW_PROCESS,
                                           RP_TAGS_NOTIFICATION_TERMINATE_PROCESS,
                                           RP_TAGS_NOTIFICATION_MODULE_LOAD };

RPRIVATE
RVOID
    _freeSmEvent
    (
        StatefulEvent* evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rRefCount_release( evt->ref, NULL );
}

RPRIVATE
RPVOID
    updateThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    StatefulEvent* statefulEvent = NULL;
    StatefulMachine* tmpMachine = NULL;
    StatefulEvent* event = NULL;
    rpcm_tag eventType = 0;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( HbsDelayBuffer_remove( g_events, (RPVOID*)&event, &eventType, MSEC_FROM_SEC( 1 ) ) )
        {
            RTIME tmp = 0;
            rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &tmp );

            if( NULL != ( statefulEvent = SMEvent_new( eventType, event ) ) )
            {
                // First we update currently running machines
                for( i = 0; i < g_liveMachines->nElements; i++ )
                {
                    //rpal_debug_info( "SM begin update ( %p / %p )", g_liveMachines->elements[ i ], ((StatefulMachine*)g_liveMachines->elements[ i ])->desc );

                    if( !SMUpdate( g_liveMachines->elements[ i ], statefulEvent ) )
                    {
                        //rpal_debug_info( "SM no longer required ( %p / %p )", g_liveMachines->elements[ i ], ((StatefulMachine*)g_liveMachines->elements[ i ])->desc );

                        // Machine indicated it is no longer live
                        SMFreeMachine( g_liveMachines->elements[ i ] );
                        if( rpal_vector_remove( g_liveMachines, i ) )
                        {
                            i--;
                        }
                    }
                }

                // Then we prime any new machines
                for( i = 0; i < ARRAY_N_ELEM( g_statefulMachines ); i++ )
                {
                    if( NULL != ( tmpMachine = SMPrime( g_statefulMachines[ i ], statefulEvent ) ) )
                    {
                        //rpal_debug_info( "SM created ( %p / %p )", tmpMachine, g_statefulMachines[ i ] );

                        // New machines get added to the pool of live machines
                        if( !rpal_vector_add( g_liveMachines, tmpMachine ) )
                        {
                            SMFreeMachine( tmpMachine );
                        }
                    }
                }

                _freeSmEvent( statefulEvent, 0 );
            }
            else
            {
                rSequence_free( event );
            }
        }
    }

    return NULL;
}

RPRIVATE
RVOID
    addNewSmEvent
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RU32 i = 0;
    RBOOL isOfInterest = FALSE;

    if( NULL != event )
    {
        // TODO: When we get more events do a binary search or something optimized.
        for( i = 0; i < ARRAY_N_ELEM( g_eventsOfInterest ); i++ )
        {
            if( g_eventsOfInterest[ i ] == notifType )
            {
                isOfInterest = TRUE;
                break;
            }
        }

        if( isOfInterest &&
            NULL != ( event = rSequence_duplicate( event ) ) )
        {
            if( !HbsDelayBuffer_add( g_events, notifType, event ) )
            {
                rpal_debug_warning( "error enqueuing delayed buffer" );
                rSequence_free( event );
            }
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_20_events[] = { STATEFUL_MACHINE_0_EVENT,
                                   STATEFUL_MACHINE_1_EVENT,
                                   0 };

RBOOL
    collector_20_init
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
        if( NULL != ( g_events = HbsDelayBuffer_new( 500 ) ) )
        {
            if( NULL != ( g_liveMachines = rpal_vector_new() ) )
            {
                if( rThreadPool_task( hbsState->hThreadPool, updateThread, NULL ) )
                {
                    isSuccess = TRUE;
                }
            }
        }

        if( isSuccess )
        {
            for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
            {
                j = 0;

                while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
                {
                    if( !notifications_subscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                  NULL, 
                                                  0, 
                                                  NULL, 
                                                  addNewSmEvent ) )
                    {
                        isSuccess = FALSE;
                        break;
                    }

                    j++;
                }
            }
        }

        if( !isSuccess )
        {
            for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
            {
                j = 0;

                while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
                {
                    if( !notifications_unsubscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                    NULL,
                                                    addNewSmEvent ) )
                    {
                        isSuccess = FALSE;
                    }

                    j++;
                }
            }
            HbsDelayBuffer_free( g_events );
            g_events = NULL;
            rpal_vector_free( g_liveMachines );
            g_liveMachines = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    collector_20_cleanup
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
        for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
        {
            j = 0;

            while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
            {
                if( !notifications_unsubscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                NULL,
                                                addNewSmEvent ) )
                {
                    isSuccess = FALSE;
                }

                j++;
            }
        }

        HbsDelayBuffer_free( g_events );
        g_events = NULL;
        for( i = 0; i < g_liveMachines->nElements; i++ )
        {
            SMFreeMachine( g_liveMachines->elements[ i ] );
        }
        rpal_vector_free( g_liveMachines );
        g_liveMachines = NULL;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_20_update
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
HBS_TEST_SUITE( 20 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}