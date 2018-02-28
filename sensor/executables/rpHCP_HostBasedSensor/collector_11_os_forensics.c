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
#include <libOs/libOs.h>
#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define RPAL_FILE_ID        77

#define _FULL_SNAPSHOT_DEFAULT_DELTA        (60*60*24)

RPRIVATE
RVOID
    os_services
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList svcList;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( NULL != ( svcList = libOs_getServices( TRUE ) ) )
        {
            if( !rSequence_addLIST( event, RP_TAGS_SVCS, svcList ) )
            {
                rList_free( svcList );
            }
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
        }

        rSequence_addTIMESTAMP( event, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() );
        hbs_publish( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, event );
    }
}


RPRIVATE
RVOID
    os_drivers
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList svcList;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( NULL != ( svcList = libOs_getDrivers( TRUE ) ) )
        {
            if( !rSequence_addLIST( event, RP_TAGS_SVCS, svcList ) )
            {
                rList_free( svcList );
            }
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, event );
    }
}


RPRIVATE
RVOID
    os_processes
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList procList = NULL;
    rSequence proc = NULL;
    rList mods = NULL;
    processLibProcEntry* entries = NULL;
    RU32 entryIndex = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) &&
        hbs_timestampEvent( event, 0 ) &&
        NULL != ( procList = rList_new( RP_TAGS_PROCESS, RPCM_SEQUENCE ) ) &&
        rSequence_addLIST( event, RP_TAGS_PROCESSES, procList ) )
    {
        entries = processLib_getProcessEntries( TRUE );

        while( NULL != entries && 0 != entries[ entryIndex ].pid )
        {
            if( NULL != ( proc = processLib_getProcessInfo( entries[ entryIndex ].pid, NULL ) ) )
            {
                if( NULL != ( mods = processLib_getProcessModules( entries[ entryIndex ].pid ) ) )
                {
                    if( !rSequence_addLIST( proc, RP_TAGS_MODULES, mods ) )
                    {
                        rList_free( mods );
                        mods = NULL;
                    }
                }

                if( !rList_addSEQUENCE( procList, proc ) )
                {
                    rSequence_free( proc );
                    proc = NULL;
                }
            }

            entryIndex++;

            proc = NULL;
            mods = NULL;
        }

        rpal_memory_free( entries );

        hbs_publish( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, event );
    }
    else
    {
        rList_free( procList );
    }
}

RPRIVATE
RVOID
    os_autoruns
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList autoruns = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rpal_memory_isValid( event ) )
        {

            if( NULL != ( autoruns = libOs_getAutoruns( TRUE ) ) )
            {
                if( !rSequence_addLIST( event, RP_TAGS_AUTORUNS, autoruns ) )
                {
                    rList_free( autoruns );
                    autoruns = NULL;
                }

                hbs_timestampEvent( event, 0 );

                hbs_publish( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, event );
            }
        }
    }
}


RPRIVATE
RPVOID
    allOsSnapshots
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rpcm_tag events[] = { RP_TAGS_NOTIFICATION_OS_AUTORUNS_REQ,
                          RP_TAGS_NOTIFICATION_OS_DRIVERS_REQ,
                          RP_TAGS_NOTIFICATION_OS_PROCESSES_REQ,
                          RP_TAGS_NOTIFICATION_OS_SERVICES_REQ };
    RU32 i = 0;
    rSequence dummy = NULL;

    UNREFERENCED_PARAMETER( ctx );

    rpal_debug_info( "beginning full os snapshots run" );
    while( !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 10 ) ) &&
            rpal_memory_isValid( isTimeToStop ) &&
            i < ARRAY_N_ELEM( events ) )
    {
        if( NULL != ( dummy = rSequence_new() ) )
        {
            hbs_publish( events[ i ], dummy );
            i++;

            rSequence_free( dummy );
        }
    }

    return NULL;
}

RPRIVATE
RVOID
    os_kill_process
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = 0;
    RPU8 atom = NULL;
    RU32 atomSize = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) ||
            ( rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atom, &atomSize ) &&
              HBS_ATOM_ID_SIZE == atomSize &&
              0 != ( pid = atoms_getPid( atom ) ) ) )
        {
            if( processLib_killProcess( pid ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_SUCCESS );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_INVALID_PARAMETER );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_OS_KILL_PROCESS_REP, event );
    }
}


RPRIVATE
RVOID
    os_suspend
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = 0;
    RU32 tid = 0;
    RPU8 atom = NULL;
    RU32 atomSize = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_THREAD_ID, &pid ) &&
            rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
        {
            if( processLib_getCurrentPid() == pid )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_ACCESS_DENIED );
            }
            else if( processLib_suspendThread( pid, tid ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_SUCCESS );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }
        else if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) ||
                 ( rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atom, &atomSize ) &&
                   HBS_ATOM_ID_SIZE == atomSize &&
                   0 != ( pid = atoms_getPid( atom ) ) ) )
        {
            if( processLib_getCurrentPid() == pid )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_ACCESS_DENIED );
            }
            else if( processLib_suspendProcess( pid ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_SUCCESS );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_INVALID_PARAMETER );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_OS_SUSPEND_REP, event );
    }
}


RPRIVATE
RVOID
    os_resume
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = 0;
    RU32 tid = 0;
    RPU8 atom = NULL;
    RU32 atomSize = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_THREAD_ID, &pid ) &&
            rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
        {
            if( processLib_getCurrentPid() == pid )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_ACCESS_DENIED );
            }
            else if( processLib_resumeThread( pid, tid ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_SUCCESS );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }
        }
        else if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) ||
                 ( rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atom, &atomSize ) &&
                   HBS_ATOM_ID_SIZE == atomSize &&
                   0 != ( pid = atoms_getPid( atom ) ) ) )
        {
            if( processLib_getCurrentPid() == pid )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_ACCESS_DENIED );
            }
            else if( processLib_resumeProcess( pid ) )
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_SUCCESS );
            }
            else
            {
                rSequence_addRU32( event, RP_TAGS_ERROR, rpal_error_getLast() );
            }    
        }
        else
        {
            rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_INVALID_PARAMETER );
        }

        hbs_timestampEvent( event, 0 );
        hbs_publish( RP_TAGS_NOTIFICATION_OS_RESUME_REP, event );
    }
}

RPRIVATE
RVOID
    os_version
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rSequence versionEx = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( NULL != ( versionEx = libOs_getOsVersionEx() ) )
        {
            hbs_publish( RP_TAGS_NOTIFICATION_OS_VERSION_REP, versionEx );
            rSequence_free( versionEx );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_11_events[] = { RP_TAGS_NOTIFICATION_OS_SERVICES_REP,
                                   RP_TAGS_NOTIFICATION_OS_DRIVERS_REP,
                                   RP_TAGS_NOTIFICATION_OS_PROCESSES_REP,
                                   RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP,
                                   RP_TAGS_NOTIFICATION_OS_KILL_PROCESS_REP,
                                   RP_TAGS_NOTIFICATION_OS_SUSPEND_REP,
                                   RP_TAGS_NOTIFICATION_OS_RESUME_REP,
                                   RP_TAGS_NOTIFICATION_OS_VERSION_REP,
                                   0 };

RBOOL
    collector_11_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU64 timeDelta = _FULL_SNAPSHOT_DEFAULT_DELTA;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_subscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REQ, NULL, 0, NULL, os_services ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REQ, NULL, 0, NULL, os_drivers ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REQ, NULL, 0, NULL, os_processes ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REQ, NULL, 0, NULL, os_autoruns ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_KILL_PROCESS_REQ, NULL, 0, NULL, os_kill_process ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_SUSPEND_REQ, NULL, 0, NULL, os_suspend ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_RESUME_REQ, NULL, 0, NULL, os_resume ) &&
            notifications_subscribe( RP_TAGS_NOTIFICATION_OS_VERSION_REQ, NULL, 0, NULL, os_version ) )
        {
            isSuccess = TRUE;

            if( rpal_memory_isValid( config ) )
            {
                if( !rSequence_getTIMEDELTA( config, RP_TAGS_TIMEDELTA, &timeDelta ) )
                {
                    timeDelta = _FULL_SNAPSHOT_DEFAULT_DELTA;
                }
            }

            if( !rThreadPool_scheduleRecurring( hbsState->hThreadPool, timeDelta, allOsSnapshots, NULL, TRUE ) )
            {
                isSuccess = FALSE;
            }
        }
        else
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REQ, NULL, os_services );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REQ, NULL, os_drivers );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REQ, NULL, os_processes );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REQ, NULL, os_autoruns );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SUSPEND_REQ, NULL, os_suspend );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_RESUME_REQ, NULL, os_resume );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_VERSION_REQ, NULL, os_version );
        }
    }

    return isSuccess;
}

RBOOL
    collector_11_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REQ, NULL, os_services );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REQ, NULL, os_drivers );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REQ, NULL, os_processes );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REQ, NULL, os_autoruns );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_KILL_PROCESS_REQ, NULL, os_kill_process );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SUSPEND_REQ, NULL, os_suspend );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_RESUME_REQ, NULL, os_resume );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_VERSION_REQ, NULL, os_version );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_11_update
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
HBS_DECLARE_TEST( os_processes )
{
    rQueue notifQueue = NULL;
    rSequence event = NULL;
    rList processes = NULL;
    RU32 size = 0;
    processLibProcEntry* entries = NULL;

    // Test the sub components of doing a process listing.
    entries = processLib_getProcessEntries( TRUE );
    if( HBS_ASSERT_TRUE( NULL != entries ) )
    {
        size = 0;
        while( NULL != entries && 0 != entries[ size ].pid )
        {
            size++;
        }

        HBS_ASSERT_TRUE( 0 != size );
        rpal_memory_free( entries );
    }

    // Do a wholistic test of the process listing.
    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );

    // Register to the notifications we expect.
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, 0, notifQueue, NULL ) );

    event = rSequence_new();
    if( HBS_ASSERT_TRUE( NULL != event ) )
    {
        os_processes( RP_TAGS_NOTIFICATION_OS_PROCESSES_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
        HBS_ASSERT_TRUE( 1 == size );
        HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &event, NULL, 0 ) );

        HBS_ASSERT_TRUE( rSequence_getLIST( event, RP_TAGS_PROCESSES, &processes ) );

        rSequence_free( event );
    }

    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, notifQueue, NULL );
    rQueue_free( notifQueue );
}

HBS_DECLARE_TEST( os_version )
{
    rQueue notifQueue = NULL;
    rSequence event = NULL;
    RU32 size = 0;
    rpcm_tag tag = 0;
    rpcm_type type = 0;
    
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_OS_VERSION_REP, NULL, 0, notifQueue, NULL ) );

    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );

    event = rSequence_new();
    if( HBS_ASSERT_TRUE( NULL != event ) )
    {
        os_version( RP_TAGS_NOTIFICATION_OS_VERSION_REQ, event );
        rSequence_free( event );

        HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &size ) );
        HBS_ASSERT_TRUE( 1 == size );
        HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &event, NULL, 0 ) );

        HBS_ASSERT_TRUE( rSequence_getElement( event, &tag, &type, NULL, &size ) );

        rSequence_free( event );
    }

    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_VERSION_REP, notifQueue, NULL );
    rQueue_free( notifQueue );
}

HBS_TEST_SUITE( 11 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        HBS_RUN_TEST( os_processes );
        HBS_RUN_TEST( os_version );
        isSuccess = TRUE;
    }

    return isSuccess;
}