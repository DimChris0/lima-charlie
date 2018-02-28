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


#define RPAL_FILE_ID                  97

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <processLib/processLib.h>

#define DENY_TREE_CLEANUP_TIMEOUT   (600)

RPRIVATE rBlob g_denied = NULL;
RPRIVATE rMutex g_deniedMutex = NULL;
RPRIVATE RTIME g_lastDenyActivity = 0;

// Provides a lexicographic ordering of atoms.
RPRIVATE
RS32
    cmpAtoms
    (
        RPU8 atomId1,
        RPU8 atomId2
    )
{
    return (RS32)rpal_memory_memcmp( atomId1, atomId2, HBS_ATOM_ID_SIZE );
}

// Add an atom to the deny list, which is just a sortled list
// on which we do binary searches.
RPRIVATE
RVOID
    addAtomToDeny
    (
        RPU8 atomId
    )
{
    if( rMutex_lock( g_deniedMutex ) )
    {
        rpal_blob_add( g_denied, atomId, HBS_ATOM_ID_SIZE );
        rpal_sort_array( rpal_blob_getBuffer( g_denied ), 
                         rpal_blob_getSize( g_denied ) / HBS_ATOM_ID_SIZE, 
                         HBS_ATOM_ID_SIZE, 
                         (rpal_ordering_func)cmpAtoms );

        g_lastDenyActivity = rpal_time_getGlobal();

        rMutex_unlock( g_deniedMutex );
    }
}

// Given an atom, check if it's on the deny list.
RPRIVATE
RBOOL
    isAtomDenied
    (
        RPU8 atomId
    )
{
    RBOOL isDenied = FALSE;

    if( rMutex_lock( g_deniedMutex ) )
    {
        if( ( -1 ) != rpal_binsearch_array( rpal_blob_getBuffer( g_denied ),
                                            rpal_blob_getSize( g_denied ) / HBS_ATOM_ID_SIZE,
                                            HBS_ATOM_ID_SIZE,
                                            atomId,
                                            (rpal_ordering_func)cmpAtoms ) )
        {
            isDenied = TRUE;
        }

        rMutex_unlock( g_deniedMutex );
    }

    return isDenied;
}

// Given an atom, find all already executing children, add them to the deny
// list and terminate their execution.
// This is not the most optimized algorithm but it's simple and only executes
// once per new deny tasking.
RPRIVATE
RVOID
    denyExistingTree
    (
        RU8 atomId[ HBS_ATOM_ID_SIZE ]
    )
{
    RU32 pid = 0;
    rBlob parents = NULL;
    RPU8 tmpAtom = NULL;
    RU32 i = 0;

    if( NULL != atomId )
    {
        addAtomToDeny( atomId );

        if( NULL != ( parents = atoms_getAtomsWithParent( atomId ) ) )
        {
            for( i = 0; i < rpal_blob_getSize( parents ) / HBS_ATOM_ID_SIZE; i++ )
            {
                if( NULL != ( tmpAtom = rpal_blob_arrElem( parents, HBS_ATOM_ID_SIZE, i ) ) )
                {
                    denyExistingTree( tmpAtom );
                }
            }

            rpal_blob_free( parents );
        }

        if( 0 != ( pid = atoms_getPid( atomId ) ) )
        {
            processLib_killProcess( pid );
        }
    }
}

// Receives a task to start denying a tree at a given root.
// Can be a single atom or a list of atoms.
RPRIVATE
RVOID
    denyNewTree
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    RU32 size = 0;
    rList atomList = NULL;

    UNREFERENCED_PARAMETER( notifType );

    // We accept a single atom, or a list of atoms
    if( rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atomId, &size ) &&
        HBS_ATOM_ID_SIZE == size )
    {
        denyExistingTree( atomId );
    }
    else if( rSequence_getLIST( event, RP_TAGS_HBS_THIS_ATOM, &atomList ) )
    {
        while( rList_getBUFFER( atomList, RP_TAGS_HBS_THIS_ATOM, &atomId, &size ) &&
               HBS_ATOM_ID_SIZE == size )
        {
            denyExistingTree( atomId );
        }
    }
}

// Receives new process notifications and check if they're on our
// deny list, if so, kill.
RPRIVATE
RVOID
    denyNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    RU32 pid = 0;

    UNREFERENCED_PARAMETER( notifType );
    
    // We use the lastActivity check here as a cheap way of seeing if there is
    // anything at all in the denied tree.
    if( 0 != g_lastDenyActivity &&
        HbsGetParentAtom( event, &atomId ) &&
        isAtomDenied( atomId ) )
    {
        // This atom is part of a tree that needs to be denied, so we do two things:
        // 1- Add its atom to the list of denied atoms.
        if( HbsGetThisAtom( event, &atomId ) )
        {
            addAtomToDeny( atomId );
        }

        // 2- As this is a process, we deny by killing it.
        if( rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
        {
            if( processLib_killProcess( pid ) )
            {
                rpal_debug_info( "denied process id " RF_U32, pid );
            }
            else
            {
                rpal_debug_warning( "failed to deny process id " RF_U32, pid );
            }
        }
    }
    else if( 0 != g_lastDenyActivity &&
             g_lastDenyActivity + DENY_TREE_CLEANUP_TIMEOUT < rpal_time_getGlobal() )
    {
        // There has not been any positive activity on any denied trees, for the sake
        // of performance we'll reset the denied trees.
        if( rMutex_lock( g_deniedMutex ) )
        {
            g_lastDenyActivity = 0;
            rpal_blob_free( g_denied );
            g_denied = rpal_blob_create( 0, HBS_ATOM_ID_SIZE * 10 );

            rMutex_unlock( g_deniedMutex );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_14_events[] = { 0 };

RBOOL
    collector_14_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );
    UNREFERENCED_PARAMETER( hbsState );

    if( notifications_subscribe( RP_TAGS_NOTIFICATION_DENY_TREE_REQ, NULL, 0, NULL, denyNewTree ) &&
        notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, denyNewProcesses ) &&
        NULL != ( g_deniedMutex = rMutex_create() ) &&
        NULL != ( g_denied = rpal_blob_create( 0, HBS_ATOM_ID_SIZE * 10 ) ) )
    {
        g_lastDenyActivity = 0;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_14_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DENY_TREE_REQ, NULL, denyNewTree );
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, denyNewProcesses );
    rMutex_lock( g_deniedMutex );
    rpal_blob_free( g_denied );
    g_denied = NULL;
    rMutex_free( g_deniedMutex );
    g_deniedMutex = NULL;
    
    isSuccess = TRUE;

    return isSuccess;
}

RBOOL
    collector_14_update
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
HBS_TEST_SUITE( 14 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}