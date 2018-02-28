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
#include <processLib/processLib.h>


#define _PROFILE_BASE_REFRESH_TIME          (60)
#define _PROFILE_RANDOM_REFRESH_FUZZ        (30)

#define _PROFILE_BASE_CHANGE_TICKETS            10
#define _PROFILE_NEW_CHANGE_TICKETS_PER_CHANGE  1

typedef struct
{
    RPVOID key;
    RTIME lastSeen;
    RTIME firstSeen;
    RU32 gensSeen;
    RU32 gensToStability;
    rBTree relations;

} _Profile;

RPRIVATE rBTree g_profiles_process_module = NULL;

//=============================================================================
// Helpers
//=============================================================================
RPRIVATE
RBOOL
    _recordGeneration
    (
        _Profile* pStub,
        RBOOL isChanged
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pStub )
    {
        pStub->gensSeen++;

        if( isChanged && 0 < pStub->gensToStability )
        {
            pStub->gensToStability += _PROFILE_NEW_CHANGE_TICKETS_PER_CHANGE;
        }

        isSuccess = TRUE;
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _isProfileStable
    (
        _Profile* pStub
    )
{
    RBOOL isStable = FALSE;

    if( NULL != pStub )
    {
        if( 0 == pStub->gensToStability )
        {
            isStable = TRUE;
        }
    }

    return isStable;
}

RPRIVATE
RS32
    _cmp_stringw
    (
        RPWCHAR* p1,
        RPWCHAR* p2
    )
{
    RS32 ret = (-1);

    if( NULL != p1 && NULL != p2 &&
        NULL != *p1 && NULL != *p2 )
    {
        ret = rpal_string_strcmpW( *p1, *p2 );
    }

    return ret;
}

RPRIVATE
RVOID
    _clean_alloc
    (
        RPVOID* p
    )
{
    if( NULL != p && NULL != *p )
    {
        rpal_memory_free( *p );
    }
}

RPRIVATE
RVOID
    _clean_profile
    (
        _Profile* p
    )
{
    if( NULL != p )
    {
        if( NULL != p->key )
        {
            rpal_memory_free( p->key );
        }

        rpal_btree_destroy( p->relations, FALSE );
    }
}

RPRIVATE
RBOOL
    _init_profile_strw_strw
    (
        _Profile* p,
        RPWCHAR key
    )
{
    RBOOL isSuccess = FALSE;

    RTIME now = 0;

    if( NULL != p )
    {
        now = rpal_time_getGlobal();

        p->firstSeen = now;
        p->lastSeen = now;
        p->gensSeen = 0;
        p->gensToStability = _PROFILE_BASE_CHANGE_TICKETS;
        if( NULL != ( p->key = rpal_string_strdupW( key ) ) )
        {
            if( NULL != ( p->relations = rpal_btree_create( sizeof( RPVOID ), 
                                                            (rpal_btree_comp_f)_cmp_stringw, 
                                                            (rpal_btree_free_f)_clean_alloc ) ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                rpal_memory_free( p->key );
            }
        }
    }

    return isSuccess;
}

//=============================================================================
// PROFILERS
//=============================================================================
RPRIVATE
RBOOL
    profile_processes
    (

    )
{
    RBOOL isSuccess = FALSE;

    processLibProcEntry* processes = NULL;
    processLibProcEntry* process = NULL;
    rSequence processInfo = NULL;
    RPWCHAR processName = NULL;
    rList modules = NULL;
    rSequence module = NULL;
    RPWCHAR moduleName = NULL;

    _Profile profile = { 0 };
    RBOOL isProfileReady = FALSE;
    RBOOL isChanged = FALSE;

    if( NULL != ( processes = processLib_getProcessEntries( FALSE ) ) )
    {
        process = processes;
        while( 0 != process->pid )
        {
            if( NULL != ( processInfo = processLib_getProcessInfo( process->pid, NULL ) ) )
            {
                if( rSequence_getSTRINGW( processInfo, RP_TAGS_FILE_PATH, &processName ) )
                {
                    isProfileReady = FALSE;

                    if( rpal_btree_search( g_profiles_process_module, &processName, &profile, FALSE ) )
                    {
                        isProfileReady = TRUE;
                    }
                    else
                    {
                        if( _init_profile_strw_strw( g_profiles_process_module, processName ) )
                        {
                            if( rpal_btree_add( g_profiles_process_module, &profile, FALSE ) )
                            {
                                isProfileReady = TRUE;
                            }
                            else
                            {
                                _clean_profile( &profile );
                            }
                        }
                    }
                    
                    if( isProfileReady )
                    {
                        if( NULL != ( modules = processLib_getProcessModules( process->pid ) ) )
                        {
                            while( rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
                            {
                                if( rSequence_getSTRINGW( module, RP_TAGS_FILE_PATH, &moduleName ) )
                                {
                                    if( !rpal_btree_search( profile.relations, &moduleName, NULL, FALSE ) &&
                                        rpal_btree_add( profile.relations, &moduleName, FALSE ) )
                                    {
                                        isChanged = TRUE;
                                        if( _isProfileStable( &profile ) )
                                        {
                                            rpal_debug_info( "Stable profile change!" );
                                        }
                                    }
                                }
                            }

                            rList_free( modules );
                        }

                        if( _recordGeneration( &profile, isChanged ) )
                        {
                            rpal_btree_update( g_profiles_process_module, &profile, &profile, FALSE );
                        }
                    }
                }

                rSequence_free( processInfo );
            }

            process++;
        }


        rpal_memory_free( processes );
    }

    return isSuccess;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_12_events[] = { 0 };

RBOOL
    collector_12_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    if( NULL != ( g_profiles_process_module = rpal_btree_create( sizeof( _Profile ), 
                                                                 (rpal_btree_comp_f)_cmp_stringw,
                                                                 (rpal_btree_free_f)_clean_profile ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_12_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );
    UNREFERENCED_PARAMETER( hbsState );

    if( NULL != g_profiles_process_module )
    {
        rpal_btree_destroy( g_profiles_process_module, FALSE );
    }

    isSuccess = TRUE;

    return isSuccess;
}

RBOOL
    collector_12_update
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
HBS_TEST_SUITE( 12 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}