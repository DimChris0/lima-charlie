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
#include <networkLib/networkLib.h>
#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>

#define RPAL_FILE_ID        79

RPRIVATE
RBOOL
    isTcpEqual
    (
        NetLib_Tcp4TableRow* row1,
        NetLib_Tcp4TableRow* row2
    )
{
    RBOOL isEqual = FALSE;

    if( NULL != row1 &&
        NULL != row2 &&
        row1->destIp == row2->destIp &&
        row2->destPort == row2->destPort &&
        row1->sourceIp == row2->sourceIp &&
        row1->sourcePort == row2->sourcePort )
    {
        isEqual = TRUE;
    }

    return isEqual;
}

RPRIVATE
RBOOL
    isUdpEqual
    (
        NetLib_UdpTableRow* row1,
        NetLib_UdpTableRow* row2
    )
{
    RBOOL isEqual = FALSE;

    if( NULL != row1 &&
        NULL != row2 &&
        row1->localIp == row2->localIp &&
        row2->localPort == row2->localPort )
    {
        isEqual = TRUE;
    }

    return isEqual;
}

RPRIVATE
RPVOID
    networkUmDiffThread
    (
        rEvent isTimeToStop
    )
{
    NetLib_Tcp4Table* currentTcp4Table = NULL;
    NetLib_Tcp4Table* oldTcp4Table = NULL;

    NetLib_UdpTable* currentUdpTable = NULL;
    NetLib_UdpTable* oldUdpTable = NULL;

    RU32 i = 0;
    RU32 j = 0;
    RBOOL isFound = FALSE;

    rSequence notif = NULL;
    rSequence comp = NULL;

    RBOOL isFirstRun = TRUE;

    Atom parentAtom = { 0 };
    RU64 curTime = 0;

    LibOsPerformanceProfile perfProfile = { 0 };

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
    perfProfile.lastTimeoutValue = 500;
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 10;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) &&
           !kAcq_isAvailable() )
    {
        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        if( NULL != oldTcp4Table )
        {
            rpal_memory_free( oldTcp4Table );
            oldTcp4Table = NULL;
        }

        if( NULL != oldUdpTable )
        {
            rpal_memory_free( oldUdpTable );
            oldUdpTable = NULL;
        }

        // Swap the old snapshot for the (prev) new one
        oldTcp4Table = currentTcp4Table;
        oldUdpTable = currentUdpTable;
        currentTcp4Table = NULL;
        currentUdpTable = NULL;

        // Generate new tables
        currentTcp4Table = NetLib_getTcp4Table();
        currentUdpTable = NetLib_getUdpTable();

        curTime = rpal_time_getGlobalPreciseTime();

        // Diff TCP snapshots for new entries
        if( rpal_memory_isValid( currentTcp4Table ) &&
            rpal_memory_isValid( oldTcp4Table ) )
        {
            for( i = 0; i < currentTcp4Table->nRows; i++ )
            {
                isFound = FALSE;

                if( rEvent_wait( isTimeToStop, 0 ) )
                {
                    break;
                }

                for( j = 0; j < oldTcp4Table->nRows; j++ )
                {
                    if( isTcpEqual( &currentTcp4Table->rows[ i ], &oldTcp4Table->rows[ j ] ) )
                    {
                        isFound = TRUE;
                        break;
                    }
                }

                if( !isFound )
                {
                    if( NULL != ( notif = rSequence_new() ) )
                    {
                        parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                        parentAtom.key.process.pid = currentTcp4Table->rows[ i ].pid;
                        if( atoms_query( &parentAtom, curTime ) )
                        {
                            HbsSetParentAtom( notif, parentAtom.id );
                        }

                        if( rSequence_addRU32( notif, 
                                               RP_TAGS_STATE, 
                                               currentTcp4Table->rows[ i ].state ) &&
                            rSequence_addRU32( notif, 
                                               RP_TAGS_PROCESS_ID, 
                                               currentTcp4Table->rows[ i ].pid ) &&
                            hbs_timestampEvent( notif, curTime ) )
                        {
                            if( NULL != ( comp = rSequence_new() ) )
                            {
                                // Add the destination components
                                if( !rSequence_addIPV4( comp, 
                                                        RP_TAGS_IP_ADDRESS, 
                                                        currentTcp4Table->rows[ i ].destIp ) ||
                                    !rSequence_addRU16( comp, 
                                                        RP_TAGS_PORT, 
                                                        rpal_ntoh16( (RU16)currentTcp4Table->rows[ i ].destPort ) ) ||
                                    !rSequence_addSEQUENCE( notif, 
                                                            RP_TAGS_DESTINATION, 
                                                            comp ) )
                                {
                                    rSequence_free( comp );
                                    comp = NULL;
                                }
                            }

                            if( NULL != ( comp = rSequence_new() ) )
                            {
                                // Add the source components
                                if( !rSequence_addIPV4( comp, 
                                                        RP_TAGS_IP_ADDRESS, 
                                                        currentTcp4Table->rows[ i ].sourceIp ) ||
                                    !rSequence_addRU16( comp, 
                                                        RP_TAGS_PORT, 
                                                        rpal_ntoh16( (RU16)currentTcp4Table->rows[ i ].sourcePort ) ) ||
                                    !rSequence_addSEQUENCE( notif, 
                                                            RP_TAGS_SOURCE, 
                                                            comp ) )
                                {
                                    rSequence_free( comp );
                                    comp = NULL;
                                }
                            }

                            rpal_debug_info( "new tcp connection: 0x%08X = 0x%08X:0x%04X ---> 0x%08X:0x%04X -- 0x%08X.",
                                             currentTcp4Table->rows[ i ].state,
                                             currentTcp4Table->rows[ i ].sourceIp,
                                             currentTcp4Table->rows[ i ].sourcePort,
                                             currentTcp4Table->rows[ i ].destIp,
                                             currentTcp4Table->rows[ i ].destPort,
                                             currentTcp4Table->rows[ i ].pid );
                            hbs_publish( RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION, notif );
                        }

                        rSequence_free( notif );
                    }
                }
            }
        }
        else if( !isFirstRun )
        {
            rpal_debug_warning( "could not get tcp connections table." );
        }


        // Diff TCP snapshots for new entries
        if( NULL != currentUdpTable &&
            NULL != oldUdpTable )
        {
            for( i = 0; i < currentUdpTable->nRows; i++ )
            {
                isFound = FALSE;

                if( rEvent_wait( isTimeToStop, 0 ) )
                {
                    break;
                }

                for( j = 0; j < oldUdpTable->nRows; j++ )
                {
                    if( isUdpEqual( &currentUdpTable->rows[ i ], &oldUdpTable->rows[ j ] ) )
                    {
                        isFound = TRUE;
                        break;
                    }
                }

                if( !isFound )
                {
                    if( NULL != ( notif = rSequence_new() ) )
                    {
                        parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                        parentAtom.key.process.pid = currentUdpTable->rows[ i ].pid;
                        if( atoms_query( &parentAtom, curTime ) )
                        {
                            HbsSetParentAtom( notif, parentAtom.id );
                        }

                        if( !rSequence_addIPV4( notif, 
                                                RP_TAGS_IP_ADDRESS, 
                                                currentUdpTable->rows[ i ].localIp ) ||
                            !rSequence_addRU16( notif, 
                                                RP_TAGS_PORT, 
                                                rpal_ntoh16( (RU16)currentUdpTable->rows[ i ].localPort ) ) ||
                            !rSequence_addRU32( notif, 
                                                RP_TAGS_PROCESS_ID, 
                                                currentUdpTable->rows[ i ].pid ) ||
                            !hbs_timestampEvent( notif, curTime ) )
                        {
                            notif = NULL;
                        }
                        else
                        {
                            rpal_debug_info( "new udp connection: 0x%08X:0x%04X -- 0x%08X.",
                                             currentUdpTable->rows[ i ].localIp,
                                             currentUdpTable->rows[ i ].localPort,
                                             currentUdpTable->rows[ i ].pid );
                            hbs_publish( RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION, notif );
                        }

                        rSequence_free( notif );
                    }
                }
            }
        }
        else if( !isFirstRun )
        {
            rpal_debug_warning( "could not get udp connections table." );
        }

        if( isFirstRun )
        {
            isFirstRun = FALSE;
        }

        libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );
    }

    rpal_memory_free( currentTcp4Table );
    rpal_memory_free( currentUdpTable );
    rpal_memory_free( oldTcp4Table );
    rpal_memory_free( oldUdpTable );

    return NULL;
}

RPRIVATE
RBOOL
    addIpToSequence
    (
        RIpAddress ip,
        rSequence seq
    )
{
    RBOOL isAdded = FALSE;

    if( NULL != seq )
    {
        if( ip.isV6 )
        {
            isAdded = rSequence_addIPV6( seq, RP_TAGS_IP_ADDRESS, (RU8*)&ip.value.v6.byteArray );
        }
        else
        {
            isAdded = rSequence_addIPV4( seq, RP_TAGS_IP_ADDRESS, ip.value.v4 );
        }
    }

    return isAdded;
}

RPRIVATE
RPVOID
    networkKmDiffThread
    (
        rEvent isTimeToStop
    )
{
    rpcm_tag event = RP_TAGS_INVALID;
    rSequence notif = NULL;
    rSequence tmpSeq = NULL;
    RU32 nScratch = 0;
    RU32 prev_nScratch = 0;
    KernelAcqNetwork new_from_kernel[ 200 ] = { 0 };
    KernelAcqNetwork prev_from_kernel[ 200 ] = { 0 };
    RU32 i = 0;
    Atom parentAtom = { 0 };

    while( rpal_memory_isValid( isTimeToStop ) &&
        !rEvent_wait( isTimeToStop, 1000 ) )
    {
        nScratch = ARRAY_N_ELEM( new_from_kernel );
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        if( !kAcq_getNewConnections( new_from_kernel, &nScratch ) )
        {
            rpal_debug_warning( "kernel acquisition for new network connections failed" );
            break;
        }

        for( i = 0; i < prev_nScratch; i++ )
        {
            if( RPROTOCOL_IP_TCP == prev_from_kernel[ i ].proto )
            {
                if( 0 != prev_from_kernel[ i ].srcIp.isV6 )
                {
                    event = RP_TAGS_NOTIFICATION_NEW_TCP6_CONNECTION;
                }
                else
                {
                    event = RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION;
                }
            }
            else if( RPROTOCOL_IP_UDP == prev_from_kernel[ i ].proto )
            {
                if( 0 != prev_from_kernel[ i ].srcIp.isV6 )
                {
                    event = RP_TAGS_NOTIFICATION_NEW_UDP6_CONNECTION;
                }
                else
                {
                    event = RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION;
                }
            }
            else
            {
                continue;
            }

            prev_from_kernel[ i ].ts += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

            if( NULL != ( notif = rSequence_new() ) )
            {
                parentAtom.key.process.pid = prev_from_kernel[ i ].pid;
                parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
                if( atoms_query( &parentAtom, prev_from_kernel[ i ].ts ) )
                {
                    HbsSetParentAtom( notif, parentAtom.id );
                }

                if( NULL != ( tmpSeq = rSequence_new() ) )
                {
                    if( !addIpToSequence( prev_from_kernel[ i ].srcIp, tmpSeq ) ||
                        !rSequence_addRU16( tmpSeq, RP_TAGS_PORT, prev_from_kernel[ i ].srcPort ) ||
                        !rSequence_addSEQUENCE( notif, RP_TAGS_SOURCE, tmpSeq ) )
                    {
                        rSequence_free( tmpSeq );
                    }
                }

                if( NULL != ( tmpSeq = rSequence_new() ) )
                {
                    if( !addIpToSequence( prev_from_kernel[ i ].dstIp, tmpSeq ) ||
                        !rSequence_addRU16( tmpSeq, RP_TAGS_PORT, prev_from_kernel[ i ].dstPort ) ||
                        !rSequence_addSEQUENCE( notif, RP_TAGS_DESTINATION, tmpSeq ) )
                    {
                        rSequence_free( tmpSeq );
                    }
                }

                if( !prev_from_kernel[ i ].isIncoming )
                {
                    rSequence_addRU8( notif, RP_TAGS_IS_OUTGOING, 1 );
                }
                else
                {
                    rSequence_addRU8( notif, RP_TAGS_IS_OUTGOING, 0 );
                }

                if( rSequence_addRU32( notif, RP_TAGS_PROCESS_ID, prev_from_kernel[ i ].pid ) &&
                    hbs_timestampEvent( notif, prev_from_kernel[ i ].ts ) )
                {
                    hbs_publish( event, notif );
                }

                rSequence_free( notif );
            }
        }

        rpal_memory_memcpy( prev_from_kernel, new_from_kernel, sizeof( prev_from_kernel ) );
        prev_nScratch = nScratch;
    }

    return NULL;
}

RPRIVATE
RPVOID
    networkDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            // We first attempt to get new network connections through
            // the kernel mode acquisition driver
            rpal_debug_info( "running kernel acquisition network notification" );
            networkKmDiffThread( isTimeToStop );
        }
        // If the kernel mode fails, or is not available, try
        // to revert to user mode
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition network notification" );
            networkUmDiffThread( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_4_events[] = { RP_TAGS_NOTIFICATION_NEW_TCP4_CONNECTION,
                                  RP_TAGS_NOTIFICATION_NEW_UDP4_CONNECTION,
                                  RP_TAGS_NOTIFICATION_NEW_TCP6_CONNECTION,
                                  RP_TAGS_NOTIFICATION_NEW_UDP6_CONNECTION,
                                  0 };

RBOOL
    collector_4_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rThreadPool_task( hbsState->hThreadPool, networkDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_4_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_4_update
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
HBS_TEST_SUITE( 4 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}