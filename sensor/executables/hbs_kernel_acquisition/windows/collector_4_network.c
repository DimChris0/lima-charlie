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
#include "helpers.h"
#include <kernelAcquisitionLib/common.h>

extern RU32 g_owner_pid;

#pragma warning(disable:4127)       // constant expressions

#ifndef _NUM_BUFFERED_CONNECTIONS
    #define _NUM_BUFFERED_CONNECTIONS   200
#endif
#ifndef _NUM_BUFFERED_DNS_BYTES
    #define _NUM_BUFFERED_DNS_BYTES     (128 * 1024)
#endif

typedef struct
{
    RPWCHAR slName;
    RPWCHAR coName;
    RPWCHAR flName;
    FWPS_CALLOUT_CLASSIFY_FN co;
    GUID guid;
    GUID slGuid;
    RBOOL slActive;
    GUID coGuid;
    RBOOL coActive;
    GUID flGuid;
    RBOOL flActive;
} LayerInfo;

static RBOOL g_is_network_segregated = FALSE;

RVOID
    coAuthConnect
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

RVOID
    coAuthRecvAccept
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

RVOID
    coInboundTransport
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

RVOID
    coOutboundTransport
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    );

static LayerInfo g_layerAuthConnect4 = {
    _WCH( "slAuthConnect4" ),
    _WCH( "coAuthConnect4" ),
    _WCH( "flAuthConnect4" ),
    coAuthConnect
};

static LayerInfo g_layerAuthConnect6 = {
    _WCH( "slAuthConnect6" ),
    _WCH( "coAuthConnect6" ),
    _WCH( "flAuthConnect6" ),
    coAuthConnect
};

static LayerInfo g_layerAuthRecvAccept4 = {
    _WCH( "slAuthRecvAccept4" ),
    _WCH( "coAuthRecvAccept4" ),
    _WCH( "flAuthRecvAccept4" ),
    coAuthRecvAccept
};

static LayerInfo g_layerAuthRecvAccept6 = {
    _WCH( "slAuthRecvAccept6" ),
    _WCH( "coAuthRecvAccept6" ),
    _WCH( "flAuthRecvAccept6" ),
    coAuthRecvAccept
};

static LayerInfo g_layerInboundTransport4 = {
    _WCH( "slInboundTransport4" ),
    _WCH( "coInboundTransport4" ),
    _WCH( "flInboundTransport4" ),
    coInboundTransport
};

static LayerInfo g_layerInboundTransport6 = {
    _WCH( "slInboundTransport6" ),
    _WCH( "coInboundTransport6" ),
    _WCH( "flInboundTransport6" ),
    coInboundTransport
};

static LayerInfo g_layerOutboundTransport4 = {
    _WCH( "slOutboundTransport4" ),
    _WCH( "coOutboundTransport4" ),
    _WCH( "flOutboundTransport4" ),
    coOutboundTransport
};

static LayerInfo g_layerOutboundTransport6 = {
    _WCH( "slOutboundTransport6" ),
    _WCH( "coOutboundTransport6" ),
    _WCH( "flOutboundTransport6" ),
    coOutboundTransport
};

static LayerInfo* g_layers[] = { &g_layerAuthConnect4,
                                 &g_layerAuthConnect6,
                                 &g_layerAuthRecvAccept4,
                                 &g_layerAuthRecvAccept6,
                                 &g_layerInboundTransport4,
                                 &g_layerInboundTransport6,
                                 &g_layerOutboundTransport4,
                                 &g_layerOutboundTransport6 };

static HANDLE g_stateChangeHandle = NULL;
static HANDLE g_engineHandle = NULL;

static KSPIN_LOCK g_collector_4_mutex = { 0 };
static KernelAcqNetwork g_connections[ _NUM_BUFFERED_CONNECTIONS ] = { 0 };
static RU32 g_nextConnection = 0;

static KSPIN_LOCK g_collector_4_mutex_dns = { 0 };
static RU8 g_dns[ _NUM_BUFFERED_DNS_BYTES ] = { 0 };
static RU32 g_nextDns = 0;

static
RBOOL
    isIpEqual
    (
        RIpAddress ip1,
        RIpAddress ip2
    )
{
    return sizeof( ip1 ) == RtlCompareMemory( &ip1, &ip2, sizeof( sizeof( ip1 ) ) );
}

static
RBOOL
    isConnectionAllowed
    (
        KernelAcqNetwork* pEvent,
        RU32 pid
    )
{
    RBOOL isAllowed = FALSE;

    if( pid == g_owner_pid )
    {
        return TRUE;
    }

    if( NULL != pEvent )
    {
        if( pEvent->isIncoming )
        {
            if( IPPROTO_UDP == pEvent->proto &&
                ( 53 == pEvent->srcPort ||
                  ( 67 == pEvent->srcPort &&
                    68 == pEvent->dstPort ) ||
                  ( 546 == pEvent->dstPort &&
                    547 == pEvent->srcPort )  ||
                  ( 0 == pEvent->dstPort &&
                    135 == pEvent->srcPort ) ) )
            {
                isAllowed = TRUE;
            }
        }
        else
        {
            if( IPPROTO_UDP == pEvent->proto &&
                ( 53 == pEvent->dstPort ||
                  ( 67 == pEvent->dstPort &&
                    68 == pEvent->srcPort ) ||
                  ( 0 == pEvent->srcPort &&
                    135 == pEvent->dstPort ) ) )
            {
                isAllowed = TRUE;
            }
        }
    }

    return isAllowed;
}

RBOOL
    task_get_new_network
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    RU32 toCopy = 0;

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( g_connections[ 0 ] );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextConnection ? g_nextConnection : toCopy );

            *resultSize = toCopy * sizeof( g_connections[ 0 ] );
            memcpy( pResult, g_connections, *resultSize );

            g_nextConnection -= toCopy;
            memmove( g_connections, g_connections + toCopy, g_nextConnection );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    task_get_new_dns
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    KernelAcqDnsPacket* pDns = NULL;

    RU32 currentFrameSize = 0;
    RU32 toCopy = 0;

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex_dns, &hMutex );

        // Unlike other kernel sources, these are variable size so
        // we have to crawl them until we've filled the buffer.
        pDns = (KernelAcqDnsPacket*)g_dns;

        while( IS_WITHIN_BOUNDS( pDns, sizeof( *pDns ), g_dns, g_nextDns ) &&
               0 != ( currentFrameSize = sizeof( *pDns ) + pDns->packetSize ) &&
               IS_WITHIN_BOUNDS( pDns, currentFrameSize, g_dns, g_nextDns ) &&
               ( toCopy + currentFrameSize ) <= *resultSize )
        {
            // Current pDns fits in buffer, add the size and move to the next packet.
            // We accumulate the buffer size so we do a single memcpy/memmove.
            toCopy += currentFrameSize;
            pDns = (KernelAcqDnsPacket*)( (RPU8)pDns + currentFrameSize );
        }

        // We now have the total size of buffer to copy.
        if( 0 != toCopy )
        {
            memcpy( pResult, g_dns, toCopy );
            g_nextDns -= toCopy;
            if( 0 != g_nextDns )
            {
                memmove( g_dns, g_dns + toCopy, g_nextDns );
            }
        }

        *resultSize = toCopy;

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}


RBOOL
    task_segregate_network
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( pResult );
    UNREFERENCED_PARAMETER( resultSize );
    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    g_is_network_segregated = TRUE;

    KeReleaseInStackQueuedSpinLock( &hMutex );

    rpal_debug_kernel( "network segregated" );
    isSuccess = TRUE;

    return isSuccess;
}

RBOOL
    task_rejoin_network
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );
    UNREFERENCED_PARAMETER( pResult );
    UNREFERENCED_PARAMETER( resultSize );

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    g_is_network_segregated = FALSE;

    KeReleaseInStackQueuedSpinLock( &hMutex );

    rpal_debug_kernel( "network rejoined" );
    isSuccess = TRUE;

    return isSuccess;
}


static RBOOL
    getIpTuple
    (
        RU16 layerId,
        const FWPS_INCOMING_VALUES* fixedVals,
        KernelAcqNetwork* netEntry
    )
{
    RBOOL isSuccess = TRUE;

    switch( layerId )
    {
        case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
            netEntry->isIncoming = FALSE;
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->srcIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS ].value.uint32 );
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS ].value.uint32 );
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
            netEntry->isIncoming = FALSE;
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
            netEntry->isIncoming = TRUE;
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->dstIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS ].value.uint32 );
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->srcIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS ].value.uint32 );
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
            netEntry->isIncoming = TRUE;
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_INBOUND_TRANSPORT_V4:
            netEntry->isIncoming = FALSE; // We say it's outgoing but in reality we're not sure
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->srcIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS ].value.uint32 );
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS ].value.uint32 );
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_INBOUND_TRANSPORT_V6:
            netEntry->isIncoming = FALSE; // We say it's outgoing but in reality we're not sure
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
            netEntry->isIncoming = FALSE; // We say it's outgoing but in reality we're not sure
            netEntry->srcIp.isV6 = FALSE;
            netEntry->dstIp.isV6 = FALSE;
            netEntry->srcIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS ].value.uint32 );
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v4 = RtlUlongByteSwap( fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS ].value.uint32 );
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL ].value.uint8;
            break;
        case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
            netEntry->isIncoming = FALSE; // We say it's outgoing but in reality we're not sure
            netEntry->srcIp.isV6 = TRUE;
            netEntry->dstIp.isV6 = TRUE;
            netEntry->srcIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS ].value.byteArray16;
            netEntry->srcPort = fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT ].value.uint16;
            netEntry->dstIp.value.v6 = *(RIpV6*)fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS ].value.byteArray16;
            netEntry->dstPort = fixedVals->incomingValue[ FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT ].value.uint16;
            netEntry->proto = fixedVals->incomingValue[ FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL ].value.uint8;
            break;

        default:
            rpal_debug_kernel( "Unknown layer protocol family: 0x%08X", layerId );
            isSuccess = FALSE;
    }

    return isSuccess;
}

RVOID
    coAuthConnect
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_PERMIT;
    }

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    if( getIpTuple( fixVals->layerId, fixVals, &g_connections[ g_nextConnection ] ) )
    {
        // If network is being segregated, check if the requestor is our owner.
        if( g_is_network_segregated )
        {
            if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) &&
                !isConnectionAllowed( &( g_connections[ g_nextConnection ] ), (RU32)metaVals->processId ) )
            {
                result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
                result->actionType = FWP_ACTION_BLOCK;
                rpal_debug_kernel( "blocking (%d != %d) %d -> %d", (RU32)metaVals->processId, g_owner_pid, g_connections[ g_nextConnection ].srcPort, g_connections[ g_nextConnection ].dstPort );
                KeReleaseInStackQueuedSpinLock( &hMutex );
                return;
            }
        }

        if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) )
        {
            g_connections[ g_nextConnection ].pid = (RU32)metaVals->processId;
        }

        g_connections[ g_nextConnection ].ts = rpal_time_getLocal();
        g_nextConnection++;
        if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
        {
            g_nextConnection = 0;
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to get tuple: 0x%08X", status );
        status = STATUS_INTERNAL_ERROR;
        RtlZeroMemory( &g_connections[ g_nextConnection ], sizeof( g_connections[ g_nextConnection ] ) );
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

RVOID
    coAuthRecvAccept
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_PERMIT;
    }

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex, &hMutex );

    if( getIpTuple( fixVals->layerId, fixVals, &g_connections[ g_nextConnection ] ) )
    {
        // If network is being segregated, check if the requestor is our owner.
        if( g_is_network_segregated )
        {
            if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) &&
                !isConnectionAllowed( &( g_connections[ g_nextConnection ] ), (RU32)metaVals->processId ) )
            {
                result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
                result->actionType = FWP_ACTION_BLOCK;
                rpal_debug_kernel( "blocking (%d != %d) %d -> %d", (RU32)metaVals->processId, g_owner_pid, g_connections[ g_nextConnection ].srcPort, g_connections[ g_nextConnection ].dstPort );
                KeReleaseInStackQueuedSpinLock( &hMutex );
                return;
            }
        }

        if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) )
        {
            g_connections[ g_nextConnection ].pid = (RU32)metaVals->processId;
        }

        g_connections[ g_nextConnection ].ts = rpal_time_getLocal();
        g_nextConnection++;
        if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
        {
            g_nextConnection = 0;
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to get tuple: 0x%08X", status );
        status = STATUS_INTERNAL_ERROR;
        RtlZeroMemory( &g_connections[ g_nextConnection ], sizeof( g_connections[ g_nextConnection ] ) );
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}

RVOID
    coInboundTransport
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    KernelAcqNetwork netEntry = { 0 };
    KernelAcqDnsPacket dnsEntry = { 0 };
    KLOCK_QUEUE_HANDLE hMutex = { 0 };
    RSIZET packetSize = 0;
    RSIZET requiredSize = 0;
    PNET_BUFFER_LIST bufferList = NULL;
    PNET_BUFFER buffer = NULL;
    RPVOID pPayload = NULL;

    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_PERMIT;
    }

    // Before locking anything check if the packet is of interest
    // Right now we only care about port 53 (DNS) in and outbound
    if( !getIpTuple( fixVals->layerId, fixVals, &netEntry ) ||
        ( 53 != netEntry.dstPort &&
          53 != netEntry.srcPort ) ||
        ( IPPROTO_UDP != netEntry.proto &&
          IPPROTO_TCP != netEntry.proto ) )
    {
        return;
    }

    if( NULL == data )
    {
        return;
    }

    // No need to advance or retreat the buffer since we just want the payload
    // regardless of protocol.

    if( FWPS_IS_METADATA_FIELD_PRESENT( metaVals, FWPS_METADATA_FIELD_PROCESS_ID ) )
    {
        dnsEntry.pid = (RU32)metaVals->processId;
    }

    // Common metadata for all packets we're about to process.
    dnsEntry.dstIp = netEntry.dstIp;
    dnsEntry.dstPort = netEntry.dstPort;
    dnsEntry.srcIp = netEntry.srcIp;
    dnsEntry.srcPort = netEntry.srcPort;
    dnsEntry.proto = netEntry.proto;
    dnsEntry.ts = rpal_time_getLocal();

    bufferList = (PNET_BUFFER_LIST)data;

    KeAcquireInStackQueuedSpinLock( &g_collector_4_mutex_dns, &hMutex );

    // We get a list of packets, so we might record more than one.
    while( NULL != bufferList )
    {
        buffer = NET_BUFFER_LIST_FIRST_NB( bufferList );
        packetSize = NET_BUFFER_DATA_LENGTH( buffer );

        // Calculate the size needed for this packet.
        requiredSize = sizeof( KernelAcqDnsPacket ) + packetSize;

        // Check to see if we have enough room in the global buffer or if we need
        // to reset it to 0.
        if( sizeof( g_dns ) - g_nextDns < requiredSize )
        {
            if( sizeof( g_dns ) < requiredSize )
            {
                // There is no way we can ever log this packet, bail.
                rpal_debug_kernel( "DNS packet too large for entire global buffer?" );
            }
            else
            {
                // Buffer overflow, reset to the beginning.
                g_nextDns = 0;
                rpal_debug_kernel( "DNS packet buffer overflow" );
            }
        }

        // Ok we did our best to accomodate this new packet, was it enought?
        if( sizeof( g_dns ) - g_nextDns >= requiredSize )
        {
            // By this point, we know we're good to log packet at g_nextDns.
            dnsEntry.packetSize = (RU32)packetSize;

            // Copy in the header.
            memcpy( g_dns + g_nextDns, &dnsEntry, sizeof( KernelAcqDnsPacket ) );

            // Now start copying the payload chunks.
            pPayload = NdisGetDataBuffer( buffer, (ULONG)packetSize, g_dns + g_nextDns + sizeof( KernelAcqDnsPacket ), 1, 0 );
            if( NULL != pPayload )
            {
                // Ndis already had the packet mapped contiguously, so we just need to copy to our buffer.
                memcpy( g_dns + g_nextDns + sizeof( KernelAcqDnsPacket ), pPayload, packetSize );
            }
            else
            {
                // Payload wasn't already continuous in memory, so the NdisGetDataBuffer stored it directly
                // in the storage area we provided.
            }

            g_nextDns += (RU32)sizeof( KernelAcqDnsPacket ) + (RU32)packetSize;
        }

        bufferList = NET_BUFFER_LIST_NEXT_NBL( bufferList );
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}


RVOID
    coOutboundTransport
    (
        const FWPS_INCOMING_VALUES* fixVals,
        const FWPS_INCOMING_METADATA_VALUES* metaVals,
        RPVOID data,
        const void* classifyCtx,
        const FWPS_FILTER* flt,
        RU64 flowCtx,
        FWPS_CLASSIFY_OUT* result
    )
{
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( classifyCtx );
    UNREFERENCED_PARAMETER( flt );
    UNREFERENCED_PARAMETER( flowCtx );
    UNREFERENCED_PARAMETER( metaVals );
    UNREFERENCED_PARAMETER( fixVals );

    if( IS_FLAG_ENABLED( result->rights, FWPS_RIGHT_ACTION_WRITE ) )
    {
        result->actionType = FWP_ACTION_PERMIT;
    }

    return;
}

static NTSTATUS
    calloutNotify
    (
        FWPS_CALLOUT_NOTIFY_TYPE type,
        const GUID* filterKey,
        const FWPS_FILTER* filter
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( type );
    UNREFERENCED_PARAMETER( filterKey );
    UNREFERENCED_PARAMETER( filter );

    return status;
}

static RVOID
    unregisterCallouts
    (

    )
{
    RU32 i = 0;
    
    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        if( g_layers[ i ]->coActive )
        {
            FwpsCalloutUnregisterByKey( &g_layers[ i ]->coGuid );
            g_layers[ i ]->coActive = FALSE;
        }
    }
}

static RVOID
    deactivateLayers
    (

    )
{
    NTSTATUS status = STATUS_SUCCESS;
    RU32 i = 0;

    if( NULL == g_engineHandle ) return;

    if( NT_SUCCESS( status = FwpmTransactionBegin( g_engineHandle, 0 ) ) )
    {
        for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
        {
            if( g_layers[ i ]->flActive )
            {
                if( !NT_SUCCESS( status = FwpmFilterDeleteByKey( g_engineHandle, &g_layers[ i ]->flGuid ) ) )
                {
                    rpal_debug_kernel( "Failed to delete filter by key: 0x%08X", status );
                    FwpmTransactionAbort( g_engineHandle );
                    break;
                }
                g_layers[ i ]->flActive = FALSE;
            }

            if( g_layers[ i ]->slActive )
            {
                if( !NT_SUCCESS( status = FwpmSubLayerDeleteByKey( g_engineHandle, &g_layers[ i ]->slGuid ) ) )
                {
                    rpal_debug_kernel( "Failed to delete sublayer sby key: 0x%08X", status );
                    FwpmTransactionAbort( g_engineHandle );
                    break;
                }
                g_layers[ i ]->slActive = FALSE;
            }
        }

        if( !NT_SUCCESS( status = FwpmTransactionCommit( g_engineHandle ) ) )
        {
            rpal_debug_kernel( "Failed to commit transaction: 0x%08X", status );
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to start transaction: 0x%08X", status );
    }

    unregisterCallouts();

    if( NULL != g_engineHandle )
    {
        FwpmEngineClose0( g_engineHandle );
        g_engineHandle = NULL;
    }
}

static NTSTATUS
    activateLayers
    (
        PDEVICE_OBJECT deviceObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    RU32 i = 0;
    
    if( NULL != g_engineHandle ) return status;

    if( !NT_SUCCESS( status = FwpmEngineOpen( NULL, 
                                              RPC_C_AUTHN_DEFAULT, 
                                              NULL, 
                                              NULL, 
                                              &g_engineHandle ) ) )
    {
        return status;
    }

    if( !NT_SUCCESS( status = FwpmTransactionBegin( g_engineHandle, 0 ) ) )
    {
        rpal_debug_kernel( "Failed to start transaction: 0x%08X", status );
        return status;
    }

    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        FWPS_CALLOUT callout = { 0 };
        callout.calloutKey = g_layers[ i ]->coGuid;
        callout.classifyFn = g_layers[ i ]->co;
        callout.notifyFn = calloutNotify;
        callout.flowDeleteFn = NULL;

        if( !NT_SUCCESS( status = FwpsCalloutRegister( deviceObject, &callout, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to register callout %d: 0x%08X", i, status );
            break;
        }

        g_layers[ i ]->coActive = TRUE;
    }

    if( !NT_SUCCESS( status ) )
    {
        unregisterCallouts();
        FwpmTransactionAbort( g_engineHandle );
        FwpmEngineClose( g_engineHandle );
        g_engineHandle = NULL;
        return status;
    }

    for( i = 0; i < ARRAY_N_ELEM( g_layers ); i++ )
    {
        FWPM_SUBLAYER sublayer = { 0 };
        FWPM_CALLOUT callout = { 0 };
        FWPM_FILTER filter = { 0 };

        sublayer.subLayerKey = g_layers[ i ]->slGuid;
        sublayer.displayData.name = g_layers[ i ]->slName;

        callout.calloutKey = g_layers[ i ]->coGuid;
        callout.displayData.name = g_layers[ i ]->coName;
        callout.applicableLayer = g_layers[ i ]->guid;

        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.filterKey = g_layers[ i ]->flGuid;
        filter.layerKey = g_layers[ i ]->guid;
        filter.displayData.name = g_layers[ i ]->flName;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = g_layers[ i ]->coGuid;
        filter.subLayerKey = g_layers[ i ]->slGuid;
        filter.weight.type = FWP_EMPTY;

        if( !NT_SUCCESS( status = FwpmSubLayerAdd( g_engineHandle, &sublayer, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add sublayer: 0x%08X", status );
            break;
        }

        g_layers[ i ]->slActive = TRUE;

        if( !NT_SUCCESS( status = FwpmCalloutAdd( g_engineHandle, &callout, NULL, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add callout: 0x%08X", status );
            break;
        }

        if( !NT_SUCCESS( status = FwpmFilterAdd( g_engineHandle, &filter, NULL, NULL ) ) )
        {
            rpal_debug_kernel( "Failed to add filter: 0x%08X", status );
            break;
        }

        g_layers[ i ]->flActive = TRUE;
    }

    if( !NT_SUCCESS( status ) )
    {
        unregisterCallouts();
        FwpmTransactionAbort( g_engineHandle );
        FwpmEngineClose( g_engineHandle );
        g_engineHandle = NULL;
        return status;
    }

    if( !NT_SUCCESS( status = FwpmTransactionCommit( g_engineHandle ) ) )
    {
        rpal_debug_kernel( "Failed to commit transaction: 0x%08X", status );
        return status;
    }

    return status;
}


RVOID
    stateChangeCallback
    (
        RPVOID ctx,
        FWPM_SERVICE_STATE newState
    )
{
    PDEVICE_OBJECT deviceObject = (PDEVICE_OBJECT)ctx;

    switch( newState )
    {
        case FWPM_SERVICE_STOP_PENDING:
            KeEnterGuardedRegion();
            deactivateLayers();
            KeLeaveGuardedRegion();
            break;
        case FWPM_SERVICE_RUNNING:
            KeEnterGuardedRegion();
            activateLayers( deviceObject );
            KeLeaveGuardedRegion();
            break;
        default:
            break;
    }
}

static NTSTATUS
    installWfp
    (
        PDEVICE_OBJECT deviceObject
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect4.flGuid ) ) )
        {
            g_layerAuthConnect4.guid = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authConnect4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthConnect6.flGuid ) ) )
        {
            g_layerAuthConnect6.guid = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authConnect6 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept4.flGuid ) ) )
        {
            g_layerAuthRecvAccept4.guid = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authRecvAccept4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerAuthRecvAccept6.flGuid ) ) )
        {
            g_layerAuthRecvAccept6.guid = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create authRecvAccept4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport4.flGuid ) ) )
        {
            g_layerInboundTransport4.guid = FWPM_LAYER_INBOUND_TRANSPORT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create inboundTransport4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerInboundTransport6.flGuid ) ) )
        {
            g_layerInboundTransport6.guid = FWPM_LAYER_INBOUND_TRANSPORT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create inboundTransport6 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport4.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport4.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport4.flGuid ) ) )
        {
            g_layerOutboundTransport4.guid = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create outboundTransport4 GUIDs: 0x%08X", status );
            break;
        }

        if( NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport6.slGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport6.coGuid ) ) &&
            NT_SUCCESS( status = ExUuidCreate( &g_layerOutboundTransport6.flGuid ) ) )
        {
            g_layerOutboundTransport6.guid = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
        }

        if( !NT_SUCCESS( status ) )
        {
            rpal_debug_kernel( "Failed to create outboundTransport6 GUIDs: 0x%08X", status );
            break;
        }

        if( !NT_SUCCESS( status = FwpmBfeStateSubscribeChanges( deviceObject,
                                                                stateChangeCallback,
                                                                (RPVOID)deviceObject,
                                                                &g_stateChangeHandle ) ) )
        {
            rpal_debug_kernel( "Failed to subscribe to changes: 0x%08X", status );
            g_stateChangeHandle = NULL;
            break;
        }

        if( FWPM_SERVICE_RUNNING == FwpmBfeStateGet() )
        {
            KeEnterGuardedRegion();
            status = activateLayers( deviceObject );
            KeLeaveGuardedRegion();
        }
        else
        {
            rpal_debug_kernel( "Engine not running" );
        }
    } while( FALSE );

    return status;
}

static RVOID
    uninstallWfp
    (

    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if( NULL != g_stateChangeHandle )
    {
        if( !NT_SUCCESS( status = FwpmBfeStateUnsubscribeChanges( g_stateChangeHandle ) ) )
        {
            rpal_debug_kernel( "Failed to unsubscribe to changes: 0x%08X", status );
        }
        g_stateChangeHandle = NULL;
    }

    KeEnterGuardedRegion();
    deactivateLayers();
    KeLeaveGuardedRegion();
}

RBOOL
    collector_4_initialize
    (
        PDRIVER_OBJECT driverObject,
        PDEVICE_OBJECT deviceObject
    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER( driverObject );

#ifndef _DISABLE_COLLECTOR_4
    KeInitializeSpinLock( &g_collector_4_mutex );
    KeInitializeSpinLock( &g_collector_4_mutex_dns );

    g_is_network_segregated = FALSE;

    status = installWfp( deviceObject );

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to initialize: 0x%08X", status );
    }
#else
    UNREFERENCED_PARAMETER( deviceObject );
    isSuccess = TRUE;
#endif

    return isSuccess;
}

RBOOL
    collector_4_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

#ifndef _DISABLE_COLLECTOR_4
    uninstallWfp();

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to deinitialize: 0x%08X", status );
    }
#else
    isSuccess = TRUE;
#endif

    return isSuccess;
}
