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
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/kpi_mbuf.h>
#include <netinet/in.h>
#include <sys/types.h>

#ifndef _NUM_BUFFERED_CONNECTIONS
    #define _NUM_BUFFERED_CONNECTIONS   200
#endif
#ifndef _NUM_BUFFERED_DNS
    #define _NUM_BUFFERED_DNS           (128 * 1024)
#endif

#define _FLT_HANDLE_BASE            0x52484350// RHCP
#define _FLT_NAME                   "com.refractionpoint.hbs.acq.net"

static rMutex g_collector_4_mutex = NULL;
static KernelAcqNetwork g_connections[ _NUM_BUFFERED_CONNECTIONS ] = { 0 };
static uint32_t g_nextConnection = 0;
static rMutex g_collector_4_mutex_dns = NULL;
static RU8 g_dns[ _NUM_BUFFERED_DNS ] = { 0 };
static uint32_t g_nextDns = 0;
static uint32_t g_socketsPending = 0;
static RBOOL g_shuttingDown = FALSE;

static RBOOL g_is_network_segregated = FALSE;
extern int g_owner_pid;

typedef struct
{
    RBOOL isReported;
    RBOOL isConnected;
    RBOOL isAllowed;
    int addrFamily;
    RBOOL isComplete;
    KernelAcqNetwork netEvent;
    
} SockCookie;

static RBOOL
    isConnectionAllowed
    (
        SockCookie* sc
    )
{
    if( g_is_network_segregated &&
        NULL != sc )
    {
        if( sc->isAllowed )
        {
            return TRUE;
        }

        // We allow DNS and DHCP.
        if( sc->netEvent.isIncoming &&
            IPPROTO_UDP == sc->netEvent.proto )
        {
            if( 53 == sc->netEvent.srcPort ||
                ( 67 == sc->netEvent.srcPort &&
                  68 == sc->netEvent.dstPort ) )
            {
                sc->isAllowed = TRUE;
                return TRUE;
            }
        }
        else if( IPPROTO_UDP == sc->netEvent.proto )
        {
            if( 53 == sc->netEvent.dstPort ||
                ( 67 == sc->netEvent.dstPort &&
                  68 == sc->netEvent.srcPort ) )
            {
                sc->isAllowed = TRUE;
                return TRUE;
            }
        }

        if( g_owner_pid == sc->netEvent.pid ||
            g_owner_pid == proc_selfpid() )
        {
            sc->isAllowed = TRUE;
            return TRUE;
        }

        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

static void
    next_connection
    (

    )
{
    g_nextConnection++;
    if( g_nextConnection == _NUM_BUFFERED_CONNECTIONS )
    {
        g_nextConnection = 0;
        rpal_debug_warning( "overflow of the network connection buffer" );
    }
}

static
RBOOL
    getPacket
    (
        mbuf_t* mbuf,
        RPU8* pPacket,
        RSIZET* pPacketSize
    )
{
    mbuf_t data = NULL;
    RPU8 packet = NULL;
    RSIZET packetLength = 0;
    
    if( NULL == mbuf ||
        NULL == pPacket ||
        NULL == pPacketSize )
    {
        return FALSE;
    }
    
    data = *mbuf;
    while( NULL != data && MBUF_TYPE_DATA != mbuf_type( data ) )
    {
        data = mbuf_next( data );
    }
    
    if( NULL == data )
    {
        return FALSE;
    }
    
    if( NULL == ( packet = mbuf_data( data ) ) )
    {
        return FALSE;
    }
    
    if( 0 == (packetLength = mbuf_len( data ) ) )
    {
        return FALSE;
    }
    
    *pPacket = packet;
    *pPacketSize = packetLength;
    
    return TRUE;
}

static
errno_t
    cbAttach
    (
        void** cookie,
        socket_t so
    )
{
    errno_t ret = EINVAL;
    RBOOL isShuttingDown = FALSE;
    int addrFamily = 0;
    int sockType = 0;
    int protocol = 0;
    SockCookie* sc = NULL;
    
    if( NULL == cookie ) return ret;
    
    rpal_mutex_lock( g_collector_4_mutex );
    if( g_shuttingDown )
    {
        isShuttingDown = TRUE;
    }
    else
    {
        g_socketsPending++;
    }
    rpal_mutex_unlock( g_collector_4_mutex );
    
    if( isShuttingDown ) return ret;
    
    if( KERN_SUCCESS == sock_gettype( so, &addrFamily, &sockType, &protocol ) )
    {
        if( ( PF_INET == addrFamily || PF_INET6 == addrFamily ) &&
            ( IPPROTO_TCP == protocol || IPPROTO_UDP == protocol ) )
        {
            if( NULL != ( sc = rpal_memory_alloc( sizeof( SockCookie ) ) ) )
            {
                sc->addrFamily = addrFamily;
                sc->netEvent.proto = (RU8)protocol;
                sc->netEvent.ts = rpal_time_getLocal();
                sc->netEvent.pid = proc_selfpid();
                sc->isReported = FALSE;
                sc->isAllowed = FALSE;
                sc->isComplete = FALSE;
                
                *cookie = sc;
                ret = KERN_SUCCESS;
            }
            else
            {
                ret = ENOMEM;
            }
        }
        else
        {
            ret = EPROTONOSUPPORT;
        }
    }
    
    if( 0 != ret )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        g_socketsPending--;
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    
    return ret;
}

static
void
    cbDetach
    (
        void* cookie,
        socket_t so
    )
{
    if( NULL != cookie )
    {
        rpal_memory_free( cookie );
        rpal_mutex_lock( g_collector_4_mutex );
        g_socketsPending--;
        rpal_mutex_unlock( g_collector_4_mutex );
    }
}

static
RBOOL
    populateCookie
    (
        SockCookie* sc,
        socket_t so,
        const struct sockaddr* remote
    )
{
    RBOOL isPopulated = FALSE;
    
    errno_t ret = KERN_SUCCESS;
    RBOOL isIpV6 = FALSE;
    struct sockaddr_in local4 = { 0 };
    struct sockaddr_in remote4 = { 0 };
    struct sockaddr_in6 local6 = { 0 };
    struct sockaddr_in6 remote6 = { 0 };
    
    if( NULL != sc )
    {
        if( sc->isComplete )
        {
            return TRUE;
        }

        if( 0 == sc->netEvent.pid )
        {
            sc->netEvent.pid = proc_selfpid();

            sc->isComplete = TRUE;
        }

        if( PF_INET == sc->addrFamily )
        {
            isIpV6 = FALSE;
        }
        else
        {
            isIpV6 = TRUE;
        }
        
        if( !isIpV6 )
        {
            if( 0 != ( ret = sock_getsockname( so, (struct sockaddr*)&local4, sizeof( local4 ) ) ) )
            {
                rpal_debug_info( "^^^^^^ ERROR getting local sockname4: %d", ret );
                sc->isComplete = FALSE;
            }

            if( NULL != remote )
            {
                memcpy( &remote4, ( struct sockaddr_in* )remote, sizeof( remote4 ) );
            }
            else if( 0 != ( ret = sock_getpeername( so, ( struct sockaddr* )&remote4, sizeof( remote4 ) ) ) ||
                     0 == remote4.sin_addr.s_addr )
            {
                rpal_debug_info( "^^^^^^ ERROR getting remote sockname5: %d", ret );
                sc->isComplete = FALSE;
            }
        }
        else
        {
            // We only receive IP4 or IP6 so this is always IP6
            if( 0 != ( ret = sock_getsockname( so, (struct sockaddr*)&local6, sizeof( local6 ) ) ) )
            {
                rpal_debug_info( "^^^^^^ ERROR getting local sockname6: %d", ret );
                sc->isComplete = FALSE;
            }

            if( NULL != remote )
            {
                memcpy( &remote6, ( struct sockaddr_in6* )remote, sizeof( remote6 ) );
            }
            else if( 0 != ( ret = sock_getpeername( so, (struct sockaddr*)&remote6, sizeof( remote6 ) ) ) )
            {
                rpal_debug_info( "^^^^^^ ERROR getting remote sockname6: %d", ret );
                sc->isComplete = FALSE;
            }
        }
        
        if( sc->netEvent.isIncoming )
        {
            if( !isIpV6 )
            {
                sc->netEvent.srcIp.isV6 = FALSE;
                sc->netEvent.srcIp.value.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( remote4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.value.v4 = local4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( local4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.value.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.value.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
            }
        }
        else
        {
            if( !isIpV6 )
            {
                sc->netEvent.srcIp.isV6 = FALSE;
                sc->netEvent.srcIp.value.v4 = local4.sin_addr.s_addr;
                sc->netEvent.srcPort = ntohs( local4.sin_port );
                sc->netEvent.dstIp.isV6 = FALSE;
                sc->netEvent.dstIp.value.v4 = remote4.sin_addr.s_addr;
                sc->netEvent.dstPort = ntohs( remote4.sin_port );
            }
            else
            {
                sc->netEvent.srcIp.isV6 = TRUE;
                memcpy( &sc->netEvent.srcIp.value.v6.byteArray,
                        &local6.sin6_addr,
                        sizeof( sc->netEvent.srcIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( local6.sin6_port );
                sc->netEvent.dstIp.isV6 = TRUE;
                memcpy( &sc->netEvent.dstIp.value.v6.byteArray,
                        &remote6.sin6_addr,
                        sizeof( sc->netEvent.dstIp.value.v6.byteArray ) );
                sc->netEvent.srcPort = ntohs( remote6.sin6_port );
            }
        }
        
        isPopulated = TRUE;
    }
    
    return isPopulated;
}

static
errno_t
    cbDataIn
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* from,
        mbuf_t* data,
        mbuf_t* control,
        sflt_data_flag_t flags
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    RPU8 packet = NULL;
    RSIZET packetSize = 0;
    
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( control );
    UNREFERENCED_PARAMETER( flags );
    
    if( NULL != cookie )
    {
        populateCookie( sc, so, from );

        // Report on the connection event
        if( !sc->isReported )
        {
            if( !sc->isConnected )
            {
                sc->netEvent.isIncoming = TRUE;
            }
            
            if( !isConnectionAllowed( sc ) )
            {
                return EPERM;
            }
            
            rpal_mutex_lock( g_collector_4_mutex );
        
            sc->isReported = TRUE;
            g_connections[ g_nextConnection ] = sc->netEvent;
            next_connection();
            
            rpal_mutex_unlock( g_collector_4_mutex );
        }

        if( !isConnectionAllowed( sc ) )
        {
            return EPERM;
        }
        
        // See if we need to report on any content based parsing
        // Looking for DNS responses
        if( ( 53 == sc->netEvent.dstPort ||
              53 == sc->netEvent.srcPort )&&
            ( IPPROTO_TCP == sc->netEvent.proto ||
              IPPROTO_UDP == sc->netEvent.proto ) &&
            getPacket( data, &packet, &packetSize ) &&
            0 != packetSize )
        {
            KernelAcqDnsPacket dnsRecord = {0};
            RU32 requiredSize = 0;
            
            dnsRecord.ts = sc->netEvent.ts;
            dnsRecord.dstIp = sc->netEvent.dstIp;
            dnsRecord.dstPort = sc->netEvent.dstPort;
            dnsRecord.srcIp = sc->netEvent.srcIp;
            dnsRecord.srcPort = sc->netEvent.srcPort;
            dnsRecord.pid = sc->netEvent.pid;
            dnsRecord.proto = sc->netEvent.proto;
            dnsRecord.packetSize = (RU32)packetSize;
            
            requiredSize = (RU32)sizeof( KernelAcqDnsPacket ) + (RU32)packetSize;
            
            rpal_mutex_lock( g_collector_4_mutex_dns );
            
            if( sizeof( g_dns ) - g_nextDns < requiredSize )
            {
                // Buffer overflow, reset to the beginning.
                g_nextDns = 0;
                rpal_debug_info( "DNS packet buffer overflow" );
            }
            
            if( sizeof( g_dns ) - g_nextDns >= requiredSize )
            {
                memcpy( g_dns + g_nextDns, &dnsRecord, sizeof( KernelAcqDnsPacket ) );
                memcpy( g_dns + g_nextDns + sizeof( KernelAcqDnsPacket ), packet, packetSize );
                g_nextDns += requiredSize;
            }
            
            rpal_mutex_unlock( g_collector_4_mutex_dns );
        }
    }
    
    return KERN_SUCCESS;
}


static
errno_t
    cbDataOut
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* to,
        mbuf_t* data,
        mbuf_t* control,
        sflt_data_flag_t flags
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    UNREFERENCED_PARAMETER( data );
    UNREFERENCED_PARAMETER( control );
    UNREFERENCED_PARAMETER( flags );
    
    if( NULL != cookie &&
        !sc->isReported )
    {
        populateCookie( sc, so, to );

        if( !sc->isConnected )
        {
            sc->netEvent.isIncoming = FALSE;
        }

        if( !isConnectionAllowed( sc ) )
        {
            return EPERM;
        }
        
        rpal_mutex_lock( g_collector_4_mutex );
    
        sc->isReported = TRUE;
        g_connections[ g_nextConnection ] = sc->netEvent;
        next_connection();
        
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    
    return KERN_SUCCESS;
}

static
errno_t
    cbConnectIn
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* from
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = TRUE;
        sc->isConnected = TRUE;

        populateCookie( sc, so, from );

        if( !isConnectionAllowed( sc ) )
        {
            return EPERM;
        }
    }
    
    return KERN_SUCCESS;
}

static
errno_t
    cbConnectOut
    (
        void* cookie,
        socket_t so,
        const struct sockaddr* to
    )
{
    SockCookie* sc = (SockCookie*)cookie;
    
    if( NULL != cookie )
    {
        sc->netEvent.isIncoming = FALSE;
        sc->isConnected = TRUE;
        
        populateCookie( sc, so, to );

        if( !isConnectionAllowed( sc ) )
        {
            return EPERM;
        }
    }
    
    return KERN_SUCCESS;
}

static
RBOOL
    register_filter
    (
        int fltHandle,
        int addrFamily,
        int sockType,
        int protocol
    )
{
    RBOOL isSuccess = FALSE;
    
    struct sflt_filter flt = { 0 };
    flt.sf_handle = _FLT_HANDLE_BASE + fltHandle;
    flt.sf_flags = SFLT_GLOBAL;
    flt.sf_name = _FLT_NAME;
    flt.sf_attach = cbAttach;
    flt.sf_detach = cbDetach;
    flt.sf_connect_in = cbConnectIn;
    flt.sf_connect_out = cbConnectOut;
    flt.sf_data_in = cbDataIn;
    flt.sf_data_out = cbDataOut;
    
    if( 0 == sflt_register( &flt, addrFamily, sockType, protocol ) )
    {
        isSuccess = TRUE;
    }
    
    return isSuccess;
}

static
RBOOL
    unregister_filter
    (
        int fltHandle
    )
{
    RBOOL isUnregistered = FALSE;
    
    if( 0 == sflt_unregister( _FLT_HANDLE_BASE + fltHandle ) )
    {
        isUnregistered = TRUE;
    }
    
    return isUnregistered;
}

int
    task_get_new_connections
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    
    int toCopy = 0;
    
    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        toCopy = (*resultSize) / sizeof( KernelAcqNetwork );
        
        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextConnection ? g_nextConnection : toCopy );
            
            *resultSize = toCopy * sizeof( KernelAcqNetwork );
            memcpy( pResult, g_connections, *resultSize );
            
            g_nextConnection -= toCopy;
            if( 0 != g_nextConnection )
            {
                memmove( g_connections,
                         &g_connections[ toCopy ],
                         g_nextConnection * sizeof( KernelAcqNetwork ) );
            }
        }
        else
        {
            *resultSize = 0;
        }
        
        rpal_mutex_unlock( g_collector_4_mutex );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
    task_get_new_dns
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    KernelAcqDnsPacket* pDns = NULL;
    
    RU32 currentFrameSize = 0;
    RU32 toCopy = 0;
    
    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        rpal_mutex_lock( g_collector_4_mutex_dns );
        
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
        
        rpal_mutex_unlock( g_collector_4_mutex_dns );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
    task_segregate_network
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    
    rpal_mutex_lock( g_collector_4_mutex );
    
    g_is_network_segregated = TRUE;

    rpal_mutex_unlock( g_collector_4_mutex );

    return ret;
}

int
    task_rejoin_network
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;

    rpal_mutex_lock( g_collector_4_mutex );

    g_is_network_segregated = FALSE;

    rpal_mutex_unlock( g_collector_4_mutex );

    return ret;
}

int
    collector_4_initialize
    (
        void* d
    )
{
    int isSuccess = 0;

#ifndef _DISABLE_COLLECTOR_4
    if( NULL != ( g_collector_4_mutex = rpal_mutex_create() ) &&
        NULL != ( g_collector_4_mutex_dns = rpal_mutex_create() ) )
    {
        g_is_network_segregated = FALSE;

        if( register_filter( 0, AF_INET, SOCK_STREAM, IPPROTO_TCP ) &&
            register_filter( 1, AF_INET6, SOCK_STREAM, IPPROTO_TCP ) &&
            register_filter( 2, AF_INET, SOCK_DGRAM, IPPROTO_UDP ) &&
            register_filter( 3, AF_INET6, SOCK_DGRAM, IPPROTO_UDP ) )
        {
            isSuccess = 1;
        }
        else
        {
            unregister_filter( 0 );
            unregister_filter( 1 );
            unregister_filter( 2 );
            unregister_filter( 3 );
        }

        if( !isSuccess )
        {
            rpal_mutex_free( g_collector_4_mutex );
            rpal_mutex_free( g_collector_4_mutex_dns );
        }
    }
#else
    UNREFERENCED_PARAMETER( d );
    isSuccess = 1;
#endif
    
    return isSuccess;
}

int
    collector_4_deinitialize
    (

    )
{
#ifndef _DISABLE_COLLECTOR_4
    RBOOL isDone = FALSE;
    
    rpal_mutex_lock( g_collector_4_mutex );
    g_shuttingDown = TRUE;
    rpal_mutex_unlock( g_collector_4_mutex );
    
    unregister_filter( 0 );
    unregister_filter( 1 );
    unregister_filter( 2 );
    unregister_filter( 3 );
    
    while( !isDone )
    {
        rpal_mutex_lock( g_collector_4_mutex );
        if( 0 == g_socketsPending )
        {
            isDone = TRUE;
        }
        rpal_mutex_unlock( g_collector_4_mutex );
        
        if( !isDone )
        {
            //IOSleep( 500 );
        }
    }
    
    rpal_mutex_free( g_collector_4_mutex );
    rpal_mutex_free( g_collector_4_mutex_dns );
#endif
    return 1;
}
