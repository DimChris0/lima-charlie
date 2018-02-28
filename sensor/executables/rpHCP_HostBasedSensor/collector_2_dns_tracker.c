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
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>

#define RPAL_FILE_ID          71

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#pragma warning( disable: 4214 )
#include <WinDNS.h>

RPRIVATE HMODULE hDnsApi = NULL;
RPRIVATE DnsGetCacheDataTable_f getCache = NULL;
RPRIVATE DnsFree_f freeCacheEntry = NULL;
#endif

#define DNS_LABEL_MAX_SIZE      254
#define DNS_SANITY_MAX_RECORDS  50
#define DNS_KB_PACKET_BUFFER    128
#define DNS_A_RECORD            0x0001
#define DNS_AAAA_RECORD         0x001C
#define DNS_CNAME_RECORD        0x0005

// Labels in DNS can be literals or relative offsets.
// http://www.zytrax.com/books/dns/ch15/
#define DNS_LABEL_POINTER_INDICATOR 0xC0
#define DNS_LABEL_IS_OFFSET( pLabel ) ((pLabel)->nChar >= DNS_LABEL_POINTER_INDICATOR)
#define DNS_LABEL_POINTER_BASE      0xC000
#define DNS_LABEL_OFFSET( pLabel ) (rpal_ntoh16( *(RU16*)(pLabel) ) - DNS_LABEL_POINTER_BASE)

typedef struct
{
    RU16 type;
    RU16 unused;
    RU32 flags;
    RPNCHAR name;

} _dnsRecord;


#pragma pack(push, 1)
typedef struct
{
    RU16 msgId;
    RU8 rd : 1;
    RU8 tc : 1;
    RU8 aa : 1;
    RU8 opCode : 4;
    RU8 qr : 1;
    RU8 rCode : 4;
    RU8 reserved : 3;
    RU8 ra : 1;
    RU16 qdCount;
    RU16 anCount;
    RU16 nsCount;
    RU16 arCount;
    RU8 data[];

} DnsHeader;

typedef struct
{
    RU8 nChar;
    RU8 label[];

} DnsLabel;

typedef struct
{
    RU16 recordType;
    RU16 recordClass;

} DnsQuestionInfo;

typedef struct
{
    RU16 recordType;
    RU16 recordClass;
    RU32 ttl;
    RU16 rDataLength;
    RU8 rData[];

} DnsResponseInfo;
#pragma pack(pop)

// Parses a label from a DNS packet and returns a pointer to the next byte after the label
// or label chain to be used to continue parsing the packet.
// If a human label is specified, will also assemble a human readable version of the labels
// in the buffer.
RPRIVATE
DnsLabel*
    dnsReadLabels
    (
        DnsLabel* pLabel,
        RCHAR humanLabel[ DNS_LABEL_MAX_SIZE ],
        RPU8 packetStart,
        RSIZET packetSize,
        RU32 labelOffset,
        RU32 recursiveDepth
    )
{
    RU32 copied = labelOffset;

    if( 3 < recursiveDepth )
    {
        return NULL;
    }

    if( NULL == pLabel )
    {
        return NULL;
    }

    while( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ), packetStart, packetSize ) &&
            ( DNS_LABEL_IS_OFFSET( pLabel ) ||
                ( IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ) + pLabel->nChar, packetStart, packetSize ) &&
                0 != pLabel->nChar ) ) )
    {
        // It's possible for a pointer to be terminating a traditional label
        if( DNS_LABEL_IS_OFFSET( pLabel ) )
        {
            // Pointer to a label
            DnsLabel* tmpLabel = NULL;
            RU16 offset = DNS_LABEL_OFFSET( pLabel );

            if( !IS_WITHIN_BOUNDS( (RPU8)packetStart + offset, sizeof( RU16 ), packetStart, packetSize ) )
            {
                rpal_debug_warning( "error parsing dns packet" );
                return NULL;
            }

            tmpLabel = (DnsLabel*)( (RPU8)packetStart + offset );

            if( NULL == dnsReadLabels( tmpLabel, humanLabel, packetStart, packetSize, copied, recursiveDepth + 1 ) )
            {
                return NULL;
            }

            // Pointers are always terminating the label. So since there is
            // no 0 terminated label we don't need to skip an extra byte, we
            // just skip the current label pointer value.
            pLabel = (DnsLabel*)( (RPU8)pLabel + sizeof( RU16 ) );
            return pLabel;
        }
        else
        {
            if( DNS_LABEL_MAX_SIZE < copied + 1 + pLabel->nChar )
            {
                rpal_debug_warning( "error parsing dns packet" );
                return NULL;
            }

            if( NULL != humanLabel )
            {
                if( 0 != copied )
                {
                    humanLabel[ copied ] = '.';
                    copied++;
                }
                rpal_memory_memcpy( (RPU8)humanLabel + copied, pLabel->label, pLabel->nChar );
                copied += pLabel->nChar;
            }

            pLabel = (DnsLabel*)( (RPU8)pLabel + pLabel->nChar + 1 );
        }
    }

    // We do a last sanity check. A valid label parsing should end in a 0-val nChar within
    // the buffer, so we check it's all valid, otherwise we'll assume an error and will return an error.
    if( !IS_WITHIN_BOUNDS( pLabel, sizeof( *pLabel ), packetStart, packetSize ) ||
        0 != pLabel->nChar )
    {
        rpal_debug_warning( "error parsing dns packet" );
        return NULL;
    }

    // Get to the next valid byte, so we skip the 0-termination.
    pLabel = (DnsLabel*)( (RPU8)pLabel + 1 );

    return pLabel;
}

RPRIVATE
RVOID
    _freeRecords
    (
        rBlob recs
    )
{
    RU32 i = 0;
    _dnsRecord* pRec = NULL;

    if( NULL != recs )
    {
        i = 0;
        while( NULL != ( pRec = rpal_blob_arrElem( recs, sizeof( *pRec ), i++ ) ) )
        {
            if( NULL != pRec->name )
            {
                rpal_memory_free( pRec->name );
            }
        }
    }
}

RPRIVATE
RS32
    _cmpDns
    (
        _dnsRecord* rec1,
        _dnsRecord* rec2
    )
{
    RS32 ret = 0;

    if( NULL != rec1 &&
        NULL != rec2 )
    {
        if( 0 == ( ret = rpal_memory_memcmp( rec1, 
                                             rec2, 
                                             sizeof( *rec1 ) - sizeof( RPWCHAR ) ) ) )
        {
            ret = rpal_string_strcmp( rec1->name, rec2->name );
        }
    }

    return ret;
}

RPRIVATE
RVOID
    dnsUmDiffThread
    (
        rEvent isTimeToStop
    )
{
    rSequence notif = NULL;
    rBlob snapCur = NULL;
    rBlob snapPrev = NULL;
    _dnsRecord rec = { 0 };
    _dnsRecord* pCurRec = NULL;
    RU32 i = 0;
    LibOsPerformanceProfile perfProfile = { 0 };
    
#ifdef RPAL_PLATFORM_WINDOWS
    PDNSCACHEENTRY pDnsEntry = NULL;
    PDNSCACHEENTRY pPrevDnsEntry = NULL;
#endif

    perfProfile.enforceOnceIn = 1;
    perfProfile.sanityCeiling = MSEC_FROM_SEC( 10 );
    perfProfile.lastTimeoutValue = 100;
    perfProfile.targetCpuPerformance = 0;
    perfProfile.globalTargetCpuPerformance = GLOBAL_CPU_USAGE_TARGET;
    perfProfile.timeoutIncrementPerSec = 1;

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() )
        {
            if( NULL != snapPrev )
            {
                _freeRecords( snapPrev );
                rpal_blob_free( snapPrev );
                snapPrev = NULL;
            }
            // If kernel acquisition becomes available, try kernel again.
            return;
        }

        libOs_timeoutWithProfile( &perfProfile, FALSE, isTimeToStop );

        if( NULL != ( snapCur = rpal_blob_create( 0, 10 * sizeof( rec ) ) ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            if( TRUE == getCache( &pDnsEntry ) )
            {
                while( NULL != pDnsEntry )
                {
                    rec.flags = pDnsEntry->dwFlags;
                    rec.type = pDnsEntry->wType;
                    if( NULL != ( rec.name = rpal_string_strdup( pDnsEntry->pszName ) ) )
                    {
                        rpal_blob_add( snapCur, &rec, sizeof( rec ) );
                    }

                    pPrevDnsEntry = pDnsEntry;
                    pDnsEntry = pDnsEntry->pNext;

                    freeCacheEntry( pPrevDnsEntry->pszName, DnsFreeFlat );
                    freeCacheEntry( pPrevDnsEntry, DnsFreeFlat );
                }

                rpal_sort_array( rpal_blob_getBuffer( snapCur ), 
                                 rpal_blob_getSize( snapCur ) / sizeof( rec ), 
                                 sizeof( rec ), 
                                 _cmpDns );
            }
#elif defined( RPAL_PLATFORM_MACOSX )
            rpal_thread_sleep( MSEC_FROM_SEC( 2 ) );
#endif

            // Do a general diff of the snapshots to find new entries.
            if( NULL != snapPrev )
            {
                i = 0;
                while( !rEvent_wait( isTimeToStop, 0 ) &&
                       NULL != ( pCurRec = rpal_blob_arrElem( snapCur, sizeof( rec ), i++ ) ) )
                {
                    if( -1 == rpal_binsearch_array( rpal_blob_getBuffer( snapPrev ), 
                                                    rpal_blob_getSize( snapPrev ) / sizeof( rec ), 
                                                    sizeof( rec ), 
                                                    pCurRec,
                                                    (rpal_ordering_func)_cmpDns ) )
                    {
                        if( NULL != ( notif = rSequence_new() ) )
                        {
                            rSequence_addSTRINGN( notif, RP_TAGS_DOMAIN_NAME, pCurRec->name );
                            rSequence_addRU16( notif, RP_TAGS_DNS_TYPE, pCurRec->type );
                            rSequence_addRU32( notif, RP_TAGS_DNS_FLAGS, pCurRec->flags );
                            hbs_timestampEvent( notif, 0 );

                            hbs_publish( RP_TAGS_NOTIFICATION_DNS_REQUEST, notif );

                            rSequence_free( notif );
                        }
                    }
                }
            }
        }

        if( NULL != snapPrev )
        {
            _freeRecords( snapPrev );
            rpal_blob_free( snapPrev );
            snapPrev = NULL;
        }

        snapPrev = snapCur;
        snapCur = NULL;

        libOs_timeoutWithProfile( &perfProfile, TRUE, isTimeToStop );
    }

    if( NULL != snapPrev )
    {
        _freeRecords( snapPrev );
        rpal_blob_free( snapPrev );
        snapPrev = NULL;
    }
}

RPRIVATE
RVOID
    processDnsPacket
    (
        KernelAcqDnsPacket* pDns
    )
{
    rSequence notification = NULL;
    RU32 i = 0;
    DnsLabel* pLabel = NULL;
    DnsHeader* dnsHeader = NULL;
    DnsResponseInfo* pResponseInfo = NULL;
    RCHAR domain[ DNS_LABEL_MAX_SIZE ] = { 0 };
    RU16 recordType = 0;
    RU64 timestamp = 0;
    Atom parentAtom = { 0 };

    if( NULL == pDns )
    {
        return;
    }

    dnsHeader = (DnsHeader*)( (RPU8)pDns + sizeof( *pDns ) );
    pLabel = (DnsLabel*)dnsHeader->data;

    // We are parsing DNS packets coming from the kernel. They may:
    // 1- Be requests and not responses, check there are Answers.
    // 2- Be maliciously crafter packets so we need extra checking for sanity.
    if( 0 == dnsHeader->anCount ||
        0 == dnsHeader->qr ||
        DNS_SANITY_MAX_RECORDS < rpal_ntoh16( dnsHeader->qdCount ) ||
        DNS_SANITY_MAX_RECORDS < rpal_ntoh16( dnsHeader->anCount ) )
    {
        return;
    }

    // We need to walk the Questions first to get to the Answers
    // but we don't really care to record them since they'll be repeated
    // in the Answers.
    for( i = 0; i < rpal_ntoh16( dnsHeader->qdCount ); i++ )
    {
        DnsQuestionInfo* pQInfo = NULL;

        pLabel = dnsReadLabels( pLabel, NULL, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );

        pQInfo = (DnsQuestionInfo*)( pLabel );
        if( !IS_WITHIN_BOUNDS( pQInfo, sizeof( *pQInfo ), dnsHeader, pDns->packetSize ) )
        {
            rpal_debug_warning( "error parsing dns packet" );
            break;
        }

        pLabel = (DnsLabel*)( (RPU8)pQInfo + sizeof( *pQInfo ) );
    }

    if( !IS_WITHIN_BOUNDS( pLabel, sizeof( RU16 ), dnsHeader, pDns->packetSize ) )
    {
        rpal_debug_warning( "error parsing dns packet" );
        return;
    }

    // This is what we care about, the Answers (which also point to each Question).
    // We will emit one event per Answer so as to keep the DNS_REQUEST event flat and atomic.
    for( i = 0; i < rpal_ntoh16( dnsHeader->anCount ); i++ )
    {
        pResponseInfo = NULL;
            
        // This was the Question for this answer.
        rpal_memory_zero( domain, sizeof( domain ) );
        pLabel = dnsReadLabels( pLabel, domain, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );

        pResponseInfo = (DnsResponseInfo*)pLabel;
        pLabel = (DnsLabel*)( (RPU8)pResponseInfo + sizeof( *pResponseInfo ) + rpal_ntoh16( pResponseInfo->rDataLength ) );

        if( !IS_WITHIN_BOUNDS( pResponseInfo, sizeof( *pResponseInfo ), dnsHeader, pDns->packetSize ) )
        {
            rpal_debug_warning( "error parsing dns packet" );
            break;
        }

        if( NULL == ( notification = rSequence_new() ) )
        {
            rpal_debug_warning( "error parsing dns packet" );
            break;
        }

        // This is a timestamp coming from the kernel so it is not globally adjusted.
        // We'll adjust it with the global offset.
        timestamp = pDns->ts;
        timestamp += MSEC_FROM_SEC( rpal_time_getGlobalFromLocal( 0 ) );

        // Try to relate the DNS request to the owner process, this only works on OSX
        // at the moment (since the kernel does not expose the PID at the packet capture
        // stage), and even on OSX it's the DNSResolver process. So it's not super useful
        // but regardless we have the mechanism here as it's better than nothing and when
        // we add better resolving in the kernel it will work transparently.
        parentAtom.key.process.pid = pDns->pid;
        parentAtom.key.category = RP_TAGS_NOTIFICATION_NEW_PROCESS;
        if( atoms_query( &parentAtom, timestamp ) )
        {
            HbsSetParentAtom( notification, parentAtom.id );
        }

        rSequence_addTIMESTAMP( notification, RP_TAGS_TIMESTAMP, timestamp );
        rSequence_addSTRINGA( notification, RP_TAGS_DOMAIN_NAME, domain );
        rSequence_addRU32( notification, RP_TAGS_PROCESS_ID, pDns->pid );

        recordType = rpal_ntoh16( pResponseInfo->recordType );

        rSequence_addRU16( notification, RP_TAGS_MESSAGE_ID, rpal_ntoh16( dnsHeader->msgId ) );
        rSequence_addRU16( notification, RP_TAGS_DNS_TYPE, recordType );

        if( DNS_A_RECORD == recordType )
        {
            rSequence_addIPV4( notification, RP_TAGS_IP_ADDRESS, *(RU32*)pResponseInfo->rData );
        }
        else if( DNS_AAAA_RECORD == recordType )
        {
            rSequence_addIPV6( notification, RP_TAGS_IP_ADDRESS, pResponseInfo->rData );
        }
        else if( DNS_CNAME_RECORD == recordType )
        {
            // CNAME records will have another label as a value and not an IP.
            rpal_memory_zero( domain, sizeof( domain ) );
            dnsReadLabels( (DnsLabel*)pResponseInfo->rData, domain, (RPU8)dnsHeader, pDns->packetSize, 0, 0 );
            rSequence_addSTRINGA( notification, RP_TAGS_CNAME, domain );
        }
        else
        {
            // Right now we only care for A, CNAME and AAAA records.
            rSequence_free( notification );
            notification = NULL;
            continue;
        }

        hbs_publish( RP_TAGS_NOTIFICATION_DNS_REQUEST, notification );
        rSequence_free( notification );
        notification = NULL;
    }
}

RPRIVATE
RVOID
    dnsKmDiffThread
    (
        rEvent isTimeToStop
    )
{
    RU8 new_from_kernel[ DNS_KB_PACKET_BUFFER * 1024 ] = { 0 };
    RU8 prev_from_kernel[ DNS_KB_PACKET_BUFFER * 1024 ] = { 0 };

    RU32 sizeInNew = 0;
    RU32 sizeInPrev = 0;

    KernelAcqDnsPacket* pPacket = NULL;

    while( !rEvent_wait( isTimeToStop, 1000 ) )
    {
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        sizeInNew = sizeof( new_from_kernel );

        if( !kAcq_getNewDnsPackets( (KernelAcqDnsPacket*)new_from_kernel, &sizeInNew ) )
        {
            rpal_debug_warning( "kernel acquisition for new dns packets failed" );
            break;
        }

        pPacket = (KernelAcqDnsPacket*)prev_from_kernel;
        while( IS_WITHIN_BOUNDS( pPacket, sizeof( *pPacket ), prev_from_kernel, sizeInPrev ) &&
               0 != pPacket->ts &&
               IS_WITHIN_BOUNDS( pPacket, sizeof( *pPacket ) + pPacket->packetSize, prev_from_kernel, sizeInPrev ) )
        {
            processDnsPacket( pPacket );

            pPacket = (KernelAcqDnsPacket*)( (RPU8)pPacket + sizeof( *pPacket ) + pPacket->packetSize );
        }

        rpal_memory_memcpy( prev_from_kernel, new_from_kernel, sizeInNew );
        sizeInPrev = sizeInNew;
    }
}

RPRIVATE
RPVOID
    dnsDiffThread
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
            rpal_debug_info( "running kernelmode acquisition dns notification" );
            dnsKmDiffThread( isTimeToStop );
        }
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition dns notification" );
            dnsUmDiffThread( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_2_events[] = { RP_TAGS_NOTIFICATION_DNS_REQUEST,
                                  0 };

RBOOL
    collector_2_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RWCHAR apiName[] = _WCH( "dnsapi.dll" );
        RCHAR funcName1[] = "DnsGetCacheDataTable";
        RCHAR funcName2[] = "DnsFree";

        if( NULL != ( hDnsApi = LoadLibraryW( (RPWCHAR)&apiName ) ) )
        {
            // TODO: investigate the DnsQuery API on Windows to get the DNS resolutions.
            if( NULL != ( getCache = (DnsGetCacheDataTable_f)GetProcAddress( hDnsApi, (RPCHAR)&funcName1 ) ) &&
                NULL != ( freeCacheEntry = (DnsFree_f)GetProcAddress( hDnsApi, (RPCHAR)&funcName2 ) ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_warning( "failed to get dns undocumented function" );
                FreeLibrary( hDnsApi );
            }
        }
        else
        {
            rpal_debug_warning( "failed to load dns api" );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        isSuccess = TRUE;
#endif
        if( isSuccess )
        {
            isSuccess = FALSE;

            if( rThreadPool_task( hbsState->hThreadPool, dnsDiffThread, NULL ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_2_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( NULL != hDnsApi )
        {
            getCache = NULL;
            freeCacheEntry = NULL;
            FreeLibrary( hDnsApi );
        }
#endif
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    collector_2_update
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
HBS_DECLARE_TEST( dns_read_label )
{
    RCHAR tmpText[ DNS_LABEL_MAX_SIZE ] = { 0 };
    RPU8 buffer = NULL;
    RU32 bufferSize = 0;
    RU32 i = 0;
    DnsLabel* pLabel = NULL;

    RU8 label_1[] = { 0x03, 'w', 'w', 'w', 
                      0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                      0x03, 'c', 'o', 'm',
                      0x00 };
    RU32 offset1 = 0;
    RCHAR value1[] = { "www.google.com" };
    DnsLabel* nextLabel1 = (DnsLabel*)( label_1 + sizeof( label_1 ) );

    RU8 label_2[] = { 0xFF,
                      0x03, 'w', 'w', 'w',
                      0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                      0x03, 'c', 'o', 'm',
                      0x00,
                      0x03, 'a', 'p', 'i',
                      DNS_LABEL_POINTER_INDICATOR, 0x05,
                      0x04, 'n', 'o', 'p', 'e',
                      0x00 };
    RU32 offset2 = 17;
    RCHAR value2[] = { "api.google.com" };
    DnsLabel* nextLabel2 = (DnsLabel*)( label_2 + 23 );

    RU8 label_3[] = { 0xFF,
                      0x03, 'w', 'w', 'w',
                      0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                      0x03, 'c', 'o', 'm',
                      0x00,
                      0x02, 'l', 'c',
                      DNS_LABEL_POINTER_INDICATOR, 0x05,
                      DNS_LABEL_POINTER_INDICATOR, 0x14,
                      0x04, 'n', 'o', 'p', 'e',
                      0x00 };
    RU32 offset3 = 22;
    RCHAR value3[] = { "google.com" };
    DnsLabel* nextLabel3 = (DnsLabel*)( label_3 + 24 );

    RU8 label_4[] = { 0xFF,
                      0x03, 'w', 'w', 'w',
                      DNS_LABEL_POINTER_INDICATOR, 0x01,
                      DNS_LABEL_POINTER_INDICATOR, 0x05,
                      DNS_LABEL_POINTER_INDICATOR, 0x07,
                      DNS_LABEL_POINTER_INDICATOR, 0x09 };
    RU32 offset4 = 11;

    // Small fuzzing of the function.
    for( i = 0; i < 100; i++ )
    {
        bufferSize = ( rpal_rand() % ( 128 * 1024 ) ) + 1024;
        buffer = rpal_memory_alloc( bufferSize );
        HBS_ASSERT_TRUE( NULL != buffer );
        HBS_ASSERT_TRUE( CryptoLib_genRandomBytes( buffer, bufferSize ) );

        pLabel = (DnsLabel*)buffer;
        
        // Random data might contain something valid-looking so we can't assert == NULL.
        // We just this just as a fuzz to make sure we generate no crashes.
        rpal_memory_zero( tmpText, sizeof( tmpText ) );
        dnsReadLabels( pLabel, tmpText, buffer, bufferSize, 0, 0 );

        rpal_memory_free( buffer );
    }

    // Reading a simple single label.
    pLabel = (DnsLabel*)( label_1 + offset1 );
    buffer = label_1;
    bufferSize = sizeof( label_1 );

    rpal_memory_zero( tmpText, sizeof( tmpText ) );
    HBS_ASSERT_TRUE( nextLabel1 == dnsReadLabels( pLabel, tmpText, buffer, bufferSize, 0, 0 ) );
    HBS_ASSERT_TRUE( 0 == rpal_string_strcmpA( tmpText, value1 ) );

    // Reading a label using a pointer.
    // Also make sure that the pointer jump terminates the parsing (as per RFC).
    pLabel = (DnsLabel*)( label_2 + offset2 );
    buffer = label_2;
    bufferSize = sizeof( label_2 );

    rpal_memory_zero( tmpText, sizeof( tmpText ) );
    HBS_ASSERT_TRUE( nextLabel2 == dnsReadLabels( pLabel, tmpText, buffer, bufferSize, 0, 0 ) );
    HBS_ASSERT_TRUE( 0 == rpal_string_strcmpA( tmpText, value2 ) );

    // Reading a label using a pointer to a pointer.
    // Also make sure that the pointer jump terminates the parsing (as per RFC).
    pLabel = (DnsLabel*)( label_3 + offset3 );
    buffer = label_3;
    bufferSize = sizeof( label_3 );

    rpal_memory_zero( tmpText, sizeof( tmpText ) );
    HBS_ASSERT_TRUE( nextLabel3 == dnsReadLabels( pLabel, tmpText, buffer, bufferSize, 0, 0 ) );
    HBS_ASSERT_TRUE( 0 == rpal_string_strcmpA( tmpText, value3 ) );

    // Reading a label using a pointer to a pointer to a pointer past max_depth. In this case we
    // should not return a valid label.
    pLabel = (DnsLabel*)( label_4 + offset4 );
    buffer = label_4;
    bufferSize = sizeof( label_4 );

    rpal_memory_zero( tmpText, sizeof( tmpText ) );
    HBS_ASSERT_TRUE( NULL == dnsReadLabels( pLabel, tmpText, buffer, bufferSize, 0, 0 ) );
}

HBS_DECLARE_TEST( dns_process_packet )
{
    RPU8 buffer = NULL;
    RU32 bufferSize = 0;
    RU32 i = 0;
    KernelAcqDnsPacket* packet = NULL;
    RU32 nEvents = 0;
    rSequence event = NULL;
    RPCHAR domain = NULL;
    RU32 ip4 = 0;

    RU8 test_packet1[] = {
        0x2c, 0xe5, 0xca, 0xb5, 0x5b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0xb2, 0xdf, 0x10, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x3b, 0xe5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xdf, 0x10, 0xac, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 
        0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x8f, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x03, 0x73, 0x73, 0x6c, 0x07, 0x67, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 
        0x00, 0x00, 0x05, 0x00, 0x04, 0xac, 0xd9, 0x05, 0x63
    };
    RCHAR test_domain1[] = "ssl.gstatic.com";
    RU32 test_ip1 = 0x6305d9ac;

    rQueue notifQueue = NULL;

    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_DNS_REQUEST, NULL, 0, notifQueue, NULL ) );

    // We keep the test here somewhat simple since the packet is validated by the caller
    // above and the heavy structure validation is done at the label level. So we'll just
    // fuzz it a bit.
    for( i = 0; i < 100; i++ )
    {
        bufferSize = ( rpal_rand() % ( 128 * 1024 ) ) + 1024;
        buffer = rpal_memory_alloc( bufferSize );
        HBS_ASSERT_TRUE( NULL != buffer );
        HBS_ASSERT_TRUE( CryptoLib_genRandomBytes( buffer, bufferSize ) );

        packet = (KernelAcqDnsPacket*)buffer;

        // Random data might contain something valid-looking so we can't assert 
        // that no event will be generated.
        // We just this just as a fuzz to make sure we generate no crashes.
        processDnsPacket( packet );

        rpal_memory_free( buffer );
    }

    // Wipe the queue in case we generated events.
    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DNS_REQUEST, notifQueue, NULL );
    rQueue_free( notifQueue );

    // Try parsing sample packet 1
    HBS_ASSERT_TRUE( rQueue_create( &notifQueue, rSequence_freeWithSize, 10 ) );
    HBS_ASSERT_TRUE( notifications_subscribe( RP_TAGS_NOTIFICATION_DNS_REQUEST, NULL, 0, notifQueue, NULL ) );

    processDnsPacket( (KernelAcqDnsPacket*)test_packet1 );

    // Make sure we generate one event as expected.
    HBS_ASSERT_TRUE( rQueue_getSize( notifQueue, &nEvents ) );
    HBS_ASSERT_TRUE( 1 == nEvents );
    if( HBS_ASSERT_TRUE( rQueue_remove( notifQueue, &event, NULL, 0 ) ) )
    {
        HBS_ASSERT_TRUE( rSequence_getSTRINGA( event, RP_TAGS_DOMAIN_NAME, &domain ) );
        HBS_ASSERT_TRUE( 0 == rpal_string_strcmpA( domain, test_domain1 ) );
        HBS_ASSERT_TRUE( rSequence_getIPV4( event, RP_TAGS_IP_ADDRESS, &ip4 ) );
        HBS_ASSERT_TRUE( ip4 == test_ip1 );
        rSequence_free( event );
    }

    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DNS_REQUEST, notifQueue, NULL );
    rQueue_free( notifQueue );
}

HBS_TEST_SUITE( 2 )
{
    RBOOL isSuccess = FALSE;

    if( NULL != hbsState &&
        NULL != testContext )
    {
        HBS_RUN_TEST( dns_read_label );
        HBS_RUN_TEST( dns_process_packet );
        isSuccess = TRUE;
    }

    return isSuccess;
}