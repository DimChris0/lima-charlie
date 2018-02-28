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

#include <libOs/libOs.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <cryptoLib/cryptoLib.h>

#define RPAL_FILE_ID   35

#ifdef RPAL_PLATFORM_WINDOWS
#pragma warning( disable: 4127 )
#pragma warning( disable: 4306 )
#include <windows_undocumented.h>
#include <setupapi.h>
#define FILETIME2ULARGE( uli, ft )  (uli).u.LowPart = (ft).dwLowDateTime, (uli).u.HighPart = (ft).dwHighDateTime

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <errno.h>
#include <sys/time.h>
#if defined( RPAL_PLATFORM_MACOSX )
#include <ifaddrs.h>
#include <sys/sysctl.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <launch.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <mach/clock.h>
#include <mach/mach.h>
#elif defined( RPAL_PLATFORM_LINUX )
#include <mntent.h>
#include <sys/utsname.h>
#endif
#endif


static RBOOL g_isNetworkingInitialize = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
static WSADATA g_wsaData = {0};

static HMODULE wintrustLib = NULL;
static WinVerifyTrust_f WinVerifyTrust = NULL;
static WTHelperGetProvSignerFromChain_f WTHelperGetProvSignerFromChain = NULL;
static WTHelperProvDataFromStateData_f WTHelperProvDataFromStateData = NULL;
static CryptCATAdminAcquireContext_f CryptCATAdminAcquireContext = NULL;
static CryptCATAdminReleaseContext_f CryptCATAdminReleaseContext = NULL;
static CryptCATAdminReleaseCatalogContext_f CryptCATAdminReleaseCatalogContext = NULL;
static CryptCATAdminEnumCatalogFromHash_f CryptCATAdminEnumCatalogFromHash = NULL;
static CryptCATAdminCalcHashFromFileHandle_f CryptCATAdminCalcHashFromFileHandle = NULL;
static CryptCATCatalogInfoFromContext_f CryptCATCatalogInfoFromContext = NULL;

static HMODULE crypt32 = NULL;
static CertNameToStr_f RCertNameToStr = NULL;
static CertFreeCertificateChainEngine_f RCertFreeCertificateChainEngine = NULL;
static CertFreeCertificateChain_f RCertFreeCertificateChain = NULL;
static CertVerifyCertificateChainPolicy_f RCertVerifyCertificateChainPolicy = NULL;
static CertGetCertificateChain_f RCertGetCertificateChain = NULL;
static CertCreateCertificateChainEngine_f RCertCreateCertificateChainEngine = NULL;

RPRIVATE
RBOOL
    libOs_getFileSignature
    (
        RPNCHAR   pwfilePath,
        rSequence signature,
        RU32      operation,
        RBOOL*    pIsSigned,
        RBOOL*    pIsVerified_local,
        RBOOL*    pIsVerified_global
    );

// TODO : Code a generic lib loader
RPRIVATE
RBOOL
    loadCrypt32
    (

    )
{
    RBOOL isLoaded = FALSE;

    RWCHAR importCrypt32[] = _NC( "crypt32.dll" );
    RCHAR import1[] = "CertNameToStrA";
    RCHAR import2[] = "CertFreeCertificateChainEngine";
    RCHAR import3[] = "CertFreeCertificateChain";
    RCHAR import4[] = "CertVerifyCertificateChainPolicy";
    RCHAR import5[] = "CertGetCertificateChain";
    RCHAR import6[] = "CertCreateCertificateChainEngine";

    if( NULL == crypt32 )
    {
        // Some potential weird race condition, but extremely unlikely
        if( NULL != ( crypt32 = GetModuleHandle( (RPCHAR)&importCrypt32  ) ) ||
            NULL != ( crypt32 = LoadLibraryW( (RPWCHAR)&importCrypt32 ) ) )
        {
            RCertNameToStr = (CertNameToStr_f)GetProcAddress( crypt32, (RPCHAR)&import1 );
            RCertFreeCertificateChainEngine = (CertFreeCertificateChainEngine_f)GetProcAddress( crypt32, (RPCHAR)&import2 );
            RCertFreeCertificateChain = (CertFreeCertificateChain_f)GetProcAddress( crypt32, (RPCHAR)&import3 );
            RCertVerifyCertificateChainPolicy = (CertVerifyCertificateChainPolicy_f)GetProcAddress( crypt32, (RPCHAR)&import4 );
            RCertGetCertificateChain = (CertGetCertificateChain_f)GetProcAddress( crypt32, (RPCHAR)&import5 );
            RCertCreateCertificateChainEngine = (CertCreateCertificateChainEngine_f)GetProcAddress( crypt32, (RPCHAR)&import6 );
        }
    }
    
    if( NULL != RCertNameToStr &&
        NULL != RCertFreeCertificateChainEngine &&
        NULL != RCertFreeCertificateChain &&
        NULL != RCertVerifyCertificateChainPolicy &&
        NULL != RCertGetCertificateChain &&
        NULL != RCertCreateCertificateChainEngine )
    {
        isLoaded = TRUE;
    }

    return isLoaded;
}


RPRIVATE
RBOOL
    loadWinTrustApi
    (

    )
{
    RBOOL isLoaded = FALSE;

    RWCHAR importLibWintrust[] = _NC( "wintrust.dll" );
    RCHAR import1[] = "WinVerifyTrust";
    RCHAR import2[] = "WTHelperGetProvSignerFromChain";
    RCHAR import3[] = "WTHelperProvDataFromStateData";
    RCHAR import4[] = "CryptCATAdminAcquireContext";
    RCHAR import5[] = "CryptCATAdminReleaseContext";
    RCHAR import6[] = "CryptCATAdminReleaseCatalogContext";
    RCHAR import7[] = "CryptCATAdminEnumCatalogFromHash";
    RCHAR import8[] = "CryptCATAdminCalcHashFromFileHandle";
    RCHAR import9[] = "CryptCATCatalogInfoFromContext";

    if( NULL == wintrustLib )
    {
        // Some potential weird race condition, but extremely unlikely
        if( NULL != ( wintrustLib = LoadLibraryW( (RPWCHAR)&importLibWintrust ) ) )
        {
            WinVerifyTrust = (WinVerifyTrust_f)GetProcAddress( wintrustLib, (RPCHAR)&import1 );
            WTHelperGetProvSignerFromChain = (WTHelperGetProvSignerFromChain_f)GetProcAddress( wintrustLib, (RPCHAR)&import2 );
            WTHelperProvDataFromStateData = (WTHelperProvDataFromStateData_f)GetProcAddress( wintrustLib, (RPCHAR)&import3 );
            CryptCATAdminAcquireContext = (CryptCATAdminAcquireContext_f)GetProcAddress( wintrustLib, (RPCHAR)&import4 );
            CryptCATAdminReleaseContext = (CryptCATAdminReleaseContext_f)GetProcAddress( wintrustLib, (RPCHAR)&import5 );
            CryptCATAdminReleaseCatalogContext = (CryptCATAdminReleaseCatalogContext_f)GetProcAddress( wintrustLib, (RPCHAR)&import6 );
            CryptCATAdminEnumCatalogFromHash = (CryptCATAdminEnumCatalogFromHash_f)GetProcAddress( wintrustLib, (RPCHAR)&import7 );
            CryptCATAdminCalcHashFromFileHandle = (CryptCATAdminCalcHashFromFileHandle_f)GetProcAddress( wintrustLib, (RPCHAR)&import8 );
            CryptCATCatalogInfoFromContext = (CryptCATCatalogInfoFromContext_f)GetProcAddress( wintrustLib, (RPCHAR)&import9 );
        }
    }

    if( NULL != WinVerifyTrust &&
        NULL != WTHelperGetProvSignerFromChain &&
        NULL != WTHelperProvDataFromStateData &&
        NULL != CryptCATAdminAcquireContext &&
        NULL != CryptCATAdminReleaseContext &&
        NULL != CryptCATAdminReleaseCatalogContext &&
        NULL != CryptCATAdminEnumCatalogFromHash &&
        NULL != CryptCATAdminCalcHashFromFileHandle &&
        NULL != CryptCATCatalogInfoFromContext )
    {
        isLoaded = TRUE;
    }

    return isLoaded;
}
#endif

RBOOL
    _initializeNetworking
    (

    )
{
    RBOOL isSuccess = FALSE;

    if( g_isNetworkingInitialize )
    {
        isSuccess = TRUE;
    }
    else
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( 0 == WSAStartup( MAKEWORD(2, 2), &g_wsaData ) )
        {
            isSuccess = TRUE;
        }
#else
    isSuccess = TRUE;
#endif

        if( isSuccess )
        {
            g_isNetworkingInitialize = TRUE;
        }
    }

    return isSuccess;
}




RPCHAR
    libOs_getHostName
    (
        
    )
{
    RPCHAR outName = NULL;
    RCHAR name[ 256 ] = {0};

    if( _initializeNetworking() )
    {
        if( 0 == gethostname( (RPCHAR)&name, 256 ) )
        {
            outName = rpal_string_strdupA( name );
        }
    }

    return outName;
}

RU32
    libOs_getMainIp
    (

    )
{
    RU32 ip = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    RCHAR name[ 256 ] = {0};
    struct hostent* hostinfo = NULL;
    struct in_addr addr = {0};

    if( _initializeNetworking() )
    {
        if( 0 == gethostname( (RPCHAR)&name, 256 ) )
        {
            if( NULL != ( hostinfo = gethostbyname( (RPCHAR)&name ) ) )
            {
#ifdef RPAL_PLATFORM_64_BIT
                char** tmp = NULL;
                tmp = hostinfo->h_addr_list;
                if( ( (RU64)tmp & 0x00000000FFFFFFFF ) == 0x00000000BAADF00D )
                {
                    tmp = (char**)(((RU64)tmp & 0xFFFFFFFF00000000) >> 32);
                }

                addr.s_addr = *(u_long*)(tmp[ 0 ]);
#else
                if( 0 != hostinfo->h_addr_list[ 0 ] )
                {
                    addr.s_addr = *(u_long *) hostinfo->h_addr_list[ 0 ];
                }
#endif
                ip = addr.S_un.S_addr;
            }
        }
    }
#elif defined( RPAL_PLATFORM_LINUX )
    static struct ifreq ifreqs[ 32 ];
    struct ifconf ifconf;
    int sd = 0;
    int r = 0;
    int i = 0;
    int ifc_num = 0;
    
    memset( &ifconf, 0, sizeof( ifconf ) );
    ifconf.ifc_req = ifreqs;
    ifconf.ifc_len = sizeof( ifreqs );

    if( 0 <= ( sd = socket( PF_INET, SOCK_STREAM, 0 ) ) )
    {
        if( 0 == ( r = ioctl( sd, SIOCGIFCONF, (char *)&ifconf ) ) )
        {
            ifc_num = ifconf.ifc_len / sizeof( struct ifreq );
            for( i = 0; i < ifc_num; ++i )
            {
                if( AF_INET != ifreqs[ i ].ifr_addr.sa_family ||
                    0x0100007F == (RU32)( (struct sockaddr_in *)&ifreqs[ i ].ifr_addr )->sin_addr.s_addr )
                {
                    continue;
                }
        
                ip = (RU32)( (struct sockaddr_in *)&ifreqs[ i ].ifr_addr )->sin_addr.s_addr;
                break;
            }
        }
    }

    close( sd );
#elif defined( RPAL_PLATFORM_MACOSX )
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    // retrieve the current interfaces - returns 0 on success
    if( 0 == ( success = getifaddrs( &interfaces ) ) )
    {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while( NULL != temp_addr )
        {
            if( AF_INET == temp_addr->ifa_addr->sa_family &&
                0x0100007F != (RU32)( ( (struct sockaddr_in *)temp_addr->ifa_addr )->sin_addr.s_addr ) )
            {
                ip = (RU32)( ( (struct sockaddr_in *)temp_addr->ifa_addr )->sin_addr.s_addr );
                break;
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs( interfaces );
#else
    rpal_debug_not_implemented();
#endif
    return ip;
}


RU8
    libOs_getCpuUsage
    (

    )
{
    RU8 percent = (RU8)(-1);

#ifdef RPAL_PLATFORM_WINDOWS
    static RBOOL isLoadable = TRUE;
    static GetSystemTimes_f getSysTimes = NULL;
    RCHAR libName[] = "kernel32.dll";
    RCHAR funcName[] = "GetSystemTimes";
    ULARGE_INTEGER tIdle;
    ULARGE_INTEGER tKernel;
    ULARGE_INTEGER tUser;

    static ULARGE_INTEGER hIdle;
    static ULARGE_INTEGER hKernel;
    static ULARGE_INTEGER hUser;

    ULONGLONG curIdle;
    ULONGLONG curUsed;
    FLOAT prt = 0;

    if( NULL == getSysTimes &&
        isLoadable )
    {
        // Try to load the function, only available XP SP1++
        getSysTimes = (GetSystemTimes_f)GetProcAddress( LoadLibraryA( libName ), funcName );

        isLoadable = FALSE;
    }

    if( NULL != getSysTimes )
    {
        if( getSysTimes( (LPFILETIME)&tIdle, (LPFILETIME)&tKernel, (LPFILETIME)&tUser ) )
        {
            curIdle = tIdle.QuadPart - hIdle.QuadPart;
            curUsed = tKernel.QuadPart - hKernel.QuadPart;
            curUsed += tUser.QuadPart - hUser.QuadPart;

            if( 0 != curUsed )
            {
                prt = (FLOAT)( (curUsed - curIdle) * 100 / curUsed );
            }
            else
            {
                prt = 0;
            }

            percent = (BYTE)( prt );

            hUser.QuadPart = tUser.QuadPart;
            hKernel.QuadPart = tKernel.QuadPart;
            hIdle.QuadPart = tIdle.QuadPart;
        }
    }
#elif defined( RPAL_PLATFORM_LINUX )
    static long long int hIdle;
    static long long int hKernel;
    static long long int hUser;
    static long long int hUserLow;
    long long int tUser = 0;
    long long int tKernel = 0;
    long long int tIdle = 0;
    long long int tUserLow = 0;
    long long int total = 0;
    long long int used = 0;
    FILE* hStat = NULL;
    RCHAR statFile[] = "/proc/stat";
    int unused;
    
    if( NULL != ( hStat = fopen( (RPCHAR)statFile, "r" ) ) )
    {
        unused = fscanf( hStat, "cpu %llu %llu %llu %llu",
             &tUser,
             &tUserLow,
             &tKernel,
             &tIdle );
    
        fclose( hStat );
    
        if( hUser > tUser ||
            hKernel > tKernel ||
            hIdle > tIdle ||
            hUserLow > tUserLow )
        {
            // Overflow
            percent = 0;
        }
        else
        {
            total = ( tUser - hUser ) + ( tUserLow - hUserLow ) + ( tKernel - hKernel );
            used = total;
            total += ( tIdle - hIdle );
            if( 0 == used || 0 == total )
            {
                percent = 0;
            }
            else
            {
                percent = ( (float)used / (float)total ) * 100;
            }
        }
    
        hIdle = tIdle;
        hUser = tUser;
        hUserLow = tUserLow;
        hKernel = tKernel;
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    double load = 0;
    if( 1 == getloadavg( &load, 1 ) )
    {
        if( 1 > load )
        {
            percent = load * 100;
        }
        else
        {
            percent = 100;
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return percent;
}


RU32
    libOs_getUsageProportionalTimeout
    (
        RU32 maxTimeout
    )
{
    RU32 timeout = 0;
    RU8 usage = 0;

    usage = libOs_getCpuUsage();
    if( 0xFF == usage )
    {
        // Looks like we don't have access to the usage
        // so let's assume 50%... :-/
        usage = 50;
    }

    timeout = (RU32)( ( (RFLOAT)usage / 100 ) * maxTimeout );
    
    return timeout;
}


RU32
    libOs_getOsVersion
    (

    )
{
    RU32 version = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    OSVERSIONINFO versionEx = {0};

    versionEx.dwOSVersionInfoSize = sizeof( versionEx );

    if( GetVersionEx( &versionEx ))
    {
        if( 5 > versionEx.dwMajorVersion ||
            ( 5 == versionEx.dwMajorVersion && 1 > versionEx.dwMinorVersion ) )
        {
            version = OSLIB_VERSION_WINDOWS_OLD;
        }
        else if( 5 == versionEx.dwMajorVersion && 1 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_XP;
        }
        else if( 5 == versionEx.dwMajorVersion && 2 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_2K3;
        }
        else if( 6 == versionEx.dwMajorVersion && 0 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_VISTA_2K8;
        }
        else if( 6 == versionEx.dwMajorVersion && 1 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_7_2K8R2;
        }
        else if( 6 == versionEx.dwMajorVersion && 2 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_8;
        }
        else if( 6 == versionEx.dwMajorVersion && 3 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_8_1;
        }
        else if( 10 == versionEx.dwMajorVersion && 0 == versionEx.dwMinorVersion )
        {
            version = OSLIB_VERSION_WINDOWS_10;
        }
        else if( 10 < versionEx.dwMajorVersion ||
                 ( 10 == versionEx.dwMajorVersion && 0 < versionEx.dwMinorVersion ) )
        {
            version = OSLIB_VERSION_WINDOWS_FUTURE;
        }
    }
#else
    rpal_debug_not_implemented();
#endif

    return version;
}

rSequence
    libOs_getOsVersionEx
    (

    )
{
    rSequence info = NULL;

    if( NULL != ( info = rSequence_new() ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        rSequence servicePack = NULL;
        OSVERSIONINFOEX versionEx = { 0 };

        versionEx.dwOSVersionInfoSize = sizeof( versionEx );

        // Don't mind the casting, this is just one of those odd Windows things. By setting the Ex struct
        // size as member size and casting, the API knows it is dealing with an Ex.
        if( GetVersionEx( (LPOSVERSIONINFO)&versionEx ) )
        {
            rSequence_addRU32( info, RP_TAGS_VERSION_MAJOR, versionEx.dwMajorVersion );
            rSequence_addRU32( info, RP_TAGS_VERSION_MINOR, versionEx.dwMinorVersion );
            rSequence_addRU32( info, RP_TAGS_BUILD_NUMBER, versionEx.dwBuildNumber );
            rSequence_addRU16( info, RP_TAGS_SUITE, versionEx.wSuiteMask );
            rSequence_addRU8( info, RP_TAGS_PRODUCT_TYPE, versionEx.wProductType );

            if( NULL != ( servicePack = rSequence_new() ) )
            {
                rSequence_addRU16( servicePack, RP_TAGS_VERSION_MAJOR, versionEx.wServicePackMajor );
                rSequence_addRU16( servicePack, RP_TAGS_VERSION_MINOR, versionEx.wServicePackMinor );
                if( !rSequence_addSEQUENCE( info, RP_TAGS_SERVICE_PACK, servicePack ) )
                {
                    rSequence_free( servicePack );
                }
            }
        }
#elif defined( RPAL_PLATFORM_LINUX )
        struct utsname nameInfo = {0};

        if( 0 == uname( &nameInfo ) )
        {
            rSequence_addSTRINGA( info, RP_TAGS_VERSION_MAJOR, nameInfo.release );
            rSequence_addSTRINGA( info, RP_TAGS_VERSION_MINOR, nameInfo.version );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        char kernRelease[] = "kern.osrelease";
        char kernVersion[] = "kern.version";
        char version[ 256 ] = {0};
        size_t size = sizeof( version );

        if( 0 == sysctlbyname( kernRelease, version, &size, NULL, 0 ) )
        {
            rSequence_addSTRINGA( info, RP_TAGS_VERSION_MAJOR, version );
        }

        rpal_memory_zero( version, sizeof( version ) );
        size = sizeof( version );

        if( 0 == sysctlbyname( kernVersion, version, &size, NULL, 0 ) )
        {
            rSequence_addSTRINGA( info, RP_TAGS_VERSION_MINOR, version );
        }
#else
        rpal_debug_not_implemented();
#endif
    }

    return info;
}


RBOOL
    libOs_getInstalledPackages
    (
        LibOsPackageInfo** pPackages,
        RU32* nPackages
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    HKEY root = HKEY_LOCAL_MACHINE;
    RWCHAR packagesDir[] = _WCH( "software\\microsoft\\windows\\currentversion\\uninstall\\" );
    RWCHAR dName[] = _WCH( "displayname" );
    RWCHAR dVersion[] = _WCH( "displayversion" );
    RWCHAR packId[ 256 ] = {0};
    RWCHAR tmp[ 512 ] = {0};
    HKEY hPackages = NULL;
    HKEY hPackage = NULL;
    RU32 type = 0;
    RU32 size = 0;
#endif

    if( NULL != pPackages &&
        NULL != nPackages )
    {
        *pPackages = NULL;
        *nPackages = 0;
#ifdef RPAL_PLATFORM_WINDOWS
        if( ERROR_SUCCESS == RegOpenKeyW( root, packagesDir, &hPackages ) )
        {
            while( ERROR_SUCCESS == RegEnumKeyW( hPackages, i, packId, sizeof( packId ) / sizeof( RWCHAR ) ) )
            {
                i++;
                isSuccess = TRUE;
                *nPackages = i;

                if( ERROR_SUCCESS == RegOpenKeyW( hPackages, packId, &hPackage ) )
                {
                    *pPackages = rpal_memory_realloc( *pPackages, sizeof( LibOsPackageInfo ) * i );

                    if( NULL != *pPackages )
                    {
                        rpal_memory_zero( &(*pPackages)[ i - 1 ], sizeof( (*pPackages)[ i - 1 ] ) );
                        size = sizeof( tmp ) - sizeof( RWCHAR );

                        if( ERROR_SUCCESS == RegQueryValueExW( hPackage, dName, NULL, (LPDWORD)&type, (RPU8)tmp, (LPDWORD)&size ) )
                        {
                            if( REG_SZ == type ||
                                REG_EXPAND_SZ == type )
                            {
                                size = rpal_string_strlen( tmp ) * sizeof( RWCHAR );
                                rpal_memory_memcpy( &(*pPackages)[ i - 1 ].name, tmp, size >= sizeof( (*pPackages)[ i - 1 ].name ) ? sizeof( (*pPackages)[ i - 1 ].name ) - sizeof( RWCHAR ) : size );
                            }
                        }

                        if( ERROR_SUCCESS == RegQueryValueExW( hPackage, dVersion, NULL, (LPDWORD)&type, (RPU8)tmp, (LPDWORD)&size ) )
                        {
                            if( REG_SZ == type ||
                                REG_EXPAND_SZ == type )
                            {
                                size = rpal_string_strlen( tmp );
                                rpal_memory_memcpy( &(*pPackages)[ i - 1 ].version, tmp, size >= sizeof( (*pPackages)[ i - 1 ].version ) ? sizeof( (*pPackages)[ i - 1 ].version ) - sizeof( RWCHAR ) : size );
                            }
                        }
                    }
                    else
                    {
                        isSuccess = FALSE;
                        break;
                    }

                    RegCloseKey( hPackage );
                }

                rpal_memory_zero( tmp, sizeof( tmp ) );
            }

            RegCloseKey( hPackages );
        }

        if( !isSuccess )
        {
            rpal_memory_free( *pPackages );
            *pPackages = NULL;
            *nPackages = 0;
        }
#else
        rpal_debug_not_implemented();
#endif
    }

    return isSuccess;
}


#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
RBOOL
    libOS_validateCertChain
    (
        rSequence  signature,
        RU32       operation,
        RBOOL*     pIsVerified_local,
        RBOOL*     pIsVerified_global,
        CRYPT_PROVIDER_SGNR* cryptProviderSigner
    )
{
    RBOOL isSucceed = FALSE;
    RU32 tag = RP_TAGS_CERT_CHAIN_ERROR;
    PCCERT_CHAIN_CONTEXT pchainContext = NULL;
    HCERTCHAINENGINE     hchainEngine  = NULL;

    CERT_CHAIN_PARA           chainPara    = {0};
    CERT_CHAIN_ENGINE_CONFIG  engineConfig = {0};
    RU32 chainBuildingFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                              CERT_CHAIN_CACHE_END_CERT;

    if ( loadCrypt32() &&
         NULL != pIsVerified_local   &&
         NULL != pIsVerified_global  &&
         NULL != cryptProviderSigner &&
         NULL != cryptProviderSigner->pasCertChain &&
         NULL != cryptProviderSigner->pasCertChain->pCert )
    {
        *pIsVerified_local = FALSE;
        *pIsVerified_global = FALSE;

        rpal_memory_zero( &engineConfig, sizeof( engineConfig ) );
        engineConfig.cbSize = sizeof( engineConfig );
        engineConfig.dwUrlRetrievalTimeout = 0;

        if( RCertCreateCertificateChainEngine( &engineConfig,
                                               &hchainEngine ) )
        {   
            rpal_memory_zero( &chainPara, sizeof( chainPara ) );
            chainPara.cbSize = sizeof( chainPara );
            chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
            chainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
            chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;

            if (  IS_FLAG_ENABLED( OSLIB_SIGNCHECK_NO_NETWORK, operation ) )
            {
                chainBuildingFlags = chainBuildingFlags | 
                                     CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
                                     CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
            }
            
            // Chain building must be done with the certificate timestamp
            // See this article for info : https://www.eldos.com/security/articles/5731.php?page=all
            if( RCertGetCertificateChain( hchainEngine,
                                          cryptProviderSigner->pasCertChain->pCert,
                                          &cryptProviderSigner->sftVerifyAsOf,
                                          NULL,
                                          &chainPara,
                                          chainBuildingFlags,
                                          NULL,
                                          &pchainContext ) )
            {       
                switch ( pchainContext->TrustStatus.dwErrorStatus )
                {
                    case CERT_TRUST_NO_ERROR :
                        *pIsVerified_local = TRUE;
                        tag = RP_TAGS_CERT_CHAIN_VERIFIED;
                        break;

                    case CERT_TRUST_IS_PARTIAL_CHAIN |
                         CERT_TRUST_IS_UNTRUSTED_ROOT |
                         CERT_TRUST_IS_NOT_SIGNATURE_VALID:
                        tag = RP_TAGS_CERT_CHAIN_UNTRUSTED;
                        break;

                    case CERT_TRUST_IS_NOT_TIME_VALID:
                        tag = RP_TAGS_CERT_TRUST_IS_NOT_TIME_VALID;
                        break;
        
                    case CERT_TRUST_IS_REVOKED:
                        tag = RP_TAGS_CERT_TRUST_IS_REVOKED;
                        break;

                    default:
                        tag = RP_TAGS_CERT_CHAIN_UNTRUSTED;
                }

                // Check for self signed certificats
                if( pchainContext->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED )
                {
                    tag = RP_TAGS_CERT_SELF_SIGNED;
                }
                isSucceed = TRUE;
            }
        }
    }
    rSequence_addRU32( signature, RP_TAGS_CERT_CHAIN_STATUS, tag );

    if ( !IS_FLAG_ENABLED( OSLIB_SIGNCHECK_NO_NETWORK, operation ) )
    {
        *pIsVerified_global = *pIsVerified_local;
    }

    if( NULL != pchainContext ) RCertFreeCertificateChain( pchainContext );
    if( NULL != hchainEngine )  RCertFreeCertificateChainEngine( hchainEngine );
    return isSucceed;
}
#endif


#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
RU32
    libOS_decodeCertName
    (
        RU32 certEncodingType,
        PCERT_NAME_BLOB pName,
        RU32 strType,
        RPCHAR *str
    )
{
    RU32 strSize  = 0;

    if ( ( NULL != pName ) && ( NULL == (*str) ) )
    {
        strSize = RCertNameToStr( certEncodingType,
                                  pName,
                                  strType,
                                  NULL,
                                  0 );

        if( (  0 != strSize ) &&
            ( NULL != ( ( *str ) = rpal_memory_alloc( ( strSize * sizeof( RCHAR ) ) + 1 ) ) ) )
        {
            if( 0 == RCertNameToStr( certEncodingType,
                                     pName,
                                     strType,
                                     *str,
                                     strSize ) )
            {
                rpal_memory_free( *str );
                strSize = 0;
                str = NULL;
            }
            else
            {
                // I don't trust the Windows API and since this may be coming from user data, we play it safe.
                (*str)[ strSize * sizeof( RCHAR ) ] = 0;
            }
        }
    }
    return strSize;
}
#endif


#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
RBOOL
    libOs_retreiveSignatureInfo
    (
        WINTRUST_DATA*  winTrust_data,
        rSequence       signature,
        RU32            operation,
        RBOOL*          pIsVerified_local,
        RBOOL*          pIsVerified_global
    )
{
    RBOOL      isSucceed  = FALSE;
    RPCHAR     issuerStr  = NULL;
    RPCHAR     subjectStr = NULL;
    //FILETIME   fileTime   = { 0 };
    //SYSTEMTIME sysTime    = { 0 };
    CRYPT_PROVIDER_DATA* cryptProviderData   = NULL;
    CRYPT_PROVIDER_SGNR* cryptProviderSigner = NULL;

    if( loadWinTrustApi()  &&
        loadCrypt32()      &&
        NULL != pIsVerified_local &&
        NULL != pIsVerified_global )
    {
        if( NULL != winTrust_data &&
            NULL != winTrust_data->hWVTStateData )
        {

            cryptProviderData = WTHelperProvDataFromStateData( winTrust_data->hWVTStateData );
            cryptProviderSigner = WTHelperGetProvSignerFromChain( cryptProviderData, 0, FALSE, 0 );
            if( NULL != cryptProviderSigner &&
                NULL != cryptProviderSigner->pasCertChain &&
                NULL != cryptProviderSigner->pasCertChain->pCert &&
                NULL != cryptProviderSigner->pasCertChain->pCert->pCertInfo )
            {
                if( 0 != libOS_decodeCertName( X509_ASN_ENCODING,
                                               &cryptProviderSigner->pasCertChain->pCert->pCertInfo->Issuer,
                                               CERT_X500_NAME_STR,
                                               &issuerStr ) )
                {
                    rSequence_addSTRINGA( signature, RP_TAGS_CERT_ISSUER, issuerStr );
                }

                if( 0 != libOS_decodeCertName( X509_ASN_ENCODING,
                                               &cryptProviderSigner->pasCertChain->pCert->pCertInfo->Subject,
                                               CERT_X500_NAME_STR,
                                               &subjectStr ) )
                {
                    rSequence_addSTRINGA( signature, RP_TAGS_CERT_SUBJECT, subjectStr );        
                }

                if( ( IS_FLAG_ENABLED( OSLIB_SIGNCHECK_INCLUDE_RAW_CERT, operation ) ) &&
                    ( 0 != cryptProviderSigner->pasCertChain->pCert->cbCertEncoded )   &&
                    ( NULL != (RPU8)cryptProviderSigner->pasCertChain->pCert->pbCertEncoded ) )
                {
                    rSequence_addBUFFER( signature, RP_TAGS_CERT_BUFFER,
                                         (RPU8)cryptProviderSigner->pasCertChain->pCert->pbCertEncoded,
                                         (RU32)cryptProviderSigner->pasCertChain->pCert->cbCertEncoded );
                }

                if( IS_FLAG_ENABLED(OSLIB_SIGNCHECK_CHAIN_VERIFICATION, operation) )
                {
                    isSucceed = libOS_validateCertChain( signature,
                                                         operation,
                                                         pIsVerified_local,
                                                         pIsVerified_global,
                                                         cryptProviderSigner );
                }
                else
                {
                    rSequence_addRU32( signature, RP_TAGS_CERT_CHAIN_STATUS, RP_TAGS_CERT_CHAIN_NOT_VERIFIED );
                    isSucceed = TRUE;
                    *pIsVerified_local = FALSE;
                    *pIsVerified_global = FALSE;
                }

                rpal_memory_free( issuerStr );
                rpal_memory_free( subjectStr );
            }
        }
    }
    return isSucceed;
}
#endif


#ifdef RPAL_PLATFORM_WINDOWS
RPRIVATE
RBOOL
    libOs_getCATSignature
    (
        RPWCHAR   pwFilePath,
        rSequence signature,
        RU32      operation,
        RBOOL*    pIsSigned,
        RBOOL*    pIsVerified_local,
        RBOOL*    pIsVerified_global
    )
{
    RBOOL    isSucceed = FALSE;
    HCATINFO catalogHandle = NULL;
    CATALOG_INFO catalogInfo = {0};
    HCATADMIN hAdmin = NULL;
    HANDLE fileHandle = NULL;
    RU8*  hash = NULL;
    DWORD hashSize = 0;

    if ( loadWinTrustApi() &&
         NULL != pIsSigned &&
         NULL != pIsVerified_local &&
         NULL != pIsVerified_global )
    {
        fileHandle = CreateFileW( pwFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
        if( fileHandle != INVALID_HANDLE_VALUE )
        {

            CryptCATAdminCalcHashFromFileHandle( fileHandle, &hashSize, NULL, 0 );
            if( 0 < hashSize ) 
            {
                if( NULL != ( hash = rpal_memory_alloc( hashSize * sizeof(RU8) ) ) )
                {
                    if( CryptCATAdminCalcHashFromFileHandle( fileHandle, &hashSize, hash, 0 ) &&
                        CryptCATAdminAcquireContext( &hAdmin, NULL, 0 ) &&
                        NULL != hAdmin )
                    {
                        // Enum catalogs to find the ones that contains the hash
                        catalogHandle = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, hashSize, 0, NULL);
                        if ( NULL != catalogHandle)
                        {
                            rpal_memory_zero( &catalogInfo, sizeof(catalogInfo) );
                            if( CryptCATCatalogInfoFromContext( catalogHandle, &catalogInfo, 0 ) )
                            {
                                isSucceed = libOs_getFileSignature( catalogInfo.wszCatalogFile, signature, operation, pIsSigned, pIsVerified_local, pIsVerified_global );
                            }
                            CryptCATAdminReleaseCatalogContext( hAdmin, catalogHandle, 0 );
                        }
                        else
                        {
                            // No CAT found for this file
                            isSucceed = TRUE;
                            *pIsSigned = FALSE;
                            *pIsVerified_local = FALSE;
                            *pIsVerified_global = FALSE;
                        }
                    }
                    rpal_memory_free( hash );
                    CryptCATAdminReleaseContext( hAdmin, 0 );
                }
            }
            CloseHandle( fileHandle );
        }
    }
    return isSucceed;
}
#endif

RPRIVATE
RBOOL
    libOs_getFileSignature
    (
        RPNCHAR pwfilePath,
        rSequence  signature,
        RU32       operation,
        RBOOL*     pIsSigned,
        RBOOL*     pIsVerified_local,
        RBOOL*     pIsVerified_global
    )
{
    RBOOL isSucceed = FALSE;
#ifdef RPAL_PLATFORM_WINDOWS
    RU32  lStatus = 0;
    DWORD dwLastError = 0;

    if( loadWinTrustApi() && 
        NULL != pIsSigned &&
        NULL != pIsVerified_local &&
        NULL != pIsVerified_global)
    {
        WINTRUST_FILE_INFO fileInfo = {0};
        WINTRUST_DATA winTrustData  = {0};
        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        *pIsSigned = FALSE;

        rpal_memory_zero( &fileInfo, sizeof( fileInfo ) );
        fileInfo.cbStruct = sizeof( fileInfo );
        fileInfo.pcwszFilePath = pwfilePath;
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        rpal_memory_zero( &winTrustData, sizeof( winTrustData ) );
        winTrustData.cbStruct = sizeof( winTrustData );
        winTrustData.pPolicyCallbackData = NULL;
        winTrustData.pSIPClientData = NULL;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = NULL;
        winTrustData.pwszURLReference = NULL;
        winTrustData.dwUIContext = 0;
        winTrustData.pFile = &fileInfo;

        lStatus = WinVerifyTrust( NULL, &WVTPolicyGUID, &winTrustData );

        switch( lStatus ) 
        {
            case 0:
                // If the Windows trust provider verifies that the subject is trusted
                // for the specified action, the return value is zero.
                *pIsSigned = TRUE;
                isSucceed = libOs_retreiveSignatureInfo( &winTrustData, signature, operation, pIsVerified_local, pIsVerified_global );
                break;
        
            case TRUST_E_NOSIGNATURE:
                dwLastError = rpal_error_getLast();

                if ( TRUST_E_NOSIGNATURE == dwLastError ||
                     TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                     TRUST_E_PROVIDER_UNKNOWN == dwLastError ) 
                {
                    isSucceed = libOs_getCATSignature( pwfilePath, signature, operation, pIsSigned, pIsVerified_local, pIsVerified_global );
                } 
                break;

            // Case where the file is signed but the signature is unknown (untrusted) by Windows. Most thirdparty signature will end here.
            case CRYPT_E_SECURITY_SETTINGS:
            case TRUST_E_SUBJECT_NOT_TRUSTED:
            case CERT_E_CHAINING:
                *pIsSigned = TRUE;
                libOs_retreiveSignatureInfo( &winTrustData, signature, operation, pIsVerified_local, pIsVerified_global );
                break;

            case CRYPT_E_FILE_ERROR:
                rpal_debug_warning( "file IO error 0x%x", lStatus );
                break;

            case TRUST_E_SUBJECT_FORM_UNKNOWN:
                break;

            default:
                rpal_debug_warning( "error checking sig 0x%x", lStatus );
                break;
        }

        // Cleanup
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        lStatus = WinVerifyTrust( NULL, &WVTPolicyGUID, &winTrustData );
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    rpal_debug_not_implemented();
#endif
    return isSucceed;
}   


RBOOL
    libOs_getSignature
    (
        RPNCHAR  pwfilePath,
        rSequence* signature,
        RU32       operation,
        RBOOL*     pIsSigned,
        RBOOL*     pIsVerified_local,
        RBOOL*     pIsVerified_global
    )
{
    RBOOL isSucceed = FALSE;
    RPNCHAR tmpPath = NULL;

    if( NULL != signature &&
        NULL != pIsSigned  &&
        NULL != pIsVerified_local  &&
        NULL != pIsVerified_global &&
        NULL != ( *signature = rSequence_new() ) )
    {
        rpal_string_expand( pwfilePath, &tmpPath );
        rSequence_addSTRINGN( *signature, RP_TAGS_FILE_PATH, tmpPath ? tmpPath : pwfilePath );
        isSucceed = libOs_getFileSignature( tmpPath ? tmpPath : pwfilePath, *signature, operation, pIsSigned, pIsVerified_local, pIsVerified_global );

        if( isSucceed )
        {
            rSequence_addRU8( *signature, RP_TAGS_FILE_IS_SIGNED, *pIsSigned ? 1 : 0 );
            rSequence_addRU8( *signature, RP_TAGS_FILE_CERT_IS_VERIFIED_LOCAL, *pIsVerified_local ? 1 : 0 );
            rSequence_addRU8( *signature, RP_TAGS_FILE_CERT_IS_VERIFIED_GLOBAL, *pIsVerified_global ? 1 : 0 );
        }
        else if( NULL != *signature )
        {
            rSequence_free( *signature );
            *signature = NULL;
        }

        rpal_memory_free( tmpPath );
    }
    return isSucceed;
}

RBOOL
    libOs_getProcessInfo
    (
        RU64* pTime,
        RU64* pSizeMemResident,
        RU64* pNumPageFaults
    )
{
    RBOOL isSuccess = FALSE;
#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hSelf = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE,
                                GetCurrentProcessId() );

    FILETIME ftCreation = { 0 };
    FILETIME ftExit = { 0 };
    FILETIME ftKernel = { 0 };
    FILETIME ftUser = { 0 };

    ULARGE_INTEGER uKernel = { 0 };
    ULARGE_INTEGER uUser = { 0 };
    
    static GetProcessMemoryInfo_f gpmi = NULL;
    PROCESS_MEMORY_COUNTERS pmc = { 0 };

    RCHAR k32GetProcessMemoryInfo[] = "K32GetProcessMemoryInfo";
    RCHAR getProcessMemoryInfo[] = "GetProcessMemoryInfo";

    if( NULL != hSelf )
    {
        isSuccess = TRUE;

        if( NULL != pTime )
        {
            if( GetProcessTimes( hSelf, &ftCreation, &ftExit, &ftKernel, &ftUser ) )
            {
                FILETIME2ULARGE( uKernel, ftKernel );
                FILETIME2ULARGE( uUser, ftUser );
                *pTime = uUser.QuadPart + uKernel.QuadPart;
            }
            else
            {
                rpal_debug_error( "Cannot get process times -- error code %u.", GetLastError() );
                isSuccess = FALSE;
            }
        }

        if( NULL != pSizeMemResident || NULL != pNumPageFaults )
        {
            if( NULL == gpmi )
            {
                gpmi = (GetProcessMemoryInfo_f)GetProcAddress( GetModuleHandleW( _WCH( "kernel32.dll" ) ),
                                                               k32GetProcessMemoryInfo );
                if( NULL == gpmi )
                {
                    gpmi = (GetProcessMemoryInfo_f)GetProcAddress( GetModuleHandleW( _WCH( "kernel32.dll" ) ),
                                                                   getProcessMemoryInfo );
                    if( NULL == gpmi )
                    {
                        rpal_debug_error(
                                "Cannot load the address to GetProcessMemoryInfo nor K32GetProcessMemoryInfo -- error code %u.",
                                GetLastError()
                                );
                        isSuccess = FALSE;
                    }
                }
            }

            if( NULL != gpmi && 
                gpmi( hSelf, &pmc, sizeof( pmc ) ) )
            {
                if( NULL != pNumPageFaults )
                {
                    *pNumPageFaults = pmc.PageFaultCount;
                }
                if( NULL != pSizeMemResident )
                {
                    *pSizeMemResident = pmc.WorkingSetSize;
                }
            }
            else
            {
                rpal_debug_error( "Failure while fetching process memory info -- error code %u.", GetLastError() );
                isSuccess = FALSE;
            }
        }

        CloseHandle( hSelf );
    }

#else
    struct rusage usage = { 0 };

    if( 0 == getrusage( RUSAGE_SELF, &usage ) )
    {
        isSuccess = TRUE;
        if( NULL != pTime )
        {
            *pTime = ( (RU64)usage.ru_utime.tv_sec ) * 1000000 + (RU64)usage.ru_utime.tv_usec;
            *pTime += ( (RU64)usage.ru_stime.tv_sec ) * 1000000 + (RU64)usage.ru_stime.tv_usec;
        }
        if( NULL != pNumPageFaults )
        {
            *pNumPageFaults = usage.ru_majflt;  /* Only care about I/O-causing page faults. */
        }
        if( NULL != pSizeMemResident )
        {
#if defined( RPAL_PLATFORM_LINUX )
            *pSizeMemResident = usage.ru_maxrss * 1024;  /* Linux gives this in KB. */
#elif defined( RPAL_PLATFORM_MACOSX )
            *pSizeMemResident = usage.ru_maxrss;         /* OS X gives this in B. */
#else
        rpal_debug_not_implemented();
#endif
        }
    }
    else
    {
        rpal_debug_error( "Cannot get process resource usage information -- error code %u.", errno );
        isSuccess = FALSE;
    }
#endif
    return isSuccess;
}


RBOOL
    libOs_getThreadTime
    (
        rThreadID threadId,
        RU64* pTime
    )
{
    RBOOL isSuccess = TRUE;

    if( NULL != pTime )
    {
#if defined( RPAL_PLATFORM_WINDOWS )
        HANDLE hThread = NULL;
        FILETIME ftCreation = { 0 };
        FILETIME ftExit = { 0 };
        FILETIME ftSystem = { 0 };
        FILETIME ftUser = { 0 };
        ULARGE_INTEGER uSystem = { 0 };
        ULARGE_INTEGER uUser = { 0 };

        if( 0 == threadId )
        {
            hThread = GetCurrentThread();
        }
        else
        {
            hThread = OpenThread( THREAD_QUERY_INFORMATION, FALSE, threadId );
        }
        if( NULL != hThread )
        {
            if( GetThreadTimes( hThread, &ftCreation, &ftExit, &ftSystem, &ftUser ) )
            {
                FILETIME2ULARGE( uSystem, ftSystem );
                FILETIME2ULARGE( uUser, ftUser );
                *pTime = uUser.QuadPart + uSystem.QuadPart;
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_error( "GetThreadTimes failed for thread ID %u, handle %p.", threadId, hThread );
            }
            CloseHandle( hThread );
        }
        else
        {
            rpal_debug_error( "Unable to open a new handle to thread ID %u to get its performance.\n", threadId );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        kern_return_t kr;
        thread_basic_info_data_t info = { 0 };
        mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;

        if( 0 == threadId )
        {
            threadId = rpal_thread_self();
        }

        if( KERN_SUCCESS == ( kr = thread_info( threadId, THREAD_BASIC_INFO, (thread_info_t)&info, &count ) ) )
        {
            *pTime = ( (RU64)info.user_time.seconds + (RU64)info.system_time.seconds ) * 1000000 +
                    (RU64)info.user_time.microseconds + (RU64)info.system_time.microseconds;
            isSuccess = TRUE;
        }
        else
        {
            rpal_debug_error( "Access to thread info failed -- return code %d.", (int)kr );
            isSuccess = FALSE;
        }
#elif defined( RPAL_PLATFORM_LINUX )
    static RU64 user_hz = 0;
    char path_stat[ 1024 ] = { 0 };
    FILE* file_stat = NULL;
    long tmp = 0;
    unsigned long utime = 0;
    unsigned long stime = 0;

    if( 0 == threadId )
    {
        threadId = rpal_thread_self();
    }

    if( 0 == user_hz )
    {
        tmp = sysconf( _SC_CLK_TCK );
        if( tmp < 0 )
        {
            rpal_debug_error( "Cannot find the proc clock tick size -- error code %u.", errno );
            return FALSE;
        }
        user_hz = (RU64)tmp;
    }

    snprintf( path_stat, sizeof( path_stat ), "/proc/%d/task/%d/stat", getpid(), threadId );
    if( NULL != ( file_stat = fopen( path_stat, "r" ) ) )
    {
        if( 2 == fscanf( file_stat,
                         "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", 
                         &utime,
                         &stime ) )
        {
            /* user_hz = clock ticks per second; we want time in microseconds. */
            *pTime = ( ( (RU64)utime + (RU64)stime ) * 1000000 ) / user_hz;
            isSuccess = TRUE;
        }
        else
        {
            rpal_debug_error( "Unable to read file %s properly.", path_stat );
        }

        fclose( file_stat );
    }
#else
    rpal_debug_not_implemented();
#endif
    }

    return isSuccess;
}

RU32
    libOs_getPageSize
    (

    )
{
    RU32 pSize = 0;
#ifdef RPAL_PLATFORM_WINDOWS
    SYSTEM_INFO sysInfo;
    GetSystemInfo (&sysInfo);
    pSize = sysInfo.dwPageSize;
#elif defined( RPAL_PLATFORM_LINUX )
    pSize = sysconf( _SC_PAGESIZE );
#elif defined( RPAL_PLATFORM_MACOSX )
    pSize = getpagesize();
#endif

    return pSize;
}

RU8
    libOs_getCurrentThreadCpuUsage
    (
        LibOsThreadTimeContext* ctx
    )
{
    RU8 percent = (RU8)( -1 );

    RU64 curSystemTime = 0;
    RU64 curThreadTime = 0;
    RU64 deltaSystem = 0;
    RU64 deltaThread = 0;
    RFLOAT pr = 0;
    RTIME curTime = 0;

    curTime = rpal_time_getLocal();
    if( curTime < ctx->lastCheckTime + 1 )
    {
        percent = ctx->lastResult;
    }
    else if( rpal_time_getCPU( &curSystemTime ) &&
             libOs_getThreadTime( 0, &curThreadTime ) )
    {
        if( curSystemTime >= ctx->lastSystemTime &&
            curThreadTime >= ctx->lastThreadTime )
        {
            deltaSystem = curSystemTime - ctx->lastSystemTime;
            deltaThread = curThreadTime - ctx->lastThreadTime;

            if( 0 != deltaSystem &&
                0 != deltaThread )
            {
                deltaSystem = deltaSystem / libOs_getNumCpus();
                pr = ( (RFLOAT)deltaThread / deltaSystem ) * 100;
                percent = (RU8)pr;
                ctx->lastResult = percent;
                ctx->lastCheckTime = curTime;
            }
        }

        ctx->lastSystemTime = curSystemTime;
        ctx->lastThreadTime = curThreadTime;
    }

    return percent;
}

RVOID
    libOs_timeoutWithProfileFrom
    (
        LibOsPerformanceProfile* perfProfile,
        RBOOL isEnforce,
        rEvent isTimeToStop,
        RPCHAR from
    )
{
    RU8 currentPerformance = 0;
    RTIME currentTime = 0;
    RU32 increment = 0;
    
#ifndef RPAL_PLATFORM_DEBUG
    UNREFERENCED_PARAMETER( from );
#endif
    
    if( NULL != perfProfile )
    {
        rpal_time_getCPU( &currentTime );
        currentTime = SEC_FROM_MSEC( currentTime / NSEC_100_PER_MSEC );

        if( 0 == perfProfile->lastUpdate ) perfProfile->lastUpdate = currentTime;
        if( 0 == perfProfile->lastSummary ) perfProfile->lastSummary = currentTime;

        if( !isEnforce &&
            currentTime >= perfProfile->lastUpdate + 1 )
        {
            // We look for time aberrations where the clock has changed by a large amount
            // which may be due to some form of hibernation or rollover. We try to use a 
            // realtime clock but for some reason sometimes it fails.
            if( currentTime < perfProfile->lastUpdate )
            {
                // Let's not try to calculate the actual value, cut our losses and assume
                // things haven't changed much.
                perfProfile->lastUpdate = currentTime;
                return;
            }

            increment = (RU32)( perfProfile->timeoutIncrementPerSec * ( currentTime - perfProfile->lastUpdate ) );
            perfProfile->lastUpdate = currentTime;
            currentPerformance = libOs_getCurrentThreadCpuUsage( &perfProfile->threadTimeContext );

            if( 0xFF == currentPerformance )
            {
                // Error getting times, keep going.
            }
            else if( currentPerformance > perfProfile->targetCpuPerformance )
            {
                if( perfProfile->sanityCeiling > perfProfile->lastTimeoutValue + increment )
                {
                    perfProfile->lastTimeoutValue += increment;
                    //rpal_debug_info( "INCREMENT: %d (%d)", perfProfile->lastTimeoutValue, currentPerformance );
                }
            }
            else if( currentPerformance <= perfProfile->targetCpuPerformance &&
                     perfProfile->lastTimeoutValue > 0 )
            {
                perfProfile->lastTimeoutValue -= MIN_OF( increment,
                                                         perfProfile->lastTimeoutValue );
                //rpal_debug_info( "DECREMENT: %d (%d)", perfProfile->lastTimeoutValue, currentPerformance );
            }

            if( 0xFF != currentPerformance && 20 < currentPerformance )
            {
                rpal_debug_warning( "Thread running hot: %s / %d%% (%d)", 
                                    from, 
                                    currentPerformance, 
                                    perfProfile->lastTimeoutValue );
            }

            currentPerformance = libOs_getCurrentProcessCpuUsage();
            if( 0xFF == currentPerformance )
            {
                // Error getting times, keep going.
            }
            else if( currentPerformance > perfProfile->globalTargetCpuPerformance )
            {
                if( perfProfile->sanityCeiling > perfProfile->globalTimeoutValue )
                {
                    perfProfile->globalTimeoutValue += increment;
                    //rpal_debug_info( "GLOBAL INCREMENT: %d (%d)", perfProfile->globalTimeoutValue, currentPerformance );
                }
            }
            else if( perfProfile->globalTimeoutValue > 0 )
            {
                perfProfile->globalTimeoutValue -= MIN_OF( increment,
                                                           perfProfile->globalTimeoutValue );
                //rpal_debug_info( "GLOBAL DECREMENT: %d (%d)", perfProfile->globalTimeoutValue, currentPerformance );
            }

            if( ( 60 * 1 ) <= currentTime - perfProfile->lastSummary )
            {
                rpal_debug_info( "Profile: %s = last(%d) global(%d)",
                                 from,
                                 perfProfile->lastTimeoutValue,
                                 perfProfile->globalTimeoutValue );

                perfProfile->lastSummary = currentTime;
            }
        }
        else
        {
            if( perfProfile->counter == perfProfile->enforceOnceIn )
            {
                perfProfile->counter = 0;

                rEvent_wait( isTimeToStop, perfProfile->lastTimeoutValue + perfProfile->globalTimeoutValue );
            }

            perfProfile->counter++;
        }
    }
}

RBOOL
    libOs_getProcessTime
    (
        RU32 processId,
        RU64* pTime
    )
{
    RBOOL isSuccess = TRUE;

    if( NULL != pTime )
    {
#if defined( RPAL_PLATFORM_WINDOWS )
        HANDLE hProcess = NULL;
        FILETIME ftCreation = { 0 };
        FILETIME ftExit = { 0 };
        FILETIME ftSystem = { 0 };
        FILETIME ftUser = { 0 };
        ULARGE_INTEGER uSystem = { 0 };
        ULARGE_INTEGER uUser = { 0 };

        if( 0 == processId )
        {
            hProcess = GetCurrentProcess();
        }
        else
        {
            hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, processId );
        }
        if( NULL != hProcess )
        {
            if( GetProcessTimes( hProcess, &ftCreation, &ftExit, &ftSystem, &ftUser ) )
            {
                FILETIME2ULARGE( uSystem, ftSystem );
                FILETIME2ULARGE( uUser, ftUser );
                *pTime = uUser.QuadPart + uSystem.QuadPart;
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_error( "GetTProcessTimes failed for thread ID %u, handle %p.", 
                                  processId, 
                                  hProcess );
            }
            CloseHandle( hProcess );
        }
        else
        {
            rpal_debug_error( "Unable to open a new handle to process ID %u to get its performance.\n", 
                              processId );
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        kern_return_t kr;
        struct task_basic_info info = { 0 };
        mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;

        if( 0 == processId )
        {
            processId = getpid();
        }

        if( KERN_SUCCESS == ( kr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &count) ) )
        {
            *pTime = ( (RU64)info.user_time.seconds + (RU64)info.system_time.seconds ) * 1000000 +
                       (RU64)info.user_time.microseconds + (RU64)info.system_time.microseconds;
            isSuccess = TRUE;
        }
        else
        {
            rpal_debug_error( "Access to process info failed -- return code %d.", (int)kr );
            isSuccess = FALSE;
        }
#elif defined( RPAL_PLATFORM_LINUX )
        static RU64 user_hz = 0;
        char path_stat[ 1024 ] = { 0 };
        FILE* file_stat = NULL;
        long tmp = 0;
        unsigned long utime = 0;
        unsigned long stime = 0;

        if( 0 == processId )
        {
            processId = getpid();
        }

        if( 0 == user_hz )
        {
            tmp = sysconf( _SC_CLK_TCK );
            if( tmp < 0 )
            {
                rpal_debug_error( "Cannot find the proc clock tick size -- error code %u.", errno );
                return FALSE;
            }
            user_hz = (RU64)tmp;
        }

        snprintf( path_stat, sizeof( path_stat ), "/proc/%d/stat", processId );
        if( NULL != ( file_stat = fopen( path_stat, "r" ) ) )
        {
            if( 2 == fscanf( file_stat,
                "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                &utime,
                &stime ) )
            {
                /* user_hz = clock ticks per second; we want time in microseconds. */
                *pTime = ( ( (RU64)utime + (RU64)stime ) * 1000000 ) / user_hz;
                isSuccess = TRUE;
            }
            else
            {
                rpal_debug_error( "Unable to read file %s properly.", path_stat );
            }

            fclose( file_stat );
        }
#else
        rpal_debug_not_implemented();
#endif
    }

    return isSuccess;
}

RU8
    libOs_getCurrentProcessCpuUsage
    (

    )
{
    RU8 percent = (RU8)( -1 );

    RU64 curSystemTime = 0;
    RU64 curProcessTime = 0;
    RU64 deltaSystem = 0;
    RU64 deltaProcess = 0;
    static RU64 lastSystemTime;
    static RU64 lastProcessTime;
    static volatile RTIME lastCheckTime = 0;
    static volatile RU8 lastResult = 0;
    RTIME tmpTime = 0;
    RFLOAT pr = 0;
    RTIME curTime = 0;

    if( 0 == lastCheckTime )
    {
        lastCheckTime = rpal_time_getLocal();
    }

    curTime = rpal_time_getLocal();

    // We check and set the value in an atomic way to avoid race conditions.
#ifdef RPAL_PLATFORM_64_BIT
    tmpTime = rInterlocked_set64( &lastCheckTime, curTime );
#else
    // We do not have true atomic exchange for 64 bit ints on 32 bit so we'll do best effort.
    tmpTime = lastCheckTime;
    lastCheckTime = curTime;
#endif

    if( curTime < tmpTime + 3 )
    {
        // Replace the previous last check time to avoid constantly
        // chasing an incrementing value.
        lastCheckTime = tmpTime;

        // Use the cached result.
        percent = lastResult;
    }
    else if( rpal_time_getCPU( &curSystemTime ) &&
             libOs_getProcessTime( 0, &curProcessTime ) )
    {
        if( curSystemTime >= lastSystemTime &&
            curProcessTime >= lastProcessTime )
        {
            deltaSystem = curSystemTime - lastSystemTime;
            deltaProcess = curProcessTime - lastProcessTime;

            if( 0 != deltaSystem )
            {
                deltaSystem = deltaSystem / libOs_getNumCpus();
                pr = ( (RFLOAT)deltaProcess / deltaSystem ) * 100;
                percent = (RU8)pr;
                lastResult = percent;
            }
        }

        lastSystemTime = curSystemTime;
        lastProcessTime = curProcessTime;
    }

    return percent;
}

#ifdef RPAL_PLATFORM_WINDOWS

RPRIVATE
RBOOL
    _getAssociatedExecutable
    (
        RPWCHAR serviceName,
        RPWCHAR* executable,
        RPWCHAR* dll
    )
{
    RBOOL isSuccess = FALSE;

    HKEY root = HKEY_LOCAL_MACHINE;
    HKEY curService = 0;
    RWCHAR services[] = _WCH( "system\\currentcontrolset\\services\\" );
    RWCHAR forDll[] = _WCH( "\\Parameters\\" );
    RWCHAR fullService[ 512 ] = { 0 };
    RWCHAR imagePath[] = _WCH( "ImagePath" );
    RWCHAR serviceDll[] = _WCH( "ServiceDll" );
    RU32 type = 0;
    RWCHAR tmp[ 512 ] = { 0 };
    RU32 size = 0;

    if( NULL != serviceName &&
        NULL != executable &&
        NULL != dll )
    {
        *executable = NULL;
        *dll = NULL;

        if( ( ( ARRAY_N_ELEM( services ) + rpal_string_strlen( serviceName ) + 1 ) < ARRAY_N_ELEM( fullService ) - 1 ) &&
            rpal_string_strcat( fullService, services ) &&
            rpal_string_strcat( fullService, serviceName ) )
        {
            if( ERROR_SUCCESS == RegOpenKeyW( root, fullService, &curService ) )
            {
                size = sizeof( tmp ) - sizeof( RWCHAR );
                if( ERROR_SUCCESS == RegQueryValueExW( curService, imagePath, NULL, (LPDWORD)&type, (RPU8)&tmp, (LPDWORD)&size ) &&
                    REG_EXPAND_SZ == type ||
                    REG_SZ == type )
                {
                    *(RPWCHAR)( (RPU8)&tmp + size ) = 0;
                    *executable = rpal_string_strdup( tmp );
                    isSuccess = TRUE;
                }

                RegCloseKey( curService );
            }
        }

        rpal_memory_zero( fullService, sizeof( fullService ) );
        rpal_memory_zero( tmp, sizeof( tmp ) );

        if( ( ( ARRAY_N_ELEM( services ) + rpal_string_strlen( serviceName ) + ARRAY_N_ELEM( forDll ) + 1 ) < ARRAY_N_ELEM( fullService ) - 1 ) &&
            rpal_string_strcat( fullService, services ) &&
            rpal_string_strcat( fullService, serviceName ) &&
            rpal_string_strcat( fullService, forDll ) )
        {
            if( ERROR_SUCCESS == RegOpenKeyW( root, fullService, &curService ) )
            {
                size = sizeof( tmp ) - sizeof( RWCHAR );
                if( ERROR_SUCCESS == RegQueryValueExW( curService, serviceDll, NULL, (LPDWORD)&type, (RPU8)&tmp, (LPDWORD)&size ) &&
                    REG_EXPAND_SZ == type ||
                    REG_SZ == type )
                {
                    *(RPWCHAR)( (RPU8)&tmp + size ) = 0;
                    *dll = rpal_string_strdup( tmp );
                    isSuccess = TRUE;
                }

                RegCloseKey( curService );
            }
        }

        rpal_memory_zero( fullService, sizeof( fullService ) );
        rpal_memory_zero( tmp, sizeof( tmp ) );
    }

    return isSuccess;
}

RPRIVATE
rList
    _getWindowsService
    (
        RU32 type
    )
{
    rList svcs = NULL;

    SC_HANDLE hSvc;
    RU32 dwServiceType = type;
    RU32 dwBytesNeeded = 0;
    RU32 dwServicesReturned = 0;
    RU32 dwResumedHandle = 0;
    RU32 dwSvcStructSize = 0;
    ENUM_SERVICE_STATUS_PROCESSW* pServices = NULL;
    RU32 i;
    rSequence svc = NULL;
    RPWCHAR assExe = NULL;
    RPWCHAR assDll = NULL;
    RPWCHAR cleanPath = NULL;

    if( NULL != ( svcs = rList_new( RP_TAGS_SVC, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( hSvc = OpenSCManager( NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE ) ) )
        {
            if( !EnumServicesStatusExW( hSvc,
                                        SC_ENUM_PROCESS_INFO,
                                        dwServiceType,
                                        SERVICE_STATE_ALL,
                                        NULL, 0,
                                        (LPDWORD)&dwBytesNeeded,
                                        (LPDWORD)&dwServicesReturned,
                                        (LPDWORD)&dwResumedHandle,
                                        NULL ) &&
                GetLastError() == ERROR_MORE_DATA )
            {
                // now allocate memory for the structure...
                dwSvcStructSize = sizeof( ENUM_SERVICE_STATUS ) + dwBytesNeeded;
                if( NULL != ( pServices = (ENUM_SERVICE_STATUS_PROCESSW *)rpal_memory_alloc( dwSvcStructSize ) ) )
                {
                    if( EnumServicesStatusExW( hSvc,
                                               SC_ENUM_PROCESS_INFO,
                                               dwServiceType,
                                               SERVICE_STATE_ALL,
                                               (RPU8)pServices,
                                               dwSvcStructSize,
                                               (LPDWORD)&dwBytesNeeded,
                                               (LPDWORD)&dwServicesReturned,
                                               (LPDWORD)&dwResumedHandle,
                                               NULL ) )
                    {
                        for( i = 0; i < dwServicesReturned; i++ )
                        {
                            // create a sequence to contain Service information
                            if( NULL != ( svc = rSequence_new() ) )
                            {
                                rSequence_addSTRINGW( svc, RP_TAGS_SVC_NAME, pServices[ i ].lpServiceName );
                                rSequence_addSTRINGW( svc, RP_TAGS_SVC_DISPLAY_NAME, pServices[ i ].lpDisplayName );
                                rSequence_addRU32( svc, RP_TAGS_SVC_TYPE, pServices[ i ].ServiceStatusProcess.dwServiceType );
                                rSequence_addRU32( svc, RP_TAGS_SVC_STATE, pServices[ i ].ServiceStatusProcess.dwCurrentState );
                                rSequence_addRU32( svc, RP_TAGS_PROCESS_ID, pServices[ i ].ServiceStatusProcess.dwProcessId );

                                if( _getAssociatedExecutable( pServices[ i ].lpServiceName, &assExe, &assDll ) )
                                {
                                    if( NULL != assExe )
                                    {
                                        cleanPath = rpal_file_clean( assExe );

                                        // TODO: Fix in a more permanent way the issues in glibc with undocumented'
                                        // incompatibility with mis-aligned pointers in things like strlen and wcstombs.
                                        //rpal_debug_info( "found associated service exe: %ls", assExe );
                                        rSequence_addSTRINGW( svc, RP_TAGS_EXECUTABLE, cleanPath ? cleanPath : assExe );
                                        rpal_memory_free( assExe );
                                        rpal_memory_free( cleanPath );
                                    }

                                    if( NULL != assDll )
                                    {
                                        cleanPath = rpal_file_clean( assDll );

                                        // TODO: Fix in a more permanent way the issues in glibc with undocumented'
                                        // incompatibility with mis-aligned pointers in things like strlen and wcstombs.
                                        //rpal_debug_info( "found associated service dll: %ls", assDll );
                                        rSequence_addSTRINGW( svc, RP_TAGS_DLL, cleanPath ? cleanPath : assDll );
                                        rpal_memory_free( assDll );
                                        rpal_memory_free( cleanPath );
                                    }
                                }

                                if( !rList_addSEQUENCE( svcs, svc ) )
                                {
                                    rSequence_free( svc );
                                }
                            }
                        }
                    }

                    rpal_memory_free( pServices );
                }
            }

            CloseServiceHandle( hSvc );
        }
    }

    return svcs;
}
#endif


RPRIVATE
RBOOL
    _thorough_file_hash
    (
        RPNCHAR filePath,
        RPNCHAR* pEffectivePath,
        CryptoLib_Hash* pHash
    )
{
    RBOOL isHashed = FALSE;

    RPWCHAR dupPath = NULL;
    RPWCHAR cleanPath = NULL;
    RU32 i = 0;
    rString tmpString = NULL;
    RPWCHAR tmpPath = NULL;
    RU32 tmpLen = 0;
    RPWCHAR pPattern = NULL;
    RWCHAR sysDir[] = _WCH( "%WINDIR%\\system32\\" );
    RWCHAR winDir[] = _WCH( "%WINDIR%\\" );
    RWCHAR extPattern[] = _WCH( ".exe " );
    RU32 originalLength = 0;
    RWCHAR defaultExt[] = _WCH( ".dll" );
    RWCHAR defaultExt2[] = _WCH( "exe" );

    if( NULL != filePath &&
        NULL != pHash )
    {
        if( CryptoLib_hashFile( filePath, pHash, TRUE ) )
        {
            isHashed = TRUE;
        }

#ifdef RPAL_PLATFORM_WINDOWS
        do
        {
            if( NULL == ( dupPath = rpal_string_strdup( filePath ) ) )
            {
                break;
            }

            cleanPath = dupPath;

            // Step 1: Is this a quoted path?
            if( _WCH( '"' ) == cleanPath[ 0 ] )
            {
                // Skip the first quote.
                cleanPath++;

                // Find the closing quote and terminate the string there.
                while( 0 != cleanPath[ i ] &&
                       _WCH( '"' ) != cleanPath[ i ] )
                {
                    i++;
                }
                cleanPath[ i ] = 0;

                if( CryptoLib_hashFile( cleanPath, pHash, TRUE ) )
                {
                    isHashed = TRUE;
                    if( NULL != pEffectivePath )
                    {
                        *pEffectivePath = rpal_string_strdup( cleanPath );
                    }
                    break;
                }
            }

            // Next check for an executable with args lile ...some.exe /somearg
            if( NULL != ( pPattern = rpal_string_stristr( cleanPath, extPattern ) ) )
            {
                pPattern += ARRAY_N_ELEM( extPattern ) - 2;
                *pPattern = 0;

                if( CryptoLib_hashFile( cleanPath, pHash, TRUE ) )
                {
                    isHashed = TRUE;
                    if( NULL != pEffectivePath )
                    {
                        *pEffectivePath = rpal_string_strdup( cleanPath );
                    }
                    break;
                }
            }

            // If this is not an absolute path, try the default system paths
            if( !rpal_string_stristr( cleanPath, _WCH( "\\" ) ) )
            {
                if( NULL != ( tmpString = rpal_stringbuffer_new( 0, 0 ) ) )
                {
                    if( rpal_stringbuffer_add( tmpString, sysDir ) &&
                        rpal_stringbuffer_add( tmpString, cleanPath ) )
                    {
                        if( CryptoLib_hashFile( rpal_stringbuffer_getString( tmpString ), pHash, TRUE ) )
                        {
                            isHashed = TRUE;
                        }
                        else
                        {
                            originalLength = rpal_string_strlen( cleanPath );

                            // If there is no file extension, try the default ones
                            if( 4 > originalLength ||
                                _WCH( '.' ) != cleanPath[ originalLength - 4 ] )
                            {
                                if( rpal_stringbuffer_add( tmpString, defaultExt ) )
                                {
                                    if( CryptoLib_hashFile( rpal_stringbuffer_getString( tmpString ), pHash, TRUE ) )
                                    {
                                        isHashed = TRUE;
                                    }
                                    else
                                    {
                                        if( NULL != ( tmpPath = rpal_stringbuffer_getString( tmpString ) ) )
                                        {
                                            tmpLen = rpal_string_strlen( tmpPath );
                                            rpal_memory_memcpy( &( tmpPath[ tmpLen - 3 ] ), 
                                                                defaultExt2, 
                                                                sizeof( defaultExt2 ) - sizeof( RWCHAR ) );
                                            if( CryptoLib_hashFile( rpal_stringbuffer_getString( tmpString ), pHash, TRUE ) )
                                            {
                                                isHashed = TRUE;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if( isHashed &&
                        NULL != pEffectivePath )
                    {
                        *pEffectivePath = rpal_string_strdup( rpal_stringbuffer_getString( tmpString ) );
                    }

                    rpal_stringbuffer_free( tmpString );
                }

                if( NULL != ( tmpString = rpal_stringbuffer_new( 0, 0 ) ) )
                {
                    if( !isHashed &&
                        rpal_stringbuffer_add( tmpString, winDir ) &&
                        rpal_stringbuffer_add( tmpString, cleanPath ) )
                    {
                        if( CryptoLib_hashFile( rpal_stringbuffer_getString( tmpString ), pHash, TRUE ) )
                        {
                            isHashed = TRUE;
                        }
                        else
                        {
                            // If there is no file extension, try the default ones
                            if( 4 > originalLength ||
                                _WCH( '.' ) != cleanPath[ originalLength - 4 ] )
                            {
                                if( rpal_stringbuffer_add( tmpString, defaultExt ) )
                                {
                                    if( CryptoLib_hashFile( rpal_stringbuffer_getString( tmpString ), pHash, TRUE ) )
                                    {
                                        isHashed = TRUE;
                                    }
                                }
                            }
                        }
                    }

                    if( isHashed &&
                        NULL != pEffectivePath )
                    {
                        *pEffectivePath = rpal_string_strdup( rpal_stringbuffer_getString( tmpString ) );
                    }
                }

                rpal_stringbuffer_free( tmpString );
            }

        } while( FALSE );

        rpal_memory_free( dupPath );
#endif
    }

    return isHashed;
}


RPRIVATE
RVOID
    _enhanceServicesWithHashes
    (
        rList svcList
    )
{
    rSequence svcEntry = NULL;
    RPNCHAR entryDll = NULL;
    RPNCHAR entryExe = NULL;
    CryptoLib_Hash hash = { 0 };
    RPNCHAR effective = NULL;

    while( rList_getSEQUENCE( svcList, RP_TAGS_SVC, &svcEntry ) )
    {
        entryExe = NULL;
        entryDll = NULL;
        effective = NULL;

        rSequence_getSTRINGN( svcEntry, RP_TAGS_EXECUTABLE, &entryExe );

        rSequence_getSTRINGN( svcEntry, RP_TAGS_DLL, &entryDll );

        rSequence_unTaintRead( svcEntry );

        if( NULL == entryDll )
        {
            if( NULL != entryExe && _thorough_file_hash( entryExe, &effective, &hash ) )
            {
                rSequence_addBUFFER( svcEntry, RP_TAGS_HASH, (RPU8)&hash, sizeof( hash ) );
                rSequence_addSTRINGN( svcEntry, RP_TAGS_FILE_PATH, effective );
            }
        }
        else
        {
            if( NULL != entryDll && _thorough_file_hash( entryDll, &effective, &hash ) )
            {
                rSequence_addBUFFER( svcEntry, RP_TAGS_HASH, (RPU8)&hash, sizeof( hash ) );
                rSequence_addSTRINGN( svcEntry, RP_TAGS_FILE_PATH, effective );
            }
        }

        rpal_memory_free( effective );
    }
}


#ifdef RPAL_PLATFORM_MACOSX
RPRIVATE
RVOID
    iterateJobAttributes
    (
        const launch_data_t data,
        const char* str,
        void* ptr
    )
{
    rSequence svc = (rSequence)ptr;
    RPCHAR attrName = (RPCHAR)str;

    if( NULL != data &&
        NULL != attrName &&
        NULL != svc )
    {
        switch( launch_data_get_type( data ) )
        {
            // For a complet list of attributes :
            // https://developer.apple.com/library/mac/documentation/Darwin/Reference/Manpages/man5/launchd.plist.5.html
            case LAUNCH_DATA_STRING:
                if( 0 == rpal_string_strcmp( attrName, "Program" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_EXECUTABLE, (const RPCHAR)launch_data_get_string( data ) );
                }
                else if( 0 == rpal_string_strcmp( attrName, "Label" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_SVC_NAME, (const RPCHAR)launch_data_get_string( data ) );
                }
                else if( 0 == rpal_string_strcmp( attrName, "ProcessType" ) )
                {
                    rSequence_addSTRINGA( svc, RP_TAGS_SVC_TYPE, (const RPCHAR)launch_data_get_string( data ) );
                }
                break;

            case LAUNCH_DATA_ARRAY:
                if( 0 == rpal_string_strcmp( attrName, "ProgramArguments" ) )
                {
                    // Get first argument ( executable path )
                    launch_data_t iterator = launch_data_array_get_index( data, 0 );

                    if( launch_data_get_type( iterator ) == LAUNCH_DATA_STRING )
                    {
                        rSequence_addSTRINGA( svc, RP_TAGS_EXECUTABLE, (const RPCHAR)launch_data_get_string( data ) );
                    }
                }
                break;

            case LAUNCH_DATA_INTEGER:
                if( 0 == rpal_string_strcmp( attrName, "PID" ) )
                {
                    rSequence_addRU64( svc, RP_TAGS_EXECUTABLE, (RU64)launch_data_get_string( data ) );
                }
                break;

            case LAUNCH_DATA_BOOL:
            case LAUNCH_DATA_DICTIONARY:
            case LAUNCH_DATA_FD:
            case LAUNCH_DATA_MACHPORT:
            default:
                // Unused
                break;
        }
    }
}

RPRIVATE
RVOID
    iterateJobs
    (
        const launch_data_t data,
        const char* name,
        void* ptr
    )
{
    rList svcs = (rList)ptr;
    rSequence svc = NULL;

    if( NULL != data &&
        NULL != name )
    {
        if( launch_data_get_type( data ) == LAUNCH_DATA_DICTIONARY &&
            NULL != ( svc = rSequence_new() ) )
        {
            launch_data_dict_iterate( data, iterateJobAttributes, svc );
            if( !rList_addSEQUENCE( svcs, svc ) )
            {
                rSequence_free( svc );
            }
        }
    }
}
#endif

rList
    libOs_getServices
    (
        RBOOL isWithHashes
    )
{
    rList services = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    services = _getWindowsService( SERVICE_WIN32 );
#elif defined( RPAL_PLATFORM_LINUX )
    const RPCHAR rootDir = "/etc/init.d/";
    RU32 nMaxDepth = 1;
    RPCHAR fileExp[] = { "*", NULL };
    rDirCrawl hCrawl = NULL;
    rFileInfo fileInfo = { 0 };
    rSequence svc = NULL;

    if( NULL != ( services = rList_new( RP_TAGS_SVC, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( hCrawl = rpal_file_crawlStart( rootDir, (RPNCHAR*)&fileExp, 0 ) ) )
        {
            while( rpal_file_crawlNextFile( hCrawl, &fileInfo ) )
            {
                if( !IS_FLAG_ENABLED( RPAL_FILE_ATTRIBUTE_DIRECTORY, fileInfo.attributes ) &&
                    IS_FLAG_ENABLED( RPAL_FILE_ATTRIBUTE_EXECUTE, fileInfo.attributes ) )
                {
                    if( NULL != ( svc = rSequence_new() ) )
                    {
                        rSequence_addSTRINGN( svc, RP_TAGS_SVC_NAME, fileInfo.fileName );
                        if( !rList_addSEQUENCE( services, svc ) )
                        {
                            rSequence_free( svc );
                        }
                    }
                }
            }
            rpal_file_crawlStop( hCrawl );
        }
    }
#elif defined( RPAL_PLATFORM_MACOSX )
    launch_data_t resp = NULL;
    launch_data_t msg = NULL;

    msg = launch_data_new_string( LAUNCH_KEY_GETJOBS );
    if( NULL != ( resp = launch_msg( msg ) ) )
    {
        if( launch_data_get_type( resp ) == LAUNCH_DATA_DICTIONARY )
        {
            if( NULL != ( services = rList_new( RP_TAGS_SVC, RPCM_SEQUENCE ) ) )
            {
                launch_data_dict_iterate( resp, iterateJobs, services );
            }
        }
        launch_data_free( resp );
    }
    launch_data_free( msg );
#else
    rpal_debug_not_implemented();
#endif

    if( isWithHashes )
    {
        _enhanceServicesWithHashes( services );
    }

    return services;
}

rList
    libOs_getDrivers
    (
        RBOOL isWithHashes
    )
{
    rList drivers = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    drivers = _getWindowsService( SERVICE_DRIVER );
#else
    rpal_debug_not_implemented();
    drivers = rList_new( RP_TAGS_SVC, RPCM_SEQUENCE );
#endif

    if( isWithHashes )
    {
        _enhanceServicesWithHashes( drivers );
    }

    return drivers;
}

RPRIVATE
RVOID
    _enhanceAutorunsWithHashes
    (
        rList autoList
    )
{
    rSequence autoEntry = NULL;
    RPNCHAR entryExe = NULL;
    CryptoLib_Hash hash = { 0 };

    while( rList_getSEQUENCE( autoList, RP_TAGS_AUTORUN, &autoEntry ) )
    {
        if( rSequence_getSTRINGN( autoEntry, RP_TAGS_FILE_PATH, &entryExe ) )
        {
            rSequence_unTaintRead( autoEntry );

            if( NULL != entryExe && _thorough_file_hash( entryExe, NULL, &hash ) )
            {
                rSequence_addBUFFER( autoEntry, RP_TAGS_HASH, (RPU8)&hash, sizeof( hash ) );
            }
        }
    }
}

#ifdef RPAL_PLATFORM_WINDOWS

RPRIVATE_TESTABLE
RBOOL
    _processRegValue
    (
        DWORD type,
        RPWCHAR path,
        RPWCHAR keyName,
        RPU8 value,
        DWORD size,
        rList listEntries
    )
{
    rSequence entry = NULL;
    RPWCHAR state = NULL;
    RPWCHAR tmp = NULL;
    RU8 keyValue[ 1024 * sizeof( RWCHAR ) ] = { 0 };
    RU32 pathLen = 0;
    RBOOL isSuccess = FALSE;

    if( NULL == value ||
        NULL == path ||
        NULL == keyName )
    {
        return FALSE;
    }

    // We accept size - sizeof( RWCHAR ) in calling function so this is always safe.
    if( 0 == size % sizeof( RWCHAR ) )
    {
        *(RPWCHAR)( value + size ) = 0;
    }
    else
    {
        // We're expecting all this to be wide char, but if the size (in bytes) doesn't align
        // with this, make sure we null terminate as widechar for safety.
        *(RPWCHAR)( value + size + 1 ) = 0;
    }

    if( ( REG_SZ == type ||
          REG_EXPAND_SZ == type ) &&
        0 != size )
    {
        // Short circuit empty string.
        if( sizeof( RWCHAR ) >= size &&
            0 == *(RPWCHAR)value )
        {
            return TRUE;
        }

        // We remove any NULL characters in the string as it's a technique used by some malware.
        if( sizeof( RWCHAR ) <= size )
        {
            rpal_string_fill( (RPWCHAR)value, size / sizeof( RWCHAR ) - 1, _WCH( ' ' ) );
        }

        tmp = rpal_string_strtok( (RPWCHAR)value, _WCH( ',' ), &state );

        while( NULL != tmp &&
               0 != tmp[ 0 ] )
        {
            if( NULL != ( entry = rSequence_new() ) )
            {
                isSuccess = TRUE;
                if( rSequence_addSTRINGW( entry, RP_TAGS_FILE_PATH, (RPWCHAR)value ) )
                {
                    keyValue[ 0 ] = 0;

                    pathLen = rpal_string_strlen( path );

                    if( sizeof( keyValue ) > ( pathLen + rpal_string_strlen( keyName ) + 
                                               rpal_string_strlen( _WCH( "\\" ) ) ) * sizeof( RWCHAR ) )
                    {
                        rpal_string_strcpy( (RPWCHAR)&keyValue, path );
                        if( _WCH( '\\' ) != path[ pathLen - 1 ] )
                        {
                            rpal_string_strcat( (RPWCHAR)&keyValue, _WCH( "\\" ) );
                        }
                        rpal_string_strcat( (RPWCHAR)&keyValue, keyName );
                        rSequence_addSTRINGW( entry, RP_TAGS_REGISTRY_KEY, (RPWCHAR)&keyValue );
                    }
                    else
                    {
                        rSequence_addSTRINGW( entry, RP_TAGS_REGISTRY_KEY, _WCH( "_" ) );
                    }

                    if( !rList_addSEQUENCE( listEntries, entry ) )
                    {
                        rSequence_free( entry );
                        entry = NULL;
                    }
                }
                else
                {
                    rSequence_free( entry );
                    entry = NULL;
                }
            }

            tmp = rpal_string_strtok( NULL, _WCH( ',' ), &state );
            while( NULL != tmp && _WCH( ' ' ) == tmp[ 0 ] )
            {
                tmp++;
            }
        }
    }
    else if( REG_MULTI_SZ == type )
    {
        // Short circuit empty string.
        if( sizeof( RWCHAR ) >= size &&
            0 == *(RPWCHAR)value )
        {
            return TRUE;
        }

        tmp = (RPWCHAR)value;
        while( IS_WITHIN_BOUNDS( tmp, rpal_string_strsize( tmp ), value, size ) )
        {
            if( 0 != rpal_string_strlen( tmp ) )
            {
                if( NULL != ( entry = rSequence_new() ) )
                {
                    isSuccess = TRUE;
                    if( rSequence_addSTRINGW( entry, RP_TAGS_FILE_PATH, tmp ) )
                    {
                        keyValue[ 0 ] = 0;
                        rpal_string_strcpy( (RPWCHAR)&keyValue, path );
                        rpal_string_strcat( (RPWCHAR)&keyValue, keyName );
                        rSequence_addSTRINGW( entry, RP_TAGS_REGISTRY_KEY, (RPWCHAR)&keyValue );

                        if( !rList_addSEQUENCE( listEntries, entry ) )
                        {
                            rSequence_free( entry );
                            entry = NULL;
                        }
                    }
                    else
                    {
                        rSequence_free( entry );
                        entry = NULL;
                    }
                }
            }

            tmp += rpal_string_strlen( tmp ) + 1;
        }
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _processRegKey
    (
        HKEY keyRoot,
        RPWCHAR keyPath,
        RPWCHAR valueExpr,
        rList autoruns
    )
{
    RBOOL isSuccess = FALSE;
    HKEY hKey = NULL;
    DWORD type = 0;
    RU8 value[ 1024 ] = { 0 };
    DWORD size = 0;
    RU32 iKey = 0;
    DWORD tmpKeyNameSize = 0;
    RWCHAR tmpKeyName[ 1024 ] = { 0 };

    if( ERROR_SUCCESS == RegOpenKeyW( keyRoot, keyPath, &hKey ) )
    {
        if( _WCH( '*' ) != valueExpr[ 0 ] )
        {
            // This key is a specific leaf value
            size = sizeof( value ) - ( sizeof( RWCHAR ) * 2 );
            if( ERROR_SUCCESS == RegQueryValueExW( hKey,
                                                   valueExpr,
                                                   NULL,
                                                   &type,
                                                   (LPBYTE)value,
                                                   &size ) )
            {
                if( !_processRegValue( type, 
                                       keyPath, 
                                       valueExpr, 
                                       (RPU8)value, 
                                       size, 
                                       autoruns ) )
                {
                    rpal_debug_warning( "key contains unexpected data" );
                }
                else
                {
                    isSuccess = TRUE;
                }
            }
        }
        else
        {
            isSuccess = TRUE;

            // This key is *, meaning all leaf values so we must enumerate
            tmpKeyNameSize = ARRAY_N_ELEM( tmpKeyName );
            size = sizeof( value ) - ( sizeof( RWCHAR ) * 2 );
            while( ERROR_SUCCESS == RegEnumValueW( hKey, 
                                                   iKey, 
                                                   (RPWCHAR)&tmpKeyName, 
                                                   &tmpKeyNameSize, 
                                                   NULL, 
                                                   &type, 
                                                   (RPU8)value, 
                                                   &size ) )
            {
                tmpKeyName[ tmpKeyNameSize ] = 0;

                if( !_processRegValue( type, keyPath, tmpKeyName, (RPU8)value, size, autoruns ) )
                {
                    rpal_debug_warning( "key contains unexpected data" );
                    isSuccess = FALSE;
                }

                iKey++;
                tmpKeyNameSize = ARRAY_N_ELEM( tmpKeyName );
                size = sizeof( value ) - ( sizeof( RWCHAR ) * 2 );
            }
        }

        RegCloseKey( hKey );
    }

    return isSuccess;
}

RPRIVATE
RBOOL
    _getWindowsAutoruns
    (
        rList autoruns
    )
{
    RBOOL isSuccess = FALSE;

    rDirCrawl dirCrawl = NULL;
    struct
    {
        RPWCHAR path;
        RPWCHAR fileExpr[ 2 ];
    } crawlInfo[] = { { _WCH( "%ALLUSERSPROFILE%\\Start Menu\\Programs\\Startup" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%systemdrive%\\users\\*\\Start Menu\\Programs\\Startup" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%systemdrive%\\users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%systemdrive%\\documents and settings\\*\\Start Menu\\Programs\\Startup" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%systemdrive%\\documents and settings\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start" ), { _WCH( "*" ), NULL } },
                      { _WCH( "%systemroot%\\Tasks" ), { _WCH( "*.job" ), NULL } },
                      { _WCH( "%systemroot%\\system32\\Tasks" ), { _WCH( "*.job" ), NULL } } };
    rFileInfo finfo = { 0 };

    RU32 i = 0;
    RPWCHAR lnkDest = NULL;
    rSequence entry = NULL;
    RU32 iKey = 0;
    HKEY hKey = NULL;
    RU32 iTermKey = 0;
    RWCHAR tmpKeyName[ 1024 ] = { 0 };
    RPWCHAR tmp = NULL;

    struct
    {
        HKEY root;
        RPWCHAR path;
        RPWCHAR keyName;
    } keys[] = {
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOne" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ), _WCH( "Userinit" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ), _WCH( "Shell" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ), _WCH( "Taskman" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ), _WCH( "System" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\" ), _WCH( "Notify" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccount\\Userlists" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Active Setup\\" ), _WCH( "Installed Components" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\" ), _WCH( "Installed Components" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellExecuteHooks" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellExecuteHooks" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "Browser Helper Objects" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "Browser Helper Objects" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows NT\\CurrentVersion\\" ), _WCH( "Drivers32" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\" ), _WCH( "Drivers32" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\" ), _WCH( "debugger" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\" ), _WCH( "debugger" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Classes\\Exefile\\Shell\\Open\\Command\\" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\" ), _WCH( "Appinit_Dlls" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\" ), _WCH( "Appinit_Dlls" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\" ), _WCH( "SchedulingAgent" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\" ), _WCH( "Approved" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\" ), _WCH( "SvcHost" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Session Manager\\" ), _WCH( "AppCertDlls" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\" ), _WCH( "SecurityProviders" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\CurrentControlSet\\Control\\Lsa\\" ), _WCH( "Authentication Packages" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\CurrentControlSet\\Control\\Lsa\\" ), _WCH( "Notification Packages" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\CurrentControlSet\\Control\\Lsa\\" ), _WCH( "Security Packages" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\ControlSet00.$current.\\Control\\Session Manager\\" ), _WCH( "CWDIllegalInDllSearch" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\ControlSet00.$current.\\Control\\" ), _WCH( "SafeBoot" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Session Manager" ), _WCH( "SetupExecute" ) },  // Values: SetupExecute, Execute, S0InitialCommand
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Session Manager" ), _WCH( "Execute" ) },  // Values: SetupExecute, Execute, S0InitialCommand
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Session Manager" ), _WCH( "S0InitialCommand" ) },  // Values: SetupExecute, Execute, S0InitialCommand
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Session Manager" ), _WCH( "AppCertDlls" ) }, // Read all values of this key
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control" ), _WCH( "ServiceControlManagerExtension" ) },   // Value: ServiceControlManagerExtension
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Command Processor" ), _WCH( "AutoRun" ) },   // Value: AutoRun
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Microsoft\\Command Processor" ), _WCH( "AutoRun" ) },   // Value: AutoRun
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\Setup\\" ), _WCH( "CmdLine" ) },   // Value: CmdLine
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\Setup\\" ), _WCH( "LsaStart" ) },   // Value: LsaStart
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ), _WCH( "GinaDLL" ) },   // Value: GinaDLL
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ), _WCH( "UIHost" ) },   // Value: GinaDLL
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ), _WCH( "AppSetup" ) },   // Value: AppSetup
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ), _WCH( "VmApplet" ) },   // Value: VmApplet
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" ), _WCH( "Shell" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" ), _WCH( "AlternateShell" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\SafeBoot\\Option\\" ), _WCH( "UseAlternateShell" ) },  // This one has to be 1
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" ), _WCH( "*" ) },  // syntax: http://support.microsoft.com/default.aspx?scid=KB;en-us;232509
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" ), _WCH( "*" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\" ), _WCH( "Startup" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\" ), _WCH( "Logon" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\" ), _WCH( "StartupPrograms" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\" ), _WCH( "Startup" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "System\\CurrentControlSet\\Control\\BootVerificationProgram" ), _WCH( "ImagePath" ) },   // Value: ImagePath
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Classes\\Protocols\\" ), _WCH( "Handler" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\" ), _WCH( "Components" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "Shell Folders" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Microsoft\\Windows NT\\CurrentVersion\\" ), _WCH( "Windows" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "SharedTaskScheduler" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "SharedTaskScheduler" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellServiceObjects" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellServiceObjects" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" ), _WCH( "ShellServiceObjectDelayLoad" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\" ), _WCH( "ShellServiceObjectDelayLoad" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows CE Services\\" ), _WCH( "AutoStartOnConnect" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\" ), _WCH( "AutoStartOnConnect" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows CE Services\\" ), _WCH( "AutoStartOnDisconnect" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\" ), _WCH( "AutoStartOnDisconnect" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "Browser Helper Objects" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\*\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\*\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Drive\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Drive\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\*\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\*\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\AllFileSystemObjects\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Directory\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Directory\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Directory\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Directory\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Directory\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Directory\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Directory\\ShellEx\\" ), _WCH( "CopyHookHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Directory\\ShellEx\\" ), _WCH( "CopyHookHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Directory\\Background\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Directory\\Background\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Folder\\ShellEx\\" ), _WCH( "ColumnHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Folder\\ShellEx\\" ), _WCH( "ColumnHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Folder\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Folder\\ShellEx\\" ), _WCH( "ContextMenuHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Folder\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Folder\\ShellEx\\" ), _WCH( "DragDropHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Folder\\ShellEx\\" ), _WCH( "ExtShellFolderViews" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Folder\\ShellEx\\" ), _WCH( "ExtShellFolderViews" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Classes\\Folder\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "Software\\Wow6432Node\\Classes\\Folder\\ShellEx\\" ), _WCH( "PropertySheetHandlers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellIconOverlayIdentifiers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\" ), _WCH( "ShellIconOverlayIdentifiers" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Ctf\\" ), _WCH( "LangBarAddin" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Internet Explorer\\" ), _WCH( "UrlSearchHooks" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Internet Explorer\\" ), _WCH( "Toolbar" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Internet Explorer\\" ), _WCH( "Toolbar" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Internet Explorer\\" ), _WCH( "Explorer Bars" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Internet Explorer\\" ), _WCH( "Explorer Bars" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Microsoft\\Internet Explorer\\" ), _WCH( "Extensions" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Wow6432Node\\Microsoft\\Internet Explorer\\" ), _WCH( "Extensions" ) },
        { HKEY_LOCAL_MACHINE, _WCH( "SOFTWARE\\Classes\\" ), _WCH( "Filter" ) },
    };

    // First we check for Registry autoruns
    for( i = 0; i < ARRAY_N_ELEM( keys ); i++ )
    {
        if( rpal_string_endswith( keys[ i ].path, _WCH( "\\*\\" ) ) )
        {
            iKey = 0;
            iTermKey = rpal_string_strlen( keys[ i ].path ) - 2;
            if( NULL != ( tmp = rpal_string_strdup( keys[ i ].path ) ) )
            {
                tmp[ iTermKey ] = 0;
                if( ERROR_SUCCESS == RegOpenKeyW( keys[ i ].root, tmp, &hKey ) )
                {
                    while( ERROR_SUCCESS == RegEnumKeyW( hKey, iKey, tmpKeyName, ARRAY_N_ELEM( tmpKeyName ) ) )
                    {
                        if( NULL != ( tmp = rpal_string_strcatEx( tmp, tmpKeyName ) ) )
                        {
                            _processRegKey( keys[ i ].root, tmp, keys[ i ].keyName, autoruns );
                        }

                        tmp[ iTermKey ] = 0;

                        iKey++;
                    }

                    RegCloseKey( hKey );
                }

                rpal_memory_free( tmp );
            }
        }
        else
        {
            _processRegKey( keys[ i ].root, keys[ i ].path, keys[ i ].keyName, autoruns );
        }
    }

    // Now we look for dir-based autoruns
    for( i = 0; i < ARRAY_N_ELEM( crawlInfo ); i++ )
    {
        if( NULL != ( dirCrawl = rpal_file_crawlStart( crawlInfo[ i ].path, crawlInfo[ i ].fileExpr, 1 ) ) )
        {
            while( rpal_file_crawlNextFile( dirCrawl, &finfo ) )
            {
                if( !IS_FLAG_ENABLED( finfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) &&
                    0 != rpal_string_stricmp( _WCH( "desktop.ini" ), finfo.fileName ) &&
                    NULL != ( entry = rSequence_new() ) )
                {
                    tmp = finfo.filePath;
                    lnkDest = NULL;

                    if( rpal_string_endswith( finfo.filePath, _WCH( ".lnk" ) ) )
                    {
                        if( rpal_file_getLinkDest( tmp, &lnkDest ) )
                        {
                            tmp = lnkDest;
                        }
                    }

                    rSequence_addSTRINGW( entry, RP_TAGS_FILE_PATH, tmp );

                    if( NULL != lnkDest )
                    {
                        rpal_memory_free( lnkDest );
                    }

                    if( !rList_addSEQUENCE( autoruns, entry ) )
                    {
                        rSequence_free( entry );
                    }
                }
            }

            rpal_file_crawlStop( dirCrawl );
        }
    }

    isSuccess = TRUE;

    return isSuccess;
}
#elif defined(RPAL_PLATFORM_MACOSX)
static
    RBOOL
    _getMacOSXAutoruns
    (
        rList autoruns
    )
{
    RBOOL isSuccess = FALSE;

    RU32 i = 0;
    rSequence entry = NULL;
    rDirCrawl dirCrawl = NULL;
    RPCHAR crawlFiles[] = { "*", NULL };
    RPCHAR paths[] = {
        "/System/Library/StartupItems",
        "/Library/StartupItems" };
    rFileInfo finfo = { 0 };

    // Look for dir-based autoruns
    for( i = 0; i < ARRAY_N_ELEM( paths ); i++ )
    {
        if( NULL != ( dirCrawl = rpal_file_crawlStart( paths[ i ], crawlFiles, 1 ) ) )
        {
            while( rpal_file_crawlNextFile( dirCrawl, &finfo ) )
            {
                if( !IS_FLAG_ENABLED( finfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) &&
                    NULL != ( entry = rSequence_new() ) )
                {
                    rSequence_addSTRINGA( entry, RP_TAGS_FILE_PATH, finfo.filePath );

                    if( !rList_addSEQUENCE( autoruns, entry ) )
                    {
                        rSequence_free( entry );
                    }
                }
            }

            rpal_file_crawlStop( dirCrawl );
        }
    }

    isSuccess = TRUE;

    return isSuccess;
}
#endif

rList
    libOs_getAutoruns
    (
        RBOOL isWithHashes
    )
{
    rList autoruns = NULL;

    if( NULL != ( autoruns = rList_new( RP_TAGS_AUTORUN, RPCM_SEQUENCE ) ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( !_getWindowsAutoruns( autoruns ) )
        {
            rpal_debug_warning( "error getting windows autoruns" );
        }
#elif defined(RPAL_PLATFORM_MACOSX)
        if( !_getMacOSXAutoruns( autoruns ) )
        {
            rpal_debug_warning( "error getting mac autoruns" );
        }
#else
        rpal_debug_not_implemented();
#endif
        if( isWithHashes )
        {
            _enhanceAutorunsWithHashes( autoruns );
        }
    }

    return autoruns;
}

rList
    libOs_getDevices
    (

    )
{
    rList devices = NULL;
    rSequence device = NULL;

    if( NULL != ( devices = rList_new( RP_TAGS_DEVICE, RPCM_SEQUENCE ) ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS

        HDEVINFO hDevInfo = NULL;
        SP_DEVINFO_DATA devInfo = { 0 };
        RU32 i = 0;
        RWCHAR desc[ 1024 ] = { 0 };

        if( INVALID_HANDLE_VALUE != ( hDevInfo = SetupDiGetClassDevs( NULL,
                                                                      0,
                                                                      0,
                                                                      DIGCF_PRESENT | DIGCF_ALLCLASSES ) ) )
        {
            devInfo.cbSize = sizeof( devInfo );
            for( i = 0; SetupDiEnumDeviceInfo( hDevInfo, i, &devInfo ); i++ )
            {
                if( NULL != ( device = rSequence_new() ) )
                {
                    if( SetupDiGetDeviceRegistryPropertyW( hDevInfo,
                                                           &devInfo,
                                                           SPDRP_DEVICEDESC,
                                                           NULL,
                                                           (PBYTE)desc,
                                                           sizeof( desc ),
                                                           NULL ) )
                    {
                        rSequence_addSTRINGW( device, RP_TAGS_DEVICE_NAME, desc );
                    }
                    else
                    {
                        rpal_debug_warning( "device info too long" );
                    }

                    if( SetupDiGetDeviceRegistryPropertyW( hDevInfo,
                                                           &devInfo,
                                                           SPDRP_HARDWAREID,
                                                           NULL,
                                                           (PBYTE)desc,
                                                           sizeof( desc ),
                                                           NULL ) )
                    {
                        rSequence_addSTRINGW( device, RP_TAGS_DEVICE_HW_ID, desc );
                    }
                    else
                    {
                        rpal_debug_warning( "device info too long" );
                    }

                    if( !rList_addSEQUENCE( devices, device ) )
                    {
                        rSequence_free( device );
                    }
                }
            }

            SetupDiDestroyDeviceInfoList( hDevInfo );
        }
#else
        rpal_debug_not_implemented();
#endif
    }
    return devices;
}

rList
    libOs_getVolumes
    (

    )
{
    rList volumes = NULL;
    rSequence volume = NULL;

    if( NULL != ( volumes = rList_new( RP_TAGS_VOLUME, RPCM_SEQUENCE ) ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RU32 driveIndex = 0;
        RU32 drivesMask = 0;
        RWCHAR driveRoot[ 4 ] = { _WCH('0'), _WCH(':'), 0 , 0 };
        RWCHAR deviceName[ RPAL_MAX_PATH ] = { 0 };
        
        if( 0 != ( drivesMask = GetLogicalDrives() ) )
        {
            while( driveIndex < 32 )
            {
                driveIndex++;

                if( 0 == ( 0x00000001 & drivesMask ) )
                {
                    drivesMask = drivesMask >> 1;
                    continue;
                }

                drivesMask = drivesMask >> 1;

                driveRoot[ 0 ] = _WCH('A') + (RWCHAR)driveIndex - 1;

                if( NULL != ( volume = rSequence_new() ) )
                {
                    if( 0 != QueryDosDeviceW( driveRoot, deviceName, ARRAY_N_ELEM( deviceName ) ) )
                    {
                        rSequence_addSTRINGW( volume, RP_TAGS_DEVICE_NAME, deviceName );
                    }

                    rSequence_addSTRINGW( volume, RP_TAGS_VOLUME_PATH, driveRoot );

                    if( !rList_addSEQUENCE( volumes, volume ) )
                    {
                        rSequence_free( volume );
                    }
                }
            }
        }
#elif defined( RPAL_PLATFORM_MACOSX )
        RU32 nVolumes = 0;
        RU32 i = 0;
        struct statfs* fsInfo = NULL;
        if( 0 != ( nVolumes = getmntinfo( &fsInfo, MNT_NOWAIT ) ) )
        {
            for( i = 0; i < nVolumes; i++ )
            {
                if( NULL != ( volume = rSequence_new() ) )
                {
                    rSequence_addSTRINGA( volume, RP_TAGS_VOLUME_PATH, fsInfo[ i ].f_mntonname );
                    rSequence_addSTRINGA( volume, RP_TAGS_VOLUME_NAME, fsInfo[ i ].f_mntfromname );

                    if( !rList_addSEQUENCE( volumes, volume ) )
                    {
                        rSequence_free( volume );
                    }
                }
            }
        }
#elif defined( RPAL_PLATFORM_LINUX )
        FILE* mtab = NULL;
        RCHAR tabPath[] = { "/etc/mtab" };
        struct mntent* fsInfo = NULL;

        if( NULL != ( mtab = setmntent( tabPath, "r" ) ) )
        {
            while( NULL != ( fsInfo = getmntent( mtab ) ) )
            {
                if( NULL != ( volume = rSequence_new() ) )
                {
                    rSequence_addSTRINGA( volume, RP_TAGS_VOLUME_PATH, fsInfo->mnt_dir );
                    rSequence_addSTRINGA( volume, RP_TAGS_VOLUME_NAME, fsInfo->mnt_fsname );

                    if( !rList_addSEQUENCE( volumes, volume ) )
                    {
                        rSequence_free( volume );
                    }
                }
            }

            endmntent( mtab );
        }
#else
        rpal_debug_not_implemented();
#endif
    }
    return volumes;
}

RU32
    libOs_getNumCpus
    (

    )
{
    static RU32 nCores = 0;

    if( 0 != nCores )
    {
        return nCores;
    }
    {
#ifdef RPAL_PLATFORM_WINDOWS
        SYSTEM_INFO sysinfo = { 0 };
        GetSystemInfo( &sysinfo );
        nCores = sysinfo.dwNumberOfProcessors;
#elif defined( RPAL_PLATFORM_MACOSX )
        int mib[ 4 ] = { CTL_HW, HW_AVAILCPU, 0, 0 };
        size_t len = sizeof( nCores );
        sysctl( mib, 2, &nCores, &len, NULL, 0 );
        if( nCores < 1 )
        {
            mib[ 1 ] = HW_NCPU;
            sysctl( mib, 2, &nCores, &len, NULL, 0 );

            if( nCores < 1 )
            {
                nCores = 1;
            }
        }
#elif defined( RPAL_PLATFORM_LINUX )
        nCores = sysconf( _SC_NPROCESSORS_ONLN );
#else
        rpal_debug_not_implemented();
#endif
    }

    return nCores;
}

/* EOF */
