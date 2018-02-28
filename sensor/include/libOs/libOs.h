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

#ifndef _LIB_OS_H
#define _LIB_OS_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>

//=============================================================================
//  Windows Versions
//=============================================================================
#define OSLIB_VERSION_WINDOWS_FUTURE        ((RU32)-1)
#define OSLIB_VERSION_WINDOWS_UNKNOWN       0
#define OSLIB_VERSION_WINDOWS_OLD           1
#define OSLIB_VERSION_WINDOWS_XP            2
#define OSLIB_VERSION_WINDOWS_2K3           3
#define OSLIB_VERSION_WINDOWS_VISTA_2K8     4
#define OSLIB_VERSION_WINDOWS_7_2K8R2       5
#define OSLIB_VERSION_WINDOWS_8             6
#define OSLIB_VERSION_WINDOWS_8_1           7
#define OSLIB_VERSION_WINDOWS_10            8

//=============================================================================
//  SignCheck operations
//=============================================================================
#define OSLIB_SIGNCHECK_NO_NETWORK               1  // IF SET, no network verification is done for cert chain verification
#define OSLIB_SIGNCHECK_CHAIN_VERIFICATION       2  // IF SET, the certificate chain is built to verify his authenticity
#define OSLIB_SIGNCHECK_INCLUDE_RAW_CERT         4  // IF SET, the raw certificate is included within the signature rSequence

//=============================================================================
//  Package Info
//=============================================================================
typedef struct
{
    RWCHAR name[ 256 ];
    RWCHAR version[ 64 ];
} LibOsPackageInfo;

typedef struct
{
    RU64 lastSystemTime;
    RU64 lastThreadTime;
    RTIME lastCheckTime;
    RU8 lastResult;
} LibOsThreadTimeContext;

typedef struct
{
    RU8 targetCpuPerformance;
    RU8 globalTargetCpuPerformance;
    RU32 lastTimeoutValue;
    RU32 globalTimeoutValue;
    RU32 timeoutIncrementPerSec;
    RU32 sanityCeiling;
    RU32 enforceOnceIn;
    RU32 counter;
    RTIME lastUpdate;
    RTIME lastSummary;
    LibOsThreadTimeContext threadTimeContext;
} LibOsPerformanceProfile;

//=============================================================================
//  API
//=============================================================================
RPCHAR
    libOs_getHostName
    (
        
    );

RU32
    libOs_getMainIp
    (

    );

RU8
    libOs_getCpuUsage
    (

    );

RU32
    libOs_getUsageProportionalTimeout
    (
        RU32 maxTimeout
    );

RU32
    libOs_getOsVersion
    (

    );

rSequence
    libOs_getOsVersionEx
    (

    );

RBOOL
    libOs_getInstalledPackages
    (
        LibOsPackageInfo** pPackages,
        RU32* nPackages
    );

RBOOL
    libOs_getSignature
	(
	    RPNCHAR  pwfilePath,
		rSequence* signature,
		RU32       operation,
		RBOOL*     pIsSigned,
		RBOOL*     pIsVerified_local,
		RBOOL*     pIsVerified_global
	);

RBOOL
    libOs_getProcessInfo
    (
        RU64* pTime,
        RU64* pSizeMemResident,
        RU64* pNumPageFaults
    );

RBOOL
    libOs_getThreadTime
    (
        rThreadID threadID,
        RU64* pTime
    );

RU32
    libOs_getPageSize
    (

    );

RU8
    libOs_getCurrentThreadCpuUsage
    (
        LibOsThreadTimeContext* ctx
    );

RBOOL
    libOs_getProcessTime
    (
        RU32 processId,
        RU64* pTime
    );

RU8
    libOs_getCurrentProcessCpuUsage
    (

    );

#define libOs_timeoutWithProfile( perfProfile, isEnforce, isTimeToStop ) libOs_timeoutWithProfileFrom((perfProfile),(isEnforce),(isTimeToStop),(RPCHAR)__FUNCTION__)

RVOID
    libOs_timeoutWithProfileFrom
    (
        LibOsPerformanceProfile* perfProfile,
        RBOOL isEnforce,
        rEvent isTimeToStop,
        RPCHAR from
    );

rList
    libOs_getServices
    (
        RBOOL isWithHashes
    );

rList
    libOs_getDrivers
    (
        RBOOL isWithHashes
    );

rList
    libOs_getAutoruns
    (
        RBOOL isWithHashes
    );

rList
    libOs_getDevices
    (

    );

rList
    libOs_getVolumes
    (

    );
    
RU32
    libOs_getNumCpus
    (

    );

#endif
