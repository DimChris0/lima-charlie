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

#ifndef _RP_HCP_COMMON_H
#define _RP_HCP_COMMON_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>

#pragma pack(push)
#pragma pack(1)

#define RP_HCP_UUID_SIZE    16
#define RP_HCP_FORMAT_UUID  RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32 RF_U32
#define RP_HCP_UUID_TO_COMPONENTS(uuid) uuid[ 0 ], uuid[ 0 ], uuid[ 1 ], uuid[ 2 ], uuid[ 3 ], uuid[ 4 ], uuid[ 5 ], uuid[ 6 ], uuid[ 7 ], uuid[ 8 ], uuid[ 9 ], uuid[ 10 ], uuid[ 11 ], uuid[ 12 ], uuid[ 13 ], uuid[ 14 ]

typedef struct
{
    RU8 sensor_id[ RP_HCP_UUID_SIZE ];
    RU8 org_id[ RP_HCP_UUID_SIZE ];
    RU8 ins_id[ RP_HCP_UUID_SIZE ];
    RU32 architecture;
    RU32 platform;
} rpHCPId;


#define RP_HCP_PLATFORM_ARCH_ANY            0x00000000
#define RP_HCP_PLATFORM_ARCH_X86            0x00000001
#define RP_HCP_PLATFORM_ARCH_X64            0x00000002

#define RP_HCP_PLATFORM_ANY                 0x00000000

#define RP_HCP_PLATFORM_WINDOWS             0x10000000

#define RP_HCP_PLATFORM_LINUX               0x20000000

#define RP_HCP_PLATFORM_MACOS               0x30000000
#define RP_HCP_PLATFORM_IOS                 0x40000000

#define RP_HCP_PLATFORM_ANDROID             0x50000000

// Current Platform
#ifndef RP_HCP_PLATFORM_CURRENT_ARCH
#ifdef RPAL_PLATFORM_64_BIT
#define RP_HCP_PLATFORM_CURRENT_ARCH        RP_HCP_PLATFORM_ARCH_X64
#else
#define RP_HCP_PLATFORM_CURRENT_ARCH        RP_HCP_PLATFORM_ARCH_X86
#endif
#endif

#ifndef RP_HCP_PLATFORM_CURRENT_MAJOR

#ifdef RPAL_PLATFORM_WINDOWS
#define RP_HCP_PLATFORM_CURRENT             RP_HCP_PLATFORM_WINDOWS
#elif defined( RPAL_PLATFORM_ANDROID )  /* Make it precede over Linux, as Android also defines RPAL_PLATFORM_LINUX. */
#define RP_HCP_PLATFORM_CURRENT             RP_HCP_PLATFORM_ANDROID
#elif defined( RPAL_PLATFORM_LINUX )
#define RP_HCP_PLATFORM_CURRENT             RP_HCP_PLATFORM_LINUX
#elif defined( RPAL_PLATFORM_MACOSX )
#define RP_HCP_PLATFORM_CURRENT             RP_HCP_PLATFORM_MACOS
#elif defined( RPAL_PLATFORM_IOS )
#define RP_HCP_PLATFORM_CURRENT             RP_HCP_PLATFORM_IOS
#endif

#endif

typedef RU8 RpHcp_ModuleId;
#define RP_HCP_MODULE_ID_BOOTSTRAP          0
#define RP_HCP_MODULE_ID_HCP                1
#define RP_HCP_MODULE_ID_HBS                2
#define RP_HCP_MODULE_ID_TEST               3
#define RP_HCP_MODULE_ID_AAD                4
#define RP_HCP_MODULE_ID_KERNEL_ACQ         5

typedef struct
{
    rpal_PContext rpalContext;
    rpHCPId* pCurrentId;
    RBOOL (*func_sendHome)( RpHcp_ModuleId sourceModuleId, rList toSend );
    rEvent isTimeToStop;
    rEvent isOnlineEvent;

} rpHCPModuleContext;

#pragma pack(pop)
#endif
