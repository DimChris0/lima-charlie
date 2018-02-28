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
#include <cryptoLib/cryptoLib.h>
#include "atoms.h"


typedef struct
{
    RU32 nTests;
    RU32 nFailures;
    rSequence config;
    rSequence originalTestRequest;

} SelfTestContext;

typedef struct _HbsState
{
    rEvent isTimeToStop;
    rEvent isOnlineEvent;
    rThreadPool hThreadPool;
    rQueue outQueue;
    RU8 currentConfigHash[ CRYPTOLIB_HASH_SIZE ];
    RU32 maxQueueNum;
    RU32 maxQueueSize;
    rMutex mutex;
    struct
    {
        RBOOL isEnabled;
        RBOOL( *init )( struct _HbsState* hbsState, rSequence config );
        RBOOL( *cleanup )( struct _HbsState* hbsState, rSequence config );
        RBOOL( *update )( struct _HbsState* hbsState, rSequence update );
        RBOOL( *test )( struct _HbsState* hbsState, SelfTestContext* testContext );
        rSequence conf;
        rpcm_tag* externalEvents;
        RTIME lastConfUpdate;
    } collectors[ 23 ];
} HbsState;

#define GLOBAL_CPU_USAGE_TARGET             1
#define GLOBAL_CPU_USAGE_TARGET_WHEN_TASKED 10

//=============================================================================
// Collector Naming Convention
//=============================================================================
#define DECLARE_COLLECTOR(num) extern rpcm_tag collector_ ##num## _events[]; \
                               RBOOL collector_ ##num## _init( HbsState* hbsState, \
                                                               rSequence config ); \
                               RBOOL collector_ ##num## _cleanup( HbsState* hbsState, \
                                                                  rSequence config ); \
                               RBOOL collector_ ##num## _update( HbsState* hbsState, \
                                                                 rSequence update ); \
                               RBOOL collector_ ##num## _test( HbsState* hbsState, \
                                                               SelfTestContext* testContext );

#define ENABLED_COLLECTOR(num) { TRUE, collector_ ##num## _init, collector_ ##num## _cleanup, collector_ ##num## _update, collector_ ##num## _test, NULL, collector_ ##num## _events, 0 }
#define DISABLED_COLLECTOR(num) { FALSE, collector_ ##num## _init, collector_ ##num## _cleanup, collector_ ##num## _update, collector_ ##num## _test, NULL, collector_ ##num## _events, 0 }

#ifdef RPAL_PLATFORM_WINDOWS
    #define ENABLED_WINDOWS_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define ENABLED_LINUX_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define ENABLED_OSX_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define DISABLED_WINDOWS_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define DISABLED_LINUX_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define DISABLED_OSX_COLLECTOR(num) ENABLED_COLLECTOR(num)
#elif defined( RPAL_PLATFORM_LINUX )
    #define ENABLED_WINDOWS_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define ENABLED_LINUX_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define ENABLED_OSX_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define DISABLED_WINDOWS_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define DISABLED_LINUX_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define DISABLED_OSX_COLLECTOR(num) ENABLED_COLLECTOR(num)
#elif defined( RPAL_PLATFORM_MACOSX )
    #define ENABLED_WINDOWS_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define ENABLED_LINUX_COLLECTOR(num) DISABLED_COLLECTOR(num)
    #define ENABLED_OSX_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define DISABLED_WINDOWS_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define DISABLED_LINUX_COLLECTOR(num) ENABLED_COLLECTOR(num)
    #define DISABLED_OSX_COLLECTOR(num) DISABLED_COLLECTOR(num)
#endif

//=============================================================================
//  Declaration of all collectors for the HBS Core
//=============================================================================
DECLARE_COLLECTOR( 0 );
DECLARE_COLLECTOR( 1 );
DECLARE_COLLECTOR( 2 );
DECLARE_COLLECTOR( 3 );
DECLARE_COLLECTOR( 4 );
DECLARE_COLLECTOR( 5 );
DECLARE_COLLECTOR( 6 );
DECLARE_COLLECTOR( 7 );
DECLARE_COLLECTOR( 8 );
DECLARE_COLLECTOR( 9 );
DECLARE_COLLECTOR( 10 );
DECLARE_COLLECTOR( 11 );
DECLARE_COLLECTOR( 12 );
DECLARE_COLLECTOR( 13 );
DECLARE_COLLECTOR( 14 );
DECLARE_COLLECTOR( 15 );
DECLARE_COLLECTOR( 16 );
DECLARE_COLLECTOR( 17 );
DECLARE_COLLECTOR( 18 );
DECLARE_COLLECTOR( 19 );
DECLARE_COLLECTOR( 20 );
DECLARE_COLLECTOR( 21 );
DECLARE_COLLECTOR( 22 );

//=============================================================================
//  Higher Level Helper Data Structures
//=============================================================================
typedef RPVOID HbsRingBuffer;
typedef RBOOL(*HbsRingBufferCompareFunc)( rSequence seq, RPVOID ref );
typedef RPVOID HbsDelayBuffer;

//=============================================================================
//  Helper Functionality
//=============================================================================
RBOOL
    hbs_markAsRelated
    (
        rSequence parent,
        rSequence toMark
    );

RBOOL
    hbs_timestampEvent
    (
        rSequence event,
        RTIME optOriginal
    );

RBOOL
    hbs_whenCpuBelow
    (
        RU8 percent,
        RTIME timeout,
        rEvent abortEvent
    );

HbsRingBuffer
    HbsRingBuffer_new
    (
        RU32 nMaxElements,
        RU32 maxTotalSize
    );

RVOID
    HbsRingBuffer_free
    (
        HbsRingBuffer hrb
    );

RBOOL
    HbsRingBuffer_add
    (
        HbsRingBuffer hrb,
        rSequence elem
    );

RBOOL
    HbsRingBuffer_find
    (
        HbsRingBuffer hrb,
        HbsRingBufferCompareFunc compareFunction,
        RPVOID ref,
        rSequence* pFound
    );

RBOOL
    hbs_sendCompletionEvent
    (
        rSequence originalRequest,
        rpcm_tag eventType,
        RU32 errorCode,
        RPCHAR errorMessage
    );

RBOOL
    hbs_publish
    (
        rpcm_tag eventType,
        rSequence event
    );


HbsDelayBuffer
    HbsDelayBuffer_new
    (
        RU32 nMilliSeconds
    );

RVOID
    HbsDelayBuffer_free
    (
        HbsDelayBuffer hdb
    );


RBOOL
    HbsDelayBuffer_add
    (
        HbsDelayBuffer hdb,
        rpcm_tag eventType,
        rSequence event
    );

RBOOL
    HbsDelayBuffer_remove
    (
        HbsDelayBuffer hdb,
        rSequence* pEvent,
        rpcm_tag* pEventType,
        RU32 milliSecTimeout
    );

RBOOL
    HbsSetThisAtom
    (
        rSequence msg,
        RU8 atomId[ HBS_ATOM_ID_SIZE ]
    );

RBOOL
    HbsSetParentAtom
    (
        rSequence msg,
        RU8 atomId[ HBS_ATOM_ID_SIZE ]
    );

RBOOL
    HbsGetThisAtom
    (
        rSequence msg,
        RPU8* pAtomId
    );

RBOOL
    HbsGetParentAtom
    (
        rSequence msg,
        RPU8* pAtomId
    );

//=============================================================================
//  Collector Testing
//=============================================================================
RBOOL
    HbsAssert
    (
        SelfTestContext* ctx,
        RU32 fileId,
        RU32 lineId,
        RBOOL value,
        rSequence mtd
    );

#define HBS_ASSERT(value,mtd) (HbsAssert(testContext, RPAL_FILE_ID, __LINE__, (value), (mtd)))
#define HBS_ASSERT_TRUE(value)      HBS_ASSERT((value),NULL)
#define HBS_ASSERT_FALSE(value)     HBS_ASSERT(!(value),NULL)

#define HBS_TEST_NAME(testName)     hbs_test_ ##testName
#define HBS_RUN_TEST(testName)      HBS_TEST_NAME(testName)( testContext );
#define HBS_DECLARE_TEST(testName)  RPRIVATE\
                                    RVOID\
                                        HBS_TEST_NAME(testName)\
                                        (\
                                            SelfTestContext* testContext\
                                        )
#define HBS_TEST_SUITE(collectorId) RBOOL\
                                        collector_ ##collectorId##_test\
                                        (\
                                            HbsState* hbsState,\
                                            SelfTestContext* testContext\
                                        )
