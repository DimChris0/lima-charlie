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

#ifndef _RPAL_THREAD_H
#define _RPAL_THREAD_H

#include <rpal/rpal.h>

#ifdef RPAL_PLATFORM_WINDOWS
    #define RPAL_THREAD_FUNC __stdcall
    #pragma warning(disable: 4055)
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    // Linux implementation
    #define RPAL_THREAD_FUNC
#endif

typedef RPVOID rThread;
typedef RPVOID rThreadPool;

#if defined( RPAL_PLATFORM_WINDOWS )
typedef DWORD rThreadID;
#elif defined( RPAL_PLATFORM_MACOSX ) 
#include <mach/mach_port.h>
typedef mach_port_t rThreadID;
#elif defined( RPAL_PLATFORM_LINUX )
#include <pthread.h>
typedef RS32 rThreadID;
#endif

typedef struct
{
    rThreadID tid;
    RU32 fileId;
    RU32 lineNum;
} rThreadPoolTask;

//=============================================================================
// Threads and thread IDs
//=============================================================================
typedef RU32 (RPAL_THREAD_FUNC *rpal_thread_func)( RPVOID context );

rThread
    rpal_thread_new
    (
        rpal_thread_func pStartFunction,
        RPVOID pContext
    );

rThreadID
    rpal_thread_self
    (
    );

RBOOL
    rpal_thread_wait
    (
        rThread hThread,
        RU32 timeout
    );

RBOOL
    rpal_thread_terminate
    (
        rThread hThread
    );

RVOID
    rpal_thread_free
    (
        rThread hThread
    );

RVOID
    rpal_thread_sleep
    (
        RU32 miliSec
    );

RVOID
    rpal_thread_sleepInSec
    (
        RU32 sec
    );

//=============================================================================
//  Thread Pools
//=============================================================================
typedef RPVOID (*rpal_thread_pool_func)( rEvent timeToStopEvent, RPVOID taskData );

rThreadPool
    rThreadPool_create
    (
        RU32 minThreads,
        RU32 maxThreads,
        RU32 threadTtl
    );

RVOID
    rThreadPool_destroy
    (
        rThreadPool pool,
        RBOOL isWaitForTasksToFinish
    );

RU32
    rThreadPool_getNbThreads
    (
        rThreadPool pool
    );

RBOOL
    rThreadPool_getTaskQueueLength
    (
        rThreadPool pool,
        RU32* pLength
    );

RBOOL
    rThreadPool_taskEx
    (
        rThreadPool pool,
        rpal_thread_pool_func taskFunction,
        RPVOID taskData,
        RU32 fileId,
        RU32 lineNum
    );
#define rThreadPool_task(pool, taskFunction, taskData) (rThreadPool_taskEx((pool), (taskFunction), (taskData), RPAL_FILE_ID, __LINE__))

RBOOL
    rThreadPool_scheduleOneTimeEx
    (
        rThreadPool pool,
        RU64 absoluteTime,
        rpal_thread_pool_func taskFunction,
        RPVOID taskData,
        RU32 fileId,
        RU32 lineNum
    );
#define rThreadPool_scheduleOneTime(pool, absoluteTime, taskFunction, taskData) (rThreadPool_scheduleOneTimeEx((pool), (absoluteTime), (taskFunction), (taskData), RPAL_FILE_ID, __LINE__))

RBOOL
    rThreadPool_scheduleRecurringEx
    (
        rThreadPool pool,
        RU64 timeInterval,
        rpal_thread_pool_func taskFunction,
        RPVOID taskData,
        RBOOL isRandomStartOffset,
        RU32 fileId,
        RU32 lineNum
    );
#define rThreadPool_scheduleRecurring(pool, timeInterval, taskFunction, taskData, isRandomStartOffset) (rThreadPool_scheduleRecurringEx((pool), (timeInterval), (taskFunction), (taskData), (isRandomStartOffset), RPAL_FILE_ID, __LINE__))

RBOOL
    rThreadPool_pause
    (
        rThreadPool pool
    );

RBOOL
    rThreadPool_resume
    (
        rThreadPool pool
    );

RBOOL
    rThreadPool_isIdle
    (
        rThreadPool pool
    );

RBOOL
    rThreadPool_getRunning
    (
        rThreadPool pool,
        rThreadPoolTask** pTasks,
        RU32* nTasks
    );

#endif
