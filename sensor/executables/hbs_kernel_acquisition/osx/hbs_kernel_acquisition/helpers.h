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

#ifndef helpers_h
#define helpers_h

#define RPAL_PLATFORM_DEBUG

#include <stdarg.h>
#include <sys/systm.h>
#define rpal_debug_critical(format,...)   printf( "CRITICAL !!!!! %s: %d %s() - " #format "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__ )
#define rpal_debug_error(format,...)      printf( "ERROR ++++++++ %s: %d %s() - " #format "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__ )

#ifdef RPAL_PLATFORM_DEBUG
#define rpal_debug_warning(format,...)    printf( "WARNING ====== %s: %d %s() - " #format "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__ )
#define rpal_debug_info(format,...)       printf( "INFO --------- %s: %d %s() - " #format "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__ )
#else
#define rpal_debug_warning(format,...)
#define rpal_debug_info(format,...)
#endif

#define ARRAY_N_ELEM(arr)               (sizeof(arr) / sizeof((arr)[0]))

// Copy paste from rpal.h since importing it is not an option at the moment.
// At some point it would be nice to make rpal.h compatible KM/UM on all platforms.
#define IS_WITHIN_BOUNDS(elem,elemSize,container,containerSize) (((RU64)(elem) >= (RU64)(container)) &&\
                                                                 ((RU64)(elem) < ((RU64)(container) + (RU64)(containerSize))) &&\
                                                                 ((((RU64)(container) + (RU64)(containerSize)) - (RU64)(elem)) >= (RU64)(elemSize)))

void*
    rpal_memory_alloc
    (
        uint32_t size
    );

void
    rpal_memory_free
    (
        void* ptr
    );


typedef lck_mtx_t* rMutex;

rMutex
    rpal_mutex_create
    (

    );

void
    rpal_mutex_free
    (
        rMutex mutex
    );

void
    rpal_mutex_lock
    (
        rMutex mutex
    );

void
    rpal_mutex_unlock
    (
        rMutex mutex
    );

uint64_t
    rpal_time_getLocal
    (

    );

#include <kernelAcquisitionLib/common.h>

#endif /* helpers_h */
