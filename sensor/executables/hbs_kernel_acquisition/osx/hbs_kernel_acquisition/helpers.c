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

#include "helpers.h"
#include <sys/systm.h>
#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <sys/types.h>
#include <kern/clock.h>

static OSMallocTag g_mem_tag = 0;

static lck_grp_t* g_lck_group = NULL;

void*
    rpal_memory_alloc
    (
        uint32_t size
    )
{
    void* ptr = NULL;
    unsigned char* realPtr = NULL;
    
    if( 0 == g_mem_tag )
    {
        g_mem_tag = OSMalloc_Tagalloc( "hcp_hbs_acq", 0 );
    }
    
    size += sizeof( uint32_t );
    
    realPtr = OSMalloc( size, g_mem_tag );
    
    if( NULL != realPtr )
    {
        bzero( realPtr, size );
        *(uint32_t*)realPtr = size;
        ptr = realPtr + sizeof( uint32_t );
    }
    
    return ptr;
}

void
    rpal_memory_free
    (
        void* ptr
    )
{
    unsigned char* realPtr = ptr;
    uint32_t* pSize = NULL;
    
    if( NULL != ptr )
    {
        realPtr -= sizeof( uint32_t );
        pSize = (uint32_t*)realPtr;
        
        OSFree( realPtr, *pSize, g_mem_tag );
    }
}

rMutex
    rpal_mutex_create
    (

    )
{
    lck_mtx_t* mutex = NULL;
    
    lck_grp_attr_t* gattr = NULL;
    lck_attr_t* lattr = NULL;
    
    if( 0 == g_lck_group )
    {
        rpal_debug_info( "mutex group not created, creating" );
        
        gattr = lck_grp_attr_alloc_init();
        
        if( NULL == gattr )
        {
            rpal_debug_critical( "could not create mutex group" );
            return NULL;
        }
        
        lck_grp_attr_setstat( gattr );
        
        g_lck_group = lck_grp_alloc_init( "hcphbs", gattr );
        
        lck_grp_attr_free( gattr );
    }
    
    if( NULL == g_lck_group )
    {
        return NULL;
    }
    
    lattr = lck_attr_alloc_init();
    
    if( NULL != lattr )
    {
        mutex = lck_mtx_alloc_init( g_lck_group, lattr );
        lck_attr_free( lattr );
    }
    else
    {
        rpal_debug_critical( "could not create mutex attributes" );
    }
    
    return mutex;
}

void
    rpal_mutex_free
    (
        rMutex mutex
    )
{
    if( NULL != mutex )
    {
        lck_mtx_free( mutex, g_lck_group );
    }
}

void
    rpal_mutex_lock
    (
        rMutex mutex
    )
{
    if( NULL != mutex )
    {
        lck_mtx_lock( mutex );
    }
}

void
    rpal_mutex_unlock
    (
        rMutex mutex
    )
{
    if( NULL != mutex )
    {
        lck_mtx_unlock( mutex );
    }
}

uint64_t
    rpal_time_getLocal
    (

    )
{
    clock_sec_t ts = 0;
    clock_usec_t us = 0;
    
    clock_get_calendar_microtime( &ts, &us );
    
    return ((uint64_t)ts * 1000) + ((uint64_t)us / 1000);
}


