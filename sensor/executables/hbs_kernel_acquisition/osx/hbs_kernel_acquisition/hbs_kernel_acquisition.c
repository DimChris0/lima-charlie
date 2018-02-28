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

#define RPAL_PLATFORM_MACOSX

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/kern_control.h>

#include <sys/types.h>

#include "collectors.h"
#include "helpers.h"

#define MAX_CLIENTS_CONNECTED   1

static struct kern_ctl_reg krnlCommsCtl = { 0 };
static kern_ctl_ref krnlCommsRef = { 0 };
static int g_n_connected = 0;
static int g_is_shutting_down = 0;
int g_owner_pid = 0;


kern_return_t hbs_kernel_acquisition_start(kmod_info_t * ki, void *d);
kern_return_t hbs_kernel_acquisition_stop(kmod_info_t *ki, void *d);

typedef struct
{
    int (*initializer)( void* d );
    int (*deinitializer)();
} CollectorContext;

static rMutex g_connection_mutex = NULL;

#define _COLLECTOR_INIT(cId) { collector_ ## cId ## _initialize, collector_ ## cId ## _deinitialize }
#define _COLLECTOR_DISABLED(cId) { NULL, NULL }

//=========================================================================
//  Built-in Tasks
//=========================================================================
static
int
    task_ping
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    
    if( NULL != pArgs &&
       sizeof(uint32_t) == argsSize &&
       NULL != pResult &&
       NULL != resultSize &&
       sizeof(uint32_t) == *resultSize &&
       ACQUISITION_COMMS_CHALLENGE == *(uint32_t*)pArgs )
    {
        *(uint32_t*)pResult = ACQUISITION_COMMS_RESPONSE;
        *resultSize = sizeof(uint32_t);
    }
    else
    {
        ret = EINVAL;
        rpal_debug_error( "invalid challenge: %p:%d / %p:%d",
                          pArgs,
                          argsSize,
                          pResult,
                          (int)sizeof(uint32_t) );
    }
    
    return ret;
}

//=========================================================================
//  Dispatcher
//=========================================================================
static CollectorContext g_collectors[] = { _COLLECTOR_INIT( 1 ),
                                           _COLLECTOR_INIT( 2 ),
                                           _COLLECTOR_DISABLED( 3 ),
                                           _COLLECTOR_INIT( 4 ) };
static collector_task g_tasks[ KERNEL_ACQ_NUM_OPS ] = { task_ping,
                                                        task_get_new_processes,
                                                        task_get_new_fileio,
                                                        NULL,
                                                        task_get_new_connections,
                                                        task_get_new_dns,
                                                        task_segregate_network,
                                                        task_rejoin_network };

static
int
    um_dispatcher
    (
        int op,
        KernelAcqCommand* cmd
    )
{
    int error = 0;
    void* pLocalArgs = NULL;
    void* pLocalRes = NULL;
    uint32_t resSize = 0;
    
    if( NULL != cmd )
    {
        // rpal_debug_info( "OP: %d, ARG: %p, ARGS: %d, RES: %p, RESS: %d",
        //                 op,
        //                 cmd->pArgs,
        //                 cmd->argsSize,
        //                 cmd->pResult,
        //                 cmd->resultSize );
        
        if( op >= ARRAY_N_ELEM( g_tasks ) ||
            NULL == g_tasks[ op ] )
        {
            rpal_debug_error( "invalid op specified: %d", op );
            error = EINVAL;
            return error;
        }
        
        resSize = cmd->resultSize;
        
        if( NULL != cmd->pArgs &&
           0 != cmd->argsSize )
        {
            pLocalArgs = rpal_memory_alloc( cmd->argsSize );
        }
        if( NULL != cmd->pResult &&
           0 != cmd->resultSize )
        {
            pLocalRes = rpal_memory_alloc( cmd->resultSize );
        }
        
        if( ( NULL != pLocalArgs ||
             NULL == cmd->pArgs ||
             0 == cmd->argsSize ) &&
           ( NULL != pLocalRes ||
            NULL == cmd->pResult ||
            0 == cmd->resultSize ) )
        {
            if( NULL == pLocalArgs ||
               0 == copyin( (user_addr_t)cmd->pArgs, pLocalArgs, cmd->argsSize ) )
            {
                error = g_tasks[ op ]( pLocalArgs, cmd->argsSize, pLocalRes, &resSize );
                
                if( 0 != error )
                {
                    rpal_debug_error( "op returned error: %d", error );
                }
                else
                {
                    // rpal_debug_info( "op success" );
                    
                    if( NULL != cmd->pResult &&
                       0 != resSize &&
                       0 != copyout( pLocalRes, (user_addr_t)cmd->pResult, resSize ) )
                    {
                        rpal_debug_error( "error copying out results: %p %d", cmd->pResult, resSize );
                        error = ENOMEM;
                    }
                    else if( NULL != cmd->pSizeUsed &&
                            0 != copyout( &resSize, (user_addr_t)cmd->pSizeUsed, sizeof(uint32_t) ) )
                    {
                        rpal_debug_error( "error copying out size used: %p %d", cmd->pSizeUsed, resSize );
                        error = ENOMEM;
                    }
                }
            }
            else
            {
                rpal_debug_error( "error copying in arguments: %p %d", cmd->pArgs, cmd->argsSize );
                error = ENOMEM;
            }
        }
        else
        {
            rpal_debug_error( "could not allocate memory for arguments or results: %d / %d", cmd->argsSize, cmd->resultSize );
            error = ENOMEM;
        }
        
        if( NULL != pLocalArgs ) rpal_memory_free( pLocalArgs );
        if( NULL != pLocalRes ) rpal_memory_free( pLocalRes );
    }
    
    return error;
}

//=========================================================================
//  Kernel / User Comms
//=========================================================================
static
errno_t
    comms_handle_send
    (
        kern_ctl_ref ctlref,
        unsigned int unit,
        void *userdata,
        mbuf_t m,
        int flags
    )
{
    int error = EINVAL;
    
    if( g_is_shutting_down ) return EBUSY;
    
    return error;
}

static
errno_t
    comms_handle_get
    (
        kern_ctl_ref ctlref,
        unsigned int unit,
        void *userdata, int opt,
        void *data,
        size_t *len
    )
{
    int error = EINVAL;
    
    if( g_is_shutting_down ) return EBUSY;
    
    return error;
}

static
errno_t
    comms_handle_set
    (
        kern_ctl_ref ctlref,
        unsigned int unit,
        void *userdata,
        int opt,
        void *data,
        size_t len
    )
{
    int error = EINVAL;
    
    if( g_is_shutting_down ) return EBUSY;
    
    // rpal_debug_info( "received request" );
    
    if( NULL != data &&
       sizeof(KernelAcqCommand) <= len )
    {
        // rpal_debug_info( "calling dispatcher" );
        
        error = um_dispatcher( opt, data );
    }
    else
    {
        rpal_debug_critical( "not enough data for request" );
    }
    
    // rpal_debug_info( "returned status: %d", error );
    
    return error;
}

static
errno_t
    comms_handle_connect
    (
        kern_ctl_ref ctlref,
        struct sockaddr_ctl *sac,
        void **unitinfo
    )
{
    errno_t status = 0;
    if( g_is_shutting_down ) return EBUSY;

    rpal_mutex_lock( g_connection_mutex );
    if( MAX_CLIENTS_CONNECTED > g_n_connected )
    {
        g_n_connected++;
        g_owner_pid = proc_selfpid();
    }
    else
    {
        status = EBUSY;
    }
    rpal_mutex_unlock( g_connection_mutex );
    rpal_debug_info( "now %d clients connected with %d", g_n_connected, g_owner_pid );
    return status;
}

static
errno_t
    comms_handle_disconnect
    (
        kern_ctl_ref ctlref,
        unsigned int unit,
        void *unitinfo
    )
{
    rpal_mutex_lock( g_connection_mutex );
    if( 0 != g_n_connected ) g_n_connected--;
    rpal_mutex_unlock( g_connection_mutex );
    rpal_debug_info( "now %d clients connected", g_n_connected );
    return 0;
}

//=========================================================================
//  Entry Points
//=========================================================================

kern_return_t hbs_kernel_acquisition_start(kmod_info_t * ki, void *d)
{
    kern_return_t status = KERN_FAILURE;
    errno_t error = 0;
    int i = 0;
    
    g_is_shutting_down = 0;
    g_n_connected = 0;

    if( NULL != ( g_connection_mutex = rpal_mutex_create() ) )
    {
        status = KERN_SUCCESS;

        rpal_debug_info( "Initializing collectors" );

        for( i = 0; i < ARRAY_N_ELEM( g_collectors ); i++ )
        {
            if( NULL == g_collectors[ i ].initializer ) continue;

            if( !g_collectors[ i ].initializer( d ) )
            {
                rpal_debug_critical( "error initializing collector %d", i );
                error = EBADEXEC;
                break;
            }
            else
            {
                rpal_debug_info( "collector %d loaded", i );
            }
        }

        if( 0 != error )
        {
            for( i = i - 1; i >= 0; i-- )
            {
                if( NULL == g_collectors[ i ].deinitializer ) continue;

                g_collectors[ i ].deinitializer();
            }
        }

        if( 0 == error )
        {
            rpal_debug_info( "collectors OK" );
            rpal_debug_info( "initializing KM/UM comms" );

            krnlCommsCtl.ctl_id = 0;
            krnlCommsCtl.ctl_unit = 0;
            strncpy( krnlCommsCtl.ctl_name, ACQUISITION_COMMS_NAME, sizeof( krnlCommsCtl.ctl_name ) );
            krnlCommsCtl.ctl_flags = CTL_FLAG_PRIVILEGED;
            krnlCommsCtl.ctl_send = comms_handle_send;
            krnlCommsCtl.ctl_getopt = comms_handle_get;
            krnlCommsCtl.ctl_setopt = comms_handle_set;
            krnlCommsCtl.ctl_connect = comms_handle_connect;
            krnlCommsCtl.ctl_disconnect = comms_handle_disconnect;

            error = ctl_register( &krnlCommsCtl, &krnlCommsRef );
            if( 0 == error )
            {
                rpal_debug_info( "KM/UM comms initialized OK" );
            }
            else
            {
                rpal_debug_critical( "KM/UM comms initialize error: %d", error );
            }
        }
    }
    
    return status;
}

kern_return_t hbs_kernel_acquisition_stop(kmod_info_t *ki, void *d)
{
    errno_t error = 0;
    int i = 0;
    
    g_is_shutting_down = 1;
    
    rpal_debug_info( "unregistering KM/UM comms (%d clients connected)", g_n_connected );
    error = ctl_deregister( krnlCommsRef );
    if( 0 == error )
    {
        rpal_debug_info( "KM/UM comms unregistered" );
    }
    else
    {
        rpal_debug_critical( "error unregistering KM/UM comms (clients still present?): %d", error );
        return KERN_FAILURE;
    }
    
    rpal_debug_info( "stopping collectors" );
    for( i = 0; i < ARRAY_N_ELEM( g_collectors ); i++ )
    {
        if( NULL == g_collectors[ i ].deinitializer ) continue;

        if( !g_collectors[ i ].deinitializer() )
        {
            rpal_debug_critical( "error deinitializing collector %d", i );
        }
    }

    if( NULL != g_connection_mutex )
    {
        rpal_mutex_free( g_connection_mutex );
        g_connection_mutex = NULL;
    }
    
    return KERN_SUCCESS;
}

