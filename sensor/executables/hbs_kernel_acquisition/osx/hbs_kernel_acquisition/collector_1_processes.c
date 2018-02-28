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

#ifndef _NUM_BUFFERED_PROCESSES
    #define _NUM_BUFFERED_PROCESSES 200
#endif

//==============================================================================
//  Enable the following flag to revert to the KAUTH method of process
//  monitoring. KAUTH is not as reliable and will miss fork-based execution
//  however it is officially supported by Apple and less likely to break between
//  new releases.
//==============================================================================
#define _USE_KAUTH

static rMutex g_collector_1_mutex = NULL;
static KernelAcqProcess g_processes[ _NUM_BUFFERED_PROCESSES ] = { 0 };
static uint32_t g_nextProcess = 0;

#ifdef _USE_KAUTH
#include <sys/kauth.h>

static kauth_listener_t g_listener = NULL;

static int
    new_proc_listener
    (
        kauth_cred_t   credential,
        void *         idata,
        kauth_action_t action,
        uintptr_t      arg0,
        uintptr_t      arg1,
        uintptr_t      arg2,
        uintptr_t      arg3
    )
#else
#include <security/mac_policy.h>

mac_policy_handle_t g_policy = 0;
static struct mac_policy_conf g_policy_conf = { 0 };
static struct mac_policy_ops g_policy_ops = { 0 };

static int
    new_proc_listener
    (
        kauth_cred_t cred,
        struct vnode *vp,
        struct vnode *scriptvp,
        struct label *vnodelabel,
        struct label *scriptlabel,
        struct label *execlabel,
        struct componentname *cnp,
        u_int *csflags,
        void *macpolicyattr,
        size_t macpolicyattrlen
    )
#endif
{
    #ifdef _USE_KAUTH
    vnode_t prog = (vnode_t)arg0;
    const char* file_path = (const char*)arg1;
    #else
    int pathLen = sizeof( g_processes[ 0 ].path );
    #endif
    
    pid_t pid = 0;
    pid_t ppid = 0;
    uid_t uid = 0;
    
    #ifdef _USE_KAUTH
    if( KAUTH_FILEOP_EXEC != action ||
        ( NULL != prog &&
          VREG != vnode_vtype( prog ) ) )
    {
        return KAUTH_RESULT_DEFER;
    }
    #endif
    
    uid = kauth_getuid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    
    // We skip a known false positive
    if( 0 == ppid && 1 == pid )
    {
        #ifdef _USE_KAUTH
            return KAUTH_RESULT_DEFER;
        #else
            return 0; // Always allow
        #endif
    }
    
    if( NULL != file_path )
    {
        // rpal_debug_info( "!!!!!! process start: %d/%d/%d %s", ppid, pid, uid, file_path );
    }
    
    rpal_mutex_lock( g_collector_1_mutex );
    
#ifdef _USE_KAUTH
    if( NULL != file_path )
    {
        strncpy( g_processes[ g_nextProcess ].path,
                 file_path,
                 sizeof( g_processes[ g_nextProcess ].path ) - 1 );
    }
#else
    vn_getpath( vp, g_processes[ g_nextProcess ].path, &pathLen );
#endif

    g_processes[ g_nextProcess ].pid = pid;
    g_processes[ g_nextProcess ].ppid = ppid;
    g_processes[ g_nextProcess ].uid = uid;
    g_processes[ g_nextProcess ].ts = rpal_time_getLocal();
    
    g_nextProcess++;
    if( g_nextProcess == _NUM_BUFFERED_PROCESSES )
    {
        g_nextProcess = 0;
        rpal_debug_warning( "overflow of the execution buffer" );
    }
    
    // rpal_debug_info( "now %d processes in buffer", g_nextProcess );
    
    rpal_mutex_unlock( g_collector_1_mutex );

#ifdef _USE_KAUTH
    return KAUTH_RESULT_DEFER;
#else
    return 0; // Always allow
#endif
}

int
    task_get_new_processes
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
        rpal_mutex_lock( g_collector_1_mutex );
        toCopy = (*resultSize) / sizeof( KernelAcqProcess );
        toCopy = ( toCopy > g_nextProcess ? g_nextProcess : toCopy );
        *resultSize = toCopy * sizeof( KernelAcqProcess );
        
        if( 0 != toCopy )
        {
            memcpy( pResult, g_processes, *resultSize );
            
            g_nextProcess -= toCopy;
            if( 0 != g_nextProcess )
            {
                memmove( g_processes,
                         &g_processes[ toCopy ],
                         g_nextProcess * sizeof( KernelAcqProcess ) );
            }
        }
        
        rpal_mutex_unlock( g_collector_1_mutex );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
    collector_1_initialize
    (
        void* d
    )
{
    int isSuccess = 0;

#ifndef _DISABLE_COLLECTOR_1
    if( NULL != ( g_collector_1_mutex = rpal_mutex_create() ) )
    {
#ifdef _USE_KAUTH
        g_listener = kauth_listen_scope( KAUTH_SCOPE_FILEOP, new_proc_listener, NULL );
        if( NULL != g_listener )
        {
            isSuccess = 1;
        }
#else
        g_policy_ops.mpo_vnode_check_exec = (mpo_vnode_check_exec_t*)new_proc_listener;
        
        g_policy_conf.mpc_name = "rp_hcp_hbs";
        g_policy_conf.mpc_fullname = "LimaCharlie Host Based Sensor";
        g_policy_conf.mpc_labelnames = NULL;
        g_policy_conf.mpc_labelname_count = 0;
        g_policy_conf.mpc_ops = &g_policy_ops;
        g_policy_conf.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK;
        g_policy_conf.mpc_field_off = NULL;
        g_policy_conf.mpc_runtime_flags = 0;
        g_policy_conf.mpc_list = NULL;
        g_policy_conf.mpc_data = NULL;
        
        mac_policy_register( &g_policy_conf, &g_policy, d );
        if( 0 != g_policy )
        {
            isSuccess = 1;
        }
#endif
        
        if( !isSuccess )
        {
            rpal_mutex_free( g_collector_1_mutex );
        }
    }
#else
    UNREFERENCED_PARAMETER( d );
    isSuccess = 1;
#endif
    
    return isSuccess;
}

int
    collector_1_deinitialize
    (

    )
{
#ifndef _DISABLE_COLLECTOR_1
    rpal_mutex_lock( g_collector_1_mutex );
#ifdef _USE_KAUTH
    kauth_unlisten_scope( g_listener );
#else
    mac_policy_unregister( g_policy );
#endif
    rpal_mutex_free( g_collector_1_mutex );
#endif
    return 1;
}
