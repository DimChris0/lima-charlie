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

#include <rpHostCommonPlatformIFaceLib/rpHostCommonPlatformIFaceLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define RPAL_FILE_ID     49

FORCE_LINK_THIS(HCP_IFACE);

#pragma warning( disable: 4127 ) // Disabling error on constant expression in condition

rpHCPModuleContext* g_Module_Context = NULL;
extern RpHcp_ModuleId g_current_Module_id;
extern RU32( RPAL_THREAD_FUNC RpHcpI_mainThread )( rEvent isTimeToStop );
extern RVOID( RpHcpI_receiveMessage )( rSequence message );

RU32
RPAL_EXPORT
RPAL_THREAD_FUNC
    rpHcpI_entry
    (
        rpHCPModuleContext* moduleContext
    )
{
    RU32 ret = (RU32)(-1);
    rThread hMain = 0;

    if( NULL != moduleContext )
    {
        g_Module_Context = moduleContext;

        if( rpal_initialize( moduleContext->rpalContext, g_current_Module_id ) )
        {
            ret = (RU32)(-2);

            if( 0 != ( hMain = rpal_thread_new( RpHcpI_mainThread, 
                                                g_Module_Context->isTimeToStop ) ) )
            {
                rpal_debug_info( "main module worker started" );
                ret = 0;

                while( TRUE )
                {
                    if( rpal_thread_wait( hMain, ( 1 * 1000 ) ) )
                    {
                        break;
                    }
                }
                
                rpal_debug_info( "main module worker finished" );

                rpal_thread_free( hMain );
            }
            else
            {
                rpal_debug_error( "failed spawning module main worker" );
            }

            rpal_Context_cleanup();

            rpal_Context_deinitialize();
        }
        else
        {
            rpal_debug_error( "failed IFace init" );
        }
    }

    return ret;
}

RU32
RPAL_EXPORT
RPAL_THREAD_FUNC
    rpHcpI_receiveMessage
    (
        rSequence message
    )
{
    RpHcpI_receiveMessage( message );
    return 0;
}

RBOOL
    rpHcpI_sendHome
    (
        rList requests
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != g_Module_Context &&
        NULL != g_Module_Context->func_sendHome )
    {
        isSuccess = g_Module_Context->func_sendHome( g_current_Module_id, requests );
    }

    return isSuccess;
}


RBOOL
    rpHcpI_getId
    (
        rpHCPId* pId
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != g_Module_Context &&
        NULL != g_Module_Context->pCurrentId &&
        NULL != pId )
    {
        isSuccess = TRUE;
        *pId = *g_Module_Context->pCurrentId;
    }

    return isSuccess;
}

rSequence
    rpHcpI_hcpIdToSeq
    (
        rpHCPId id
    )
{
    rSequence seq = NULL;

    if( NULL != ( seq = rSequence_new() ) )
    {
        if( !rSequence_addBUFFER( seq, RP_TAGS_HCP_SENSOR_ID, id.sensor_id, sizeof( id.sensor_id ) ) ||
            !rSequence_addBUFFER( seq, RP_TAGS_HCP_ORG_ID, id.org_id, sizeof( id.org_id ) ) ||
            !rSequence_addBUFFER( seq, RP_TAGS_HCP_INSTALLER_ID, id.ins_id, sizeof( id.ins_id ) ) ||
            !rSequence_addRU32( seq, RP_TAGS_HCP_ARCHITECTURE, id.architecture ) ||
            !rSequence_addRU32( seq, RP_TAGS_HCP_PLATFORM, id.platform ) )
        {
            DESTROY_AND_NULL( seq, rSequence_free );
        }
    }

    return seq;
}

rpHCPId
    rpHcpI_seqToHcpId
    (
        rSequence seq
    )
{
    rpHCPId id = {0};
    RPU8 tmpSensorId = NULL;
    RU32 tmpSize = 0;
    RPU8 tmpOrgId = NULL;
    RPU8 tmpInsId = NULL;

    if( NULL != seq )
    {
        if( rSequence_getBUFFER( seq, RP_TAGS_HCP_SENSOR_ID, &tmpSensorId, &tmpSize ) &&
            sizeof( id.sensor_id ) == tmpSize )
        {
            rpal_memory_memcpy( id.sensor_id, tmpSensorId, sizeof( id.sensor_id ) );
        }

        if( rSequence_getBUFFER( seq, RP_TAGS_HCP_ORG_ID, &tmpOrgId, &tmpSize ) &&
            sizeof( id.org_id ) == tmpSize )
        {
            rpal_memory_memcpy( id.org_id, tmpOrgId, sizeof( id.org_id ) );
        }

        if( rSequence_getBUFFER( seq, RP_TAGS_HCP_INSTALLER_ID, &tmpInsId, &tmpSize ) &&
            sizeof( id.ins_id ) == tmpSize )
        {
            rpal_memory_memcpy( id.ins_id, tmpInsId, sizeof( id.ins_id ) );
        }

        rSequence_getRU32( seq, RP_TAGS_HCP_ARCHITECTURE, &id.architecture );
        rSequence_getRU32( seq, RP_TAGS_HCP_PLATFORM, &id.platform );
    }

    return id;
}

rEvent
    rpHcpI_getOnlineEvent
    (

    )
{
    rEvent isOnlineEvent = NULL;

    if( NULL != g_Module_Context )
    {
        isOnlineEvent = g_Module_Context->isOnlineEvent;
    }

    return isOnlineEvent;
}