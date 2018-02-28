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

#ifndef _PRIVATE_HCP_H
#define _PRIVATE_HCP_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <rpHostCommonPlatformLib/rpHCP_Common.h>
#include "globalContext.h"

rBlob
    wrapFrame
    (
        RpHcp_ModuleId moduleId,
        rList messages,
        RBOOL isIncludeUncompressedSize
    );

RBOOL
    unwrapFrame
    (
        rBlob frame,
        RpHcp_ModuleId* pModuleId,
        rList* pMessages
    );

RBOOL
    sendFrame
    (
        rpHCPContext* pContext,
        RpHcp_ModuleId moduleId,
        rList messages,
        RBOOL isForAnotherSensor
    );

RBOOL
    recvFrame
    (
        rpHCPContext* pContext,
        RpHcp_ModuleId* targetModuleId,
        rList* pMessages,
        RU32 timeoutSec
    );

RBOOL
    loadModule
    (
        rpHCPContext* hcpContext,
        rSequence seq
    );

RBOOL
    unloadModule
    (
        rpHCPContext* hcpContext,
        rSequence seq
    );

RBOOL
    saveHcpId
    (
        RPNCHAR storePath,
        rpHCPIdentStore* ident,
        RPU8 token,
        RU32 tokenSize
    );

RBOOL
    getStoreConfID
    (
        RPNCHAR storePath,
        rpHCPContext* hcpContext
    );

RBOOL
    upgradeHcp
    (
        rSequence seq
    );

#endif
