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

#ifndef _RP_HCP_BEACON_H
#define _RP_HCP_BEACON_H

#include <rpal/rpal.h>
#include <rpHostCommonPlatformLib/rpHCP_Common.h>
#include <librpcm/librpcm.h>

RBOOL
    startBeacons
    (

    );

RBOOL
    stopBeacons
    (

    );

RBOOL
    doSend
    (
        RpHcp_ModuleId sourceModuleId,
        rList toSend
    );

#endif
