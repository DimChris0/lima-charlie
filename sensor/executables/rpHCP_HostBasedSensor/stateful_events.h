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
#include <rpHostCommonPlatformLib/rTags.h>
#include "stateful_framework.h"

//=============================================================================
// Stateful Detects Naming Convention
//=============================================================================
#define ENABLED_STATEFUL(num) &(STATEFUL_MACHINE_NAME(num))
#define DISABLED_STATEFUL(num) NULL

#ifdef RPAL_PLATFORM_WINDOWS
#define ENABLED_WINDOWS_STATEFUL(num) ENABLED_STATEFUL(num)
#define ENABLED_LINUX_STATEFUL(num) DISABLED_STATEFUL(num)
#define ENABLED_OSX_STATEFUL(num) DISABLED_STATEFUL(num)
#define DISABLED_WINDOWS_STATEFUL(num) DISABLED_STATEFUL(num)
#define DISABLED_LINUX_STATEFUL(num) ENABLED_STATEFUL(num)
#define DISABLED_OSX_STATEFUL(num) ENABLED_STATEFUL(num)
#elif defined( RPAL_PLATFORM_LINUX )
#define ENABLED_WINDOWS_STATEFUL(num) DISABLED_STATEFUL(num)
#define ENABLED_LINUX_STATEFUL(num) ENABLED_STATEFUL(num)
#define ENABLED_OSX_STATEFUL(num) DISABLED_STATEFUL(num)
#define DISABLED_WINDOWS_STATEFUL(num) ENABLED_STATEFUL(num)
#define DISABLED_LINUX_STATEFUL(num) DISABLED_STATEFUL(num)
#define DISABLED_OSX_STATEFUL(num) ENABLED_STATEFUL(num)
#elif defined( RPAL_PLATFORM_MACOSX )
#define ENABLED_WINDOWS_STATEFUL(num) DISABLED_STATEFUL(num)
#define ENABLED_LINUX_STATEFUL(num) DISABLED_STATEFUL(num)
#define ENABLED_OSX_STATEFUL(num) ENABLED_STATEFUL(num)
#define DISABLED_WINDOWS_STATEFUL(num) ENABLED_STATEFUL(num)
#define DISABLED_LINUX_STATEFUL(num) ENABLED_STATEFUL(num)
#define DISABLED_OSX_STATEFUL(num) DISABLED_STATEFUL(num)
#endif

#define DECLARE_STATEFUL_MACHINE(machineId) extern StatefulMachineDescriptor STATEFUL_MACHINE_NAME(machineId)

//=============================================================================
//  Declaration of all stateful detects
//=============================================================================
DECLARE_STATEFUL_MACHINE( 0 );
#define STATEFUL_MACHINE_0_EVENT    RP_TAGS_NOTIFICATION_RECON_BURST

DECLARE_STATEFUL_MACHINE( 1 );
#define STATEFUL_MACHINE_1_EVENT    RP_TAGS_NOTIFICATION_LATE_MODULE_LOAD

DECLARE_STATEFUL_MACHINE( 2 );
#define STATEFUL_MACHINE_2_EVENT    RP_TAGS_NOTIFICATION_POSSIBLE_DOC_EXPLOIT
