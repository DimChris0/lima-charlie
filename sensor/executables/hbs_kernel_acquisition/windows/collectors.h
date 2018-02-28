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

#ifndef _KERNEL_ACQUISITION_COLLECTORS_H
#define _KERNEL_ACQUISITION_COLLECTORS_H

#include <rpal/rpal_datatypes.h>
#include "helpers.h"

// Due to the structure of the Ioctl in Windows, REMEMBER THAT ARGS AND RESULT BUFFER
// ARE ONE AND THE SAME, COPY OUT AN DATA YOU NEED FROM THE ARGS BEFORE WRITING RESULTS.
typedef int( *collector_task )( RPU8 pArgs, RU32 argsSize, RPU8 pResult, RU32* resultSize );

#define _DECLARE_COLLECTOR(cId) RBOOL collector_ ## cId ## _initialize( PDRIVER_OBJECT driverObject, PDEVICE_OBJECT deviceObject );\
                                RBOOL collector_ ## cId ## _deinitialize();

#define _DECLARE_TASK(name) RBOOL name( RPU8 pArgs, RU32 argSize, RPU8 pResult, RU32* resultSize )

_DECLARE_COLLECTOR( 1 );
_DECLARE_COLLECTOR( 2 );
_DECLARE_COLLECTOR( 3 );
_DECLARE_COLLECTOR( 4 );
_DECLARE_TASK( task_get_new_processes );
_DECLARE_TASK( task_get_new_module_loads );
_DECLARE_TASK( task_get_new_files );
_DECLARE_TASK( task_get_new_network );
_DECLARE_TASK( task_get_new_dns );
_DECLARE_TASK( task_segregate_network );
_DECLARE_TASK( task_rejoin_network );


#endif
