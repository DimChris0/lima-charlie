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

#ifndef collectors_h
#define collectors_h

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/vnode.h>

#include "helpers.h"

typedef int (*collector_task)( void* pArgs, int argsSize, void* pResult, uint32_t* resultSize );

#define _DECLARE_COLLECTOR(cId) int collector_ ## cId ## _initialize( void* d );\
int collector_ ## cId ## _deinitialize();

#define _DECLARE_TASK(name) int name( void* pArgs, int argSize, void* pResult, uint32_t* resultSize )

_DECLARE_COLLECTOR( 1 );
_DECLARE_COLLECTOR( 2 );
_DECLARE_COLLECTOR( 4 );
_DECLARE_TASK( task_get_new_processes );
_DECLARE_TASK( task_get_new_fileio );
_DECLARE_TASK( task_get_new_connections );
_DECLARE_TASK( task_get_new_dns );
_DECLARE_TASK( task_segregate_network );
_DECLARE_TASK( task_rejoin_network );



#endif /* collectors_h */
