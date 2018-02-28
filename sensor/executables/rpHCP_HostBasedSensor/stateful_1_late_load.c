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

#include "stateful_framework.h"
#include "stateful_helpers.h"
#include "stateful_events.h"

#define LOAD_LATE_AFTER_SEC (MSEC_FROM_SEC(60))

static tr_match_params matching_module = {
    RPCM_RU32,
    PATH_ROOT_PID,
    PATH_ROOT_PID,
    { 0 },
    FALSE,
    LOAD_LATE_AFTER_SEC,
    0,
    TRUE,
    FALSE
};

// State 0: New process starting
STATE( 0, 1, TRANSITION( FALSE, 
                         TRUE,
                         FALSE,
                         RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                         1, 
                         PATH_EMPTY,
                         NULL ) );
// State 1: Modules after X time, if terminated delete (state 0)
STATE( 1, 2, TRANSITION( FALSE,
                         FALSE,
                         FALSE,
                         RP_TAGS_NOTIFICATION_TERMINATE_PROCESS,
                         0, // Bail without reporting
                         MATCHING_PID,
                         tr_match ),
             TRANSITION( FALSE,
                         FALSE,
                         FALSE,
                         RP_TAGS_NOTIFICATION_NEW_PROCESS,
                         0, // Bail without reporting
                         MATCHING_PID,
                         tr_match ),
             TRANSITION( TRUE,
                         TRUE,
                         FALSE,
                         RP_TAGS_NOTIFICATION_MODULE_LOAD,
                         0, // We only match the first late loading module so that processes 
                            // commonly loading late modules don't keep producing events
                         matching_module,
                         tr_match ) );

STATEFUL_MACHINE( 1, STATEFUL_MACHINE_1_EVENT, 2, STATE_PTR( 0 ),
                                                  STATE_PTR( 1 ) );
