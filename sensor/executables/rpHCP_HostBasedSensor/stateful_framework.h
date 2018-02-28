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

#ifndef HBS_STATEFUL_FRAMEWORK_H
#define HBS_STATEFUL_FRAMEWORK_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define STATEFUL_MACHINE_NAME(machineId) stateful_ ##machineId##_desc
#define STATEFUL_MACHINE(machineId,reportEvent,nStates,...) StatefulMachineDescriptor STATEFUL_MACHINE_NAME( machineId ) = { (reportEvent), (nStates), { __VA_ARGS__ } }
#define TRANSITION(isReportOnMatch,isRecordEventOnMatch,isFinishOnEmptySet,eventTypeOnly,destState,params,matchFunction) { (isReportOnMatch), (isRecordEventOnMatch), (isFinishOnEmptySet), (eventTypeOnly), (destState), (&(params)), ((transition_eval_func)matchFunction) }
#define STATE(stateId,nTransitions,...) static StatefulState state_ ##stateId##_def = { (nTransitions), { __VA_ARGS__ } }

#define STATE_PTR(stateId) &state_ ##stateId##_def

typedef struct
{
    rpcm_tag eventType;
    rSequence data;
    rRefCount ref;
    RTIME ts;

} StatefulEvent;


typedef struct
{
    rpcm_tag reportEventType;
    RU32 nStates;
    RPVOID states[];
} StatefulMachineDescriptor;

typedef struct
{
    rVector history;
    RU32 currentState;
    StatefulMachineDescriptor* desc;

} StatefulMachine;

typedef RBOOL( *transition_eval_func )( StatefulMachine* machine, StatefulEvent* event, RPVOID parameters );

typedef struct
{
    RBOOL isReportOnMatch;
    RBOOL isRecordEventOnMatch;
    RBOOL isFinishOnEmptySet;
    rpcm_tag eventTypeOnly;
    RU32 destState;
    RPVOID parameters;
    transition_eval_func transition;
} StatefulTransition;

typedef struct
{
    RU32 nTransitions;
    StatefulTransition transitions[];

} StatefulState;


RBOOL
    SMUpdate
    (
        StatefulMachine*  machine,
        StatefulEvent* event
    );

StatefulMachine*
    SMPrime
    (
        StatefulMachineDescriptor* desc,
        StatefulEvent* event
    );

RVOID
    SMFreeMachine
    (
        StatefulMachine* machine
    );

StatefulEvent*
    SMEvent_new
    (
        rpcm_tag eventType,
        rSequence data
    );

//=============================================================================
//  TRANSITIONS
//=============================================================================

typedef struct
{
    rpcm_type matchType;
    rpcm_tag* newPathMatch;
    rpcm_tag* histPathMatch;
    rpcm_elem_record newMatchValue;
    RBOOL isMatchPattern;
    RTIME withinAtLeast;
    RTIME withinAtMost;
    RBOOL isMatchFirstEventOnly;
    RBOOL isRemoveMatching;
    RBOOL isInvertMatch;
} tr_match_params;

RBOOL
    tr_match
    (
        StatefulMachine* machine, 
        StatefulEvent* event,
        tr_match_params* parameters
    );

typedef struct
{
    tr_match_params params[ 2 ];
} tr_and_match_params;

RBOOL
    tr_and_match
    (
        StatefulMachine* machine,
        StatefulEvent* event,
        tr_and_match_params* parameters
    );


#endif
