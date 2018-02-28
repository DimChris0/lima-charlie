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
#include <librpcm/librpcm.h>
#include "stateful_framework.h"

//=============================================================================
//  COMMON PATHS INSIDE EVENTS
//=============================================================================
#define DECLARE_PATH(name)          extern rpcm_tag name[]
DECLARE_PATH( PATH_EMPTY );
DECLARE_PATH( PATH_ROOT_FILE );
DECLARE_PATH( PATH_ROOT_PID );
DECLARE_PATH( PATH_ROOT_PARENT_PID );

//=============================================================================
//  COMMON MATCHING
//=============================================================================
#define _MATCHING_PID               { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, FALSE, FALSE }
#define _MATCHING_PARENT_PID        { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PARENT_PID, { 0 }, FALSE, 0, 0, FALSE, FALSE, FALSE }
#define _MATCHING_FIRST_PID         { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, TRUE, FALSE, FALSE }
#define _MATCHING_FIRST_PARENT_PID  { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PARENT_PID, { 0 }, FALSE, 0, 0, TRUE, FALSE, FALSE }
#define _MATCHING_PID_REMOVE        { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, TRUE, FALSE }
#define _MATCHING_PARENT_PID_REMOVE { RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PARENT_PID, { 0 }, FALSE, 0, 0, FALSE, TRUE, FALSE }
#define DECLARE_MATCH(name)         extern tr_match_params name; \
                                    extern tr_match_params NOT_ ##name
extern tr_match_params MATCHING_EMPTY;
DECLARE_MATCH( MATCHING_PID );
DECLARE_MATCH( MATCHING_PARENT_PID );
DECLARE_MATCH( MATCHING_FIRST_PID );
DECLARE_MATCH( MATCHING_FIRST_PARENT_PID );
DECLARE_MATCH( MATCHING_PID_REMOVE );
DECLARE_MATCH( MATCHING_PARENT_PID_REMOVE );

//==============================================================================
//  COMMON GENERATOR MACROS
//==============================================================================
#define NATIVE_STRING_LITERAL(progName) { 0, RPCM_STRINGN, 0, _NC( progName ) }
#define EXECUTABLE_MATCHES(progName) { RPCM_STRINGN, PATH_ROOT_FILE, NULL, NATIVE_STRING_LITERAL(progName), TRUE, 0, 0, FALSE, FALSE, FALSE }
#define AND_MATCH(...)  { NUMARGS( __VA_ARGS__ ), { __VA_ARGS__ } }