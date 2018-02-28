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
#include "stateful_helpers.h"
#include "stateful_framework.h"

//=============================================================================
//  COMMON PATHS INSIDE EVENTS
//=============================================================================
#define DEFINE_PATH(name,...)       rpcm_tag name[] = { __VA_ARGS__ }
DEFINE_PATH( PATH_EMPTY, 0 );
DEFINE_PATH( PATH_ROOT_FILE, RPCM_ANY_ONE_TAG, RP_TAGS_FILE_PATH, RPCM_END_TAG );
DEFINE_PATH( PATH_ROOT_PID, RPCM_ANY_ONE_TAG, RP_TAGS_PROCESS_ID, RPCM_END_TAG );
DEFINE_PATH( PATH_ROOT_PARENT_PID, RPCM_ANY_ONE_TAG, RP_TAGS_PARENT, RP_TAGS_PROCESS_ID, RPCM_END_TAG );

//=============================================================================
//  COMMON MATCHING
//=============================================================================
#define DEFINE_MATCH(name,matchType,newPathMatch,histPathMatch,newMatchValue,isMatchPattern,withinAtLeast,withinAtMost,isMatchFirstEventOnly,isRemoveMatching) tr_match_params name = { matchType, newPathMatch, histPathMatch, newMatchValue, isMatchPattern, withinAtLeast, withinAtMost, isMatchFirstEventOnly, isRemoveMatching, FALSE }; \
                                                                                                                                                               tr_match_params NOT_ ##name = { matchType, newPathMatch, histPathMatch, newMatchValue, isMatchPattern, withinAtLeast, withinAtMost, isMatchFirstEventOnly, isRemoveMatching, TRUE }
tr_match_params MATCHING_EMPTY = { 0 };
DEFINE_MATCH( MATCHING_PID, RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, FALSE );
DEFINE_MATCH( MATCHING_PARENT_PID, RPCM_RU32, PATH_ROOT_PARENT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, FALSE );
DEFINE_MATCH( MATCHING_FIRST_PID, RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, TRUE, FALSE );
DEFINE_MATCH( MATCHING_FIRST_PARENT_PID, RPCM_RU32, PATH_ROOT_PARENT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, TRUE, FALSE );
DEFINE_MATCH( MATCHING_PID_REMOVE, RPCM_RU32, PATH_ROOT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, TRUE );
DEFINE_MATCH( MATCHING_PARENT_PID_REMOVE, RPCM_RU32, PATH_ROOT_PARENT_PID, PATH_ROOT_PID, { 0 }, FALSE, 0, 0, FALSE, TRUE );
