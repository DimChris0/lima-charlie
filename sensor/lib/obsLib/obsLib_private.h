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

#ifndef _OBSLIB_PRIVATE_H
#define _OBSLIB_PRIVATE_H

#include <obsLib/obsLib.h>

typedef struct
{
    RU32 sigSize;
    RPVOID pContext;

} ObsSig, *PObsSig;

typedef struct
{
    PObsSig* pSigsHit;
    RU8 startOffset;
    RU8 nElements;
    RU8 nAllocated;
    RPVOID elements[];

} ObsNode, *PObsNode;


typedef struct
{
    ObsType searchType;
    RPVOID targetBuffer;
    RU32 targetBufferSize;
    RU32 currentOffset;
    RU32 maxDepth;
    RU32 maxMem;
    PObsNode root;
    PObsNode currentState;
    PObsSig* curHits;
    RU32 curDepth;
    RU32 nPatterns;

} _HObs, *_PHObs;





#endif
