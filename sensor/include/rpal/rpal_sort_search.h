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

#ifndef _RPAL_SORT_SEARCH
#define _RPAL_SORT_SEARCH

#include <rpal/rpal.h>

typedef RS32( *rpal_ordering_func )( RPVOID p1, RPVOID p2 );

RBOOL
    rpal_sort_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        rpal_ordering_func orderFunc
    );

RU32
    rpal_binsearch_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        RPVOID key,
        rpal_ordering_func orderFunc
    );

RU32
    rpal_binsearch_array_closest
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        RPVOID key,
        rpal_ordering_func orderFunc,
        RBOOL isFromBelow
    );

RS32
    rpal_order_RU32
    (
        RPU32 p1,
        RPU32 p2
    );


RS32
    rpal_order_RU64
    (
        RPU64 p1,
        RPU64 p2
    );

#endif
