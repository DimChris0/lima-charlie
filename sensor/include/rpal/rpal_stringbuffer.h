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

#ifndef _RPAL_STRINGBUFFER
#define _RPAL_STRINGBUFFER

#include <rpal/rpal.h>

typedef RPVOID	rString;

rString
    rpal_stringbuffer_new
    (
        RU32 initialSize,
        RU32 growBy
    );

RVOID
    rpal_stringbuffer_free
    (
        rString pStringBuffer
    );

RVOID
    rpal_stringbuffer_freeWrapper
    (
        rString pStringBuffer
    );

RBOOL
    rpal_stringbuffer_add
    (
        rString pStringBuffer,
        RPNCHAR pString
    );

RPNCHAR
    rpal_stringbuffer_getString
    (
        rString pStringBuffer
    );

#endif
