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

#include "helpers.h"

RU64
    rpal_time_getLocal
    (

    )
{
    RU64 t = 0;

    KeQuerySystemTime( (PLARGE_INTEGER)&t );

    t = t / ( 10000 ) - 11644473600000;    // To POSIX epoch in msec

    return t;
}

RBOOL
    _copyUnicodeStringToBuffer
    (
        PCUNICODE_STRING str,
        RPWCHAR buff,
        RU32 buffSize
    )
{
    RBOOL isCopied = FALSE;
    RU32 sizeToCopy = 0;

    if( NULL != str )
    {
        sizeToCopy = MIN_OF( str->Length, buffSize - sizeof( WCHAR ) );
        memcpy( buff, str->Buffer, sizeToCopy );
        buff[ sizeToCopy / sizeof( WCHAR ) ] = 0;
    }

    return isCopied;
}