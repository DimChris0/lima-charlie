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

#ifndef _RPAL_STRING_H
#define _RPAL_STRING_H

#include <rpal/rpal.h>

RBOOL 
    rpal_string_isprint 
    (
        RNCHAR ch
    );

RBOOL
    rpal_string_isprintW
    (
        RWCHAR ch
    );

RBOOL
    rpal_string_isprintA
    (
        RCHAR ch
    );

RU8
    rpal_string_str_to_byte
    (
        RPNCHAR str
    );

RVOID
    rpal_string_byte_to_str
    (
        RU8 b,
        RNCHAR c[ 2 ]
    );

RU32
    rpal_string_strlen
    (
        RPNCHAR str
    );

RU32
    rpal_string_strlenA
    (
        RPCHAR str
    );

RU32
    rpal_string_strlenW
    (
        RPWCHAR str
    );

RU32
    rpal_string_strsize
    (
        RPNCHAR str
    );


RU32
    rpal_string_strsizeW
    (
        RPWCHAR str
    );

RU32
    rpal_string_strsizeA
    (
        RPCHAR str
    );

RBOOL
    rpal_string_expandW
    (
        RPWCHAR str,
        RPWCHAR*  outStr
    );

RBOOL
    rpal_string_expandA
    (
        RPCHAR  str,
        RPCHAR*  outStr
    );

RBOOL
    rpal_string_expand
    (
        RPNCHAR  str,
        RPNCHAR*  outStr
    );

RPWCHAR
    rpal_string_atow
    (
        RPCHAR str
    );

RPCHAR
    rpal_string_wtoa
    (
        RPWCHAR str
    );

RPWCHAR
    rpal_string_ntow
    (
        RPNCHAR str
    );

RPCHAR
    rpal_string_ntoa
    (
        RPNCHAR str
    );

RPNCHAR
    rpal_string_wton
    (
        RPWCHAR str
    );

RPNCHAR
    rpal_string_aton
    (
        RPCHAR str
    );

RPNCHAR
    rpal_string_strcat
    (
        RPNCHAR str,
        RPNCHAR toAdd
    );

RPNCHAR
    rpal_string_strstr
    (
        RPNCHAR haystack,
        RPNCHAR needle
    );

RPNCHAR
    rpal_string_stristr
    (
        RPNCHAR haystack,
        RPNCHAR needle
    );

RPNCHAR
    rpal_string_itos
    (
        RU32 num,
        RPNCHAR outBuff,
        RU32 radix
    );

RPCHAR
    rpal_string_itosA
    (
        RU32 num,
        RPCHAR outBuff,
        RU32 radix
    );

RPWCHAR
    rpal_string_itosW
    (
        RU32 num,
        RPWCHAR outBuff,
        RU32 radix
    );

RPNCHAR
    rpal_string_strdup
    (
        RPNCHAR str
    );

RPWCHAR
    rpal_string_strdupW
    (
        RPWCHAR str
    );

RPCHAR
    rpal_string_strdupA
    (
        RPCHAR str
    );

RBOOL
    rpal_string_match
    (
        RPNCHAR pattern,
        RPNCHAR str,
        RBOOL isCaseSensitive
    );

RBOOL
    rpal_string_matchW
    (
        RPWCHAR pattern,
        RPWCHAR str,
        RBOOL isCaseSensitive
    );

RBOOL
    rpal_string_matchA
    (
        RPCHAR pattern,
        RPCHAR str,
        RBOOL isCaseSensitive
    );

RPNCHAR
    rpal_string_strcatEx
    (
        RPNCHAR strToExpand,
        RPNCHAR strToCat
    );

RPNCHAR
    rpal_string_strtok
    (
        RPNCHAR str,
        RNCHAR token,
        RPNCHAR* state
    );

RS32
    rpal_string_strcmp
    (
        RPNCHAR str1,
        RPNCHAR str2
    );

RS32
    rpal_string_strcmpW
    (
        RPWCHAR str1,
        RPWCHAR str2
    );

RS32
    rpal_string_strcmpA
    (
        RPCHAR str1,
        RPCHAR str2
    );

RS32
    rpal_string_stricmp
    (
        RPNCHAR str1,
        RPNCHAR str2
    );

RPNCHAR
    rpal_string_toupper
    (
        RPNCHAR str
    );

RPNCHAR
    rpal_string_tolower
    (
        RPNCHAR str
    );

RPWCHAR
    rpal_string_tolowerW
    (
        RPWCHAR str
    );

RPCHAR
    rpal_string_tolowerA
    (
        RPCHAR str
    );

RPNCHAR
    rpal_string_strcpy
    (
        RPNCHAR dst,
        RPNCHAR src
    );

RBOOL
    rpal_string_stoi
    (
        RPNCHAR str,
        RU32* pNum,
        RBOOL isStrict
    );

RBOOL
    rpal_string_hstoi
    (
        RPNCHAR str,
        RU32* pNum,
        RBOOL isStrict
    );
    
RBOOL
    rpal_string_fill
    (
        RPNCHAR str,
        RU32 nChar,
        RNCHAR fillWith
    );
    
RBOOL
    rpal_string_startswith
    (
        RPNCHAR haystack,
        RPNCHAR needle
    );
RBOOL
    rpal_string_startswithi
    (
        RPNCHAR haystack,
        RPNCHAR needle
    );

RBOOL
    rpal_string_endswith
    (
        RPNCHAR haystack,
        RPNCHAR needle
    );

RBOOL
    rpal_string_trim
    (
        RPNCHAR str,
        RPNCHAR charsToTrim
    );

RBOOL
    rpal_string_charIsAscii
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsAlphaNum
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsAlpha
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsNum
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsUpper
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsLower
    (
        RNCHAR c
    );

RBOOL
    rpal_string_charIsUpperW
    (
        RWCHAR c
    );

RBOOL
    rpal_string_charIsLowerW
    (
        RWCHAR c
    );

RBOOL
    rpal_string_charIsUpperA
    (
        RCHAR c
    );

RBOOL
    rpal_string_charIsLowerA
    (
        RCHAR c
    );

RNCHAR
    rpal_string_charToUpper
    (
        RNCHAR c
    );

RNCHAR
    rpal_string_charToLower
    (
        RNCHAR c
    );

RWCHAR
    rpal_string_charToUpperW
    (
        RWCHAR c
    );

RWCHAR
    rpal_string_charToLowerW
    (
        RWCHAR c
    );

RCHAR
    rpal_string_charToUpperA
    (
        RCHAR c
    );

RCHAR
    rpal_string_charToLowerA
    (
        RCHAR c
    );

#include <stdio.h>
#define rpal_string_snprintf(outStr,buffLen,format,...) snprintf((outStr),(buffLen),(format),__VA_ARGS__)
#define rpal_string_sscanf(inStr,format,...) sscanf((inStr),(format),__VA_ARGS__)

#define rpal_string_isEmpty(str) (NULL == (str) && 0 == (str)[ 0 ])

#endif
