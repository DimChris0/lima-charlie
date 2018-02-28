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

#include <rpal/rpal_string.h>

#define RPAL_FILE_ID    9

#ifdef RPAL_PLATFORM_WINDOWS
#pragma warning( disable: 4996 ) // Disabling error on deprecated/unsafe
#endif

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )

#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>
#include <ctype.h>

static char*
    strupr
    (
        char* s
    )
{
    char* p = s;
    if( NULL != s )
    {
        while ( 0 != ( *p = toupper( *p ) ) )
        {
            p++;
        }
    }
    return s;
}

static char*
    strlwr
    (
        char* s
    )
{
    char* p = s;
    if( NULL != s )
    {
        while( 0 != ( *p = tolower( *p ) ) )
        {
            p++;
        }
    }
    return s;
}

static RWCHAR*
    wcsupr
    (
        RWCHAR* s
    )
{
    RWCHAR* p = s;
    if( NULL != s )
    {
        while ( 0 != ( *p = towupper( *p ) ) )
        {
            p++;
        }
    }
    return s;
}

static RWCHAR*
    wcslwr
    (
        RWCHAR* s
    )
{
    RWCHAR* p = s;
    if( NULL != s )
    {
        while( 0 != ( *p = towlower( *p ) ) )
        {
            p++;
        }
    }
    return s;
}
#endif

static 
RU8 _hexToByteRef[ 0xFF ] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                              0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

static
RCHAR _byteToHexRef[ 0x10 ] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

RBOOL
    rpal_string_isprintW
    (
        RWCHAR ch
    )
{
    return iswprint( ch );
}

RBOOL
    rpal_string_isprintA
    (
        RCHAR ch
    )
{
    return isprint( ch );
}

RBOOL 
    rpal_string_isprint 
    (
        RNCHAR ch
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_isprintW( ch );
#else
    return rpal_string_isprintA( ch );
#endif
}

RU8
    rpal_string_str_to_byte
    (
        RPNCHAR str
    )
{
    RU8 b = 0;

    if( NULL != str )
    {
        b = _hexToByteRef[ ((RU8*)str)[ 0 ] ] << 4;
        b |= _hexToByteRef[ ((RU8*)str)[ 1 ] ];
    }

    return b;
}

RVOID
    rpal_string_byte_to_str
    (
        RU8 b,
        RNCHAR c[ 2 ]
    )
{
    c[ 0 ] = _byteToHexRef[ (b & 0xF0) >> 4 ];
    c[ 1 ] = _byteToHexRef[ (b & 0x0F) ];
}

RU32
    rpal_string_strlenW
    (
        RPWCHAR str
    )
{
    RU32 size = 0;

    if( NULL != str )
    {
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        // The glibc implementation is broken on non-alignmed pointers
        // which is not acceptable, FFS.
        while( 0 != *str )
        {
            size++;
            str++;
        }
#else
        size = (RU32)wcslen( str );
#endif
    }

    return size;
}

RU32
    rpal_string_strlenA
    (
        RPCHAR str
    )
{
    RU32 size = 0;

    if( NULL != str )
    {
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        // The glibc implementation is broken on non-alignmed pointers
        // which is not acceptable, FFS.
        while( 0 != *str )
        {
            size++;
            str++;
        }
#else
        size = (RU32)strlen( str );
#endif
    }

    return size;
}

RU32
    rpal_string_strlen
    (
        RPNCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_strlenW( str );
#else
    return rpal_string_strlenA( str );
#endif
}

RU32
    rpal_string_strsizeW
    (
        RPWCHAR str
    )
{
    RU32 size = 0;

    if( NULL != str )
    {
        size = (RU32)( rpal_string_strlenW( str ) + 1 ) * sizeof( RWCHAR );
    }

    return size;
}

RU32
    rpal_string_strsizeA
    (
        RPCHAR str
    )
{
    RU32 size = 0;

    if( NULL != str )
    {
        size = (RU32)( rpal_string_strlenA( str ) + 1 ) * sizeof( RCHAR );
    }

    return size;
}

RU32
    rpal_string_strsize
    (
        RPNCHAR str
    )
{
    RU32 size = 0;

    if( NULL != str )
    {
        size = (RU32)( rpal_string_strlen( str ) + 1 ) * sizeof( RNCHAR );
    }

    return size;
}


RBOOL
    rpal_string_expandW
    (
        RPWCHAR str,
        RPWCHAR*  outStr
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != str &&
        NULL != outStr )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RPWCHAR tmp = NULL;
        RU32 size = 0;
        RU32 len = 0;

        if( _WCH( '"' ) == str[ 0 ] )
        {
            len = rpal_string_strlen( str );

            if( _WCH( '"' == str[ len - 1 ] ) )
            {
                str[ len - 1 ] = 0;
            }

            str++;
        }

        size = ExpandEnvironmentStringsW( str, NULL, 0 );

        if( 0 != size )
        {
            tmp = rpal_memory_alloc( ( size + 1 ) * sizeof( RWCHAR ) );

            if( rpal_memory_isValid( tmp ) )
            {
                size = ExpandEnvironmentStringsW( str, tmp, size );

                if( 0 != size &&
                    rpal_memory_isValid( tmp ) )
                {
                    isSuccess = TRUE;

                    *outStr = tmp;
                }
                else
                {
                    rpal_memory_free( tmp );
                }
            }
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( NULL != ( *outStr = rpal_string_strdupW( str ) ) )
        {
            isSuccess = TRUE;
        }
#endif
    }

    return isSuccess;
}

RBOOL
    rpal_string_expandA
    (
        RPCHAR  str,
        RPCHAR*  outStr
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != str &&
        NULL != outStr )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RPCHAR tmp = NULL;
        RU32 size = 0;
        RU32 len = 0;

        if( '"' == str[ 0 ] )
        {
            len = rpal_string_strlenA( str );

            if( '"' == str[ len - 1 ] )
            {
                str[ len - 1 ] = 0;
            }

            str++;
        }

        size = ExpandEnvironmentStringsA( str, NULL, 0 );

        if( 0 != size )
        {
            tmp = rpal_memory_alloc( ( size + 1 ) * sizeof( RCHAR ) );

            if( rpal_memory_isValid( tmp ) )
            {
                size = ExpandEnvironmentStringsA( str, tmp, size );

                if( 0 != size &&
                    rpal_memory_isValid( tmp ) )
                {
                    isSuccess = TRUE;

                    *outStr = tmp;
                }
                else
                {
                    rpal_memory_free( tmp );
                }
            }
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( NULL != ( *outStr = rpal_string_strdupA( str ) ) )
        {
            isSuccess = TRUE;
        }
#endif
    }

    return isSuccess;
}

RBOOL
    rpal_string_expand
    (
        RPNCHAR  str,
        RPNCHAR*  outStr
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_expandW( str, outStr );
#else
    return rpal_string_expandA( str, outStr );
#endif
}

RPWCHAR
    rpal_string_atow
    (
        RPCHAR str
    )
{
    RPWCHAR wide = NULL;
    RU32 nChar = 0;
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPCHAR tmp = NULL;
#endif

    if( NULL != str )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        nChar = MultiByteToWideChar( CP_UTF8, 
                                     0, 
                                     str, 
                                     -1, 
                                     NULL, 
                                     0 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        // glibc is broken on unaligned wide strings so we must
        // fix their shit for them.
        if( ! IS_PTR_ALIGNED( str ) )
        {
            // Got to realign, let's waste time and mmeory
            tmp = rpal_string_strdup( str );
        }
        nChar = (RU32)mbstowcs( NULL, NULL != tmp ? tmp : str, 0 );
#endif
        if( 0 != nChar &&
            (RU32)(-1) != nChar )
        {
            wide = rpal_memory_alloc( ( nChar + 1 ) * sizeof( RWCHAR ) );

            if( NULL != wide )
            {
                if( 
#ifdef RPAL_PLATFORM_WINDOWS
                    0 == MultiByteToWideChar( CP_UTF8,
                                              0, 
                                              str, 
                                              -1, 
                                              wide, 
                                              nChar + 1 )
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                    (-1) == mbstowcs( wide, NULL != tmp ? tmp : str, nChar + 1 )
#endif
                    )
                {
                    rpal_memory_free( wide );
                    wide = NULL;
                }
            }
        }
    }
    
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    if( NULL != tmp )
    {
        rpal_memory_free( tmp );
    }
#endif

    return wide;
}

RPCHAR
    rpal_string_wtoa
    (
        RPWCHAR str
    )
{
    RPCHAR ascii = NULL;
    RU32 size = 0;
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPWCHAR tmp = NULL;
#endif

    if( NULL != str )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        size = WideCharToMultiByte( CP_UTF8, 
                                    0, 
                                    str, 
                                    -1, 
                                    NULL, 
                                    0, 
                                    NULL, 
                                    NULL );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        // glibc is broken on unaligned wide strings so we must
        // fix their shit for them.
        if( ! IS_PTR_ALIGNED( str ) )
        {
            // Got to realign, let's waste time and mmeory
            tmp = rpal_string_strdupW( str );
        }
        
        size = (RU32)wcstombs( NULL, NULL != tmp ? tmp : str, 0 );
#endif
        if( 0 != size &&
            (RU32)(-1) != size )
        {
            ascii = rpal_memory_alloc( ( size + 1 ) * sizeof( RCHAR ) );

            if( 
#ifdef RPAL_PLATFORM_WINDOWS
                0 == WideCharToMultiByte( CP_UTF8, 
                                          0, 
                                          str, 
                                          -1, 
                                          ascii, 
                                          size + 1, 
                                          NULL, 
                                          NULL )
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                (-1) == wcstombs( ascii, NULL != tmp ? tmp : str, size + 1 )
#endif
                )
            {
                rpal_memory_free( ascii );
                ascii = NULL;
            }
        }
    }
    
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    if( NULL != tmp )
    {
        rpal_memory_free( tmp );
    }
#endif

    return ascii;
}


RPNCHAR
    rpal_string_wton
    (
        RPWCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_strdup( str );
#else
    return rpal_string_wtoa( str );
#endif
}

RPNCHAR
    rpal_string_aton
    (
        RPCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_atow( str );
#else
    return rpal_string_strdup( str );
#endif
}

RPWCHAR
    rpal_string_ntow
    (
        RPNCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_strdup( str );
#else
    return rpal_string_atow( str );
#endif
}

RPCHAR
    rpal_string_ntoa
    (
        RPNCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_wtoa( str );
#else
    return rpal_string_strdup( str );
#endif
}

RPNCHAR
    rpal_string_strcat
    (
        RPNCHAR str,
        RPNCHAR toAdd
    )
{
    RPNCHAR out = NULL;
    RU32 originalSize = 0;
    RU32 toAddSize = 0;

    if( NULL != str &&
        NULL != toAdd )
    {
        originalSize = rpal_string_strlen( str ) * sizeof( RNCHAR );
        toAddSize = rpal_string_strlen( toAdd ) * sizeof( RNCHAR );
        
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        // glibc is broken on unaligned strings so we must
        // fix their shit for them.
        if( ! IS_PTR_ALIGNED( str ) )
        {
            rpal_memory_memcpy( str + originalSize, toAdd, toAddSize );
            out = str;
        }
        else
        {
#endif
#ifdef RNATIVE_IS_WIDE
            out = wcscat( str, toAdd );
#else
            out = strcat( str, toAdd );
#endif
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        }
#endif
        
        if( NULL != out )
        {
            out[ ( originalSize + toAddSize ) / sizeof( RNCHAR ) ] = 0;
        }
    }

    return out;
}

RPNCHAR
    rpal_string_strstr
    (
        RPNCHAR haystack,
        RPNCHAR needle
    )
{
    RPNCHAR out = NULL;

    if( NULL != haystack &&
        NULL != needle )
    {
#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        RPAL_PLATFORM_TODO(Confirm GLIBC doesnt break this with optimizations);
#endif
#ifdef RNATIVE_IS_WIDE
        out = wcsstr( haystack, needle );
#else
        out = strstr( haystack, needle );
#endif
    }

    return out;
}

RPNCHAR
    rpal_string_stristr
    (
        RPNCHAR haystack,
        RPNCHAR needle
    )
{
    RPNCHAR out = NULL;
    RPNCHAR tmpHaystack = NULL;
    RPNCHAR tmpNeedle = NULL;

    if( NULL != haystack &&
        NULL != needle )
    {
        tmpHaystack = rpal_string_strdup( haystack );
        tmpNeedle = rpal_string_strdup( needle );

        if( NULL != tmpHaystack &&
            NULL != tmpNeedle )
        {
            tmpHaystack = rpal_string_toupper( tmpHaystack );
            tmpNeedle = rpal_string_toupper( tmpNeedle );

            out = rpal_string_strstr( tmpHaystack, tmpNeedle );

            if( NULL != out )
            {
                out = haystack + ( out - tmpHaystack );
            }
        }

        if( NULL != tmpHaystack )
        {
            rpal_memory_free( tmpHaystack );
        }

        if( NULL != tmpNeedle )
        {
            rpal_memory_free( tmpNeedle );
        }
    }

    return out;
}

RPNCHAR
    rpal_string_itos
    (
        RU32 num,
        RPNCHAR outBuff,
        RU32 radix
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    return rpal_string_itosW( num, outBuff, radix );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    return rpal_string_itosA( num, outBuff, radix );
#endif
}

RPCHAR
    rpal_string_itosA
    (
        RU32 num,
        RPCHAR outBuff,
        RU32 radix
    )
{
    if( 10 == radix )
    {
        if( 0 < sprintf( outBuff, "%d", num ) )
        {
            return outBuff;
        }
    }
    else if( 16 == radix )
    {
        if( 0 < sprintf( outBuff, "%X", num ) )
        {
            return outBuff;
        }
    }

    return NULL;
}

RPWCHAR
    rpal_string_itosW
    (
        RU32 num,
        RPWCHAR outBuff,
        RU32 radix
    )
{
#ifdef RPAL_PLATFORM_WINDOWS
    return _itow( num, outBuff, radix );
#else
    rpal_debug_not_implemented();
    return NULL;
#endif
}

RPWCHAR
    rpal_string_strdupW
    (
        RPWCHAR str
    )
{
    RPWCHAR out = NULL;
    RU32 len = 0;

    if( NULL != str )
    {
        len = rpal_string_strlenW( str ) * sizeof( RWCHAR );

        out = rpal_memory_alloc( len + sizeof( RWCHAR ) );

        if( rpal_memory_isValid( out ) )
        {
            rpal_memory_memcpy( out, str, len );
            out[ len / sizeof( RWCHAR ) ] = 0;
        }
    }

    return out;
}

RPCHAR
    rpal_string_strdupA
    (
        RPCHAR str
    )
{
    RPCHAR out = NULL;
    RU32 len = 0;

    if( NULL != str )
    {
        len = rpal_string_strlenA( str ) * sizeof( RCHAR );

        out = rpal_memory_alloc( len + sizeof( RCHAR ) );

        if( rpal_memory_isValid( out ) )
        {
            rpal_memory_memcpy( out, str, len );
            out[ len / sizeof( RCHAR ) ] = 0;
        }
    }

    return out;
}

RPNCHAR
    rpal_string_strdup
    (
        RPNCHAR str
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_strdupW( str );
#else
    return rpal_string_strdupA( str );
#endif
}

RBOOL
    rpal_string_matchW
    (
        RPWCHAR pattern,
        RPWCHAR str,
        RBOOL isCaseSensitive
    )
{
    // Taken and modified from:
    // http://www.codeproject.com/Articles/19694/String-Wildcard-Matching-and

    enum State
    {
        Exact,      	// exact match
        Any,        	// ?
        AnyRepeat,    	// *
        AnyAtLeastOne,  // +
        Escaped         // [backslash] 
    };

    RWCHAR *s = str;
    RWCHAR *p = pattern;
    RWCHAR *q = 0;
    RU32 state = 0;

    RBOOL match = TRUE;

    while( match && *p )
    {
        if( *p == _WCH( '*' ) )
        {
            state = AnyRepeat;
            q = p + 1;
        }
        else if( *p == _WCH( '?' ) )
        {
            state = Any;
        }
        else if( *p == _WCH( '\\' ) )
        {
            state = Exact;
            // Only escape if the next character is a wildcard
            // otherwise it's just a normal backslash, avoids
            // some common problems when user forgets to double
            // backslash a path seperator for example.
            if( *( p + 1 ) == _WCH( '?' ) ||
                *( p + 1 ) == _WCH( '*' ) ||
                *( p + 1 ) == _WCH( '+' ) ||
                *( p + 1 ) == _WCH( '\\' ) )
            {
                p++;
            }
        }
        else if( *p == _WCH( '+' ) )
        {
            state = AnyRepeat;

            if( 0 != *s )
            {
                q = p + 1;
                s++;
            }
            else
            {
                // Ensures we essentially fail the match
                q = p;
            }
        }
        else
        {
            state = Exact;
        }

        if( *s == 0 ) { break; }

        switch( state )
        {
            case Exact:
                if( !isCaseSensitive )
                {
                    match = ( rpal_string_charToLowerW( *s ) ==
                              rpal_string_charToLowerW( *p ) );
                }
                else
                {
                    match = *s == *p;
                }
                s++;
                p++;
                break;

            case Any:
                match = TRUE;
                s++;
                p++;
                break;

            case AnyRepeat:
                match = TRUE;
                s++;

                if( *s == *q )
                {
                    if( rpal_string_matchW( q, s, isCaseSensitive ) )
                    {
                        p++;
                    }
                }
                break;
        }
    }

    if( state == AnyRepeat )
    {
        return ( *s == *q );
    }
    else if( state == Any )
    {
        return ( *s == *p );
    }
    else
    {
        return match && ( *s == *p );
    }
}

RBOOL
    rpal_string_matchA
    (
        RPCHAR pattern,
        RPCHAR str,
        RBOOL isCaseSensitive
    )
{
    // Taken and modified from:
    // http://www.codeproject.com/Articles/19694/String-Wildcard-Matching-and

    enum State
    {
        Exact,      	// exact match
        Any,        	// ?
        AnyRepeat,    	// *
        AnyAtLeastOne,  // +
        Escaped         // [backslash] 
    };

    RCHAR *s = str;
    RCHAR *p = pattern;
    RCHAR *q = 0;
    RU32 state = 0;

    RBOOL match = TRUE;

    while( match && *p )
    {
        if( *p == '*' )
        {
            state = AnyRepeat;
            q = p + 1;
        }
        else if( *p == '?' )
        {
            state = Any;
        }
        else if( *p == '\\' )
        {
            state = Exact;
            // Only escape if the next character is a wildcard
            // otherwise it's just a normal backslash, avoids
            // some common problems when user forgets to double
            // backslash a path seperator for example.
            if( *( p + 1 ) == '?' ||
                *( p + 1 ) == '*' ||
                *( p + 1 ) == '+' ||
                *( p + 1 ) == '\\' )
            {
                p++;
            }
        }
        else if( *p == '+' )
        {
            state = AnyRepeat;

            if( 0 != *s )
            {
                q = p + 1;
                s++;
            }
            else
            {
                // Ensures we essentially fail the match
                q = p;
            }
        }
        else
        {
            state = Exact;
        }

        if( *s == 0 ) { break; }

        switch( state )
        {
            case Exact:
                if( !isCaseSensitive )
                {
                    match = ( rpal_string_charToLowerA( *s ) ==
                              rpal_string_charToLowerA( *p ) );
                }
                else
                {
                    match = *s == *p;
                }
                s++;
                p++;
                break;

            case Any:
                match = TRUE;
                s++;
                p++;
                break;

            case AnyRepeat:
                match = TRUE;
                s++;

                if( *s == *q )
                {
                    if( rpal_string_matchA( q, s, isCaseSensitive ) )
                    {
                        p++;
                    }
                }
                break;
        }
    }

    if( state == AnyRepeat )
    {
        return ( *s == *q );
    }
    else if( state == Any )
    {
        return ( *s == *p );
    }
    else
    {
        return match && ( *s == *p );
    }
}

RBOOL
    rpal_string_match
    (
        RPNCHAR pattern,
        RPNCHAR str,
        RBOOL isCaseSensitive
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_matchW( pattern, str, isCaseSensitive );
#else
    return rpal_string_matchA( pattern, str, isCaseSensitive );
#endif
}

RPNCHAR
    rpal_string_strcatEx
    (
        RPNCHAR strToExpand,
        RPNCHAR strToCat
    )
{
    RPNCHAR res = NULL;
    RU32 finalSize = 0;

    if( NULL != strToCat )
    {
        finalSize = ( rpal_string_strlen( strToExpand ) + 
                      rpal_string_strlen( strToCat ) + 1 ) * sizeof( RNCHAR );

        strToExpand = rpal_memory_realloc( strToExpand, finalSize );

        if( NULL != strToExpand )
        {
            res = rpal_string_strcat( strToExpand, strToCat );

            if( !rpal_memory_isValid( res ) )
            {
                res = NULL;
            }
        }
    }

    return res;
}

RPNCHAR
    rpal_string_strtok
    (
        RPNCHAR str,
        RNCHAR token,
        RPNCHAR* state
    )
{
    RPNCHAR nextToken = NULL;

    if( NULL != state &&
        LOGICAL_XOR( NULL == str, NULL == *state ) )
    {
        if( NULL != str )
        {
            nextToken = str;
            *state = str;
        }
        else
        {
            nextToken = *state;
            nextToken++;
            **state = token;
            (*state)++;
        }

        while( 0 != **state &&
                token != **state )
        {
            (*state)++;
        }

        if( token == **state )
        {
            **state = 0;
        }
        else
        {
            *state = NULL;
        }
    }

    return nextToken;
}

RS32
    rpal_string_strcmpW
    (
        RPWCHAR str1,
        RPWCHAR str2
    )
{
    RS32 res = ( -1 );

    if( NULL != str1 &&
        NULL != str2 )
    {
        res = wcscmp( str1, str2 );
    }

    return res;
}

RS32
    rpal_string_strcmpA
    (
        RPCHAR str1,
        RPCHAR str2
    )
{
    RS32 res = ( -1 );

    if( NULL != str1 &&
        NULL != str2 )
    {
        res = strcmp( str1, str2 );
    }

    return res;
}

RS32
    rpal_string_strcmp
    (
        RPNCHAR str1,
        RPNCHAR str2
    )
{
    RS32 res = (-1);

    if( NULL != str1 &&
        NULL != str2 )
    {
#ifdef RNATIVE_IS_WIDE
        res = rpal_string_strcmpW( str1, str2 );   
#else
        RPAL_PLATFORM_TODO( Confirm GLIBC doesnt break this with optimizations );
        res = rpal_string_strcmpA( str1, str2 );
#endif
    }

    return res;
}

RS32
    rpal_string_stricmp
    (
        RPNCHAR str1,
        RPNCHAR str2
    )
{
    RS32 res = (-1);

    if( NULL != str1 &&
        NULL != str2 )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        res = wcsicmp( str1, str2 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        RPAL_PLATFORM_TODO(Confirm GLIBC doesnt break this with optimizations)
        res = strcasecmp( str1, str2 );
#endif
    }

    return res;
}

RPNCHAR
    rpal_string_toupper
    (
        RPNCHAR str
    )
{
    RPNCHAR ret = NULL;

    if( NULL != str )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        ret = wcsupr( str );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        ret = strupr( str );
#endif
    }

    return ret;
}


RPWCHAR
    rpal_string_tolowerW
    (
        RPWCHAR str
    )
{
    RPWCHAR ret = NULL;

    if( NULL != str )
    {
        ret = wcslwr( str );
    }

    return ret;
}


RPCHAR
    rpal_string_tolowerA
    (
        RPCHAR str
    )
{
    RPCHAR ret = NULL;

    if( NULL != str )
    {
        ret = strlwr( str );
    }

    return ret;
}


RPNCHAR
    rpal_string_tolower
    (
        RPNCHAR str
    )
{
    RPNCHAR ret = NULL;

    if( NULL != str )
    {
#ifdef RNATIVE_IS_WIDE
        ret = rpal_string_tolowerW( str );
#else
        ret = rpal_string_tolowerA( str );
#endif
    }

    return ret;
}

RPNCHAR
    rpal_string_strcpy
    (
        RPNCHAR dst,
        RPNCHAR src
    )
{
    RPNCHAR res = NULL;

    if( NULL != dst &&
        NULL != src )
    {
        res = dst;

        while( 0 != *src )
        {
            *dst = *src;
            src++;
            dst++;
        }

        *dst = 0;
    }

    return res;
}

RBOOL
    rpal_string_stoi
    (
        RPNCHAR str,
        RU32* pNum,
        RBOOL isStrict
    )
{
    RBOOL isSuccess = FALSE;
    RPNCHAR tmp = 0;

    if( NULL != str &&
        NULL != pNum )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        *pNum = (RU32)wcstol( str, &tmp, 10 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
RPAL_PLATFORM_TODO(Confirm GLIBC doesnt break this with optimizations)
        *pNum = (RU32)strtol( str, &tmp, 10 );
#endif
        
        if( NULL != tmp &&
            ( !isStrict || 0 == *tmp ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    rpal_string_hstoi
    (
        RPNCHAR str,
        RU32* pNum,
        RBOOL isStrict
    )
{
    RBOOL isSuccess = FALSE;
    RPNCHAR tmp = 0;

    if( NULL != str &&
        NULL != pNum )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        *pNum = (RU32)wcstol( str, &tmp, 16 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
RPAL_PLATFORM_TODO( Confirm GLIBC doesnt break this with optimizations )
            *pNum = (RU32)strtol( str, &tmp, 16 );
#endif

        if( NULL != tmp &&
            ( !isStrict || 0 == *tmp ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    rpal_string_fill
    (
        RPNCHAR str,
        RU32 nChar,
        RNCHAR fillWith
    )
{
    RBOOL isFilledSomething = FALSE;
    RU32 i = 0;

    if( NULL != str )
    {
        for( i = 0; i < nChar; i++ )
        {
            if( 0 == str[ i ] )
            {
                isFilledSomething = TRUE;
                str[ i ] = fillWith;
            }
        }
    }

    return isFilledSomething;
}

RBOOL
    rpal_string_startswith
    (
        RPNCHAR haystack,
        RPNCHAR needle
    )
{
    RBOOL isStartsWith = FALSE;
    
    if( NULL != haystack &&
        NULL != needle )
    {
        if( 0 == rpal_memory_memcmp( haystack, needle, rpal_string_strlen( needle ) * sizeof( RNCHAR ) ) )
        {
            isStartsWith = TRUE;
        }
    }
    
    return isStartsWith;
}

RBOOL
    rpal_string_startswithi
    (
        RPNCHAR haystack,
        RPNCHAR needle
    )
{
    RBOOL isStartsWith = FALSE;
    
    RPNCHAR tmpHaystack = NULL;
    RPNCHAR tmpNeedle = NULL;
    
    if( NULL != haystack &&
        NULL != needle )
    {
        if( NULL != ( tmpHaystack = rpal_string_strdup( haystack ) ) )
        {
            if( NULL != ( tmpNeedle = rpal_string_strdup( needle ) ) )
            {
                tmpHaystack = rpal_string_tolower( tmpHaystack );
                tmpNeedle = rpal_string_tolower( tmpNeedle );
                
                if( 0 == rpal_memory_memcmp( tmpHaystack, tmpNeedle, rpal_string_strlen( tmpNeedle ) * sizeof( RNCHAR ) ) )
                {
                    isStartsWith = TRUE;
                }
                
                rpal_memory_free( tmpNeedle );
            }
            
            rpal_memory_free( tmpHaystack );
        }
    }
    
    return isStartsWith;
}

RBOOL
    rpal_string_endswith
    (
        RPNCHAR haystack,
        RPNCHAR needle
    )
{
    RBOOL isEndsWith = FALSE;
    
    if( NULL != haystack &&
        NULL != needle )
    {
        if( 0 == rpal_memory_memcmp( haystack + rpal_string_strlen( haystack ) - 
                                                rpal_string_strlen( needle ), 
                                     needle, 
                                     rpal_string_strlen( needle ) * sizeof( RNCHAR ) ) )
        {
            isEndsWith = TRUE;
        }
    }
    
    return isEndsWith;
}

RBOOL
    rpal_string_trim
    (
        RPNCHAR str,
        RPNCHAR charsToTrim
    )
{
    RBOOL isSomethingTrimmed = FALSE;

    RS32 i = 0;
    RU32 j = 0;
    RU32 nChars = 0;

    if( NULL != str &&
        NULL != charsToTrim )
    {
        nChars = rpal_string_strlen( charsToTrim );

        if( 0 != nChars )
        {
            for( i = rpal_string_strlen( str ) - 1; i >= 0; i-- )
            {
                for( j = 0; j < nChars; j++ )
                {
                    if( charsToTrim[ j ] == str[ i ] )
                    {
                        isSomethingTrimmed = TRUE;
                        str[ i ] = 0;
                        break;
                    }
                }

                if( !isSomethingTrimmed )
                {
                    break;
                }
            }
        }
    }

    return isSomethingTrimmed;
}

RBOOL
    rpal_string_charIsAscii
    (
        RNCHAR c
    )
{
    RBOOL isAscii = FALSE;

    if( ( 0x20 <= c && 0x7E >= c ) ||
        0x09 == c || 0x0D == c || 0x0A == c )
    {
        isAscii = TRUE;
    }

    return isAscii;
}

RBOOL
    rpal_string_charIsAlphaNum
    (
        RNCHAR c
    )
{
    RBOOL isAlphaNum = FALSE;

    if( ( 0x30 <= c && 0x39 >= c ) ||
        ( 0x41 <= c && 0x5A >= c ) ||
        ( 0x61 <= c && 0x7A >= c ) )
    {
        isAlphaNum = TRUE;
    }

    return isAlphaNum;
}

RBOOL
    rpal_string_charIsAlpha
    (
        RNCHAR c
    )
{
    RBOOL isAlpha = FALSE;
    
    if( ( 0x41 <= c && 0x5A >= c ) ||
        ( 0x61 <= c && 0x7A >= c ) )
    {
        isAlpha = TRUE;
    }

    return isAlpha;
}

RBOOL
    rpal_string_charIsNum
    (
        RNCHAR c
    )
{
    RBOOL isNum = FALSE;

    if( ( 0x30 <= c && 0x39 >= c ) )
    {
        isNum = TRUE;
    }

    return isNum;
}


RBOOL
    rpal_string_charIsUpperW
    (
        RWCHAR c
    )
{
    RBOOL isUpper = FALSE;

    if( ( 0x41 <= c && 0x5A >= c ) )
    {
        isUpper = TRUE;
    }

    return isUpper;
}

RBOOL
    rpal_string_charIsLowerW
    (
        RWCHAR c
    )
{
    RBOOL isLower = FALSE;

    if( ( 0x61 <= c && 0x7A >= c ) )
    {
        isLower = TRUE;
    }

    return isLower;
}

RBOOL
    rpal_string_charIsUpperA
    (
        RCHAR c
    )
{
    RBOOL isUpper = FALSE;

    if( ( 0x41 <= c && 0x5A >= c ) )
    {
        isUpper = TRUE;
    }

    return isUpper;
}

RBOOL
    rpal_string_charIsLowerA
    (
        RCHAR c
    )
{
    RBOOL isLower = FALSE;

    if( ( 0x61 <= c && 0x7A >= c ) )
    {
        isLower = TRUE;
    }

    return isLower;
}

RBOOL
    rpal_string_charIsUpper
    (
        RNCHAR c
    )
{
    RBOOL isUpper = FALSE;

    if( ( 0x41 <= c && 0x5A >= c ) )
    {
        isUpper = TRUE;
    }

    return isUpper;
}


RBOOL
    rpal_string_charIsLower
    (
        RNCHAR c
    )
{
    RBOOL isLower = FALSE;

    if( ( 0x61 <= c && 0x7A >= c ) )
    {
        isLower = TRUE;
    }

    return isLower;
}

RWCHAR
    rpal_string_charToUpperW
    (
        RWCHAR c
    )
{
    return (RWCHAR)towupper( c );
}

RWCHAR
    rpal_string_charToLowerW
    (
        RWCHAR c
    )
{
    return (RWCHAR)towlower( c );
}

RCHAR
    rpal_string_charToUpperA
    (
        RCHAR c
    )
{
    return (RCHAR)toupper( c );
}

RCHAR
    rpal_string_charToLowerA
    (
        RCHAR c
    )
{
    return (RCHAR)towupper( c );
}

RNCHAR
    rpal_string_charToUpper
    (
        RNCHAR c
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_charToUpperW( c );
#else
    return rpal_string_charToUpperA( c );
#endif
}

RNCHAR
    rpal_string_charToLower
    (
        RNCHAR c
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_string_charToLowerW( c );
#else
    return rpal_string_charToLowerA( c );
#endif
}
