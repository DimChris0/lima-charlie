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

#ifndef _RPAL_DATATYPES_H
#define _RPAL_DATATYPES_H

#include "rpal_platform.h"

/*
 *
 * WINDOWS
 *
 */
#ifdef RPAL_PLATFORM_WINDOWS
    #ifndef _WIN32_WINNT
        #define  _WIN32_WINNT 0x0500
    #endif
    #ifdef RPAL_PLATFORM_KERNEL
        #include <fltKernel.h>
        #pragma warning(push)
        #pragma warning(disable:4201)       // unnamed struct/union
        #include <fwpsk.h>
        #pragma warning(pop)
        #include <fwpmk.h>
    #else
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <winsock2.h>
        #include <windows_undocumented.h>
        #include <winioctl.h>
    #endif
    #include <string.h>
    #include <stdlib.h>
    #include <stdio.h>
    #ifndef RPAL_PLATFORM_WINDOWS_32
        #include <varargs.h>
    #endif

    #ifdef RPAL_PLATFORM_KERNEL
        typedef int             RBOOL;
        typedef int*            RPBOOL;
        typedef UCHAR	        RU8;
        typedef UCHAR*          RPU8;
        typedef USHORT		    RU16;
        typedef USHORT*		    RPU16;
    #else
        typedef BOOL		    RBOOL;
        typedef BOOL*		    RPBOOL;
        
        typedef BYTE		    RU8;
        typedef BYTE*		    RPU8;

        typedef WORD		    RU16;
        typedef WORD*		    RPU16;
    #endif
    
    typedef UINT32		        RU32;
    typedef UINT32*		        RPU32;

    typedef LONG                RS32;
    typedef LONG*               RPS32;

    typedef UINT64	            RU64;
    typedef UINT64*	            RPU64;

    typedef INT64               RS64;
    typedef INT64*              RPS64;

    typedef	CHAR		        RCHAR;
    typedef CHAR*		        RPCHAR;

    typedef WCHAR		        RWCHAR;
    typedef WCHAR*		        RPWCHAR;

    typedef VOID		        RVOID;
    typedef PVOID		        RPVOID;

    typedef size_t		        RSIZET;

    typedef RU64                RTIME;

    typedef float               RFLOAT;
    typedef double              RDOUBLE;

    typedef RWCHAR              RNCHAR;
    typedef RPWCHAR             RPNCHAR;
    #define _NC(str)            _WCH(str)
    #define RNATIVE_IS_WIDE

    // Printf format helpers
    #define RF_STR_W            "%S"
    #define RF_STR_A            "%s"
    #define RF_STR_N            RF_STR_W
    #define RF_U32              "%I32u"
    #define RF_S32              "%I32d"
    #define RF_X32              "%I32X"
    #define RF_U64              "%I64u"
    #define RF_S64              "%I64d"
    #define RF_X64              "%I64X"
    #define RF_SIZET            "%Iu"
    #ifdef RPAL_PLATFORM_64_BIT
        #define RF_PTR          "0x%016p"
    #else
        #define RF_PTR          "0x%08p"
    #endif

#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    #include <stdint.h>
    #ifndef RPAL_PLATFORM_KERNEL
        #include <stdlib.h>
        #include <stdio.h>
        #include <errno.h>
    #endif
    #include <string.h>

    typedef int                 RBOOL;
    typedef int*		        RPBOOL;

    typedef uint8_t             RU8;
    typedef uint8_t*            RPU8;

    typedef uint16_t	        RU16;
    typedef uint16_t*           RPU16;

    typedef uint32_t            RU32;
    typedef uint32_t*           RPU32;

    typedef int32_t             RS32;
    typedef int32_t*            RPS32;

    typedef uint64_t            RU64;
    typedef uint64_t*	        RPU64;

    typedef	char		        RCHAR;
    typedef char*		        RPCHAR;

    #ifndef RPAL_PLATFORM_KERNEL
        typedef wchar_t		    RWCHAR;
        typedef wchar_t*	    RPWCHAR;
    #endif

    typedef void		        RVOID;
    typedef void*		        RPVOID;

    typedef size_t		        RSIZET;

    typedef RU64                RTIME;

    typedef float               RFLOAT;
    typedef double              RDOUBLE;

    typedef RCHAR               RNCHAR;
    typedef RPCHAR              RPNCHAR;
    #define _NC(str)            str
    #define RNATIVE_IS_BYTE

    // Printf format helpers
    #define RF_STR_W            "%ls"
    #define RF_STR_A            "%s"
    #define RF_STR_N            RF_STR_A
    #ifdef RPAL_PLATFORM_MACOSX
        #define RF_U32          "%u"
        #define RF_S32          "%d"
        #define RF_X32          "%X"
        #define RF_U64          "%llu"
        #define RF_S64          "%lld"
        #define RF_X64          "%llX"
    #else
        #define RF_U32          "%u"
        #define RF_S32          "%d"
        #define RF_X32          "%X"
        #define RF_U64          "%lu"
        #define RF_S64          "%ld"
        #define RF_X64          "%lX"
    #endif
    #define RF_SIZET            "%zu"
    #ifdef RPAL_PLATFORM_64_BIT
        #define RF_PTR          "0x%p"
    #else
        #define RF_PTR          "0x%p"
    #endif
#endif

// Common values
#ifndef NULL
    #define NULL 0
#endif

#ifndef TRUE
    #define TRUE 1
#endif

#ifndef FALSE
    #define FALSE 0
#endif

#define RINFINITE ((RU32)(-1))

#define RPAL_MAX_PATH   (260)

#define _WCH(str) L ## str

#define NUMBER_TO_PTR(num)  ((RPVOID)(RSIZET)(num))
#define PTR_TO_NUMBER(ptr)  ((RSIZET)(ptr))

#define MIN_OF(a,b)     ( (a) > (b) ? (b) : (a) )
#define MAX_OF(a,b)     ( (a) > (b) ? (a) : (b) )

#define LITERAL_64_BIT(i)   (i ## LL)

#ifndef UNREFERENCED_PARAMETER
    #define UNREFERENCED_PARAMETER(p) (p=p)
#endif

#ifdef RPAL_PLATFORM_WINDOWS
    #define RASSERT(e)          if(!(e)){ DebugBreak(); }
#else
    #define RASSERT(e)          if(!(e)){ raise( SIGTRAP ); }
#endif

#define IS_PTR_ALIGNED(ptr) (0 == (RSIZET)(ptr) % sizeof(RU32))

typedef struct
{
    RU8 byteArray[ 16 ];
} RIpV6;

typedef struct
{
    RU8 isV6;
    union
    {
        RU32 v4;
        RIpV6 v6;
    } value;
} RIpAddress;

// Export Visibility Control
#ifdef RPAL_PLATFORM_WINDOWS
    #define RPAL_EXPORT         __declspec(dllexport)
    #define RPAL_DONT_EXPORT
    #define RPAL_NATIVE_MAIN \
int\
    RPAL_EXPORT\
        wmain\
        (\
            int argc,\
            RWCHAR* argv[]\
        )
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    #define RPAL_EXPORT         __attribute__((visibility("default")))
    #define RPAL_DONT_EXPORT    __attribute__((visibility("hidden")))
    #define RPAL_NATIVE_MAIN \
int\
    RPAL_EXPORT\
        main\
        (\
            int argc,\
            RCHAR* argv[]\
        )
#endif

//=============================================================================
//  These data types must be included here instead of their own headers
//  since they are part of the core API, ie. centralized functions...
//=============================================================================

//=============================================================================
//  Handle Manager
typedef union
{
    RU64 h;
    struct
    {
        RU8 major;
        RU8 reserved1;
        RU16 reserved2;
        RU32 minor;
    } info;
} rHandle;

#define RPAL_HANDLE_INVALID             ((-1))
#define RPAL_HANDLE_INIT                {(RU64)(LITERAL_64_BIT(0xFFFFFFFFFFFFFFFF))}
typedef RBOOL (*rpal_handleManager_cleanup_f)( RPVOID val );

//=============================================================================
//  rBTree
typedef RPVOID rBTree;
typedef RS32 (*rpal_btree_comp_f)( RPVOID, RPVOID );
typedef RVOID (*rpal_btree_free_f)( RPVOID );


#endif
