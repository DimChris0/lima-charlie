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

#include <rpal/rpal_stringbuffer.h>

#define RPAL_FILE_ID    10

typedef struct
{
    rBlob blob;

} _rString;

rString
    rpal_stringbuffer_new
    (
        RU32 initialSize,
        RU32 growBy
    )
{
    _rString* pStr = NULL;

    pStr = rpal_memory_alloc( sizeof( _rString ) );

    if( rpal_memory_isValid( pStr ) )
    {
        pStr->blob = rpal_blob_create( initialSize, growBy );

        if( NULL == pStr->blob )
        {
            rpal_memory_free( pStr );
            pStr = NULL;
        }
    }

    return (rString)pStr;
}

RVOID
    rpal_stringbuffer_free
    (
        rString pStringBuffer
    )
{
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        rpal_blob_free( ((_rString*)pStringBuffer)->blob );
        rpal_memory_free( pStringBuffer );
    }
}

RVOID
    rpal_stringbuffer_freeWrapper
    (
        rString pStringBuffer
    )
{
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        rpal_blob_freeWrapperOnly( ( (_rString*)pStringBuffer )->blob );
        rpal_memory_free( pStringBuffer );
    }
}

RBOOL
    rpal_stringbuffer_add
    (
        rString pStringBuffer,
        RPNCHAR pString
    )
{
    RBOOL isSuccess = FALSE;

    _rString* pStr = (_rString*)pStringBuffer;

    if( rpal_memory_isValid( pStringBuffer ) )
    {
        isSuccess = rpal_blob_add( (rBlob)pStr->blob, pString, rpal_string_strlen( pString ) * sizeof( RNCHAR ) );
    }

    return isSuccess;
}

RPNCHAR
    rpal_stringbuffer_getString
    (
        rString pStringBuffer
    )
{
    RPNCHAR ret = NULL;

    _rString* pStr = (_rString*)pStringBuffer;
    
    if( rpal_memory_isValid( pStringBuffer ) )
    {
        ret = (RPNCHAR)rpal_blob_getBuffer( (rBlob)( pStr->blob ) );
    }

    return ret;
}
