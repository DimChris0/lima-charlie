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

#define RPAL_FILE_ID 14

#include <rpal_sort_search.h>

#define _ARRAY_ELEM(arr,n,size) ((RPU8)(((RPU8)arr) + ( n * size )))
#define _MOVE_ELEM(dest,arr,n,size) (rpal_memory_memcpy(dest,_ARRAY_ELEM(arr,n,size),size))
#define _SWAP(pElem1,pElem2,size,scratch) rpal_memory_memcpy(scratch,pElem1,size);\
                                          rpal_memory_memcpy(pElem1,pElem2,size);\
                                          rpal_memory_memcpy(pElem2,scratch,size);

static RVOID
    _quicksort
    (
        RPVOID scratch,
        RPVOID pArray,
        RU32 elemSize,
        RU32 iBegin,
        RU32 iEnd,
        rpal_ordering_func orderFunc
    )
{
    RU32 i = iBegin;
    RU32 j = 0;

    if( iBegin >= iEnd ) return;

    for( j = iBegin; j <= iEnd - 1; j++ )
    {
        if( 0 < orderFunc( _ARRAY_ELEM( pArray, j, elemSize ), _ARRAY_ELEM( pArray, iEnd, elemSize ) ) )
        {
            _SWAP( _ARRAY_ELEM( pArray, i, elemSize ),
                   _ARRAY_ELEM( pArray, j, elemSize ),
                   elemSize,
                   scratch );
            i++;
        }
    }

    _SWAP( _ARRAY_ELEM( pArray, i, elemSize ),
           _ARRAY_ELEM( pArray, iEnd, elemSize ),
           elemSize,
           scratch );

    if( 0 != i && 
        iBegin < ( i - 1 ) )
    {
        _quicksort( scratch, pArray, elemSize, iBegin, i - 1, orderFunc );
    }

    if( ( i + 1 ) < iEnd )
    {
        _quicksort( scratch, pArray, elemSize, i + 1, iEnd, orderFunc );
    }
}


RBOOL
    rpal_sort_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        rpal_ordering_func orderFunc
    )
{
    RBOOL isSuccess = FALSE;
    RPVOID tmpElem = NULL;

    if( NULL != pArray &&
        NULL != orderFunc )
    {
        if( 1 < nElements )
        {
            if( NULL != ( tmpElem = rpal_memory_alloc( elemSize ) ) )
            {
                _quicksort( tmpElem, pArray, elemSize, 0, nElements - 1, orderFunc );

                isSuccess = TRUE;

                rpal_memory_free( tmpElem );
            }
        }
        else
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}


RU32
    rpal_binsearch_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        RPVOID key,
        rpal_ordering_func orderFunc
    )
{
    RU32 iMin = 0;
    RU32 iMax = nElements;
    RU32 iMid = 0;
    RS32 order = 0;

    if( NULL != pArray &&
        NULL != orderFunc &&
        0 != nElements )
    {
        while( iMin <= iMax )
        {
            iMid = ( ( iMax - iMin ) / 2 ) + iMin;

            if( iMid >= nElements ) break;

            order = orderFunc( _ARRAY_ELEM( pArray, iMid, elemSize ), key );

            if( 0 == order )
            {
                return iMid;
            }
            else if( 0 < order )
            {
                iMin = iMid + 1;
            }
            else if( iMid != 0 )
            {
                iMax = iMid - 1;
            }
            else
            {
                break;
            }
        }
    }

    return (RU32)( -1 );
}


RU32
    rpal_binsearch_array_closest
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        RPVOID key,
        rpal_ordering_func orderFunc,
        RBOOL isFromBelow
    )
{
    RU32 iMin = 0;
    RU32 iMax = nElements - 1;
    RU32 iMid = 0;
    RS32 order = 0;

    if( NULL != pArray &&
        NULL != orderFunc &&
        0 != nElements )
    {
        while( iMin <= iMax )
        {
            iMid = ( ( iMax - iMin ) / 2 ) + iMin;

            order = orderFunc( _ARRAY_ELEM( pArray, iMid, elemSize ), key );

            if( 0 == order )
            {
                return iMid;
            }
            else if( 0 < order )
            {
                iMin = iMid + 1;
            }
            else if( iMid != 0 )
            {
                iMax = iMid - 1;
            }
            else
            {
                break;
            }
        }

        if( isFromBelow )
        {
            if( 0 < order )
            {
                return ( nElements == iMid ? iMid - 1 : iMid );
            }
            else
            {
                if( 0 < iMid )
                {
                    return iMid - 1;
                }
            }
        }
        else
        {
            if( 0 < order )
            {
                if( iMid < nElements - 1 )
                {
                    return iMid + 1;
                }
            }
            else
            {
                return iMid;
            }
        }
    }

    return (RU32)( -1 );
}


RS32
    rpal_order_RU32
    (
        RPU32 p1,
        RPU32 p2
    )
{
    RS32 order = -1;

    if( NULL != p1 &&
        NULL != p2 )
    {
        order = ( *p2 - *p1 );
    }

    return order;
}

RS32
    rpal_order_RU64
    (
        RPU64 p1,
        RPU64 p2
    )
{
    RS32 order = -1;

    if( NULL != p1 &&
        NULL != p2 )
    {
        if( *p1 == *p2 )
        {
            order = 0;
        }
        else if( *p2 > *p1 )
        {
            order = 1;
        }
        else
        {
            order = -1;
        }
    }

    return order;
}
