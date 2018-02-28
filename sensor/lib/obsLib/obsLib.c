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

#include "obsLib_private.h"

#define RPAL_FILE_ID    43

#pragma warning( disable: 4127 ) // Disabling error on constant expressions

//=============================================================================
//  Internal Macros
//=============================================================================
#define IS_IN_RANGE(node,value) ((node)->startOffset <= (value) && \
                                 (node)->startOffset + (node)->nElements > (value))

#define EFFECTIVE_INDEX(node,value) ((RU32)((value) - (node)->startOffset))

#define DEFAULT_ALLOCATED_PATTERNS  0

//=============================================================================
//  Internal Routines
//=============================================================================
RVOID
    freeSig
    (
        PObsSig sig
    )
{
    if( rpal_memory_isValid( sig ) )
    {
        rpal_memory_free( sig );
    }
}


PObsNode
    newNode
    (

    )
{
    PObsNode node = NULL;

    node = rpal_memory_alloc( sizeof( ObsNode ) + ( DEFAULT_ALLOCATED_PATTERNS * sizeof( RPVOID ) ) );

    if( rpal_memory_isValid( node ) )
    {
        node->nElements = 0;
        node->pSigsHit = NULL;
        node->startOffset = 0;
        node->nAllocated = DEFAULT_ALLOCATED_PATTERNS;
    }

    return node;
}

RVOID
    freeNode
    (
        PObsNode node
    )
{
    RU32 i = 0;
    PObsNode tmp = NULL;
    PObsSig* sig = NULL;

    if( NULL != node )
    {
        // Free all sub nodes
        for( i = 0; i < node->nElements; i++ )
        {
            if( NULL != ( tmp = node->elements[ i ] ) )
            {
                freeNode( tmp );
            }
        }

        // Free hits
        if( NULL != ( sig = node->pSigsHit ) )
        {
            while( NULL != *sig )
            {
                freeSig( *sig );
                sig++;
            }

            rpal_memory_free( node->pSigsHit );
        }
    }

    rpal_memory_free( node );
}

PObsNode
    addTransition
    (
        PObsNode parent,
        PObsNode node,
        PObsNode to,
        RU8 onValue
    )
{
    PObsNode retNode = NULL;
    RU32 currentNodeSize = 0;
    RU8 numElemToAdd = 0;
    RU8 indexToInsert = 0;
    PObsNode originalNode = node;
    RU32 i = 0;

    if( rpal_memory_isValid( node ) )
    {
        currentNodeSize = sizeof( ObsNode ) + ( node->nElements * sizeof( RPVOID ) );

        if( !IS_IN_RANGE( node, onValue ) )
        {
            if( onValue >= node->startOffset + node->nElements )
            {
                numElemToAdd = onValue - ( node->startOffset + node->nElements ) + 1;
            }
            else
            {
                numElemToAdd = node->startOffset - onValue;
            }

            if( node->nAllocated < node->nElements + numElemToAdd )
            {
                node = rpal_memory_realloc( node, currentNodeSize + ( numElemToAdd * sizeof( RPVOID ) ) );
                rpal_memory_zero( node->elements + node->nElements, numElemToAdd * sizeof( RPVOID ) );
                node->nAllocated = node->nElements + numElemToAdd;
            }

            if( onValue < node->startOffset &&
                0 < node->nElements )
            {
                rpal_memory_memmove( node->elements + numElemToAdd, node->elements, node->nElements * sizeof( RPVOID ) );
                node->startOffset = node->startOffset - (RU8)numElemToAdd;
            }

            node->nElements += numElemToAdd;

            // The above realloc may have changed the pointer so we need
            // to update it in the parent, if it exists...
            if( NULL != parent &&
                originalNode != node )
            {
                for( i = 0; i < parent->nElements; i++ )
                {
                    if( originalNode == parent->elements[ i ] )
                    {
                        parent->elements[ i ] = node;
                    }
                }
            }
        }

        indexToInsert = EFFECTIVE_INDEX( node, onValue );

        if( NULL == node->elements[ indexToInsert ] )
        {
            node->elements[ indexToInsert ] = to;

            retNode = node;
        }
    }

    return retNode;
}

PObsNode
    getNextNode
    (
        PObsNode node, 
        RU8 value
    )
{
    PObsNode next = NULL;

    if( rpal_memory_isValid( node ) &&
        IS_IN_RANGE( node, value ) )
    {
        next = node->elements[ EFFECTIVE_INDEX( node, value ) ];
    }

    return next;
}

PObsSig
    newSig
    (
        RPU8 pPattern,
        RU32 patternSize,
        RPVOID context
    )
{
    PObsSig sig = NULL;

    if( NULL != pPattern &&
        0 != patternSize )
    {
        sig = rpal_memory_alloc( sizeof( ObsSig ) + patternSize );

        if( rpal_memory_isValid( sig ) )
        {
            sig->pContext = context;
            sig->sigSize = patternSize;
        }
    }

    return sig;
}



RBOOL
    addHitToNode
    (
        PObsNode node,
        PObsSig sig
    )
{
    RBOOL isSuccess = FALSE;
    PObsSig* tmp = NULL;
    RU32 numHits = 0;

    if( rpal_memory_isValid( node ) &&
        rpal_memory_isValid( sig ) )
    {
        tmp = node->pSigsHit;

        if( NULL != tmp )
        {
            while( NULL != *tmp )
            {
                numHits++;
                tmp++;
            }
        }

        node->pSigsHit = rpal_memory_realloc( node->pSigsHit, ( ( numHits + 2 ) * sizeof( PObsSig ) ) );

        tmp = node->pSigsHit;
        if( NULL != tmp )
        {
            rpal_memory_zero( (RPU8)tmp + ( numHits * sizeof( PObsSig ) ), 2 * sizeof( PObsSig ) );

            while( NULL != *tmp )
            {
                tmp++;
            }

            *tmp = sig;

            isSuccess = TRUE;
        }
    }

    return isSuccess;
}



//=============================================================================
//  Public API
//=============================================================================
HObs
    obsLib_new
    (
        RU32 nMaxMem,
        ObsType searchType
    )
{
    _PHObs obs = NULL;

    obs = rpal_memory_alloc( sizeof( _HObs ) );

    if( rpal_memory_isValid( obs ) )
    {
        obs->root = newNode();
        if( NULL != obs->root )
        {
            obs->currentOffset = 0;
            obs->maxDepth = 0;
            obs->maxMem = nMaxMem;
            obs->searchType = searchType;
            obs->targetBuffer = NULL;
            obs->currentState = NULL;
            obs->curHits = NULL;
            obs->curDepth = 0;
            obs->nPatterns = 0;
        }
        else
        {
            rpal_memory_free( obs );
            obs = NULL;
        }
    }

    return (HObs)obs;
}


RVOID
    obsLib_free
    (
        HObs hObs
    )
{
    _PHObs obs = (_PHObs)hObs;

    if( rpal_memory_isValid( hObs ) )
    {
        freeNode( obs->root );

        rpal_memory_free( hObs );
    }
}

RBOOL
    obsLib_addPattern
    (
        HObs hObs,
        RPU8 pBytePattern,
        RU32 nBytePatternSize,
        RPVOID context
    )
{
    RBOOL isSuccess = FALSE;

    RU32 i = 0;
    PObsNode tmp = NULL;
    PObsNode next = NULL;
    PObsNode prev = NULL;
    PObsSig sig = NULL;
    _PHObs obs = (_PHObs)hObs;

    if( rpal_memory_isValid( hObs ) &&
        NULL != pBytePattern &&
        0 != nBytePatternSize &&
        NULL != obs->root )
    {
        tmp = obs->root;
        prev = NULL;
        isSuccess = TRUE;

        for( i = 0; i < nBytePatternSize; i++ )
        {
            if( NULL == ( next = getNextNode( tmp, pBytePattern[ i ] ) ) )
            {
                // We need to forge a new state and add a FSM transition to it
                if( NULL == ( next = newNode() ) ||
                    NULL == ( tmp = addTransition( prev, tmp, next, pBytePattern[ i ] ) ) )
                {
                    isSuccess = FALSE;
                    break;
                }

                // If this is the first node, we may need to update
                // the handle with the new root node pointer since
                // it could have gotten realloced.
                if( NULL == prev )
                {
                    obs->root = tmp;
                    obs->currentState = obs->root;
                }
            }

            // Follow on to the next state
            prev = tmp;
            tmp = next;
        }

        if( isSuccess )
        {
            // All went well, in the last state, record the hit
            if( NULL != ( sig = newSig( pBytePattern, nBytePatternSize, context ) ) )
            {
                if( !addHitToNode( tmp, sig ) )
                {
                    freeSig( sig );
                    isSuccess = FALSE;
                }
                else
                {
                    obs->nPatterns++;
                }
            }
            else
            {
                isSuccess = FALSE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    obsLib_addStringPatternA
    (
        HObs hObs,
        RPCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    )
{
    RBOOL isSuccess = FALSE;
    RU32 patternLength = 0;
    RPCHAR tmp = NULL;
    RU32 strLen = 0;
    RU32 i = 0;

    if( rpal_memory_isValid( hObs ) &&
        NULL != strPattern &&
        0 != rpal_string_strlenA( strPattern ) )
    {
        if( !isCaseInsensitive )
        {
            patternLength = rpal_string_strlenA( strPattern ) * sizeof( RCHAR );
            patternLength += ( isIncludeNullEnding ? 1 * sizeof( RCHAR ) : 0 );
            isSuccess = obsLib_addPattern( hObs, (RPU8)strPattern, patternLength, context );
        }
        else
        {
            if( NULL != ( tmp = rpal_string_strdupA( strPattern ) ) )
            {
                // Iteratively generate all cases for the string.
                rpal_string_tolowerA( tmp );
                strLen = rpal_string_strlenA( tmp );
                patternLength = strLen * sizeof( RCHAR );
                patternLength += ( isIncludeNullEnding ? 1 * sizeof( RCHAR ) : 0 );

                while( TRUE )
                {
                    for( i = 0; i < strLen; i++ )
                    {
                        if( rpal_string_charIsUpperA( tmp[ i ] ) )
                        {
                            tmp[ i ] = rpal_string_charToLowerA( tmp[ i ] );
                        }
                        else if( rpal_string_charIsLowerA( tmp[ i ] ) )
                        {
                            tmp[ i ] = rpal_string_charToUpperA( tmp[ i ] );
                            break;
                        }
                    }

                    // Record this combination.
                    if( FALSE == ( isSuccess = obsLib_addPattern( hObs, (RPU8)tmp, patternLength, context ) ) )
                    {
                        break;
                    }

                    if( i == strLen )
                    {
                        // We've overflowed the string so we're done.
                        break;
                    }
                }

                rpal_memory_free( tmp );
            }
        }
    }

    return isSuccess;
}

RBOOL
    obsLib_addStringPatternW
    (
        HObs hObs,
        RPWCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    )
{
    RBOOL isSuccess = FALSE;
    RU32 patternLength = 0;
    RPWCHAR tmp = NULL;
    RU32 strLen = 0;
    RU32 i = 0;

    if( rpal_memory_isValid( hObs ) &&
        NULL != strPattern &&
        0 != rpal_string_strlenW( strPattern ) )
    {
        if( !isCaseInsensitive )
        {
            patternLength = rpal_string_strlenW( strPattern ) * sizeof( RWCHAR );
            patternLength += ( isIncludeNullEnding ? 1 * sizeof( RWCHAR ) : 0 );
            isSuccess = obsLib_addPattern( hObs, (RPU8)strPattern, patternLength, context );
        }
        else
        {
            if( NULL != ( tmp = rpal_string_strdupW( strPattern ) ) )
            {
                // Iteratively generate all cases for the string.
                rpal_string_tolowerW( tmp );
                strLen = rpal_string_strlenW( tmp );
                patternLength = strLen * sizeof( RWCHAR );
                patternLength += ( isIncludeNullEnding ? 1 * sizeof( RWCHAR ) : 0 );

                while( TRUE )
                {
                    for( i = 0; i < strLen; i++ )
                    {
                        if( rpal_string_charIsUpperW( tmp[ i ] ) )
                        {
                            tmp[ i ] = rpal_string_charToLowerW( tmp[ i ] );
                        }
                        else if( rpal_string_charIsLowerW( tmp[ i ] ) )
                        {
                            tmp[ i ] = rpal_string_charToUpperW( tmp[ i ] );
                            break;
                        }
                    }

                    // Record this combination.
                    if( FALSE == ( isSuccess = obsLib_addPattern( hObs, (RPU8)tmp, patternLength, context ) ) )
                    {
                        break;
                    }

                    if( i == strLen )
                    {
                        // We've overflowed the string so we're done.
                        break;
                    }
                }

                rpal_memory_free( tmp );
            }
        }
    }

    return isSuccess;
}

RBOOL
    obsLib_addStringPatternN
    (
        HObs hObs,
        RPNCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    )
{
#ifdef RNATIVE_IS_WIDE
    return obsLib_addStringPatternW( hObs, strPattern, isIncludeNullEnding, isCaseInsensitive, context );
#else
    return obsLib_addStringPatternA( hObs, strPattern, isIncludeNullEnding, isCaseInsensitive, context );
#endif
}

RBOOL
    obsLib_setTargetBuffer
    (
        HObs hObs,
        RPVOID pTargetBuffer,
        RU32 targetBufferSize
    )
{
    RBOOL isSuccess = FALSE;

    _PHObs obs = (_PHObs)hObs;

    if( rpal_memory_isValid( hObs ) )
    {
        obs->targetBuffer = pTargetBuffer;
        obs->targetBufferSize = targetBufferSize;
        obs->currentOffset = 0;
        obs->curDepth = 0;
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    obsLib_nextHit
    (
        HObs hObs,
        RPVOID* pContextHit,
        RPVOID* pHitLocation
    )
{
    RBOOL isFound = FALSE;

    _PHObs obs = (_PHObs)hObs;
    PObsNode tmp = NULL;
    PObsSig* pSig = NULL;

    if( rpal_memory_isValid( hObs ) )
    {
        if( NULL != ( pSig = obs->curHits ) )
        {
            // We have some hits in the queue so use those up...
            isFound = TRUE;
            if( NULL != pContextHit )
            {
                *pContextHit = (*pSig)->pContext;
            }

            if( NULL != pHitLocation )
            {
                *pHitLocation = (RPU8)obs->targetBuffer + obs->currentOffset - obs->curDepth;
            }

            pSig++;
            if( NULL == *pSig )
            {
                obs->curHits = NULL;
            }
            else
            {
                obs->curHits = pSig;
            }
        }
        else if( NULL != obs->currentState )
        {
            // Ok start looking
            while( obs->currentOffset < obs->targetBufferSize )
            {
                if( obs->currentState->nElements > EFFECTIVE_INDEX( obs->currentState, ((RPU8)obs->targetBuffer)[ obs->currentOffset ] ) &&
                    NULL != ( tmp = obs->currentState->elements[ EFFECTIVE_INDEX( obs->currentState, 
                                                                                  ((RPU8)obs->targetBuffer)[ obs->currentOffset ] ) ] ) )
                {
                    // We have a state match, follow it and move on to the next byte
                    obs->currentState = tmp;
                    obs->currentOffset++;
                    obs->curDepth++;
                }
                else if( obs->currentState != obs->root )
                {
                    // We have no state transitions, replay this token from the root
                    obs->currentState = obs->root;
                    obs->curDepth = 0;
                }
                else
                {
                    // So we have no transition, and are at the root, just move up and stay here
                    obs->currentOffset++;
                }

                if( NULL != ( pSig = obs->currentState->pSigsHit ) )
                {
                    // We are on a node with hits, we'll report them before moving on
                    isFound = TRUE;
                    if( NULL != pContextHit )
                    {
                        *pContextHit = (*pSig)->pContext;
                    }

                    if( NULL != pHitLocation )
                    {
                        *pHitLocation = (RPU8)obs->targetBuffer + obs->currentOffset - obs->curDepth;
                    }

                    pSig++;
                    if( NULL == *pSig )
                    {
                        obs->curHits = NULL;
                    }
                    else
                    {
                        obs->curHits = pSig;
                    }

                    break;
                }
            }
        }
    }

    return isFound;
}

RVOID
    obsLib_resetSearchState
    (
        HObs hObs
    )
{
    _PHObs obs = NULL;

    if( NULL != hObs )
    {
        obs = (_PHObs)hObs;

        obs->currentState = obs->root;
    }
}

RU32
    obsLib_getNumPatterns
    (
        HObs hObs
    )
{
    RU32 n = 0;
    _PHObs obs = (_PHObs)hObs;

    if( NULL != hObs )
    {
        n = obs->nPatterns;
    }

    return n;
}

