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

#ifndef _OBSLIB_H
#define _OBSLIB_H

/*
obsLib: Optimized Byte Search Library.

This library is based on the Aho-Corasick algorithm in a modified state partly
using findings and suggestions from:
http://docs.idsresearch.org/OptimizingPatternMatchingForIDS.pdf

Author: Maxime Lamothe-Brassard


Summary:
The purpose of this library is to look for large number of byte sequences on large
or numerous files at once. Although a simple memcmp would work, the number of 
comparisons quickly grows as we add patterns to search 
(nPatterns * bufferSize) in its simplest expression.

This library uses a Finite State Machine (FSM) to optimize the number of comparisons per
byte searched. The result is that each byte of the target buffer is compared at
most 1 time. Additionally it allows for finding patterns on multiple chunks of
the same file separately (not reading an entire file into memory at once) similarly
to the core hashing functions like md5_init, md5_block, md5_finish.

This optimization comes at the cost of memory for the FSM, the exact cost greatly 
depends on the similarity of prefixes of the byte patterns to search for.

*/

#include <rpal/rpal.h>


// Handle type for a preprocessed obs search
typedef RPVOID HObs;

// Types of searches supported
typedef RU8 ObsType;
#define OBSLIB_FIND_SHORTEST_MATCH      0x01
#define OBSLIB_FIND_ALL_MATCHES         0x02

/**
 * Create a new obs object to search with.
 * 
 * Create an obs object and receive a handle to it. This object allows you to
 * add multiple byte patterns to it. Once all the patterns are inputted, you
 * can repeatedly set a target buffer to search in and retrieve hits by using
 * the handle as an iterator with obsLib_nextHit().
 *
 * @param   RU32    nMaxMem
 *   (Not Implemented) The maximum number of kiloBytes to use in the obs object since more byte
 *   sequences can mean increased memory usage in a non-linear fashion
 * @param   ObsType searchType
 *   (Not Implemented) Type of the search, all matches, sub-matches etc, OBSLIB_FIND_*
 *
 * @return  HObs
 *   Returns a handle to the new obs object
 */
HObs
    obsLib_new
    (
        RU32 nMaxMem,       // Not yet implemented
        ObsType searchType  // Not yet implemented
    );

/**
 * Free all memory related to an obs object.
 * 
 * @param HObs  hObs
 *   Obs handle to free
 */
RVOID
    obsLib_free
    (
        HObs hObs
    );

/**
 * Add a byte sequence to an obs object.
 * 
 * Adds a new byte sequence to the obs object. The sequence is created in
 * an internal format that is optimized for large buffers and large number
 * of sequences.
 *
 * @param   HObs    hObs
 *   The handle of the obs object to add to
 *
 * @param   RPU8    pBytePattern
 *   Pointer to the byte sequence to add (buffer)
 *
 * @param   RU32    nBytePatternSize
 *   Size in bytes of the byte pattern to add
 *
 * @param   RPVOID  context
 *   Opaque context (for obsLib) to be associated with the byte sequence, this
 *   can be meta-data related to the sequence to be retrieved at the same time
 *   as matches are found.
 *
 * @return RBOOL
 *   Returns TRUE if the pattern was added to the obs object
 */
RBOOL
    obsLib_addPattern
    (
        HObs hObs,
        RPU8 pBytePattern,
        RU32 nBytePatternSize,
        RPVOID context
    );

/**
* Add a native string to an obs object.
*
* Adds a new string to the obs object. The sequence is created in
* an internal format that is optimized for large buffers and large number
* of sequences.
*
* @param   HObs    hObs
*   The handle of the obs object to add to
*
* @param   RPNCHAR  strPattern
*   Pointer to the byte sequence to add (buffer)
*
* @param   RBOOL   isIncludeNullEnding
*   Includes the final null character in the patter, for string suffix matching
*
* @param   RBOOL   isCaseInsensitive
*   Includes patterns with all cases, this means 2^N patterns!
*
* @param   RPVOID  context
*   Opaque context (for obsLib) to be associated with the byte sequence, this
*   can be meta-data related to the sequence to be retrieved at the same time
*   as matches are found.
*
* @return RBOOL
*   Returns TRUE if the pattern was added to the obs object
*/
RBOOL
    obsLib_addStringPatternN
    (
        HObs hObs,
        RPNCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    );

/**
* Add a ascii/utf-8 string to an obs object.
*
* Adds a new string to the obs object. The sequence is created in
* an internal format that is optimized for large buffers and large number
* of sequences.
*
* @param   HObs    hObs
*   The handle of the obs object to add to
*
* @param   RPCHAR  strPattern
*   Pointer to the byte sequence to add (buffer)
*
* @param   RBOOL   isIncludeNullEnding
*   Includes the final null character in the patter, for string suffix matching
*
* @param   RBOOL   isCaseInsensitive
*   Includes patterns with all cases, this means 2^N patterns!
*
* @param   RPVOID  context
*   Opaque context (for obsLib) to be associated with the byte sequence, this
*   can be meta-data related to the sequence to be retrieved at the same time
*   as matches are found.
*
* @return RBOOL
*   Returns TRUE if the pattern was added to the obs object
*/
RBOOL
    obsLib_addStringPatternA
    (
        HObs hObs,
        RPCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    );

/**
* Add a wide string to an obs object.
*
* Adds a new string to the obs object. The sequence is created in
* an internal format that is optimized for large buffers and large number
* of sequences.
*
* @param   HObs    hObs
*   The handle of the obs object to add to
*
* @param   RPWCHAR  strPattern
*   Pointer to the byte sequence to add (buffer)
*
* @param   RBOOL   isIncludeNullEnding
*   Includes the final null character in the patter, for string suffix matching
*
* @param   RBOOL   isCaseInsensitive
*   Includes patterns with all cases, this means 2^N patterns!
*
* @param   RPVOID  context
*   Opaque context (for obsLib) to be associated with the byte sequence, this
*   can be meta-data related to the sequence to be retrieved at the same time
*   as matches are found.
*
* @return RBOOL
*   Returns TRUE if the pattern was added to the obs object
*/
RBOOL
    obsLib_addStringPatternW
    (
        HObs hObs,
        RPWCHAR strPattern,
        RBOOL isIncludeNullEnding,
        RBOOL isCaseInsensitive,
        RPVOID context
    );

/**
 * Set a target buffer to search using the obs object.
 * 
 * This sets the buffer to be searched, for example the contents of a file on
 * disk. The contents must be in memory, but obsLib calls can be chained one
 * after the other on chunks of a file without losing potential matches 
 * that overlap across 2 chunks since it uses a state machine which is only
 * reset by calling obsLib_resetSearchState.
 *
 * @param   HObs    hObs
 *   The handle of the obs object to use in the search
 *
 * @param   RPU8    pTargetBuffer
 *   Pointer to the buffer to search
 *
 * @param   RU32    targetBufferSize
 *   Size in bytes of the buffer to search
 *
 * @return RBOOL
 *   Returns TRUE if buffer to search has been correctly set in the obs object
 */
RBOOL
    obsLib_setTargetBuffer
    (
        HObs hObs,
        RPVOID pTargetBuffer,
        RU32 targetBufferSize
    );

/**
 * Get the next (or first) match found by the obs search
 * 
 * Starts the search by the obs object using the patterns
 * already inputted in the object and the target buffer previously set.
 *
 * @param   HObs    hObs
 *   The handle of the obs object to search with

 * @param   RPVOID* pContextHit
 *   OUT pointer receiving the context originally set during the 
 *   obsLib_addPattern call of the next pattern found
 *
 * @param   RPVOID* pHitLocation
 *   (optional) OUT pointer to the start of the pattern found in the target
 *   buffer. WARNING, this can be *outside* of the current iteration of the
 *   obsLib_setTargetBuffer if the pattern has been found in the current 
 *   buffer but had started in the previous call to obsLib_setTargetBuffer,
 *   meaning that it overlapped the two chunks
 *
 * @return RBOOL
 *   Returns TRUE if a pattern was found (and the OUT variables have been
 *   set to the correct values). A value of FALSE means all patterns of the
 *   obs object have been "exhausted" from the target buffer
 */
RBOOL
    obsLib_nextHit
    (
        HObs hObs,
        RPVOID* pContextHit,
        RPVOID* pHitLocation
    );

/**
 * Reset the internal state of an obs object.
 * 
 * This should be used when starting a new search on a different file
 * (for example) where looking for overlapping patterns does not make
 * sense.
 *
 * @param   HObs    hObs
 *   The handle of the obs object to reset
 */
RVOID
    obsLib_resetSearchState
    (
        HObs hObs
    );

/**
 * Get the number of patterns currently stored in the obs object.
 * 
 * @param   HObs    hObs
 *   The handle of the obs object query
 *
 * @return  RU32
 *   Returns number of patterns stored
 */
RU32
    obsLib_getNumPatterns
    (
        HObs hObs
    );

#endif
