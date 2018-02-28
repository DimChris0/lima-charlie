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

#ifndef _PROCESS_LIB_H
#define _PROCESS_LIB_H


#include <rpal/rpal.h>
#include <librpcm/librpcm.h>

typedef struct
{
    RU32 pid;

} processLibProcEntry;

#define PROCESSLIB_MEM_TYPE_UNKNOWN     0x00
#define PROCESSLIB_MEM_TYPE_IMAGE       0x01
#define PROCESSLIB_MEM_TYPE_MAPPED      0x02
#define PROCESSLIB_MEM_TYPE_PRIVATE     0x03
#define PROCESSLIB_MEM_TYPE_EMPTY       0x04
#define PROCESSLIB_MEM_TYPE_SHARED      0x05

#define PROCESSLIB_MEM_ACCESS_DENIED                0x00
#define PROCESSLIB_MEM_ACCESS_EXECUTE               0x01
#define PROCESSLIB_MEM_ACCESS_EXECUTE_READ          0x02
#define PROCESSLIB_MEM_ACCESS_EXECUTE_READ_WRITE    0x03
#define PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE_COPY    0x04
#define PROCESSLIB_MEM_ACCESS_NO_ACCESS             0x05
#define PROCESSLIB_MEM_ACCESS_READ_ONLY             0x06
#define PROCESSLIB_MEM_ACCESS_READ_WRITE            0x07
#define PROCESSLIB_MEM_ACCESS_WRITE_COPY            0x08
#define PROCESSLIB_MEM_ACCESS_WRITE_ONLY            0x09
#define PROCESSLIB_MEM_ACCESS_EXECUTE_WRITE         0x0a

RBOOL
    processLib_isPidInUse
    (
        RU32 pid
    );

processLibProcEntry*
    processLib_getProcessEntries
    (
        RBOOL isBruteForce
    );

rSequence
    processLib_getProcessInfo
    (
        RU32 processId,
        rSequence bootstrap
    );

rList
    processLib_getProcessModules
    (
        RU32 processId
    );

rList
    processLib_getProcessMemoryMap
    (
        RU32 processId
    );

RBOOL
    processLib_getProcessMemory
    (
        RU32 processId,
        RPVOID baseAddr,
        RU64 size,
        RPVOID* pBuffer,
        RBOOL isBridgeGaps
    );

rList
    processLib_getHandles
    (
        RU32 processId,
        RBOOL isOnlyReturnNamed,
        RPNCHAR optSubstring
    );

RBOOL 
    processLib_killProcess
    ( 
        RU32 pid 
    );


RU32
    processLib_getCurrentPid
    (

    );

RPNCHAR
    processLib_getCurrentModulePath
    (
    
    );

#define processLib_getProcessEnvironment( pid )    processLib_getProcessEnvironment_from( pid, RPAL_LINE_SUBTAG )
rList
    processLib_getProcessEnvironment_from
    (
        RU32 pid,
		RU32 from
    );

rList
    processLib_getStackTrace
    (
        RU32 pid,
        RU32 tid,
        RBOOL isWithSymbolNames
    );

RVOID
    processLib_decorateStackTrace
    (
        RU32 pid,
        rList stackTrace
    );

rList
    processLib_getThreads
    (
        RU32 pid
    );

RU32
    processLib_getCurrentThreadId
    (

    );

RBOOL
    processLib_suspendProcess
    (
        RU32 pid
    );

RBOOL
    processLib_suspendThread
    (
        RU32 pid,
        rThreadID tid
    );

RBOOL
    processLib_resumeProcess
    (
        RU32 pid
    );

RBOOL
    processLib_resumeThread
    (
        RU32 pid,
        rThreadID tid
    );

#endif
