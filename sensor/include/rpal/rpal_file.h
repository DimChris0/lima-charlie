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

#ifndef _RPAL_FILE_H
#define _RPAL_FILE_H

#include <rpal/rpal.h>

#pragma pack(push)
#pragma pack(1)


typedef RPVOID rDirCrawl;

typedef RPVOID rDirWatch;

typedef struct
{
    RU32 attributes;
    RU64 creationTime;
    RU64 modificationTime;
    RU64 lastAccessTime;
    RU64 size;
    RNCHAR filePath[ RPAL_MAX_PATH ];
    RPNCHAR fileName;

} rFileInfo;

        
typedef RPVOID rFile;
typedef RPVOID rDir;

enum rFileSeek
{
    rFileSeek_CUR,
    rFileSeek_END,
    rFileSeek_SET
};

#define RPAL_FILE_ATTRIBUTE_DIRECTORY       0x00000001
#define RPAL_FILE_ATTRIBUTE_HIDDEN          0x00000002
#define RPAL_FILE_ATTRIBUTE_READONLY        0x00000004
#define RPAL_FILE_ATTRIBUTE_SYSTEM          0x00000008
#define RPAL_FILE_ATTRIBUTE_TEMP            0x00000010
#define RPAL_FILE_ATTRIBUTE_EXECUTE         0x00000020

#define RPAL_FILE_OPEN_READ                 0x00000001
#define RPAL_FILE_OPEN_WRITE                0x00000002
#define RPAL_FILE_OPEN_EXISTING             0x00000004
#define RPAL_FILE_OPEN_NEW                  0x00000008
#define RPAL_FILE_OPEN_ALWAYS               0x00000010
#define RPAL_FILE_OPEN_AVOID_TIMESTAMPS     0x00000020

#pragma pack(pop)


#ifdef RPAL_PLATFORM_WINDOWS
    #define RPAL_FILE_LOCAL_DIR_SEP_W    _WCH("\\")
    #define RPAL_FILE_LOCAL_DIR_SEP_A   "\\"
    #define RPAL_FILE_LOCAL_DIR_SEP_N   RPAL_FILE_LOCAL_DIR_SEP_W
#else
    #define RPAL_FILE_LOCAL_DIR_SEP_W   { _WCH("/") }
    #define RPAL_FILE_LOCAL_DIR_SEP_A   { "/" }
    #define RPAL_FILE_LOCAL_DIR_SEP_N   RPAL_FILE_LOCAL_DIR_SEP_A
#endif

RBOOL
    rpal_file_delete
    (
        RPNCHAR filePath,
        RBOOL isSafeDelete
    );

RBOOL
    rpal_file_move
    (
        RPNCHAR srcFilePath,
        RPNCHAR dstFilePath
    );

RBOOL
    rpal_file_copy
    (
        RPNCHAR srcFilePath,
        RPNCHAR dstFilePath
    );

RBOOL
    rpal_file_getInfo
    (
        RPNCHAR filePath,
        rFileInfo* pFileInfo
    );

RBOOL
    rpal_file_getInfo
    (
        RPNCHAR filePath,
        rFileInfo* pFileInfo
    );

RBOOL
    rpal_file_read
    (
        RPNCHAR filePath,
        RPU8* pBuffer,
        RU32* pBufferSize,
        RBOOL isAvoidTimestamps
    );

RU32
    rpal_file_getSizeW
    (
        RPWCHAR filePath,
        RBOOL isAvoidTimestamps
    );

RU32
    rpal_file_getSizeA
    (
        RPCHAR filePath,
        RBOOL isAvoidTimestamps
    );

RU32
    rpal_file_getSize
    (
        RPNCHAR filePath,
        RBOOL isAvoidTimestamps
    );

RBOOL
    rpal_file_write
    (
        RPNCHAR filePath,
        RPVOID buffer,
        RU32 bufferSize,
        RBOOL isOverwrite
    );

RBOOL
    rpal_file_pathToLocalSep
    (
        RPNCHAR path
    );

RBOOL
    rpal_file_getLinkDest
    (
        RPNCHAR linkPath,
        RPNCHAR* pDestination
    );


rDirCrawl
    rpal_file_crawlStart
    (
        RPNCHAR rootExpr,
        RPNCHAR fileExpr[],
        RU32 nMaxDepth
    );

RBOOL
    rpal_file_crawlNextFile
    (
        rDirCrawl hCrawl,
        rFileInfo* pFileInfo
    );

RVOID
    rpal_file_crawlStop
    (
        rDirCrawl hDirCrawl
    );

RPNCHAR
    rpal_file_filePathToFileName
    (
        RPNCHAR filePath
    );

RBOOL
    rDir_open
    (
        RPNCHAR dirPath,
        rDir* phDir
    );

RVOID
    rDir_close
    (
        rDir hDir
    );

RBOOL
    rDir_next
    (
        rDir hDir,
        rFileInfo* pFileInfo
    );

RBOOL
    rDir_create
    (
        RPNCHAR dirPath
    );

RBOOL
    rFile_open
    (
        RPNCHAR filePath,
        rFile* phFile,
        RU32 flags
    );

RVOID
    rFile_close
    (
        rFile hFile
    );

RU64
    rFile_seek
    (
        rFile hFile,
        RU64 offset,
        enum rFileSeek origin
    );

RBOOL
    rFile_read
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    );

RU32
    rFile_readUpTo
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    );

RBOOL
    rFile_write
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    );


#define RPAL_DIR_WATCH_CHANGE_FILE_NAME         0x00000001
#define RPAL_DIR_WATCH_CHANGE_DIR_NAME          0000000002
#define RPAL_DIR_WATCH_CHANGE_ATTRIBUTES        0x00000004
#define RPAL_DIR_WATCH_CHANGE_SIZE              0x00000008
#define RPAL_DIR_WATCH_CHANGE_LAST_WRITE        0x00000010
#define RPAL_DIR_WATCH_CHANGE_LAST_ACCESS       0x00000020
#define RPAL_DIR_WATCH_CHANGE_CREATION          0x00000040
#define RPAL_DIR_WATCH_CHANGE_SECURITY          0x00000080
#define RPAL_DIR_WATCH_CHANGE_ALL               0x000000FF

#define RPAL_DIR_WATCH_ACTION_ANY               0
#define RPAL_DIR_WATCH_ACTION_ADDED             1
#define RPAL_DIR_WATCH_ACTION_REMOVED           2
#define RPAL_DIR_WATCH_ACTION_MODIFIED          3
#define RPAL_DIR_WATCH_ACTION_RENAMED_OLD       4
#define RPAL_DIR_WATCH_ACTION_RENAMED_NEW       5

rDirWatch
    rDirWatch_new
    (
        RPNCHAR dir,
        RU32 watchFlags,
        RBOOL includeSubDirs
    );

RVOID
    rDirWatch_free
    (
        rDirWatch watch
    );

RBOOL
    rDirWatch_next
    (
        rDirWatch watch,
        RU32 timeout,
        RPNCHAR* pFilePath,
        RU32* pAction
    );

RPNCHAR
    rpal_file_clean
    (
        RPNCHAR filePath
    );

#endif
