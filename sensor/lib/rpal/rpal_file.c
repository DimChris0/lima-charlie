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

// This definition is required for FTW on Linux, it MUST be the first line
// in the source, not even an ifdef.
#define _XOPEN_SOURCE 500

#include <rpal/rpal_file.h>

#define RPAL_FILE_ID     6

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    #include <dirent.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <ftw.h>
#elif defined( RPAL_PLATFORM_WINDOWS )
    #include <shobjidl.h>
    #include <shlguid.h>
    #include <strsafe.h>
    #include <shellapi.h>
#endif

#ifdef RPAL_PLATFORM_LINUX
#include <sys/inotify.h>
#include <limits.h>
#include <sys/select.h>
#endif

typedef struct
{
    rStack stack;
    RPNCHAR dirExp;
    RPNCHAR* fileExp;
    RU32 nMaxDepth;

} _rDirCrawl, *_prDirCrawl;


typedef struct
{
#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE handle;
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    DIR* handle;
#endif
    RPNCHAR dirPath;
} _rDir;

typedef struct
{
#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE handle;
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    FILE* handle;
#endif
} _rFile;


typedef struct
{
#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hDir;
    RU8 changes[ 64 * 1024 ];
    FILE_NOTIFY_INFORMATION* curChange;
    HANDLE hChange;
    RBOOL includeSubDirs;
    RU32 flags;
    RWCHAR tmpTerminator;
    RPWCHAR pTerminator;
    RBOOL isPending;
    OVERLAPPED oChange;
#elif defined( RPAL_PLATFORM_LINUX )
    RS32 hWatch;
    RU8 changes[ ( 100 * ( sizeof( struct inotify_event ) + NAME_MAX + 1 ) ) ];
    RU32 offset;
    RS32 bytesRead;
    rBTree hChanges;
    RBOOL isRecursive;
    RNCHAR latestPath[ NAME_MAX ];
    RPNCHAR root;
#endif
} _rDirWatch;

#ifdef RPAL_PLATFORM_LINUX
typedef struct
{
    RS32 handle;
    RNCHAR name[ NAME_MAX ];
} _watchStub;
#endif

#if defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
RPRIVATE
int 
    unlink_dir_cb
    ( 
        const char* path, 
        const struct stat* sb, 
        int typeFlag, 
        struct FTW* ftwBuff
    )
{
    UNREFERENCED_PARAMETER( sb );
    UNREFERENCED_PARAMETER( typeFlag );
    UNREFERENCED_PARAMETER( ftwBuff );
    return remove( path );
}
#endif

RBOOL
    rpal_file_delete
    (
        RPNCHAR filePath,
        RBOOL isSafeDelete
    )
{
    RBOOL isDeleted = FALSE;

    RPNCHAR tmpPath = NULL;
    rFileInfo info = { 0 };
    RBOOL isDir = FALSE;

    if( NULL != filePath )
    {
        if( rpal_string_expand( filePath, &tmpPath ) )
        {
            if( isSafeDelete )
            {
                // TODO: overwrite several times with random data
            }

            if( rpal_file_getInfo( tmpPath, &info ) )
            {
                isDir = IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY );
            }
#ifdef RPAL_PLATFORM_WINDOWS
            if( !isDir )
            {
                if( DeleteFileW( tmpPath ) )
                {
                    isDeleted = TRUE;
                }
            }
            else
            {
                if( NULL != ( tmpPath = rpal_memory_reAlloc( tmpPath, rpal_string_strsize( tmpPath ) + sizeof( RNCHAR ) ) ) )
                {
                    SHFILEOPSTRUCTW opInfo = { 0 };
                    opInfo.wFunc = FO_DELETE;
                    opInfo.pFrom = tmpPath;
                    ENABLE_FLAG( opInfo.fFlags, FOF_NOCONFIRMATION );
                    ENABLE_FLAG( opInfo.fFlags, FOF_SILENT );

                    if( 0 == SHFileOperationW( &opInfo ) )
                    {
                        isDeleted = TRUE;
                    }
                }
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( !isDir )
            {
                if( 0 == unlink( tmpPath ) )
                {
                    isDeleted = TRUE;
                }
            }
            else
            {
                if( 0 == nftw( tmpPath, unlink_dir_cb, 64, FTW_DEPTH | FTW_PHYS ) )
                {
                    isDeleted = TRUE;
                }
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return isDeleted;
}

RBOOL
    rpal_file_move
    (
        RPNCHAR srcFilePath,
        RPNCHAR dstFilePath
    )
{
    RBOOL isMoved = FALSE;

    RPNCHAR tmpPath1 = NULL;
    RPNCHAR tmpPath2 = NULL;

    if( NULL != srcFilePath && NULL != dstFilePath )
    {
        if( rpal_string_expand( srcFilePath, &tmpPath1 ) &&
            rpal_string_expand( dstFilePath, &tmpPath2 ) )
        {
            
#ifdef RPAL_PLATFORM_WINDOWS
            if( MoveFileW( tmpPath1, tmpPath2 ) )
            {
                isMoved = TRUE;
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( 0 == rename( tmpPath1, tmpPath2 ) )
            {
                isMoved = TRUE;
            }
#endif
        }

        rpal_memory_free( tmpPath1 );
        rpal_memory_free( tmpPath2 );
    }

    return isMoved;
}

RBOOL
    rpal_file_copy
    (
        RPNCHAR srcFilePath,
        RPNCHAR dstFilePath
    )
{
    RBOOL isCopied = FALSE;

    if( NULL != srcFilePath && NULL != dstFilePath )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RPNCHAR tmpPath1 = NULL;
        RPNCHAR tmpPath2 = NULL;

        if( rpal_string_expand( srcFilePath, &tmpPath1 ) &&
            rpal_string_expand( dstFilePath, &tmpPath2 ) &&
            CopyFileW( tmpPath1, tmpPath2, FALSE ) )
        {
            isCopied = TRUE;
        }

        rpal_memory_free( tmpPath1 );
        rpal_memory_free( tmpPath2 );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        rFile fileIn = NULL;
        rFile fileOut = NULL;
        RU8 buff[ 4 * 1024 ] = { 0 };
        RU32 read = 0;

        if( rFile_open( srcFilePath, &fileIn, RPAL_FILE_OPEN_READ | RPAL_FILE_OPEN_EXISTING ) &&
            rFile_open( dstFilePath, &fileOut, RPAL_FILE_OPEN_WRITE | RPAL_FILE_OPEN_ALWAYS ) )
        {
            isCopied = TRUE;

            while( ( read = rFile_readUpTo( fileIn, sizeof( buff ), buff ) ) > 0 )
            {
                if( !rFile_write( fileOut, read, buff ) )
                {
                    isCopied = FALSE;
                    break;
                }
            }
        }

        rFile_close( fileIn );
        rFile_close( fileOut );
#endif
    }

    return isCopied;
}

RBOOL
    rpal_file_getInfo
    (
        RPNCHAR filePath,
        rFileInfo* pFileInfo
    )
{
    RBOOL isSuccess = FALSE;
    
    RPNCHAR expFilePath = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    WIN32_FIND_DATAW findData = {0};
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    struct stat fileInfo = {0};
#endif

    if ( NULL != filePath && NULL != pFileInfo )
    {
        if( rpal_string_expand( filePath, &expFilePath ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            HANDLE hFind = NULL;

            if( INVALID_HANDLE_VALUE == ( hFind = FindFirstFileW( expFilePath, &findData ) ) )
            {
                rpal_memory_free( expFilePath );
                return FALSE;
            }
            else
            {
                FindClose( hFind );

                pFileInfo->attributes = 0;

                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_HIDDEN ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_HIDDEN );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_READONLY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_READONLY );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_SYSTEM ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_SYSTEM );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_TEMPORARY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_TEMP );
                }

                pFileInfo->creationTime = rpal_winFileTimeToMsTs( findData.ftCreationTime );
                pFileInfo->lastAccessTime = rpal_winFileTimeToMsTs( findData.ftLastAccessTime );
                pFileInfo->modificationTime = rpal_winFileTimeToMsTs( findData.ftLastWriteTime );

                pFileInfo->size = ( (RU64)findData.nFileSizeHigh << 32 ) | findData.nFileSizeLow;

                rpal_memory_zero( pFileInfo->filePath, sizeof( pFileInfo->filePath ) );

                if( RPAL_MAX_PATH > rpal_string_strlen( expFilePath ) && RPAL_MAX_PATH > rpal_string_strlen( findData.cFileName ) &&
                    NULL != rpal_string_strcpy( pFileInfo->filePath, expFilePath ) )
                {
                    isSuccess = TRUE;
                }
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            rpal_memory_zero( pFileInfo->filePath, sizeof( pFileInfo->filePath ) );

            if( RPAL_MAX_PATH > rpal_string_strlen( expFilePath ) )
            {
                if( NULL != rpal_string_strcpy( pFileInfo->filePath, expFilePath ) )
                {
                    isSuccess = TRUE;
                }
            }

            if( isSuccess )
            {
                pFileInfo->attributes = 0;
                pFileInfo->creationTime = 0;
                pFileInfo->lastAccessTime = 0;
                pFileInfo->modificationTime = 0;
                pFileInfo->size = 0;

                if( 0 == stat( expFilePath, &fileInfo ) )
                {
                    if( S_ISDIR( fileInfo.st_mode ) )
                    {
                        ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY );
                    }

                    pFileInfo->creationTime = ( (RU64) fileInfo.st_ctime );
                    pFileInfo->lastAccessTime = ( (RU64) fileInfo.st_atime );
                    pFileInfo->modificationTime = ( (RU64) fileInfo.st_mtime );

                    pFileInfo->size = ( (RU64) fileInfo.st_size );
                }
                else
                {
                    rpal_memory_zero( pFileInfo, sizeof( *pFileInfo ) );
                    isSuccess = FALSE;
                }
            }
#endif
            rpal_memory_free( expFilePath );
        }
    }

    return isSuccess;
}

RBOOL
    rpal_file_read
    (
        RPNCHAR filePath,
        RPU8* pBuffer,
        RU32* pBufferSize,
        RBOOL isAvoidTimestamps
    )
{
    RBOOL isSuccess = FALSE;

    RPNCHAR tmpPath = NULL;
    RPVOID tmpFile = NULL;
    RU32 fileSize = 0;

#ifdef RPAL_PLATFORM_WINDOWS
    HANDLE hFile = NULL;
    RU32 flags = 0;
    RU32 access = GENERIC_READ;
    RU32 read = 0;
    FILETIME disableFileTime = { (DWORD)(-1), (DWORD)(-1) };

    flags = FILE_FLAG_SEQUENTIAL_SCAN;
    if( isAvoidTimestamps )
    {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
        access |= FILE_WRITE_ATTRIBUTES;
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    FILE* hFile = NULL;
    RU8 localBuffer[ 1024 ] = {0};
    RU32 localRead = 0;
#endif

    if( NULL != filePath &&
        NULL != pBuffer &&
        NULL != pBufferSize )
    {
        if( rpal_string_expand( filePath, &tmpPath ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            hFile = CreateFileW( tmpPath, access, FILE_SHARE_READ, NULL, OPEN_EXISTING, flags, NULL );

            if( INVALID_HANDLE_VALUE != hFile )
            {
                if( isAvoidTimestamps )
                {
                    SetFileTime( hFile, NULL, &disableFileTime, NULL );
                }

                fileSize = GetFileSize( hFile, NULL );

                if( INVALID_FILE_SIZE != fileSize )
                {
                    tmpFile = rpal_memory_alloc( fileSize );

                    if( rpal_memory_isValid( tmpFile ) )
                    {
                        if( ReadFile( hFile, tmpFile, fileSize, (LPDWORD)&read, NULL ) &&
                            fileSize == read )
                        {
                            isSuccess = TRUE;

                            *pBuffer = tmpFile;
                            *pBufferSize = fileSize;
                        }
                        else
                        {
                            rpal_memory_free( tmpFile );
                        }
                    }
                }
                
                CloseHandle( hFile );
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( NULL != ( hFile = fopen( tmpPath, "r" ) ) )
            {
                // We get the file size as we read since in nix some special files (like in /proc)
                // will return a file size of 0 if we use the fseek and ftell method.
                do
                {
                    localRead = (RU32)fread( localBuffer, sizeof( RU8 ), sizeof( localBuffer ), hFile );
                        
                    if( 0 != localRead )
                    {
                        if( NULL != ( tmpFile = rpal_memory_realloc( tmpFile, fileSize + localRead ) ) )
                        {
                            rpal_memory_memcpy( (RPU8)tmpFile + fileSize, localBuffer, localRead );
                        }
                            
                        fileSize += localRead;
                    }
                }
                while( localRead == sizeof( localBuffer ) );
                    
                if( NULL != tmpFile )
                {
                    isSuccess = TRUE;
                    *pBuffer = tmpFile;
                    *pBufferSize = fileSize;
                    rpal_memory_zero( localBuffer, sizeof( localBuffer ) );
                }
                    
                fclose( hFile );
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return isSuccess;
}


RU32
    rpal_file_getSizeW
    (
        RPWCHAR filePath,
        RBOOL isAvoidTimestamps
    )
{
    RU32 size = (RU32)( -1 );

    RPWCHAR tmpPath = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    RU32 flags = 0;
    RU32 access = GENERIC_READ;
    HANDLE hFile = NULL;
    FILETIME disableFileTime = { (DWORD)( -1 ), (DWORD)( -1 ) };

    flags = 0;
    if( isAvoidTimestamps )
    {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
        access |= FILE_WRITE_ATTRIBUTES;
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPCHAR localFile = NULL;
    FILE* hFile = NULL;
#endif

    if( NULL != filePath )
    {
        if( rpal_string_expandW( filePath, &tmpPath ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            hFile = CreateFileW( tmpPath, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flags, NULL );

            if( INVALID_HANDLE_VALUE != hFile )
            {
                if( isAvoidTimestamps )
                {
                    SetFileTime( hFile, NULL, &disableFileTime, NULL );
                }

                size = GetFileSize( hFile, NULL );

                CloseHandle( hFile );
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( NULL != ( localFile = rpal_string_wtoa( tmpPath ) ) )
            {
                if( NULL != ( hFile = fopen( localFile, "r" ) ) )
                {
                    if( 0 == fseek( hFile, 0, SEEK_END ) )
                    {
                        if( ( -1 ) != ( size = (RU32)ftell( hFile ) ) )
                        {
                            // Success
                        }
                    }

                    fclose( hFile );
                }

                rpal_memory_free( localFile );
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return size;
}

RU32
    rpal_file_getSizeA
    (
        RPCHAR filePath,
        RBOOL isAvoidTimestamps
    )
{
    RU32 size = (RU32)( -1 );

    RPCHAR tmpPath = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    RU32 flags = 0;
    RU32 access = GENERIC_READ;
    HANDLE hFile = NULL;
    FILETIME disableFileTime = { (DWORD)( -1 ), (DWORD)( -1 ) };

    flags = 0;
    if( isAvoidTimestamps )
    {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
        access |= FILE_WRITE_ATTRIBUTES;
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    FILE* hFile = NULL;
#endif

    if( NULL != filePath )
    {
        if( rpal_string_expandA( filePath, &tmpPath ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            hFile = CreateFileA( tmpPath, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flags, NULL );

            if( INVALID_HANDLE_VALUE != hFile )
            {
                if( isAvoidTimestamps )
                {
                    SetFileTime( hFile, NULL, &disableFileTime, NULL );
                }

                size = GetFileSize( hFile, NULL );

                CloseHandle( hFile );
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( NULL != ( hFile = fopen( tmpPath, "r" ) ) )
            {
                if( 0 == fseek( hFile, 0, SEEK_END ) )
                {
                    if( ( -1 ) != ( size = (RU32)ftell( hFile ) ) )
                    {
                        // Success
                    }
                }

                fclose( hFile );
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return size;
}

RU32
    rpal_file_getSize
    (
        RPNCHAR filePath,
        RBOOL isAvoidTimestamps
    )
{
#ifdef RNATIVE_IS_WIDE
    return rpal_file_getSizeW( filePath, isAvoidTimestamps );
#else
    return rpal_file_getSizeA( filePath, isAvoidTimestamps );
#endif
}

RBOOL
    rpal_file_write
    (
        RPNCHAR filePath,
        RPVOID buffer,
        RU32 bufferSize,
        RBOOL isOverwrite
    )
{
    RBOOL isSuccess = FALSE;

    RPNCHAR tmpPath = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
    RU32 flags = 0;
    RU32 written = 0;
    HANDLE hFile = NULL;
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPCHAR localFile = NULL;
    FILE* hFile = NULL;
#endif

    if( NULL != filePath &&
        NULL != buffer &&
        0 != bufferSize )
    {
        if( rpal_string_expand( filePath, &tmpPath ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            hFile = CreateFileW( tmpPath, 
                                GENERIC_WRITE, 
                                0, 
                                NULL, 
                                isOverwrite ? CREATE_ALWAYS : CREATE_NEW, 
                                flags, 
                                NULL );

            if( INVALID_HANDLE_VALUE != hFile )
            {
                if( WriteFile( hFile, buffer, bufferSize, (LPDWORD)&written, NULL ) &&
                    bufferSize == written )
                {
                    isSuccess = TRUE;
                }

                CloseHandle( hFile );
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( isOverwrite ||
                NULL == ( hFile = fopen( tmpPath, "r" ) ) )
            {
                if( NULL != ( hFile = fopen( tmpPath, "w" ) ) )
                {
                    if( 1 == fwrite( buffer, bufferSize, 1, hFile ) )
                    {
                        isSuccess = TRUE;
                    }
                        
                    fclose( hFile );
                }
            }
            else
            {
                // File already exists and we're not to overwrite...
                fclose( hFile );
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return isSuccess;
}



RBOOL
    rpal_file_pathToLocalSep
    (
        RPNCHAR path
    )
{
    RBOOL isSuccess = FALSE;
    RNCHAR search = 0;
    RNCHAR replace = 0;
    RU32 i = 0;

    if( NULL != path )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        search = _NC('/');
        replace = _NC('\\');
#else
        search = '\\';
        replace = '/';
#endif

        for( i = 0; i < rpal_string_strlen( path ); i++ )
        {
            if( search == path[ i ] )
            {
                path[ i ] = replace;
            }
        }

        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    rpal_file_getLinkDest
    (
        RPNCHAR linkPath,
        RPNCHAR* pDestination
    )
{
    RBOOL isSuccess = FALSE;
    
#ifdef RPAL_PLATFORM_WINDOWS
    HRESULT hres = 0;
    REFCLSID clsid_shelllink = &CLSID_ShellLink;
    REFIID ref_ishelllink = &IID_IShellLinkW;
    REFIID ref_ipersisfile = &IID_IPersistFile;
    IShellLinkW* psl = NULL;
    IPersistFile* ppf = NULL;
    WCHAR szGotPath[ MAX_PATH ] = {0};
    
    hres = CoInitialize( NULL );
    if( S_OK == hres || 
        S_FALSE == hres || 
        RPC_E_CHANGED_MODE == hres )
    {
        hres = CoCreateInstance( clsid_shelllink, NULL, CLSCTX_INPROC_SERVER, ref_ishelllink, (LPVOID*)&psl );
        if( SUCCEEDED( hres ) )
        {
            hres = psl->lpVtbl->QueryInterface( psl, ref_ipersisfile, (void**)&ppf );
        
            if( SUCCEEDED( hres ) ) 
            {
                hres = ppf->lpVtbl->Load( ppf, linkPath, STGM_READ );
            
                if( SUCCEEDED( hres ) )
                {
                    hres = psl->lpVtbl->GetPath( psl, szGotPath, MAX_PATH, NULL, 0 );

                    if( SUCCEEDED( hres ) )
                    {
                        if( NULL != ( *pDestination = rpal_string_strdup( szGotPath ) ) )
                        {
                            isSuccess = TRUE;
                        }
                    }
                }

                ppf->lpVtbl->Release( ppf );
            }

            psl->lpVtbl->Release( psl );
        }

        CoUninitialize();
    }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    if( NULL != linkPath &&
        NULL != pDestination )
    {
        RS32 size = 0;
        RPCHAR path = NULL;
        RCHAR tmp[ RPAL_MAX_PATH + 1 ] = {0};

        size = (RU32)readlink( linkPath, (RPCHAR)&tmp, sizeof( tmp ) - 1 );
        if( -1 != size
            && ( sizeof( tmp ) - 1 ) >= size )
        {
            if( NULL != ( *pDestination = rpal_string_strdup( (RPCHAR)&tmp ) ) )
            {
                isSuccess = TRUE;
            }
        }
    }
#endif
    
    return isSuccess;
}

RPNCHAR
    rpal_file_filePathToFileName
    (
        RPNCHAR filePath
    )
{
    RPNCHAR fileName = NULL;

    RU32 len = 0;

    if( NULL != filePath )
    {
        len = rpal_string_strlen( filePath );
        while( 0 != len )
        {
            len--;

#ifdef RPAL_PLATFORM_WINDOWS
            if( _WCH( '\\' ) == filePath[ len ] ||
                _WCH( '/' ) == filePath[ len ] )
#else
            if( '/' == filePath[ len ] )
#endif
            {
                fileName = &( filePath[ len + 1 ] );
                break;
            }
        }

        if( NULL == fileName )
        {
            fileName = filePath;
        }
    }

    return fileName;
}

static
rDirCrawl
    _newCrawlDir
    (
        RPNCHAR rootExpr,
        RPNCHAR fileExpr[],
        RU32 nMaxDepth
    )
{
    _prDirCrawl pCrawl = NULL;

    if( NULL != rootExpr &&
        NULL != fileExpr )
    {
        pCrawl = rpal_memory_alloc( sizeof( _rDirCrawl ) );

        if( NULL != pCrawl )
        {
            pCrawl->stack = rStack_new( sizeof( rFileInfo ) );

            if( NULL != pCrawl->stack )
            {
                pCrawl->dirExp = NULL;
                pCrawl->fileExp = NULL;
                pCrawl->nMaxDepth = nMaxDepth;
                
                rpal_string_expand( rootExpr, &(pCrawl->dirExp) );
                pCrawl->fileExp = fileExpr;

                if( NULL == pCrawl->dirExp ||
                    NULL == pCrawl->fileExp )
                {
                    rpal_memory_free( pCrawl->dirExp );
                    rStack_free( pCrawl->stack, NULL );
                    rpal_memory_free( pCrawl );
                    pCrawl = NULL;
                }
                else
                {
                    rpal_file_pathToLocalSep( pCrawl->dirExp );
                }
            }
            else
            {
                rpal_memory_free( pCrawl );
                pCrawl = NULL;
            }
        }
    }

    return pCrawl;
}

RBOOL
    _strHasWildcards
    (
        RPNCHAR str
    )
{
    RBOOL isWild = FALSE;

    RU32 i = 0;
    RU32 len = 0;

    len = rpal_string_strlen( str );

    for( i = 0; i < len; i++ )
    {
        if( _NC('*') == str[ i ] ||
            _NC('?') == str[ i ] )
        {
            isWild = TRUE;
            break;
        }
    }

    return isWild;
}

RBOOL
    _isFileInfoInCrawl
    (
        RPNCHAR dirExp,
        RPNCHAR fileExp[],
        RU32 nMaxDepth,
        rFileInfo* pInfo,
        RBOOL isPartialOk
    )
{
    RBOOL isIncluded = FALSE;

    RNCHAR sep[] = RPAL_FILE_LOCAL_DIR_SEP_N;

    RPNCHAR state1 = NULL;
    RPNCHAR state2 = NULL;
    RPNCHAR pPattern = NULL;
    RPNCHAR pPath = NULL;

    RU32 curDepth = 0;

    RPNCHAR* tmpFileExp = NULL;

    if( NULL != dirExp &&
        NULL != fileExp &&
        NULL != pInfo )
    {
        // Start by evaluating the path
        // Temporarily terminate the path part, if this is a directory then 
        // it already is a normal path...
        if( !IS_FLAG_ENABLED( pInfo->attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) )
        {
            *( pInfo->fileName - 1 ) = 0;
        }

        // Loop through the pattern and path at the same time
        pPattern = dirExp;
        pPath = pInfo->filePath;

        pPattern = rpal_string_strtok( pPattern, sep[ 0 ], &state1 );
        pPath = rpal_string_strtok( pPath, sep[ 0 ], &state2 );

        while( NULL != pPattern &&
               NULL != pPath )
        {
            if( !rpal_string_match( pPattern, pPath, TRUE ) )
            {
                break;
            }

            do
            {
                pPattern = rpal_string_strtok( NULL, sep[ 0 ], &state1 );
            }
            while( NULL != pPattern && 0 == pPattern[ 0 ] );    // We do this to support path with "//" or "\\"

            do
            {
                pPath = rpal_string_strtok( NULL, sep[ 0 ], &state2 );
            }
            while( NULL != pPath && 0 == pPath[ 0 ] );
        }

        // The match is valid if the path matches all tokens of
        // the pattern but it can also be longer, as long as it matches.
        if( NULL == pPattern )
        {
            isIncluded = TRUE;
        }

        // If the path ran out first, check if partial match is ok. This is used
        // to match a directory and see if it should be crawled further...
        if( NULL == pPath &&
            isPartialOk )
        {
            isIncluded = TRUE;
        }
        // Unwind the path if necessary
        else if( NULL != pPath )
        {
            // So the path is longer than the criteria, this means we have to 
            // validate whether we are past maxDepth...
            do
            {
                curDepth++;
            }
            while( NULL != rpal_string_strtok( NULL, sep[ 0 ], &state2 ) );

            if( curDepth > ( nMaxDepth + 1 ) )
            {
                // We are past our depth
                isIncluded = FALSE;
            }
        }

        // Unwind the pattern if necessary
        if( NULL != pPattern )
        {
            while( NULL != rpal_string_strtok( NULL, sep[ 0 ], &state1 ) ){}
        }

        // Even if this is a dir, it doesn't hurt to overwrite the sep.
        *( pInfo->fileName - 1 ) = sep[ 0 ];

        // If the path has matched so far
        if( isIncluded )
        {
            isIncluded = FALSE;

            // If this is not a check for partial data, we much always validate the file name.
            if( !isPartialOk )
            {
                // If this is not a directory, we much check to make sure the file matches.
                tmpFileExp = fileExp;
                while( NULL != *tmpFileExp )
                {
                    if( rpal_string_match( *tmpFileExp, pInfo->fileName, TRUE ) )
                    {
                        isIncluded = TRUE;
                        break;
                    }

                    tmpFileExp++;
                }
            }
            else
            {
                isIncluded = TRUE;
            }
        }
    }

    return isIncluded;
}

RVOID
    _fixFileInfoAfterPop
    (
        rFileInfo* pInfo
    )
{
    RU32 len = 0;
    RNCHAR sep[] = RPAL_FILE_LOCAL_DIR_SEP_N;

    if( NULL != pInfo )
    {
        pInfo->fileName = NULL;

        len = rpal_string_strlen( pInfo->filePath );

        if( 0 != len )
        {
            len--;

            while( 0 != len )
            {
                if( sep[ 0 ] == pInfo->filePath[ len ] )
                {
                    pInfo->fileName = &pInfo->filePath[ len + 1 ];
                    break;
                }

                len--;
            }

            if( NULL == pInfo->fileName )
            {
                pInfo->fileName = (RPNCHAR)&(pInfo->filePath);
            }
        }
    }
}


rDirCrawl
    rpal_file_crawlStart
    (
        RPNCHAR rootExpr,
        RPNCHAR fileExpr[],
        RU32 nMaxDepth
    )
{
    _prDirCrawl pCrawl = NULL;
    RPNCHAR staticRoot = NULL;
    RPNCHAR tmpStr = NULL;
    RPNCHAR state = NULL;
    RPNCHAR sep = RPAL_FILE_LOCAL_DIR_SEP_N;
    rDir hDir = NULL;
    rFileInfo info = {0};

    pCrawl = _newCrawlDir( rootExpr, fileExpr, nMaxDepth );
    
    if( NULL != pCrawl )
    {
        pCrawl->nMaxDepth = nMaxDepth;
        
        if( NULL != ( tmpStr = rpal_string_strtok( pCrawl->dirExp, sep[ 0 ], &state ) ) )
        {
            do
            {
                if( !_strHasWildcards( tmpStr ) )
                {
                    staticRoot = rpal_string_strcatEx( staticRoot, tmpStr );
                    staticRoot = rpal_string_strcatEx( staticRoot, sep );
                }
                else
                {
                    // Unwind the tokens to restore the string
                    while( NULL != ( tmpStr = rpal_string_strtok( NULL, sep[ 0 ], &state ) ) );
                    break;
                }
            }
            while( NULL != ( tmpStr = rpal_string_strtok( NULL, sep[ 0 ], &state ) ) );
        }

        if( NULL != staticRoot )
        {
            staticRoot[ rpal_string_strlen( staticRoot ) - 1 ] = 0;
            
            if( rDir_open( staticRoot, &hDir ) )
            {
                while( rDir_next( hDir, &info ) )
                {
                    if( _isFileInfoInCrawl( pCrawl->dirExp, 
                                            pCrawl->fileExp, 
                                            pCrawl->nMaxDepth, 
                                            &info,
                                            IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) ) ||
                        ( IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) &&  // If a directory is not
                          _isFileInfoInCrawl( pCrawl->dirExp,                                 // to be crawled, it may
                                              pCrawl->fileExp,                                // still be a perfect match.
                                              pCrawl->nMaxDepth, 
                                              &info, 
                                              FALSE ) ) )
                    {
                        // Match dir against dir and file again file???????
                        if( !rStack_push( pCrawl->stack, &info ) )
                        {
                            rpal_file_crawlStop( pCrawl );
                            pCrawl = NULL;
                            break;
                        }
                    }
                }

                rDir_close( hDir );
            }

            rpal_memory_free( staticRoot );
        }
        else
        {
            rpal_file_crawlStop( pCrawl );
            pCrawl = NULL;
        }
    }

    return pCrawl;
}


RBOOL
    rpal_file_crawlNextFile
    (
        rDirCrawl hCrawl,
        rFileInfo* pFileInfo
    )
{
    RBOOL isSuccess = FALSE;

    _prDirCrawl pCrawl = (_prDirCrawl)hCrawl;
    rFileInfo info = {0};
    rDir tmpDir = NULL;
    
    if( NULL != pCrawl )
    {
        while( !isSuccess &&
               rStack_pop( pCrawl->stack, &info ) )
        {
            // The ptr in the info is a local ptr, so it probably changes when we 
            // moved the memory so we have to "re-base" it using the path.
            _fixFileInfoAfterPop( &info );

            // If it's a directory, we will report it but drill down
            if( IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) )
            {
                // Dirs on the stack do NOT necessarily match the criteria. We may have pushed
                // them simply because they PARTIALLY matched the criteria and therefore we needed
                // them to keep drilling down...
                if( _isFileInfoInCrawl( pCrawl->dirExp, pCrawl->fileExp, pCrawl->nMaxDepth, &info, FALSE ) )
                {
                    *pFileInfo = info;
                    _fixFileInfoAfterPop( pFileInfo );
                    isSuccess = TRUE;
                }

                // This is a shortcut if depth is 0, we will never want to drill down further
                if( 0 != pCrawl->nMaxDepth )
                {
                    if( rDir_open( info.filePath, &tmpDir ) )
                    {
                        while( rDir_next( tmpDir, &info ) )
                        {
                            if( _isFileInfoInCrawl( pCrawl->dirExp, 
                                                    pCrawl->fileExp, 
                                                    pCrawl->nMaxDepth, 
                                                    &info, 
                                                    IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) ) ||
                                ( IS_FLAG_ENABLED( info.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) &&  // If a directory is not
                                  _isFileInfoInCrawl( pCrawl->dirExp,                                   // to be crawled, it may
                                                      pCrawl->fileExp,                                  // still be a perfect match.
                                                      pCrawl->nMaxDepth, 
                                                      &info, 
                                                      FALSE ) ) )
                            {
                                if( !rStack_push( pCrawl->stack, &info ) )
                                {
                                    // This is bad, but not much we can do
                                    isSuccess = FALSE;
                                    break;
                                }
                            }
                        }

                        rDir_close( tmpDir );
                    }
                }
            }
            else
            {
                // Files on the stack are always matching since we check before
                // pushing them onto the stack.
                *pFileInfo = info;
                _fixFileInfoAfterPop( pFileInfo );
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}


#ifdef RPAL_PLATFORM_WINDOWS
static
RBOOL
    _freeStringWrapper
    (
        RPNCHAR str
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != str )
    {
        rpal_memory_free( str );
        isSuccess = TRUE;
    }

    return isSuccess;
}
#endif


RVOID
    rpal_file_crawlStop
    (
        rDirCrawl hDirCrawl
    )
{
    _prDirCrawl pCrawl = (_prDirCrawl)hDirCrawl;

    if( NULL != hDirCrawl )
    {
        rStack_free( pCrawl->stack, NULL );
        rpal_memory_free( pCrawl->dirExp );
        rpal_memory_free( pCrawl );
    }
}


RBOOL
    rDir_open
    (
        RPNCHAR dirPath,
        rDir* phDir
    )
{
    RBOOL isSuccess = FALSE;
    _rDir* dir = NULL;
    RNCHAR sep[] = RPAL_FILE_LOCAL_DIR_SEP_N;
    RPNCHAR tmpDir = NULL;

    if( NULL != dirPath &&
        NULL != phDir &&
        0 < rpal_string_strlen( dirPath ) )
    {
        if( rpal_string_expand( dirPath, &tmpDir ) )
        {
            dir = rpal_memory_alloc( sizeof( *dir ) );
            
            if( NULL != dir )
            {
                dir->handle = NULL;
                
                if( NULL != ( dir->dirPath = rpal_string_strdup( tmpDir ) ) )
                {
                    rpal_file_pathToLocalSep( dir->dirPath );
                    
                    if( sep[ 0 ] != dir->dirPath[ rpal_string_strlen( dir->dirPath ) - 1  ] )
                    {
                        dir->dirPath = rpal_string_strcatEx( dir->dirPath, sep );
                    }
                    
                    if( NULL != dir->dirPath )
                    {
#ifdef RPAL_PLATFORM_WINDOWS
                        *phDir = dir;
                        isSuccess = TRUE;
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
                            if( NULL != ( dir->handle = opendir( dir->dirPath ) ) )
                            {
                                *phDir = dir;
                                isSuccess = TRUE;
                            }
                            else
                            {
                                rpal_memory_free( dir->dirPath );
                                rpal_memory_free( dir );
                            }
#endif
                    }
                    else
                    {
                        rpal_memory_free( dir );
                        dir = NULL;
                    }
                }
                else
                {
                    rpal_memory_free( dir );
                }
            }
            
            rpal_memory_free( tmpDir );
        }
    }

    return isSuccess;
}

RVOID
    rDir_close
    (
        rDir hDir
    )
{
    if( NULL != hDir )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( INVALID_HANDLE_VALUE != hDir )
        {
            FindClose( ((_rDir*)hDir)->handle );
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( NULL != hDir )
        {
            closedir( ((_rDir*)hDir)->handle );
        }
#endif
        rpal_memory_free( ((_rDir*)hDir)->dirPath );

        rpal_memory_free( hDir );
    }
}

RBOOL
    rDir_next
    (
        rDir hDir,
        rFileInfo* pFileInfo
    )
{
    RBOOL isSuccess = FALSE;
    _rDir* dir = (_rDir*)hDir;
    RBOOL isDataReady = FALSE;

#ifdef RPAL_PLATFORM_WINDOWS
    WIN32_FIND_DATAW findData = {0};
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    struct dirent *findData = NULL;
    struct stat fileInfo = {0};
#endif

    if( NULL != hDir &&
        NULL != pFileInfo )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( INVALID_HANDLE_VALUE != dir->handle )
        {
            if( NULL == dir->handle )
            {
                if( _WCH('*') != dir->dirPath[ rpal_string_strlen( dir->dirPath ) - 1 ] )
                {
                    dir->dirPath = rpal_string_strcatEx( dir->dirPath, _WCH("*") );
                }

                if( INVALID_HANDLE_VALUE == ( dir->handle = FindFirstFileW( dir->dirPath, &findData ) ) )
                {
                    return FALSE;
                }
                else
                {
                    isDataReady = TRUE;
                }

                // We can now remove the trailing *
                dir->dirPath[ rpal_string_strlen( dir->dirPath ) - 1 ] = 0;
            }

            if( !isDataReady )
            {
                if( !FindNextFileW( dir->handle, &findData ) )
                {
                    return FALSE;
                }
                else
                {
                    isDataReady = TRUE;
                }
            }

            if( isDataReady )
            {
                while( 0 == rpal_string_strcmp( _WCH("."), findData.cFileName ) ||
                       0 == rpal_string_strcmp( _WCH(".."), findData.cFileName ) )
                {
                    if( !FindNextFileW( dir->handle, &findData ) )
                    {
                        isDataReady = FALSE;
                        break;
                    }
                }
            }

            if( isDataReady )
            {
                pFileInfo->attributes = 0;

                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_HIDDEN ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_HIDDEN );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_READONLY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_READONLY );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_SYSTEM ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_SYSTEM );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_ATTRIBUTE_TEMPORARY ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_TEMP );
                }
                if( IS_FLAG_ENABLED( findData.dwFileAttributes, FILE_EXECUTE ) )
                {
                    ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_EXECUTE );
                }

                pFileInfo->creationTime = rpal_winFileTimeToMsTs( findData.ftCreationTime );
                pFileInfo->lastAccessTime = rpal_winFileTimeToMsTs( findData.ftLastAccessTime );
                pFileInfo->modificationTime = rpal_winFileTimeToMsTs( findData.ftLastWriteTime );

                pFileInfo->size = ( (RU64)findData.nFileSizeHigh << 32 ) | findData.nFileSizeLow;

                rpal_memory_zero( pFileInfo->filePath, sizeof( pFileInfo->filePath ) );

                if( RPAL_MAX_PATH > ( rpal_string_strlen( dir->dirPath ) + 
                                      rpal_string_strlen( findData.cFileName ) ) &&
                    NULL != rpal_string_strcat( pFileInfo->filePath, dir->dirPath ) &&
                    NULL != ( pFileInfo->fileName = ( pFileInfo->filePath + rpal_string_strlen( pFileInfo->filePath ) ) ) &&
                    NULL != rpal_string_strcat( pFileInfo->filePath, findData.cFileName ) )
                {
                    isSuccess = TRUE;
                }
            }
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( NULL != hDir )
        {
            if( NULL != dir->handle )
            {
                if( NULL != ( findData = readdir( dir->handle ) ) )
                {
                    isDataReady = TRUE;
                }
            }
            
            if( isDataReady )
            {
                while( 0 == rpal_string_strcmp( ".", findData->d_name ) ||
                       0 == rpal_string_strcmp( "..", findData->d_name ) )
                {
                    if( NULL == ( findData = readdir( dir->handle ) ) )
                    {
                        isDataReady = FALSE;
                        break;
                    }
                }
            }
            
            if( isDataReady )
            {
                rpal_memory_zero( pFileInfo->filePath, sizeof( pFileInfo->filePath ) );
                
                if( ARRAY_N_ELEM( pFileInfo->filePath ) - 1 > 
                    rpal_string_strlen( dir->dirPath ) + rpal_string_strlen( findData->d_name ) )
                {
                    rpal_string_strcpy( pFileInfo->filePath, dir->dirPath );
                    rpal_string_strcat( pFileInfo->filePath, findData->d_name );

                    pFileInfo->fileName = pFileInfo->filePath + rpal_string_strlen( dir->dirPath );
                    isSuccess = TRUE;
                }

                if( isSuccess )
                {
                    pFileInfo->attributes = 0;
                    pFileInfo->creationTime = 0;
                    pFileInfo->lastAccessTime = 0;
                    pFileInfo->modificationTime = 0;
                    pFileInfo->size = 0;
                    
                    if( 0 == stat( pFileInfo->filePath, &fileInfo ) )
                    {
                        if( S_ISDIR( fileInfo.st_mode ) )
                        {
                            ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY );
                        }
                        if( IS_FLAG_ENABLED( S_IXUSR, fileInfo.st_mode ) )
                        {
                            ENABLE_FLAG( pFileInfo->attributes, RPAL_FILE_ATTRIBUTE_EXECUTE );
                        }
                        
                        pFileInfo->creationTime = ( (RU64) fileInfo.st_ctime );
                        pFileInfo->lastAccessTime = ( (RU64) fileInfo.st_atime );
                        pFileInfo->modificationTime = ( (RU64) fileInfo.st_mtime );
                        
                        pFileInfo->size = ( (RU64) fileInfo.st_size );
                    }
                }
            }
        }
#endif
    }

    return isSuccess;
}

RBOOL
    rDir_create
    (
        RPNCHAR dirPath
    )
{
    RBOOL isCreated = FALSE;

    RPNCHAR expDir = NULL;

    if( NULL != dirPath )
    {
        if( rpal_string_expand( dirPath, &expDir ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            if( CreateDirectoryW( expDir, NULL ) )
            {
                isCreated = TRUE;
            }
#else
            if( 0 == mkdir( expDir, 0700 ) )
            {
                isCreated = TRUE;
            }
#endif
            rpal_memory_free( expDir );
        }
    }

    return isCreated;
}

RBOOL
    rFile_open
    (
        RPNCHAR filePath,
        rFile* phFile,
        RU32 flags
    )
{
    RBOOL isSuccess = FALSE;
    _rFile* hFile = NULL;
    RPNCHAR tmpPath = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    RU32 osAccessFlags = 0;
    RU32 osCreateFlags = 0;
    RU32 osAttributeFlags = 0;
    FILETIME disableFileTime = { (DWORD)(-1), (DWORD)(-1) };
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
    RPCHAR asciiPath = NULL;
    RPCHAR fileMode = NULL;
    struct stat fileInfo = {0};
#endif

    if( NULL != filePath &&
        NULL != phFile &&
        rpal_string_expand( filePath, &tmpPath ) &&
        NULL != tmpPath )
    {
        rpal_file_pathToLocalSep( tmpPath );

        hFile = rpal_memory_alloc( sizeof( *hFile ) );

        if( NULL != hFile )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_READ ) )
            {
                ENABLE_FLAG( osAccessFlags, GENERIC_READ );
            }
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
            {
                ENABLE_FLAG( osAccessFlags, GENERIC_WRITE );
            }
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_EXISTING ) )
            {
                ENABLE_FLAG( osCreateFlags, OPEN_EXISTING );
            }
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_NEW ) )
            {
                ENABLE_FLAG( osCreateFlags, CREATE_NEW );
            }
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_ALWAYS ) )
            {
                ENABLE_FLAG( osCreateFlags, OPEN_ALWAYS );
            }
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_AVOID_TIMESTAMPS ) )
            {
                ENABLE_FLAG( osAttributeFlags, FILE_FLAG_BACKUP_SEMANTICS );
                ENABLE_FLAG( osAccessFlags, FILE_WRITE_ATTRIBUTES );
            }

            hFile->handle = CreateFileW( tmpPath,
                                         osAccessFlags,
                                         FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         NULL,
                                         osCreateFlags,
                                         osAttributeFlags,
                                         NULL );

            if( INVALID_HANDLE_VALUE == hFile->handle )
            {
                rpal_memory_free( hFile );
                hFile = NULL;
            }
            else
            {
                if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_AVOID_TIMESTAMPS ) )
                {
                    SetFileTime( hFile->handle, NULL, &disableFileTime, &disableFileTime );
                }

                isSuccess = TRUE;
                *phFile = hFile;
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_EXISTING ) )
            {
                // THE FILE MUST EXIST
                //====================
                if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_READ ) )
                {
                    if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
                    {
                        fileMode = "r+";
                    }
                    else
                    {
                        fileMode = "r";
                    }
                }
                else if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) &&
                    0 == stat( filePath, &fileInfo ) )
                {
                    fileMode = "r+";
                }
            }
            else if ( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_NEW ) &&
                0 != stat( filePath, &fileInfo ) )
            {
                // THE FILE CANNOT EXIST
                //======================
                if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_READ ) )
                {
                    if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
                    {
                        fileMode = "w+";
                    }
                    else
                    {
                        // Makes no sense to open a NEW file for READING
                        fileMode = "w+";
                    }
                }
                else if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
                {
                    fileMode = "w";
                }
            }
            else if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_ALWAYS ) )
            {
                if( 0 != stat( filePath, &fileInfo ) )
                {
                    // The file doesn't exist, we create it. None of this is atomic, but
                    // for now it should be enough to get going...
                    if( NULL != ( hFile->handle = fopen( filePath, "a+" ) ) )
                    {
                        fclose( hFile->handle );
                    }
                }

                // WE DON'T CARE IF IT EXISTS
                //======================
                if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_READ ) )
                {
                    if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
                    {
                        fileMode = "r+";
                    }
                    else
                    {
                        fileMode = "r";
                    }
                }
                else if( IS_FLAG_ENABLED( flags, RPAL_FILE_OPEN_WRITE ) )
                {
                    fileMode = "r+";
                }
            }

            // We only proceed if the file mode made sense
            if( NULL != fileMode )
            {
                if( NULL != ( hFile->handle = fopen( filePath, fileMode ) ) )
                {
                    isSuccess = TRUE;
                    *phFile = hFile;
                }
                else
                {
                    rpal_memory_free( hFile );
                    hFile = NULL;
                }
            }
#endif
            rpal_memory_free( tmpPath );
        }
    }

    return isSuccess;
}

RVOID
    rFile_close
    (
        rFile hFile
    )
{
    _rFile* pFile = (_rFile*)hFile;

    if( NULL != hFile )
    {
        if( NULL != pFile->handle )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            if( INVALID_HANDLE_VALUE != pFile->handle )
            {
                CloseHandle( pFile->handle );
            }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
            fclose( pFile->handle );
#endif
        }

        rpal_memory_free( pFile );
    }
}

RU64
    rFile_seek
    (
        rFile hFile,
        RU64 offset,
        enum rFileSeek origin
    )
{
    RU64 newPtr = (unsigned)(-1);
    _rFile* pFile = (_rFile*)hFile;
    RU32 method = 0;

    if( NULL != hFile )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        LARGE_INTEGER off;
        LARGE_INTEGER newP;
        
        off.QuadPart = offset;
        newP.QuadPart = 0;

        if( rFileSeek_CUR == origin )
        {
            method = FILE_CURRENT;
        }
        else if( rFileSeek_SET == origin )
        {
            method = FILE_BEGIN;
        }
        else if( rFileSeek_END == origin )
        {
            method = FILE_END;
        }
        
        if( SetFilePointerEx( pFile->handle, off, &newP, method ) )
        {
            newPtr = newP.QuadPart;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( rFileSeek_CUR == origin )
        {
            method = SEEK_CUR;
        }
        else if( rFileSeek_SET == origin )
        {
            method = SEEK_SET;
        }
        else if( rFileSeek_END == origin )
        {
            method = SEEK_END;
        }
        
        if( 0 == fseek( pFile->handle, offset, method ) )
        {
            newPtr = ftell( pFile->handle );
        }
#endif
    }

    return newPtr;
}

RBOOL
    rFile_read
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    )
{
    RBOOL isSuccess = FALSE;
    _rFile* pFile = (_rFile*)hFile;

    if( NULL != hFile &&
        NULL != pBuffer &&
        0 != size )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RU32 read = 0;

        if( ReadFile( pFile->handle, pBuffer, size, (LPDWORD)&read, NULL ) &&
            read == size )
        {
            isSuccess = TRUE;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( 1 == fread( pBuffer, size, 1, pFile->handle ) )
        {
            isSuccess = TRUE;
        }
#endif
    }

    return isSuccess;
}

RU32
    rFile_readUpTo
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    )
{
    RU32 read = 0;
    _rFile* pFile = (_rFile*)hFile;

    if( NULL != hFile &&
        NULL != pBuffer &&
        0 != size )
    {
#ifdef RPAL_PLATFORM_WINDOWS

        ReadFile( pFile->handle, pBuffer, size, (LPDWORD)&read, NULL );
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        read = (RU32)fread( pBuffer, 1, size, pFile->handle );
        
#endif
    }

    return read;
}

RBOOL
    rFile_write
    (
        rFile hFile,
        RU32 size,
        RPVOID pBuffer
    )
{
    RBOOL isSuccess = FALSE;
    _rFile* pFile = (_rFile*)hFile;

    if( NULL != hFile &&
        NULL != pBuffer &&
        0 != size )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RU32 written = 0;

        if( WriteFile( pFile->handle, pBuffer, size, (LPDWORD)&written, NULL ) &&
            written == size )
        {
            isSuccess = TRUE;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( 1 == fwrite( pBuffer, size, 1, pFile->handle ) )
        {
            isSuccess = TRUE;
        }
#endif
    }

    return isSuccess;
}

#ifdef RPAL_PLATFORM_LINUX
RPRIVATE
RS32
    _cmpWatchStub
    (
        _watchStub* stub1,
        _watchStub* stub2
    )
{
    RS32 ret = -1;

    if( NULL != stub1 &&
        NULL != stub2 )
    {
        ret = stub1->handle - stub2->handle;
    }

    return ret;
}

RPRIVATE
RBOOL
    _inotifyAddPath
    (
        _rDirWatch* watch,
        RPNCHAR path,
        RPNCHAR label
    )
{
    RBOOL isAdded = FALSE;

    _watchStub stub = { 0 };

    if( 0 <= ( stub.handle = inotify_add_watch( watch->hWatch, 
                                                path, 
                                                IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB |
                                                IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF ) ) )
    {
        if( rpal_string_strlen( label ) < sizeof( stub.name ) )
        {
            rpal_string_strcat( stub.name, label );

            if( rpal_btree_add( watch->hChanges, &stub, TRUE ) )
            {
                isAdded = TRUE;
            }
            else
            {
                inotify_rm_watch( watch->hWatch, stub.handle );
            }
        }
    }

    return isAdded;
}
#endif

rDirWatch
    rDirWatch_new
    (
        RPNCHAR dir,
        RU32 watchFlags,
        RBOOL includeSubDirs
    )
{
    _rDirWatch* watch = NULL;

    RPNCHAR cleanDir = NULL;

    if( NULL != dir &&
        rpal_string_expand( dir, &cleanDir ) )
    {
        if( NULL != ( watch = rpal_memory_alloc( sizeof( _rDirWatch ) ) ) )
        {
#ifdef RPAL_PLATFORM_WINDOWS
            watch->includeSubDirs = includeSubDirs;
            watch->flags = watchFlags;
            watch->curChange = NULL;
            watch->tmpTerminator = 0;
            watch->pTerminator = NULL;
            watch->isPending = FALSE;
            rpal_memory_zero( &( watch->oChange ), sizeof( watch->oChange ) );

            if( NULL != ( watch->hDir = CreateFileW( cleanDir,
                                                     FILE_LIST_DIRECTORY | GENERIC_READ,
                                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                     NULL,
                                                     OPEN_EXISTING,
                                                     FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                                     NULL ) ) )
            {
                if( NULL == ( watch->hChange = CreateEventW( NULL, FALSE, FALSE, NULL ) ) )
                {
                    CloseHandle( watch->hDir );
                    rpal_memory_free( watch );
                    watch = NULL;
                }
            }
            else
            {
                rpal_memory_free( watch );
                watch = NULL;
            }
#elif defined(RPAL_PLATFORM_LINUX)
            _watchStub stub = { 0 };
            rDirCrawl crawl = NULL;
            RPNCHAR patterns[] = { _NC("*") };
            rFileInfo fileInfo = { 0 };
            RPNCHAR label = NULL;
            watch->bytesRead = 0;
            watch->offset = 0;
            watch->isRecursive = includeSubDirs;

            if( NULL != (  watch->hChanges = rpal_btree_create( sizeof( _watchStub ), (rpal_btree_comp_f)_cmpWatchStub, NULL ) ) )
            {
                if( 0 > ( watch->hWatch = inotify_init() ) ||
                    !_inotifyAddPath( watch, cleanDir, _NC( "" ) ) )
                {
                    rpal_btree_destroy( watch->hChanges, TRUE );
                    rpal_memory_free( watch );
                    watch = NULL;
                }
            }

            if( NULL != watch &&
                watch->isRecursive )
            {
                if( NULL != ( crawl = rpal_file_crawlStart( cleanDir, patterns, 20 ) ) )
                {
                    while( rpal_file_crawlNextFile( crawl, &fileInfo ) )
                    {
                        if( IS_FLAG_ENABLED( fileInfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) )
                        {
                            // To maintain behavior with Windows, we need to strip the caller's root path.
                            label = fileInfo.filePath + rpal_string_strlen( cleanDir ) + 1;
                            _inotifyAddPath( watch, fileInfo.filePath, label );
                        }
                    }

                    rpal_file_crawlStop( crawl );
                }

                rpal_btree_optimize( watch->hChanges, TRUE );
            }

            if( NULL != watch )
            {
                watch->root = cleanDir;
                cleanDir = NULL;
            }
#endif
        }

        rpal_memory_free( cleanDir );
    }

    return (rDirWatch)watch;
}

RVOID
    rDirWatch_free
    (
        rDirWatch watch
    )
{
    _rDirWatch* pWatch = (_rDirWatch*)watch;

    if( rpal_memory_isValid( pWatch ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        if( NULL != pWatch->hDir )
        {
            if( pWatch->isPending )
            {
                CancelIo( pWatch->hDir );

                while( !HasOverlappedIoCompleted( &( pWatch->oChange ) ) )
                {
                    rpal_thread_sleep( 5 );
                }
            }
            CloseHandle( pWatch->hDir );
        }
        if( NULL != pWatch->hChange )
        {
            CloseHandle( pWatch->hChange );
        }
#elif defined( RPAL_PLATFORM_LINUX )
        _watchStub stub = { 0 };

        if( rpal_btree_minimum( pWatch->hChanges, &stub, TRUE ) )
        {
            do
            {
                if( rpal_btree_remove( pWatch->hChanges, &stub, NULL, TRUE ) )
                {
                    inotify_rm_watch( pWatch->hWatch, stub.handle );
                }
            } while( rpal_btree_after( pWatch->hChanges, &stub, &stub, TRUE ) );
        }
        rpal_btree_destroy( pWatch->hChanges, TRUE );
        close( pWatch->hWatch );
        rpal_memory_free( pWatch->root );
#endif
        rpal_memory_free( watch );
    }
}

RBOOL
    rDirWatch_next
    (
        rDirWatch watch,
        RU32 timeout,
        RPNCHAR* pFilePath,
        RU32* pAction
    )
{
    RBOOL gotChange = FALSE;

    _rDirWatch* volatile pWatch = (_rDirWatch*)watch;

    RU32 size = 0;

    if( rpal_memory_isValid( watch ) )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        // If we are at the end of our current buffer, refresh it with the OS
        if( NULL == pWatch->curChange ||
            ( (RPU8)pWatch->curChange < (RPU8)pWatch->changes ) || 
            ( (RPU8)pWatch->curChange >= (RPU8)pWatch->changes + sizeof( pWatch->changes ) ) )
        {
            if( !pWatch->isPending )
            {
                rpal_memory_zero( pWatch->changes, sizeof( pWatch->changes ) );
                pWatch->oChange.hEvent = pWatch->hChange;
            
                pWatch->curChange = NULL;
                pWatch->pTerminator = NULL;

                if( ReadDirectoryChangesW( pWatch->hDir, 
                                           &pWatch->changes, 
                                           sizeof( pWatch->changes ), 
                                           pWatch->includeSubDirs,
                                           pWatch->flags,
                                           (LPDWORD)&size,
                                           &(pWatch->oChange),
                                           NULL ) )
                {
                    pWatch->isPending = TRUE;
                }
            }

            if( pWatch->isPending )
            {
                if( WAIT_OBJECT_0 == WaitForSingleObject( pWatch->hChange, timeout ) )
                {
                    pWatch->isPending = FALSE;
                    pWatch->curChange = (FILE_NOTIFY_INFORMATION*)pWatch->changes;
                }
            }
        }

        // Return the next value
        if( NULL != pWatch->curChange )
        {
            gotChange = TRUE;

            // FileName is not NULL terminated (how awesome, MS)
            if( NULL != pWatch->pTerminator )
            {
                *pWatch->pTerminator = pWatch->tmpTerminator;
            }

            pWatch->pTerminator = (RPWCHAR)( (RPU8)pWatch->curChange->FileName + pWatch->curChange->FileNameLength );
            pWatch->tmpTerminator = *pWatch->pTerminator;
            *pWatch->pTerminator = 0;

            if( NULL != pFilePath )
            {
                *pFilePath = pWatch->curChange->FileName;
            }
            if( NULL != pAction )
            {
                *pAction = pWatch->curChange->Action;
            }
            if( 0 == pWatch->curChange->NextEntryOffset )
            {
                pWatch->curChange = NULL;
            }
            else
            {
                pWatch->curChange = (FILE_NOTIFY_INFORMATION*)( (RPU8)pWatch->curChange + pWatch->curChange->NextEntryOffset );
            }
        }
#elif defined( RPAL_PLATFORM_LINUX )
        fd_set handles;
        int n = 0;
        int waitVal = 0;
        struct inotify_event* pEvent = NULL;
        struct timeval to = { 1, 0 };
        RU32 tmpAction = 0;
        RPNCHAR subDir = NULL;
        _watchStub stub = { 0 };
        rDirCrawl crawl = NULL;
        RPNCHAR patterns[] = { _NC("*") };
        rFileInfo fileInfo = { 0 };
        RPNCHAR label = NULL;
        RU32 latestLength = 0;

        pEvent = (struct inotify_event*)( pWatch->changes + pWatch->offset );

        if( pWatch->offset >= pWatch->bytesRead ||
            !IS_WITHIN_BOUNDS( pEvent, sizeof( *pEvent ), pWatch->changes, pWatch->bytesRead ) ||
            !IS_WITHIN_BOUNDS( pEvent, sizeof( *pEvent ) + pEvent->len, pWatch->changes, pWatch->bytesRead ) )
        {
            pWatch->offset = 0;
            pWatch->bytesRead = 0;

            to.tv_sec = timeout / 1000;
            to.tv_usec = USEC_FROM_MSEC( timeout % 1000 );

            FD_ZERO( &handles );
            FD_SET( pWatch->hWatch, &handles );
            n = (int)pWatch->hWatch + 1;

            waitVal = select( n, &handles, NULL, NULL, &to );

            if( 0 != waitVal )
            {
                pWatch->bytesRead = read( pWatch->hWatch, pWatch->changes, sizeof( pWatch->changes ) );
                if( 0 == pWatch->bytesRead ||
                    -1 == pWatch->bytesRead )
                {
                    pWatch->bytesRead = 0;
                }
            }
        }

        pEvent = (struct inotify_event*)( pWatch->changes + pWatch->offset );
        pWatch->latestPath[ 0 ] = 0;
        
        while( !gotChange &&
               pWatch->offset < pWatch->bytesRead &&
               IS_WITHIN_BOUNDS( pEvent, sizeof( *pEvent ), pWatch->changes, pWatch->bytesRead ) &&
               IS_WITHIN_BOUNDS( pEvent, sizeof( *pEvent ) + pEvent->len, pWatch->changes, pWatch->bytesRead ) )
        {
            pWatch->latestPath[ 0 ] = 0;
            gotChange = TRUE;

            stub.handle = pEvent->wd;
            if( !rpal_btree_search( pWatch->hChanges, &stub, &stub, TRUE ) )
            {
                // If we can't find the handle that produced this, we assume it's because
                // we dropped it from the watch and this is an irrelevant trailing event.
                pWatch->offset += pEvent->len + sizeof( *pEvent );
                pEvent = (struct inotify_event*)( pWatch->changes + pWatch->offset );
                gotChange = FALSE;
                continue;
            }

            if( 0 != stub.name[ 0 ] )
            {
                rpal_string_strcat( pWatch->latestPath, stub.name );
                rpal_string_strcat( pWatch->latestPath, _NC( "/" ) );
            }

            // Sometimes the path len is 0 when indicate the object being watched
            // is itself the subject of the event (a dir).
            if( 0 < pEvent->len )
            {
                // Make sure we terminate the name.
                pEvent->name[ pEvent->len - 1 ] = 0;
                rpal_string_strcat( pWatch->latestPath, pEvent->name );
            }

            *pFilePath = pWatch->latestPath;
            latestLength = rpal_string_strlen( pWatch->latestPath );

            if( 0 != latestLength && 
                _NC( '/' ) == pWatch->latestPath[ latestLength - 1 ] )
            {
                // For behavior parity with Windows, remove terminating /
                pWatch->latestPath[ latestLength - 1 ] = 0;
            }
                
            if( IS_FLAG_ENABLED( pEvent->mask, IN_MODIFY ) ||
                IS_FLAG_ENABLED( pEvent->mask, IN_ATTRIB ) )
            {
                tmpAction = RPAL_DIR_WATCH_ACTION_MODIFIED;
            }

            if( IS_FLAG_ENABLED( pEvent->mask, IN_CREATE ) )
            {
                tmpAction = RPAL_DIR_WATCH_ACTION_ADDED;

                if( pWatch->isRecursive && IS_FLAG_ENABLED( pEvent->mask, IN_ISDIR ) )
                {
                    subDir = rpal_string_strcatEx( subDir, pWatch->root );
                    subDir = rpal_string_strcatEx( subDir, _NC("/") );
                    subDir = rpal_string_strcatEx( subDir, pWatch->latestPath );

                    // Add the directory itself.
                    label = subDir + rpal_string_strlen( pWatch->root ) + 1;
                    _inotifyAddPath( watch, subDir, label );

                    // And add any other subdirectories.
                    if( NULL != ( crawl = rpal_file_crawlStart( subDir, patterns, 20 ) ) )
                    {
                        while( rpal_file_crawlNextFile( crawl, &fileInfo ) )
                        {
                            if( IS_FLAG_ENABLED( fileInfo.attributes, RPAL_FILE_ATTRIBUTE_DIRECTORY ) )
                            {
                                label = fileInfo.filePath + rpal_string_strlen( pWatch->root ) + 1;
                                _inotifyAddPath( watch, fileInfo.filePath, label );
                            }
                        }

                        rpal_file_crawlStop( crawl );
                    }

                    rpal_btree_optimize( pWatch->hChanges, TRUE );

                    rpal_memory_free( subDir );
                }
            }

            if( IS_FLAG_ENABLED( pEvent->mask, IN_DELETE ) )
            {
                tmpAction = RPAL_DIR_WATCH_ACTION_REMOVED;
            }

            if( IS_FLAG_ENABLED( pEvent->mask, IN_MOVED_FROM ) )
            {
                tmpAction = RPAL_DIR_WATCH_ACTION_RENAMED_OLD;
            }

            if( IS_FLAG_ENABLED( pEvent->mask, IN_MOVED_TO ) )
            {
                tmpAction = RPAL_DIR_WATCH_ACTION_RENAMED_NEW;
            }

            if( IS_FLAG_ENABLED( pEvent->mask, IN_DELETE_SELF ) )
            {
                // This means the dir or file we're watching is deleted so
                // we will remove it from our watch.
                inotify_rm_watch( pWatch->hWatch, stub.handle );
                rpal_btree_remove( pWatch->hChanges, &stub, NULL, TRUE );

                // Still report the deletion if this is not recursive, otherwise
                // the parent will handle the event.
                if( !pWatch->isRecursive )
                {
                    tmpAction = RPAL_DIR_WATCH_ACTION_REMOVED;
                }
            }

            if( 0 == tmpAction )
            {
                *pFilePath = NULL;
                gotChange = FALSE;
            }
            else if( NULL != pAction )
            {
                *pAction = tmpAction;
            }

            pWatch->offset += pEvent->len + sizeof( *pEvent );
            pEvent = (struct inotify_event*)( pWatch->changes + pWatch->offset );
        }
#else
        UNREFERENCED_PARAMETER( pWatch );
        UNREFERENCED_PARAMETER( size );
        rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
#endif
    }

    return gotChange;
}

#ifdef RPAL_PLATFORM_WINDOWS
static RBOOL
    _driveFromDevice
    (
        RPWCHAR path,
        RPWCHAR pDrive,
        RU32* pDeviceLength
    )
{
    RBOOL isFound = FALSE;

    RU32 driveMask = 0;
    RU32 i = 0;
    RWCHAR tmpDrive[ 3 ] = { 0, _WCH( ':' ), 0 };
    RWCHAR tmpPath[ RPAL_MAX_PATH ] = { 0 };

    if( NULL != path &&
        NULL != pDrive &&
        NULL != pDeviceLength )
    {
        driveMask = GetLogicalDrives();
        for( i = 0; i < sizeof( driveMask ) * 8; i++ )
        {
            if( 1 == ( driveMask & 0x00000001 ) )
            {
                tmpDrive[ 0 ] = (RWCHAR)( _WCH( 'A' ) + i );

                if( QueryDosDeviceW( tmpDrive, tmpPath, ARRAY_N_ELEM( tmpPath ) ) )
                {
                    if( rpal_string_startswithi( path, tmpPath ) )
                    {
                        *pDrive = tmpDrive[ 0 ];
                        *pDeviceLength = rpal_string_strlen( tmpPath );
                        isFound = TRUE;
                        break;
                    }
                }
            }

            driveMask >>= 1;
        }
    }

    return isFound;
}

#endif

RPNCHAR
    rpal_file_clean
    (
        RPNCHAR filePath
    )
{
    RPNCHAR clean = NULL;

    if( NULL != filePath )
    {
#ifdef RPAL_PLATFORM_WINDOWS
        RU32 len = 0;
        RBOOL isFullPath = FALSE;
        RU32 i = 0;
        rString tmpPath = NULL;
        RPWCHAR tmpStr = NULL;
        RWCHAR sysDrive[] = _WCH( "%systemdrive%" );
        RWCHAR winDir[] = _WCH( "%windir%" );
        RWCHAR uncPath[] = _WCH( "\\??\\" );
        RWCHAR sys32Dir[] = _WCH( "\\system32" );
        RWCHAR sys32Prefix[] = _WCH( "system32\\" );
        RWCHAR sysRootDir[] = _WCH( "\\systemroot" );
        RWCHAR deviceDir[] = _WCH( "\\device\\" );
        RWCHAR defaultPath[] = _WCH( "%windir%\\system32\\" );
        RWCHAR tmpDrive[ 3 ] = { 0, _WCH( ':' ), 0 };

        // Local caches
        static RWCHAR currentSysDrive[ 3 ] = { 0 };
        static RWCHAR sysDevice[ 50 ] = { 0 };
        static RWCHAR currentWinDir[ 50 ] = { 0 };
        static RWCHAR currentDefaultPath[ 50 ] = { 0 };

        // We cache the current system drive since it'll be used all the time.
        if( 0 == currentSysDrive[ 0 ] )
        {
            if( rpal_string_expand( sysDrive, &tmpStr ) )
            {
                if( 2 == rpal_string_strlen( tmpStr ) )
                {
                    rpal_string_strcpy( currentSysDrive, tmpStr );
                }
                rpal_memory_free( tmpStr );
            }
        }

        // We cache the device of the system drive since it's the one most likely
        // to be queried for.
        if( 0 == sysDevice[ 0 ] )
        {
            QueryDosDeviceW( currentSysDrive, sysDevice, ARRAY_N_ELEM( sysDevice ) );
        }

        // Resolve a few other environment variables.
        if( 0 == currentWinDir[ 0 ] )
        {
            if( rpal_string_expand( winDir, &tmpStr ) )
            {
                if( ARRAY_N_ELEM( currentWinDir ) > rpal_string_strlen( tmpStr ) )
                {
                    rpal_string_strcpy( currentWinDir, tmpStr );
                }
                rpal_memory_free( tmpStr );
            }
        }

        if( 0 == currentDefaultPath[ 0 ] )
        {
            if( rpal_string_expand( defaultPath, &tmpStr ) )
            {
                if( ARRAY_N_ELEM( currentDefaultPath ) > rpal_string_strlen( tmpStr ) )
                {
                    rpal_string_strcpy( currentDefaultPath, tmpStr );
                }
                rpal_memory_free( tmpStr );
            }
        }

        len = rpal_string_strlen( filePath );

        if( 0 != len &&
            NULL != ( tmpPath = rpal_stringbuffer_new( 0, 0 ) ) )
        {
            // Check for a path token, if we have none, default to system32
            isFullPath = FALSE;
            for( i = 0; i < len; i++ )
            {
                if( _WCH( '\\' ) == filePath[ i ] ||
                    _WCH( '/' ) == filePath[ i ] )
                {
                    isFullPath = TRUE;
                    break;
                }
            }

            if( isFullPath )
            {
                // Many paths need to be fixed, they all start with a \ so ignore
                // the path if it doesn't.
                if( _WCH( '\\' ) == filePath[ 0 ] )
                {
                    // If the entry starts with system32, prefix it as necessary
                    if( rpal_string_startswithi( filePath, sys32Dir ) )
                    {
                        rpal_stringbuffer_add( tmpPath, currentWinDir );
                    }
                    // If the entry starts with \SystemRoot, prefix it as necessary
                    else if( rpal_string_startswithi( filePath, sysRootDir ) )
                    {
                        rpal_stringbuffer_add( tmpPath, currentWinDir );
                        filePath += rpal_string_strlen( sysRootDir );
                    }
                    // If the entry starts with \??\ we can strip the UNC prefix
                    else if( rpal_string_startswithi( filePath, uncPath ) )
                    {
                        filePath += rpal_string_strlen( uncPath );
                    }
                    // First check if it's the system drive
                    else if( rpal_string_startswithi( filePath, sysDevice ) )
                    {
                        rpal_stringbuffer_add( tmpPath, currentSysDrive );
                        filePath += rpal_string_strlen( sysDevice );
                    }
                    // If the path starts at a device not cached, resolve it
                    else if( rpal_string_startswithi( filePath, deviceDir ) )
                    {
                        if( _driveFromDevice( filePath, tmpDrive, &i ) )
                        {
                            rpal_stringbuffer_add( tmpPath, tmpDrive );
                            filePath += i;
                        }
                    }
                    // Sometimes it's just a path without drive, so add systemdrive
                    else
                    {
                        rpal_stringbuffer_add( tmpPath, currentSysDrive );
                    }
                }
                else if( rpal_string_startswithi( filePath, sys32Prefix ) )
                {
                    rpal_stringbuffer_add( tmpPath, currentWinDir );
                    rpal_stringbuffer_add( tmpPath, _WCH( "\\" ) );
                }

                rpal_stringbuffer_add( tmpPath, filePath );
            }

            tmpStr = rpal_stringbuffer_getString( tmpPath );
            clean = rpal_string_strdup( tmpStr );
            rpal_memory_isValid( clean );
            rpal_stringbuffer_free( tmpPath );
        }
#else
        clean = rpal_string_strdup( filePath );
#endif
    }

    return clean;
}
