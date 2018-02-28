/*
 * Memory DLL loading code
 * Version 0.0.2
 *
 * Copyright (c) 2004-2005 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.h
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2005
 * Joachim Bauch. All Rights Reserved.
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <rpal/rpal.h>

typedef RPVOID HMEMORYMODULE;

HMEMORYMODULE
    MemoryLoadLibrary
    (
        RPVOID libData,
        RU32 libDataSize
    );

RPVOID
    MemoryGetLibraryBase
    (
        HMEMORYMODULE hLib
    );

RPVOID
    MemoryGetProcAddress
    (
        HMEMORYMODULE hLib,
        RPCHAR exportName
    );

RVOID
    MemoryFreeLibrary
    (
        HMEMORYMODULE hLib
    );

#endif  // __MEMORY_MODULE_HEADER
