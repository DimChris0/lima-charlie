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

#ifndef _HBS_ATOMS_H
#define _HBS_ATOMS_H

#include <rpal.h>

#define HBS_ATOM_ID_SIZE    16

typedef struct
{
    RU8 id[ HBS_ATOM_ID_SIZE ];
    RU8 parentId[ HBS_ATOM_ID_SIZE ];
    struct
    {
        union
        {
            struct
            {
                RU32 pid;
            } process;
            struct
            {
                RU32 pid;
                RU64 baseAddress;
            } module;
        };
        RU32 category;
    } key;
    RU64 expiredOn;
} Atom;

RBOOL
    atoms_init
    (

    );

RBOOL
    atoms_deinit
    (

    );

RBOOL
    atoms_register
    (
        Atom* pAtom
    );

RBOOL
    atoms_update
    (
        Atom* pAtom
    );

RBOOL
    atoms_query_from
    (
        Atom* pAtom,
        RU64 atTime,
        RU32 fromFileId,
        RU32 fromLineNumber
    );
#define atoms_query(pAtom, atTime) atoms_query_from( (pAtom), (atTime), RPAL_FILE_ID, __LINE__ )

RBOOL
    atoms_remove
    (
        Atom* pAtom,
        RU64 expiredOn
    );

RBOOL
    atoms_getOneTime
    (
        Atom* pAtom
    );

RU32
    atoms_getPid
    (
        RU8 pAtomId[ HBS_ATOM_ID_SIZE ]
    );

rBlob
    atoms_getAtomsWithParent
    (
        RU8 parentAtom[ HBS_ATOM_ID_SIZE ]
    );

#endif
