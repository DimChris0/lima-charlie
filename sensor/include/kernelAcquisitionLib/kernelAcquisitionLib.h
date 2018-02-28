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

#ifndef _KERNEL_ACQUISITION_LIB_H
#define _KERNEL_ACQUISITION_LIB_H

#include <rpal/rpal.h>
#include <kernelAcquisitionLib/common.h>


RBOOL
    kAcq_init
    (

    );

RBOOL
    kAcq_deinit
    (

    );

RBOOL
    kAcq_ping
    (

    );

RBOOL
    kAcq_isAvailable
    (

    );

RBOOL
    kAcq_getNewProcesses
    (
        KernelAcqProcess* entries,
        RU32* nEntries
    );

RBOOL
    kAcq_getNewFileIo
    (
        KernelAcqFileIo* entries,
        RU32* nEntries
    );

RBOOL
    kAcq_getNewModules
    (
        KernelAcqModule* entries,
        RU32* nEntries
    );

// Shortcut for RFC 1700 protocol numbers
#define RPROTOCOL_IP_TCP    6
#define RPROTOCOL_IP_UDP    17

RBOOL
    kAcq_getNewConnections
    (
        KernelAcqNetwork* entries,
        RU32* nEntries
    );

RBOOL
    kAcq_getNewDnsPackets
    (
        KernelAcqDnsPacket* packets,
        RU32* totalSize
    );

RBOOL
    kAcq_segregateNetwork
    (

    );

RBOOL
    kAcq_rejoinNetwork
    (

    );

#endif
