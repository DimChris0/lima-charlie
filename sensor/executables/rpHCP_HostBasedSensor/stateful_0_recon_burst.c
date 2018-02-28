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

#include "stateful_framework.h"
#include "stateful_helpers.h"
#include "stateful_events.h"

#define RECONS_IN_SEC       (MSEC_FROM_SEC(5))
#define RECON_N_PER_BURST   (4)

static tr_match_params recon_tools[] = {
#ifdef RPAL_PLATFORM_WINDOWS
    EXECUTABLE_MATCHES( "*\\ipconfig.exe" ),
    EXECUTABLE_MATCHES( "*\\netstat.exe" ),
    EXECUTABLE_MATCHES( "*\\ping.exe" ),
    EXECUTABLE_MATCHES( "*\\arp.exe" ),
    EXECUTABLE_MATCHES( "*\\route.exe" ),
    EXECUTABLE_MATCHES( "*\\traceroute.exe" ),
    EXECUTABLE_MATCHES( "*\\nslookup.exe" ),
    EXECUTABLE_MATCHES( "*\\wmic.exe" ),
    EXECUTABLE_MATCHES( "*\\net.exe" ),
    EXECUTABLE_MATCHES( "*\\net?.exe" ),
    EXECUTABLE_MATCHES( "*\\whoami.exe" ),
    EXECUTABLE_MATCHES( "*\\systeminfo.exe" )
#else
    EXECUTABLE_MATCHES( "*/ifconfig" ),
    EXECUTABLE_MATCHES( "*/nslookup" ),
    EXECUTABLE_MATCHES( "*/whoami" ),
    EXECUTABLE_MATCHES( "*/ps" ),
    EXECUTABLE_MATCHES( "*/traceroute" ),
    EXECUTABLE_MATCHES( "*/netstat" )
#endif
};

static tr_match_params expired = { 
    0, NULL, NULL, { 0 }, FALSE, RECONS_IN_SEC, 0, TRUE, FALSE
};

#ifdef RPAL_PLATFORM_WINDOWS
#define RECON_TRANSITIONS(isFinal,toState) \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 0 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 1 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 2 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 3 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 4 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 5 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 6 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 7 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 8 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 9 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 10 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 11 ], tr_match ), \
    TRANSITION( FALSE, FALSE, FALSE, 0, 0, expired, tr_match )
#else
#define RECON_TRANSITIONS(isFinal,toState) \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 0 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 1 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 2 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 3 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 4 ], tr_match ), \
    TRANSITION( isFinal, TRUE, FALSE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, recon_tools[ 5 ], tr_match ), \
    TRANSITION( FALSE, FALSE, FALSE, 0, 0, expired, tr_match )
#endif



STATE( 0, ARRAY_N_ELEM( recon_tools ) + 1, RECON_TRANSITIONS( FALSE, 1 ) );
STATE( 1, ARRAY_N_ELEM( recon_tools ) + 1, RECON_TRANSITIONS( FALSE, 2 ) );
STATE( 2, ARRAY_N_ELEM( recon_tools ) + 1, RECON_TRANSITIONS( FALSE, 3 ) );
STATE( 3, ARRAY_N_ELEM( recon_tools ) + 1, RECON_TRANSITIONS( TRUE, 0 ) );

STATEFUL_MACHINE( 0, STATEFUL_MACHINE_0_EVENT, RECON_N_PER_BURST, STATE_PTR( 0 ),
                                                                  STATE_PTR( 1 ),
                                                                  STATE_PTR( 2 ),
                                                                  STATE_PTR( 3 ) );