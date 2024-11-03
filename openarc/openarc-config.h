/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_CONFIG_H_
#define _ARC_CONFIG_H_

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <sys/types.h>

/* config definition */
struct configdef arcf_config[] = {
    {"AuthResIP",                     CONFIG_TYPE_BOOLEAN, false},
    {"AuthservID",                    CONFIG_TYPE_STRING,  false},
    {"AutoRestart",                   CONFIG_TYPE_BOOLEAN, false},
    {"AutoRestartCount",              CONFIG_TYPE_INTEGER, false},
    {"AutoRestartRate",               CONFIG_TYPE_STRING,  false},
    {"Background",                    CONFIG_TYPE_BOOLEAN, false},
    {"BaseDirectory",                 CONFIG_TYPE_STRING,  false},
    {"Canonicalization",              CONFIG_TYPE_STRING,  false},
    {"ChangeRootDirectory",           CONFIG_TYPE_STRING,  false},
    {"Domain",                        CONFIG_TYPE_STRING,  false},
    {"EnableCoredumps",               CONFIG_TYPE_BOOLEAN, false},
    {"FinalReceiver",                 CONFIG_TYPE_BOOLEAN, false},
    {"FixedTimestamp",                CONFIG_TYPE_STRING,  false},
    {"Include",                       CONFIG_TYPE_INCLUDE, false},
    {"InternalHosts",                 CONFIG_TYPE_STRING,  false},
    {"KeepTemporaryFiles",            CONFIG_TYPE_BOOLEAN, false},
    {"KeyFile",                       CONFIG_TYPE_STRING,  false},
    {"MaximumHeaders",                CONFIG_TYPE_INTEGER, false},
    {"MilterDebug",                   CONFIG_TYPE_INTEGER, false},
    {"MinimumKeySizeRSA",             CONFIG_TYPE_INTEGER, false},
    {"Mode",                          CONFIG_TYPE_STRING,  false},
    {"OverSignHeaders",               CONFIG_TYPE_STRING,  false},
    {"PeerList",                      CONFIG_TYPE_STRING,  false},
    {"PermitAuthenticationOverrides", CONFIG_TYPE_BOOLEAN, false},
    {"PidFile",                       CONFIG_TYPE_STRING,  false},
    {"RequireSafeKeys",               CONFIG_TYPE_BOOLEAN, false},
    {"ResponseDisabled",              CONFIG_TYPE_STRING,  false},
    {"ResponseUnable",                CONFIG_TYPE_STRING,  false},
    {"ResponseUnwilling",             CONFIG_TYPE_STRING,  false},
    {"SealHeaderChecks",              CONFIG_TYPE_STRING,  false},
    {"Selector",                      CONFIG_TYPE_STRING,  false},
    {"SignatureAlgorithm",            CONFIG_TYPE_STRING,  false},
    {"SignHeaders",                   CONFIG_TYPE_STRING,  false},
    {"Socket",                        CONFIG_TYPE_STRING,  false},
    {"SoftwareHeader",                CONFIG_TYPE_BOOLEAN, false},
    {"Syslog",                        CONFIG_TYPE_BOOLEAN, false},
    {"SyslogFacility",                CONFIG_TYPE_STRING,  false},
    {"TemporaryDirectory",            CONFIG_TYPE_STRING,  false},
    {"TestKeys",                      CONFIG_TYPE_STRING,  false},
    {"UMask",                         CONFIG_TYPE_INTEGER, false},
    {"UserID",                        CONFIG_TYPE_STRING,  false},
    {NULL,                            (unsigned int) -1,   false}
};

#endif /* _ARC_CONFIG_H_ */
