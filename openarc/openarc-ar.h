/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2012-2014, 2016, 2017, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _OPENARC_AR_H_
#define _OPENARC_AR_H_

/* system includes */
#include <sys/types.h>

/* openarc includes */
#include "openarc.h"

/* limits */
#define MAXARESULTS 16
#define MAXPROPS    16
#define MAXAVALUE   256

/* ARES_METHOD -- type for specifying an authentication method */
typedef enum
{
    ARES_METHOD_UNKNOWN,
    ARES_METHOD_ARC,
    ARES_METHOD_AUTH,
    ARES_METHOD_DKIM,
    ARES_METHOD_DKIMADSP,
    ARES_METHOD_DKIMATPS,
    ARES_METHOD_DMARC,
    ARES_METHOD_DNSWL,
    ARES_METHOD_DOMAINKEYS,
    ARES_METHOD_IPREV,
    ARES_METHOD_RRVS,
    ARES_METHOD_SENDERID,
    ARES_METHOD_SMIME,
    ARES_METHOD_SPF,
    ARES_METHOD_VBR,
} ares_method;

/* ARES_RESULT -- type for specifying an authentication result */
typedef enum
{
    ARES_RESULT_UNDEFINED, /* "unknown" is an actual result */
    ARES_RESULT_DISCARD,
    ARES_RESULT_FAIL,
    ARES_RESULT_NEUTRAL,
    ARES_RESULT_NONE,
    ARES_RESULT_NXDOMAIN,
    ARES_RESULT_PASS,
    ARES_RESULT_PERMERROR,
    ARES_RESULT_POLICY,
    ARES_RESULT_SIGNED,
    ARES_RESULT_SOFTFAIL,
    ARES_RESULT_TEMPERROR,
    ARES_RESULT_UNKNOWN,
} ares_result;

/* ARES_PTYPE -- type for specifying an authentication property */
typedef enum
{
    ARES_PTYPE_COMMENT = -1,
    ARES_PTYPE_UNKNOWN,
    ARES_PTYPE_BODY,
    ARES_PTYPE_DNS,
    ARES_PTYPE_HEADER,
    ARES_PTYPE_POLICY,
    ARES_PTYPE_SMTP,
} ares_ptype;

/* RESULT structure -- a single result */
struct result
{
    int         result_props;
    ares_method result_method;
    ares_result result_result;
    ares_ptype  result_ptype[MAXPROPS];
    char        result_reason[MAXAVALUE + 1];
    char        result_property[MAXPROPS][MAXAVALUE + 1];
    char        result_value[MAXPROPS][MAXAVALUE + 1];
};

/* AUTHRES structure -- the entire header parsed */
struct authres
{
    int           ares_count;
    char          ares_host[ARC_MAXHOSTNAMELEN + 1];
    char          ares_version[MAXAVALUE + 1];
    struct result ares_result[MAXARESULTS];
};

extern int         ares_tokenize(const char *, char *, size_t, char **, int);
extern int         ares_parse(const char *, struct authres *, const char *);
extern bool        ares_istoken(const char *);

extern const char *ares_getmethod(ares_method);
extern const char *ares_getresult(ares_result);
extern const char *ares_getptype(ares_ptype);

#endif /* _OPENARC_AR_H_ */
