/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2014, 2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _OPENARC_H_
#define _OPENARC_H_

#define ARCF_PRODUCT   "OpenARC Filter"
#define ARCF_PRODUCTNS "OpenARC-Filter"

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <sys/types.h>

/* libmilter */
#ifdef ARCF_MILTER_PROTOTYPES
#include <libmilter/mfapi.h>
#endif /* ARCF_MILTER_PROTOTYPES */

/* libopenarc */
#include "arc-malloc.h"
#include "arc.h"

/* libjansson */
#ifdef USE_JANSSON
#include <jansson.h>
#endif /* USE_JANSSON */

/* defaults, limits, etc. */
#define BUFRSZ         2048
#define CONFIGOPTS     "Ac:flnp:P:rt:u:vV"
#define DEFCONFFILE    CONFIG_BASE "/openarc.conf"
#define DEFINTERNAL    "csl:127.0.0.1,::1"
#define DEFMAXHDRSZ    65536
#define HOSTUNKNOWN    "unknown-host"
#define JOBIDUNKNOWN   "(unknown-jobid)"
#define LOCALHOST      "127.0.0.1"
#define LOCALHOST6     "::1"
#define MAXADDRESS     256
#define MAXARGV        65536
#define MAXBUFRSZ      65536
#define MAXHDRCNT      64
#define MAXHDRLEN      78
#define MAXSIGNATURE   1024
#define MTAMARGIN      78
#define NULLDOMAIN     "(invalid)"
#define UNKNOWN        "unknown"

#define AUTHRESULTSHDR "Authentication-Results"
#define SWHEADERNAME   "ARC-Filter"

/*
**  HEADER -- a handle referring to a header
*/

typedef struct Header *Header;
struct Header
{
    char          *hdr_hdr;
    char          *hdr_val;
    struct Header *hdr_next;
    struct Header *hdr_prev;
};

/* externs */
extern bool  dolog;
extern char *progname;

/* prototypes, exported for test.c */
extern ARC_MESSAGE *arcf_getarc(void *);

#ifdef ARCF_MILTER_PROTOTYPES
extern sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
extern sfsistat mlfi_envfrom(SMFICTX *, char **);
extern sfsistat mlfi_envrcpt(SMFICTX *, char **);
extern sfsistat mlfi_header(SMFICTX *, char *, char *);
extern sfsistat mlfi_eoh(SMFICTX *);
extern sfsistat mlfi_body(SMFICTX *, unsigned char *, size_t);
extern sfsistat mlfi_eom(SMFICTX *);
extern sfsistat mlfi_abort(SMFICTX *);
extern sfsistat mlfi_close(SMFICTX *);
#endif /* ARCF_MILTER_PROTOTYPES */

#endif /* _OPENARC_H_ */
