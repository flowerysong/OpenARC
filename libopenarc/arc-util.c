/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-types.h"
#include "arc-util.h"

/* libbsd if found */
#ifdef USE_BSD_H
#include <bsd/string.h>
#endif /* USE_BSD_H */

#if defined(__RES) && (__RES >= 19940415)
#define RES_UNC_T char *
#else /* __RES && __RES >= 19940415 */
#define RES_UNC_T unsigned char *
#endif /* __RES && __RES >= 19940415 */

/*
**  ARC_HDRLIST -- build up a header list for use in a regexp
**
**  Parameters:
**  	buf -- where to write
**  	buflen -- bytes at "buf"
**  	hdrlist -- array of header names
**  	first -- first call
**
**  Return value:
**  	true iff everything fit.
*/

bool
arc_hdrlist(char *buf, size_t buflen, char **hdrlist, bool first)
{
    bool  escape = false;
    int   c;
    int   len;
    char *p;
    char *q;
    char *end;

    assert(buf != NULL);
    assert(hdrlist != NULL);

    for (c = 0;; c++)
    {
        if (hdrlist[c] == NULL)
        {
            break;
        }

        if (!first)
        {
            len = strlcat(buf, "|", buflen);
            if (len >= buflen)
            {
                return false;
            }
        }
        else
        {
            len = strlen(buf);
        }

        first = false;

        q = &buf[len];
        end = &buf[buflen - 1];

        for (p = hdrlist[c]; *p != '\0'; p++)
        {
            if (q >= end)
            {
                return false;
            }

            if (escape)
            {
                *q = *p;
                q++;
                escape = false;
            }

            switch (*p)
            {
            case '*':
                *q = '.';
                q++;
                if (q >= end)
                {
                    return false;
                }
                *q = '*';
                q++;
                break;

            case '.':
                *q = '\\';
                q++;
                if (q >= end)
                {
                    return false;
                }
                *q = '.';
                q++;
                break;

            case '\\':
                escape = true;
                break;

            default:
                *q = *p;
                q++;
                break;
            }
        }
    }

    return true;
}

/*
**  ARC_TMPFILE -- open a temporary file
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	fp -- descriptor (returned)
**  	keep -- if false, unlink() the file once created
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_tmpfile(ARC_MESSAGE *msg, int *fp, bool keep)
{
    int   fd;
    char *p;
    char  path[MAXPATHLEN + 1];

    assert(msg != NULL);
    assert(fp != NULL);

    snprintf(path, MAXPATHLEN, "%s/arc.XXXXXX", msg->arc_library->arcl_tmpdir);

    for (p = path + strlen(msg->arc_library->arcl_tmpdir) + 1; *p != '\0'; p++)
    {
        if (*p == '/')
        {
            *p = '.';
        }
    }

    fd = mkstemp(path);
    if (fd == -1)
    {
        arc_error(msg, "can't create temporary file at %s: %s", path,
                  strerror(errno));
        return ARC_STAT_NORESOURCE;
    }

    *fp = fd;

    if (!keep)
    {
        (void) unlink(path);
    }

    return ARC_STAT_OK;
}

/*
**  ARC_MIN_TIMEVAL -- determine the timeout to apply before reaching
**                     one of two timevals
**
**  Parameters:
**  	t1 -- first timeout (absolute)
**  	t2 -- second timeout (absolute) (may be NULL)
**  	t -- final timeout (relative)
**  	which -- which of t1 and t2 hit first
**
**  Return value:
**  	None.
*/

void
arc_min_timeval(struct timeval  *t1,
                struct timeval  *t2,
                struct timeval  *t,
                struct timeval **which)
{
    struct timeval *next;
    struct timeval  now;

    assert(t1 != NULL);
    assert(t != NULL);

    if (t2 == NULL || t2->tv_sec > t1->tv_sec ||
        (t2->tv_sec == t1->tv_sec && t2->tv_usec > t1->tv_usec))
    {
        next = t1;
    }
    else
    {
        next = t2;
    }

    (void) gettimeofday(&now, NULL);

    if (next->tv_sec < now.tv_sec ||
        (next->tv_sec == now.tv_sec && next->tv_usec < now.tv_usec))
    {
        t->tv_sec = 0;
        t->tv_usec = 0;
    }
    else
    {
        t->tv_sec = next->tv_sec - now.tv_sec;
        if (next->tv_usec < now.tv_usec)
        {
            t->tv_sec--;
            t->tv_usec = next->tv_usec - now.tv_usec + 1000000;
        }
        else
        {
            t->tv_usec = next->tv_usec - now.tv_usec;
        }
    }

    if (which != NULL)
    {
        *which = next;
    }
}

/*
**  ARC_CHECK_DNS_REPLY -- see if a DNS reply is truncated or corrupt
**
**  Parameters:
**  	ansbuf -- answer buffer
**  	anslen -- number of bytes returned
**  	xclass -- expected class
**  	xtype -- expected type
**
**  Return value:
**  	2 -- reply not usable
**  	1 -- reply truncated but usable
**  	0 -- reply intact (but may not be what you want)
**  	-1 -- other error
*/

int
arc_check_dns_reply(unsigned char *ansbuf, size_t anslen, int xclass, int xtype)
{
    bool     trunc = false;
    int      qdcount;
    int      ancount;
    int      n;
    uint16_t type = (uint16_t) -1;
    uint16_t class = (uint16_t) -1;
    unsigned char *cp;
    unsigned char *eom;
    HEADER         hdr;
    unsigned char  name[ARC_MAXHOSTNAMELEN + 1];

    assert(ansbuf != NULL);

    /* set up pointers */
    memcpy(&hdr, ansbuf, sizeof hdr);
    cp = ansbuf + NS_HFIXEDSZ;
    eom = ansbuf + anslen;

    /* skip over the name at the front of the answer */
    for (qdcount = ntohs((unsigned short) hdr.qdcount); qdcount > 0; qdcount--)
    {
        /* copy it first */
        (void) dn_expand((unsigned char *) ansbuf, eom, cp, (RES_UNC_T) name,
                         sizeof name);

        if ((n = dn_skipname(cp, eom)) < 0)
        {
            return 2;
        }

        cp += n;

        /* extract the type and class */
        if (cp + INT16SZ + INT16SZ > eom)
        {
            return 2;
        }

        GETSHORT(type, cp);
        GETSHORT(class, cp);
    }

    if (type != xtype || class != xclass)
    {
        return 0;
    }

    /* if NXDOMAIN, return DKIM_STAT_NOKEY */
    if (hdr.rcode == NXDOMAIN)
    {
        return 0;
    }

    /* if truncated, we can't do it */
    if (hdr.tc)
    {
        trunc = true;
    }

    /* get the answer count */
    ancount = ntohs((unsigned short) hdr.ancount);
    if (ancount == 0)
    {
        return (trunc ? 2 : 0);
    }

    /*
    **  Extract the data from the first TXT answer.
    */

    while (--ancount >= 0 && cp < eom)
    {
        /* grab the label, even though we know what we asked... */
        if ((n = dn_expand((unsigned char *) ansbuf, eom, cp, (RES_UNC_T) name,
                           sizeof name)) < 0)
        {
            return 2;
        }

        /* ...and move past it */
        cp += n;

        /* extract the type and class */
        if (cp + INT16SZ + INT16SZ + INT32SZ > eom)
        {
            return 2;
        }

        GETSHORT(type, cp);
        cp += INT16SZ; /* class */
        cp += INT32SZ; /* ttl */

        /* skip CNAME if found; assume it was resolved */
        if (type == T_CNAME)
        {
            if ((n = dn_expand((unsigned char *) ansbuf, eom, cp,
                               (RES_UNC_T) name, sizeof name)) < 0)
            {
                return 2;
            }

            cp += n;
            continue;
        }
        else if (type != xtype)
        {
            return (trunc ? 1 : 0);
        }

        /* found a record we can use; break */
        break;
    }

    /* if ancount went below 0, there were no good records */
    if (ancount < 0)
    {
        return (trunc ? 1 : 0);
    }

    /* get payload length */
    if (cp + INT16SZ > eom)
    {
        return 2;
    }

    GETSHORT(n, cp);

    if (cp + n > eom)
    {
        return 2;
    }

    return (trunc ? 1 : 0);
}
