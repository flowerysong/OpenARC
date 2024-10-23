/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2015, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

/* system includes */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "build-config.h"

/* libopendkim includes */
#include "arc-internal.h"
#include "arc-keys.h"
#include "arc-types.h"
#include "arc-util.h"

/* libidn2 */
#include <idn2.h>

/* libbsd if found */
#ifdef USE_BSD_H
#include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
#include <strl.h>
#endif /* USE_STRL_H */

/* prototypes */
extern void arc_error(ARC_MESSAGE *, const char *, ...);

/* local definitions needed for DNS queries */
#define MAXPACKET 8192
#if defined(__RES) && (__RES >= 19940415)
#define RES_UNC_T char *
#else /* __RES && __RES >= 19940415 */
#define RES_UNC_T unsigned char *
#endif /* __RES && __RES >= 19940415 */
#ifndef T_RRSIG
#define T_RRSIG 46
#endif /* ! T_RRSIG */

/*
**  ARC_GET_KEY_DNS -- retrieve a key from DNS
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_get_key_dns(ARC_MESSAGE *msg, char *buf, size_t buflen)
{
    int status;
    int qdcount;
    int ancount;
    int error;
    int dnssec = ARC_DNSSEC_UNKNOWN;
    int c;
    int n = 0;
    int rdlength = 0;
    int type = -1;
    int class = -1;
    size_t         anslen;
    void          *q;
    ARC_LIB       *lib;
    unsigned char *txtfound = NULL;
    char          *p;
    unsigned char *cp;
    unsigned char *eom;
    char          *eob;
    char           qname[ARC_MAXHOSTNAMELEN + 1];
    unsigned char  ansbuf[MAXPACKET];
    struct timeval timeout;
    HEADER         hdr;

    assert(msg != NULL);
    assert(msg->arc_selector != NULL);
    assert(msg->arc_domain != NULL);

    lib = msg->arc_library;

    n = snprintf(qname, sizeof qname - 1, "%s.%s.%s", msg->arc_selector,
                 ARC_DNSKEYNAME, msg->arc_domain);
    if (n == -1 || n > sizeof qname - 1)
    {
        arc_error(msg, "key query name too large");
        return ARC_STAT_NORESOURCE;
    }

    char *qname_idn;
    status = idn2_to_ascii_8z(qname, &qname_idn,
                              IDN2_NONTRANSITIONAL | IDN2_NFC_INPUT);
    if (status != IDN2_OK)
    {
        arc_error(msg, "failed to translate %s to ASCII: %s", qname,
                  idn2_strerror(status));
        return ARC_STAT_KEYFAIL;
    }

    if (strlcpy(qname, qname_idn, sizeof qname) >= sizeof qname)
    {
        arc_error(msg, "key query name too large");
        idn2_free(qname_idn);
        return ARC_STAT_NORESOURCE;
    }
    idn2_free(qname_idn);

    anslen = sizeof ansbuf;

    timeout.tv_sec = msg->arc_timeout;
    timeout.tv_usec = 0;

    if (lib->arcl_dns_service == NULL && lib->arcl_dns_init != NULL &&
        lib->arcl_dns_init(&lib->arcl_dns_service) != 0)
    {
        arc_error(msg, "cannot initialize resolver");
        return ARC_STAT_KEYFAIL;
    }

    status = lib->arcl_dns_start(lib->arcl_dns_service, T_TXT,
                                 (unsigned char *) qname, ansbuf, anslen, &q);

    if (status != 0)
    {
        arc_error(msg, "'%s' query failed", qname);
        return ARC_STAT_KEYFAIL;
    }

    if (lib->arcl_dns_callback == NULL)
    {
        timeout.tv_sec = msg->arc_timeout;
        timeout.tv_usec = 0;

        status = lib->arcl_dns_waitreply(
            lib->arcl_dns_service, q, msg->arc_timeout == 0 ? NULL : &timeout,
            &anslen, &error, &dnssec);
    }
    else
    {
        struct timeval  master;
        struct timeval  next;
        struct timeval *wt;

        (void) gettimeofday(&master, NULL);
        master.tv_sec += msg->arc_timeout;

        for (;;)
        {
            (void) gettimeofday(&next, NULL);
            next.tv_sec += lib->arcl_callback_int;

            arc_min_timeval(&master, &next, &timeout, &wt);

            status = lib->arcl_dns_waitreply(lib->arcl_dns_service, q,
                                             msg->arc_timeout == 0 ? NULL
                                                                   : &timeout,
                                             &anslen, &error, &dnssec);

            if (wt == &next)
            {
                if (status == ARC_DNS_NOREPLY || status == ARC_DNS_EXPIRED)
                {
                    lib->arcl_dns_callback(msg->arc_user_context);
                }
                else
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
    }

    if (status == ARC_DNS_EXPIRED)
    {
        (void) lib->arcl_dns_cancel(lib->arcl_dns_service, q);
        arc_error(msg, "'%s' query timed out", qname);
        return ARC_STAT_KEYFAIL;
    }
    else if (status == ARC_DNS_ERROR)
    {
        (void) lib->arcl_dns_cancel(lib->arcl_dns_service, q);
        arc_error(msg, "'%s' query failed", qname);
        return ARC_STAT_KEYFAIL;
    }

    (void) lib->arcl_dns_cancel(lib->arcl_dns_service, q);

    msg->arc_dnssec_key = dnssec;

    /* set up pointers */
    memcpy(&hdr, ansbuf, sizeof hdr);
    cp = (unsigned char *) &ansbuf + HFIXEDSZ;
    eom = (unsigned char *) &ansbuf + anslen;

    /* skip over the name at the front of the answer */
    for (qdcount = ntohs((unsigned short) hdr.qdcount); qdcount > 0; qdcount--)
    {
        /* copy it first */
        (void) dn_expand((unsigned char *) &ansbuf, eom, cp, qname,
                         sizeof qname);

        if ((n = dn_skipname(cp, eom)) < 0)
        {
            arc_error(msg, "'%s' reply corrupt", qname);
            return ARC_STAT_KEYFAIL;
        }
        cp += n;

        /* extract the type and class */
        if (cp + INT16SZ + INT16SZ > eom)
        {
            arc_error(msg, "'%s' reply corrupt", qname);
            return ARC_STAT_KEYFAIL;
        }
        GETSHORT(type, cp);
        GETSHORT(class, cp);
    }

    if (type != T_TXT || class != C_IN)
    {
        arc_error(msg, "'%s' unexpected reply class/type (%d/%d)", qname, class,
                  type);
        return ARC_STAT_KEYFAIL;
    }

    /* if NXDOMAIN, return ARC_STAT_NOKEY */
    if (hdr.rcode == NXDOMAIN)
    {
        arc_error(msg, "'%s' record not found", qname);
        return ARC_STAT_NOKEY;
    }

    /* if truncated, we can't do it */
    if (arc_check_dns_reply(ansbuf, anslen, C_IN, T_TXT) == 1)
    {
        arc_error(msg, "'%s' reply truncated", qname);
        return ARC_STAT_KEYFAIL;
    }

    /* get the answer count */
    ancount = ntohs((unsigned short) hdr.ancount);
    if (ancount == 0)
    {
        return ARC_STAT_NOKEY;
    }

    /*
    **  Extract the data from the first TXT answer.
    */

    while (--ancount >= 0 && cp < eom)
    {
        /* grab the label, even though we know what we asked... */
        if ((n = dn_expand((unsigned char *) &ansbuf, eom, cp,
                           (RES_UNC_T) qname, sizeof qname)) < 0)
        {
            arc_error(msg, "'%s' reply corrupt", qname);
            return ARC_STAT_KEYFAIL;
        }
        /* ...and move past it */
        cp += n;

        /* extract the type and class */
        if (cp + INT16SZ + INT16SZ + INT32SZ + INT16SZ > eom)
        {
            arc_error(msg, "'%s' reply corrupt", qname);
            return ARC_STAT_KEYFAIL;
        }

        GETSHORT(type, cp);  /* TYPE */
        GETSHORT(class, cp); /* CLASS */
        /* skip the TTL */
        cp += INT32SZ;   /* TTL */
        GETSHORT(n, cp); /* RDLENGTH */

        /* skip CNAME if found; assume it was resolved */
        if (type == T_CNAME)
        {
            cp += n;
            continue;
        }
        else if (type == T_RRSIG)
        {
            cp += n;
            continue;
        }
        else if (type != T_TXT)
        {
            arc_error(msg, "'%s' reply was unexpected type %d", qname, type);
            return ARC_STAT_KEYFAIL;
        }

        if (txtfound != NULL)
        {
            arc_error(msg, "multiple DNS replies for '%s'", qname);
            return ARC_STAT_MULTIDNSREPLY;
        }

        /* remember where this one started */
        txtfound = cp;
        rdlength = n;

        /* move forward for now */
        cp += n;
    }

    /* if ancount went below 0, there were no good records */
    if (txtfound == NULL)
    {
        arc_error(msg, "'%s' reply was unresolved CNAME", qname);
        return ARC_STAT_NOKEY;
    }

    /* come back to the one we found */
    cp = txtfound;

    /*
    **  XXX -- maybe deal with a partial reply rather than require
    **  	   it all
    */

    if (cp + rdlength > eom)
    {
        arc_error(msg, "'%s' reply corrupt", qname);
        return ARC_STAT_SYNTAX;
    }

    /* extract the payload */
    memset(buf, '\0', buflen);
    p = buf;
    eob = buf + buflen - 1;
    while (rdlength > 0 && p < eob)
    {
        c = *cp++;
        rdlength--;
        while (c > 0 && p < eob)
        {
            *p++ = *cp++;
            c--;
            rdlength--;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_GET_KEY_FILE -- retrieve a key from a text file (for testing)
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	buf -- buffer into which to write the result
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Notes:
**  	The file opened is defined by the library option ARC_OPTS_QUERYINFO
**  	and must be set prior to use of this function.  Failing to do
**  	so will cause this function to return ARC_STAT_KEYFAIL every time.
**  	The file should contain lines of the form:
**
**  		<selector>._domainkey.<domain> <space> key-data
**
**  	Case matching on the left is case-sensitive, but libopendkim already
**  	wraps the domain name to lowercase.
*/

ARC_STAT
arc_get_key_file(ARC_MESSAGE *msg, char *buf, size_t buflen)
{
    int   n;
    FILE *f;
    char *p;
    char *p2;
    char *path;
    char  name[ARC_MAXHOSTNAMELEN + 1];

    assert(msg != NULL);
    assert(msg->arc_selector != NULL);
    assert(msg->arc_domain != NULL);
    assert(msg->arc_query == ARC_QUERY_FILE);

    path = msg->arc_library->arcl_queryinfo;
    if (path[0] == '\0')
    {
        arc_error(msg, "query file not defined");
        return ARC_STAT_KEYFAIL;
    }

    f = fopen(path, "r");
    if (f == NULL)
    {
        arc_error(msg, "%s: fopen(): %s", path, strerror(errno));
        return ARC_STAT_KEYFAIL;
    }

    n = snprintf(name, sizeof name, "%s.%s.%s", msg->arc_selector,
                 ARC_DNSKEYNAME, msg->arc_domain);
    if (n == -1 || n > sizeof name)
    {
        arc_error(msg, "key query name too large");
        fclose(f);
        return ARC_STAT_NORESOURCE;
    }

    char *idn_name;
    if (idn2_to_ascii_8z(name, &idn_name,
                         IDN2_NONTRANSITIONAL | IDN2_NFC_INPUT) != IDN2_OK)
    {
        arc_error(msg, "failed to translate %s to ASCII", name);
        fclose(f);
        return ARC_STAT_KEYFAIL;
    }

    memset(buf, '\0', buflen);
    while (fgets(buf, buflen, f) != NULL)
    {
        if (buf[0] == '#')
        {
            continue;
        }

        p2 = NULL;

        for (p = buf; *p != '\0'; p++)
        {
            if (*p == '\n')
            {
                *p = '\0';
                break;
            }
            else if (isascii(*p) && isspace(*p))
            {
                *p = '\0';
                p2 = p + 1;
            }
            else if (p2 != NULL)
            {
                break;
            }
        }

        if (strcasecmp(idn_name, buf) == 0 && p2 != NULL)
        {
            memmove(buf, p2, strlen(p2) + 1);
            idn2_free(idn_name);
            fclose(f);
            return ARC_STAT_OK;
        }
    }

    idn2_free(idn_name);
    fclose(f);

    return ARC_STAT_NOKEY;
}
