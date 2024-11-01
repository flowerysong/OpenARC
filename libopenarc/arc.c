/*
**  Copyright (c) 2009-2017, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
#define _REENTRANT
#endif /* ! REENTRANT */

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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __STDC__
#include <stdarg.h>
#else /* __STDC__ */
#include <varargs.h>
#endif /* _STDC_ */

/* OpenSSL includes */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* libopenarc includes */
#include "arc-canon.h"
#include "arc-dns.h"
#include "arc-internal.h"
#include "arc-keys.h"
#include "arc-tables.h"
#include "arc-types.h"
#include "arc-util.h"
#include "arc.h"
#include "base64.h"

#include "arc-dstring.h"

/* libbsd if found */
#ifdef USE_BSD_H
#include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
#include <strl.h>
#endif /* USE_STRL_H */

/* prototypes */
void arc_error(ARC_MESSAGE *, const char *, ...);

/* macros */
#define ARC_STATE_INIT     0
#define ARC_STATE_HEADER   1
#define ARC_STATE_EOH      2
#define ARC_STATE_BODY     3
#define ARC_STATE_EOM      4
#define ARC_STATE_UNUSABLE 99

#define CRLF               "\r\n"

#define BUFRSZ             2048
#define DEFERRLEN          128
#define DEFTIMEOUT         10

/* generic array size macro */
#define NITEMS(array)      ((int) (sizeof(array) / sizeof(array[0])))

/* local definitions needed for DNS queries */
#define MAXPACKET          8192
#if defined(__RES) && (__RES >= 19940415)
#define RES_UNC_T char *
#else /* __RES && __RES >= 19940415 */
#define RES_UNC_T unsigned char *
#endif /* __RES && __RES >= 19940415 */

#ifndef T_AAAA
#define T_AAAA 28
#endif /* ! T_AAAA */

/* macros */
#define ARC_ISLWSP(x) ((x) == 011 || (x) == 013 || (x) == 014 || (x) == 040)

#define ARC_PHASH(x)  ((x) -32)

/*
**  ARC_ERROR -- log an error into a DKIM handle
**
**  Parameters:
**  	msg -- ARC message context in which this is performed
**  	format -- format to apply
**  	... -- arguments
**
**  Return value:
**  	None.
*/

static void
arc_verror(ARC_MESSAGE *msg, const char *format, va_list ap)
{
    int flen;
    int saverr;
    char *new;

    assert(msg != NULL);
    assert(format != NULL);

    saverr = errno;

    if (msg->arc_error == NULL)
    {
        msg->arc_error = ARC_MALLOC(DEFERRLEN);
        if (msg->arc_error == NULL)
        {
            errno = saverr;
            return;
        }
        msg->arc_errorlen = DEFERRLEN;
    }

    for (;;)
    {
        va_list aq;
        va_copy(aq, ap);
        flen = vsnprintf(msg->arc_error, msg->arc_errorlen, format, aq);
        va_end(aq);

        /* compensate for broken vsnprintf() implementations */
        if (flen == -1)
        {
            flen = msg->arc_errorlen * 2;
        }

        if (flen >= msg->arc_errorlen)
        {
            new = ARC_MALLOC(flen + 1);
            if (new == NULL)
            {
                errno = saverr;
                return;
            }

            ARC_FREE(msg->arc_error);
            msg->arc_error = new;
            msg->arc_errorlen = flen + 1;
        }
        else
        {
            break;
        }
    }

    errno = saverr;
}

void
arc_error(ARC_MESSAGE *msg, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    arc_verror(msg, format, va);
    va_end(va);
}

void
arc_error_cb(void *msg, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    arc_verror(msg, format, va);
    va_end(va);
}

/*
**  ARC_KEY_HASHOK -- return true iff a signature's hash is in the approved
**                    list of hashes for a given key
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	hashlist -- colon-separated approved hash list
**
**  Return value:
**  	true iff a particular hash is in the approved list of hashes.
*/

static bool
arc_key_hashok(ARC_MESSAGE *msg, char *hashlist)
{
    int   hashalg;
    char *x, *y;
    char  tmp[BUFRSZ + 1];

    assert(msg != NULL);

    if (hashlist == NULL)
    {
        return true;
    }

    x = NULL;
    memset(tmp, '\0', sizeof tmp);

    y = hashlist;
    for (;;)
    {
        if (*y == ':' || *y == '\0')
        {
            if (x != NULL)
            {
                strlcpy(tmp, x, sizeof tmp);
                tmp[y - x] = '\0';
                hashalg = arc_name_to_code(hashes, tmp);
                if (hashalg == msg->arc_hashtype)
                {
                    return true;
                }
            }

            x = NULL;
        }
        else if (x == NULL)
        {
            x = y;
        }

        if (*y == '\0')
        {
            return false;
        }
        y++;
    }

    /* NOTREACHED */
}

/*
**  ARC_KEY_HASHESOK -- return true iff this key supports at least one
**                      hash method we know about (or doesn't specify)
**
**  Parameters:
**  	hashlist -- colon-separated list of hashes (or NULL)
**
**  Return value:
**  	true iff this key supports at least one hash method we know about
**  	(or doesn't specify)
*/

static bool
arc_key_hashesok(ARC_LIB *lib, char *hashlist)
{
    char *x, *y;
    char  tmp[BUFRSZ + 1];

    assert(lib != NULL);

    if (hashlist == NULL)
    {
        return true;
    }

    x = NULL;
    memset(tmp, '\0', sizeof tmp);

    y = hashlist;
    for (;;)
    {
        if (*y == ':' || *y == '\0')
        {
            if (x != NULL)
            {
                int hashcode;

                strlcpy(tmp, x, sizeof tmp);
                tmp[y - x] = '\0';

                hashcode = arc_name_to_code(hashes, tmp);

                if (hashcode != -1 && (hashcode != ARC_HASHTYPE_SHA256 ||
                                       arc_libfeature(lib, ARC_FEATURE_SHA256)))
                {
                    return true;
                }
            }

            x = NULL;
        }
        else if (x == NULL)
        {
            x = y;
        }

        if (*y == '\0')
        {
            return false;
        }
        y++;
    }

    /* NOTREACHED */
}

/*
**  ARC_PARSE_ALGORITHM -- parse an algorithm and set the msg hash and key,
**				  as well as set the message digest algorithm for
**				  RSA_verify in the variable nid
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	alg -- string containing the algorithm to parse
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_parse_algorithm(ARC_MESSAGE *msg, const char *alg)
{
    arc_alg_t algtype;

    assert(msg != NULL);

    if (alg == NULL)
    {
        arc_error(msg, "missing algorithm passed to arc_parse_algorithm");
        return ARC_STAT_BADALG;
    }

    algtype = arc_name_to_code(algorithms, alg);

    if (algtype == ARC_SIGN_RSASHA1)
    {
        msg->arc_hashtype = ARC_HASHTYPE_SHA1;
        msg->arc_keytype = ARC_KEYTYPE_RSA;
    }
    else if (algtype == ARC_SIGN_RSASHA256)
    {
        msg->arc_hashtype = ARC_HASHTYPE_SHA256;
        msg->arc_keytype = ARC_KEYTYPE_RSA;
    }
    else
    {
        arc_error(msg, "unknown or invalid algorithm: %s", alg);
        return ARC_STAT_BADALG;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_GENAMSHDR -- generate a signature or seal header field
**
**  Parameters:
**  	arc -- ARC_MESSAGE handle
**  	dstr -- dstring to which to write
**  	delim -- delimiter
**  	seal -- true IFF a seal is being generated
**
**  Return value:
**  	Number of bytes written to "dstr", or <= 0 on error.
*/

static size_t
arc_genamshdr(ARC_MESSAGE        *msg,
              struct arc_dstring *dstr,
              char               *delim,
              bool                seal)
{
    bool                 firsthdr;
    int                  n;
    int                  status;
    int                  delimlen;
    size_t               hashlen;
    char                *format;
    unsigned char       *hash;
    struct arc_hdrfield *hdr;
    unsigned char        b64hash[ARC_MAXHEADER + 1];

    assert(msg != NULL);
    assert(dstr != NULL);
    assert(delim != NULL);

    delimlen = strlen(delim);

    /*
    **  We need to generate an ARC-Message-Signature: header field template
    **  and include it in the canonicalization.
    */

    /* basic required stuff */
    if (sizeof(msg->arc_timestamp) == sizeof(unsigned long long))
    {
        format = "i=%u;%sa=%s;%sd=%s;%ss=%s;%st=%llu";
    }
    else if (sizeof(msg->arc_timestamp) == sizeof(unsigned long))
    {
        format = "i=%u;%sa=%s;%sd=%s;%ss=%s;%st=%lu";
    }
    else
    {
        format = "i=%u;%sa=%s;%sd=%s;%ss=%s;%st=%u";
    }

    (void) arc_dstring_printf(dstr, format, msg->arc_nsets + 1, delim,
                              arc_code_to_name(algorithms, msg->arc_signalg),
                              delim, msg->arc_domain, delim, msg->arc_selector,
                              delim, msg->arc_timestamp);

    if (seal)
    {
        arc_dstring_printf(dstr, ";%scv=%s", delim,
                           arc_code_to_name(chainstatus, msg->arc_cstate));
    }
    else
    {
        arc_dstring_printf(
            dstr, ";%sc=%s/%s", delim,
            arc_code_to_name(canonicalizations, msg->arc_canonhdr),
            arc_code_to_name(canonicalizations, msg->arc_canonbody));
    }

    if (msg->arc_querymethods != NULL)
    {
        bool                firstq = true;
        struct arc_qmethod *q;

        for (q = msg->arc_querymethods; q != NULL; q = q->qm_next)
        {
            if (firstq)
            {
                arc_dstring_printf(dstr, ";%sq=%s", delim, q->qm_type);
            }
            else
            {
                arc_dstring_printf(dstr, ":%s", q->qm_type);
            }

            if (q->qm_options)
            {
                arc_dstring_printf(dstr, "/%s", q->qm_options);
            }

            firstq = false;
        }
    }

    if (msg->arc_sigttl != 0)
    {
        uint64_t expire;

        expire = msg->arc_timestamp + msg->arc_sigttl;
        if (sizeof(expire) == sizeof(unsigned long long))
        {
            arc_dstring_printf(dstr, ";%sx=%llu", delim, expire);
        }
        else if (sizeof(expire) == sizeof(unsigned long))
        {
            arc_dstring_printf(dstr, ";%sx=%lu", delim, expire);
        }
        else
        {
            arc_dstring_printf(dstr, ";%sx=%u", delim, expire);
        }
    }

    if (msg->arc_xtags != NULL)
    {
        struct arc_xtag *x;

        for (x = msg->arc_xtags; x != NULL; x = x->xt_next)
        {
            arc_dstring_printf(dstr, ";%s%s=%s", delim, x->xt_tag, x->xt_value);
        }
    }

    if (!seal)
    {
        memset(b64hash, '\0', sizeof b64hash);

        status = arc_canon_closebody(msg);
        if (status != ARC_STAT_OK)
        {
            return 0;
        }

        status = arc_canon_getfinal(msg->arc_sign_bodycanon, &hash, &hashlen);
        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "arc_canon_getfinal() failed");
            return (size_t) -1;
        }

        arc_base64_encode(hash, hashlen, b64hash, sizeof b64hash);
        arc_dstring_printf(dstr, ";%sbh=%s", delim, b64hash);

        /* l= */
        if (msg->arc_partial)
        {
            arc_dstring_printf(
                dstr, ";%sl=%lu", delim,
                (unsigned long) msg->arc_sign_bodycanon->canon_wrote);
        }

        /* h= */
        firsthdr = true;
        for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
        {
            if ((hdr->hdr_flags & ARC_HDR_SIGNED) == 0)
            {
                continue;
            }

            if (!firsthdr)
            {
                arc_dstring_cat1(dstr, ':');
            }
            else
            {
                arc_dstring_cat1(dstr, ';');
                arc_dstring_catn(dstr, delim, delimlen);
                arc_dstring_catn(dstr, "h=", 2);
            }

            firsthdr = false;

            arc_dstring_catn(dstr, hdr->hdr_text, hdr->hdr_namelen);
        }

        if (msg->arc_library->arcl_oversignhdrs != NULL &&
            msg->arc_library->arcl_oversignhdrs[0] != NULL)
        {
            bool wrote = false;

            if (firsthdr)
            {
                arc_dstring_cat1(dstr, ';');
                arc_dstring_catn(dstr, delim, delimlen);
                arc_dstring_catn(dstr, "h=", 2);
            }
            else
            {
                arc_dstring_cat1(dstr, ':');
            }

            for (n = 0; msg->arc_library->arcl_oversignhdrs[n] != NULL; n++)
            {
                if (msg->arc_library->arcl_oversignhdrs[n][0] == '\0')
                {
                    continue;
                }

                if (wrote)
                {
                    arc_dstring_cat1(dstr, ':');
                }

                arc_dstring_cat(dstr, msg->arc_library->arcl_oversignhdrs[n]);

                wrote = true;
            }
        }
    }

    /* and finally, an empty b= */
    arc_dstring_cat1(dstr, ';');
    arc_dstring_catn(dstr, delim, delimlen);
    arc_dstring_catn(dstr, "b=", 2);

    return arc_dstring_len(dstr);
}

/*
**  ARC_GETAMSHDR_D -- for signing operations, retrieve the complete signature
**                     header, doing so dynamically
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	initial -- initial line width
**  	buf -- pointer to buffer containing the signature (returned)
**  	buflen -- number of bytes at "buf" (returned)
**  	seal -- true IFF we're generating a seal
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	Per RFC6376 Section 3.7, the signature header returned here does
**  	not contain a trailing CRLF.
*/

static ARC_STAT
arc_getamshdr_d(
    ARC_MESSAGE *msg, size_t initial, char **buf, size_t *buflen, bool seal)
{
    size_t              len;
    char               *ctx;
    char               *pv;
    struct arc_dstring *tmpbuf;

    assert(msg != NULL);
    assert(buf != NULL);
    assert(buflen != NULL);

#define DELIMITER "\001"

    tmpbuf = arc_dstring_new(BUFRSZ, MAXBUFRSZ, msg, &arc_error_cb);
    if (tmpbuf == NULL)
    {
        arc_error(msg, "failed to allocate dynamic string");
        return ARC_STAT_NORESOURCE;
    }

    if (msg->arc_hdrbuf == NULL)
    {
        msg->arc_hdrbuf = arc_dstring_new(BUFRSZ, MAXBUFRSZ, msg,
                                          &arc_error_cb);
        if (msg->arc_hdrbuf == NULL)
        {
            arc_dstring_free(tmpbuf);
            arc_error(msg, "failed to allocate dynamic string");
            return ARC_STAT_NORESOURCE;
        }
    }
    else
    {
        arc_dstring_blank(msg->arc_hdrbuf);
    }

    /* compute and extract the signature header */
    len = arc_genamshdr(msg, tmpbuf, DELIMITER, seal);
    if (len == 0)
    {
        arc_dstring_free(tmpbuf);
        return ARC_STAT_INVALID;
    }

    if (msg->arc_b64sig != NULL)
    {
        arc_dstring_cat(tmpbuf, msg->arc_b64sig);
    }

    if (msg->arc_margin == 0)
    {
        bool first = true;

        for (pv = strtok_r(arc_dstring_get(tmpbuf), DELIMITER, &ctx);
             pv != NULL; pv = strtok_r(NULL, DELIMITER, &ctx))
        {
            if (!first)
            {
                arc_dstring_cat1(msg->arc_hdrbuf, ' ');
            }

            arc_dstring_cat(msg->arc_hdrbuf, pv);

            first = false;
        }
    }
    else
    {
        bool  first = true;
        bool  forcewrap;
        int   pvlen;
        int   whichlen;
        char *p;
        char *q;
        char *end;
        char  which[MAXTAGNAME + 1];

        len = initial;
        end = which + MAXTAGNAME;

        for (pv = strtok_r(arc_dstring_get(tmpbuf), DELIMITER, &ctx);
             pv != NULL; pv = strtok_r(NULL, DELIMITER, &ctx))
        {
            for (p = pv, q = which; *p != '=' && q <= end; p++, q++)
            {
                *q = *p;
                *(q + 1) = '\0';
            }

            whichlen = strlen(which);

            /* force wrapping of "b=" ? */

            forcewrap = false;
            if (msg->arc_keytype == ARC_KEYTYPE_RSA)
            {
                unsigned int siglen;

                siglen = BASE64SIZE(msg->arc_keybits / 8);
                if (strcmp(which, "b") == 0 &&
                    len + whichlen + siglen + 1 >= msg->arc_margin)
                {
                    forcewrap = true;
                }
            }

            pvlen = strlen(pv);

            if (len == 0 || first)
            {
                arc_dstring_catn(msg->arc_hdrbuf, pv, pvlen);
                len += pvlen;
                first = false;
            }
            else if (forcewrap || len + pvlen > msg->arc_margin)
            {
                arc_dstring_cat(msg->arc_hdrbuf, "\r\n\t");
                len = 8;

                if (strcmp(which, "h") == 0)
                { /* break at colons */
                    bool  ifirst = true;
                    int   tmplen;
                    char *tmp;
                    char *ctx2;

                    for (tmp = strtok_r(pv, ":", &ctx2); tmp != NULL;
                         tmp = strtok_r(NULL, ":", &ctx2))
                    {
                        tmplen = strlen(tmp);

                        if (ifirst)
                        {
                            arc_dstring_catn(msg->arc_hdrbuf, tmp, tmplen);
                            len += tmplen;
                            ifirst = false;
                        }
                        else if (len + tmplen + 1 > msg->arc_margin)
                        {
                            arc_dstring_cat1(msg->arc_hdrbuf, ':');
                            arc_dstring_cat(msg->arc_hdrbuf, "\r\n\t ");
                            len = 9;
                            arc_dstring_catn(msg->arc_hdrbuf, tmp, tmplen);
                            len += tmplen;
                        }
                        else
                        {
                            arc_dstring_cat1(msg->arc_hdrbuf, ':');
                            len += 1;
                            arc_dstring_catn(msg->arc_hdrbuf, tmp, tmplen);
                            len += tmplen;
                        }
                    }
                }
                else if (strcmp(which, "b") == 0 || strcmp(which, "bh") == 0 ||
                         strcmp(which, "z") == 0)
                { /* break at margins */
                    int   offset;
                    int   n;
                    char *x;
                    char *y;

                    offset = whichlen + 1;

                    arc_dstring_catn(msg->arc_hdrbuf, which, whichlen);
                    arc_dstring_cat1(msg->arc_hdrbuf, '=');

                    len += offset;

                    x = pv + offset;
                    y = pv + pvlen;

                    while (x < y)
                    {
                        if (msg->arc_margin - len == 0)
                        {
                            arc_dstring_cat(msg->arc_hdrbuf, "\r\n\t ");
                            len = 9;
                        }

                        n = MIN(msg->arc_margin - len, y - x);
                        arc_dstring_catn(msg->arc_hdrbuf, x, n);
                        x += n;
                        len += n;
                    }
                }
                else
                { /* break at delimiter */
                    arc_dstring_catn(msg->arc_hdrbuf, pv, pvlen);
                    len += pvlen;
                }
            }
            else
            {
                if (!first)
                {
                    arc_dstring_cat1(msg->arc_hdrbuf, ' ');
                    len += 1;
                }

                first = false;
                arc_dstring_catn(msg->arc_hdrbuf, pv, pvlen);
                len += pvlen;
            }
        }
    }

    *buf = arc_dstring_get(msg->arc_hdrbuf);
    *buflen = arc_dstring_len(msg->arc_hdrbuf);

    arc_dstring_free(tmpbuf);

    return ARC_STAT_OK;
}

/*
**  ARC_INIT -- create a library instance
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new library instance.
*/

ARC_LIB *
arc_init(void)
{
    ARC_LIB *lib;

    lib = ARC_CALLOC(1, sizeof *lib);
    if (lib == NULL)
    {
        return lib;
    }

    lib->arcl_minkeysize = ARC_DEFAULT_MINKEYSIZE;
    lib->arcl_flags = ARC_LIBFLAGS_DEFAULT;

#define FEATURE_INDEX(x)  ((x) / (8 * sizeof(unsigned int)))
#define FEATURE_OFFSET(x) ((x) % (8 * sizeof(unsigned int)))
#define FEATURE_ADD(lib, x)                                                    \
    (lib)->arcl_flist[FEATURE_INDEX((x))] |= (1 << FEATURE_OFFSET(x))

    lib->arcl_flsize = (FEATURE_INDEX(ARC_FEATURE_MAX)) + 1;
    lib->arcl_flist = ARC_CALLOC(lib->arcl_flsize, sizeof(unsigned int));
    if (lib->arcl_flist == NULL)
    {
        ARC_FREE(lib);
        return NULL;
    }

    lib->arcl_dns_callback = NULL;
    lib->arcl_dns_service = NULL;
    lib->arcl_dnsinit_done = false;
    lib->arcl_dns_init = arc_res_init;
    lib->arcl_dns_close = arc_res_close;
    lib->arcl_dns_start = arc_res_query;
    lib->arcl_dns_cancel = arc_res_cancel;
    lib->arcl_dns_waitreply = arc_res_waitreply;
    strlcpy(lib->arcl_tmpdir, DEFTMPDIR, sizeof lib->arcl_tmpdir);

    FEATURE_ADD(lib, ARC_FEATURE_SHA256);

    return lib;
}

/*
**  ARC_CLOSE -- terminate a library instance
**
**  Parameters:
**  	lib -- library instance to terminate
**
**  Return value:
**  	None.
*/

void
arc_close(ARC_LIB *lib)
{
    arc_options(lib, ARC_OP_SETOPT, ARC_OPTS_SIGNHDRS, NULL, sizeof(char **));
    arc_options(lib, ARC_OP_SETOPT, ARC_OPTS_OVERSIGNHDRS, NULL,
                sizeof(char **));
    ARC_FREE(lib->arcl_flist);
    ARC_FREE(lib);
}

/*
**  ARC_GETERROR -- return any stored error string from within the ARC
**                  context handle
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

const char *
arc_geterror(ARC_MESSAGE *msg)
{
    assert(msg != NULL);

    return msg->arc_error;
}

/*
**
**  ARC_OPTIONS -- get/set library options
**
**  Parameters:
**  	lib -- library instance of interest
**  	opt -- ARC_OP_GETOPT or ARC_OP_SETOPT
**  	arg -- ARC_OPTS_* constant
**  	val -- pointer to the new value (or NULL)
**  	valsz -- size of the thing at val
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_options(ARC_LIB *lib, int op, int arg, void *val, size_t valsz)
{
    assert(lib != NULL);
    assert(op == ARC_OP_GETOPT || op == ARC_OP_SETOPT);

    switch (arg)
    {
    case ARC_OPTS_FLAGS:
        if (val == NULL)
        {
            return ARC_STAT_INVALID;
        }

        if (valsz != sizeof lib->arcl_flags)
        {
            return ARC_STAT_INVALID;
        }

        if (op == ARC_OP_GETOPT)
        {
            memcpy(val, &lib->arcl_flags, valsz);
        }
        else
        {
            memcpy(&lib->arcl_flags, val, valsz);
        }

        return ARC_STAT_OK;

    case ARC_OPTS_TMPDIR:
        if (op == ARC_OP_GETOPT)
        {
            strlcpy((char *) val, lib->arcl_tmpdir, valsz);
        }
        else if (val == NULL)
        {
            strlcpy(lib->arcl_tmpdir, DEFTMPDIR, sizeof lib->arcl_tmpdir);
        }
        else
        {
            strlcpy(lib->arcl_tmpdir, (char *) val, sizeof lib->arcl_tmpdir);
        }
        return ARC_STAT_OK;

    case ARC_OPTS_FIXEDTIME:
        if (val == NULL)
        {
            return ARC_STAT_INVALID;
        }

        if (valsz != sizeof lib->arcl_fixedtime)
        {
            return ARC_STAT_INVALID;
        }

        if (op == ARC_OP_GETOPT)
        {
            memcpy(val, &lib->arcl_fixedtime, valsz);
        }
        else
        {
            memcpy(&lib->arcl_fixedtime, val, valsz);
        }

        return ARC_STAT_OK;

    case ARC_OPTS_TESTKEYS:
        if (val == NULL)
        {
            return ARC_STAT_INVALID;
        }

        if (op == ARC_OP_GETOPT)
        {
            strlcpy((char *) val, lib->arcl_queryinfo, valsz);
        }
        else
        {
            strlcpy(lib->arcl_queryinfo, (char *) val,
                    sizeof lib->arcl_queryinfo);
        }
        return ARC_STAT_OK;

    case ARC_OPTS_MINKEYSIZE:
        if (val == NULL)
        {
            return ARC_STAT_INVALID;
        }

        if (valsz != sizeof lib->arcl_minkeysize)
        {
            return ARC_STAT_INVALID;
        }

        if (op == ARC_OP_GETOPT)
        {
            memcpy(val, &lib->arcl_minkeysize, valsz);
        }
        else
        {
            memcpy(&lib->arcl_minkeysize, val, valsz);
        }

        return ARC_STAT_OK;

    case ARC_OPTS_SIGNHDRS:
        if (valsz != sizeof(char **) || op == ARC_OP_GETOPT)
        {
            return ARC_STAT_INVALID;
        }
        else if (val == NULL)
        {
            if (lib->arcl_signre)
            {
                (void) regfree(&lib->arcl_hdrre);
                lib->arcl_signre = false;
            }
        }
        else
        {
            int  status;
            char buf[BUFRSZ + 1];

            if (lib->arcl_signre)
            {
                (void) regfree(&lib->arcl_hdrre);
                lib->arcl_signre = false;
            }
            memset(buf, '\0', sizeof buf);

            (void) strlcpy(buf, "^(", sizeof buf);
            if (!arc_hdrlist(buf, sizeof buf, (char **) val, true))
            {
                return ARC_STAT_INVALID;
            }

            if (strlcat(buf, ")$", sizeof buf) >= sizeof buf)
            {
                return ARC_STAT_INVALID;
            }

            status = regcomp(&lib->arcl_hdrre, buf, (REG_EXTENDED | REG_ICASE));
            if (status != 0)
            {
                return ARC_STAT_INTERNAL;
            }

            lib->arcl_signre = true;
        }
        return ARC_STAT_OK;

    case ARC_OPTS_OVERSIGNHDRS:
        if (valsz != sizeof lib->arcl_oversignhdrs)
        {
            return ARC_STAT_INVALID;
        }

        if (op == ARC_OP_GETOPT)
        {
            memcpy(val, &lib->arcl_oversignhdrs, valsz);
        }
        else if (val == NULL)
        {
            if (lib->arcl_oversignhdrs != NULL)
            {
                arc_clobber_array(lib->arcl_oversignhdrs);
            }
            lib->arcl_oversignhdrs = NULL;
        }
        else
        {
            char **tmp = arc_copy_array(val);
            if (tmp == NULL)
            {
                return ARC_STAT_NORESOURCE;
            }

            if (lib->arcl_oversignhdrs != NULL)
            {
                arc_clobber_array(lib->arcl_oversignhdrs);
            }

            lib->arcl_oversignhdrs = tmp;
        }
        return ARC_STAT_OK;

    default:
        assert(0);
    }
}

/*
**  ARC_SET_DNS -- override DNS resolver
**
**  Parameters:
**      lib -- library handle
**      dns_init -- initialization function
**      dns_callback -- callback function
**      dns_callback_int -- callback interval
**      dns_close -- close function
**      dns_start -- start function
**      dns_cancel -- cancel function
**      dns_waitreply -- wait function
**
**  Return value:
**      An ARC_STAT constant.
*/

ARC_STAT
arc_set_dns(ARC_LIB *lib,
            int (*dns_init)(void **srv),
            void (*dns_callback)(const void *context),
            int dns_callback_int,
            void (*dns_close)(void *srv),
            int (*dns_start)(void          *srv,
                             int            type,
                             const char    *query,
                             unsigned char *buf,
                             size_t         buflen,
                             void         **qh),
            int (*dns_cancel)(void *srv, void *qh),
            int (*dns_waitreply)(void           *srv,
                                 void           *qh,
                                 struct timeval *to,
                                 size_t         *bytes,
                                 int            *error,
                                 int            *dnssec))
{
    if (lib->arcl_dnsinit_done)
    {
        return ARC_STAT_INTERNAL;
    }

    lib->arcl_dns_init = dns_init;
    lib->arcl_dns_callback = dns_callback;
    lib->arcl_callback_int = dns_callback_int;
    lib->arcl_dns_close = dns_close;
    lib->arcl_dns_start = dns_start;
    lib->arcl_dns_cancel = dns_cancel;
    lib->arcl_dns_waitreply = dns_waitreply;

    return ARC_STAT_OK;
}

/*
**  ARC_GETSSLBUF -- retrieve SSL error buffer
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	Pointer to the SSL buffer in the library handle.
*/

const char *
arc_getsslbuf(ARC_LIB *lib)
{
    return (const char *) arc_dstring_get(lib->arcl_sslerrbuf);
}

/*
**  ARC_CHECK_UINT -- check a parameter for a valid unsigned integer
**
**  Parameters:
**  	value -- value to check
**  	allow_zero -- if true, allow zero
**
**  Return value:
**  	true iff the input value looks like a properly formed unsigned integer
** 	that is not zero.
*/

static bool
arc_check_uint(char *value)
{
    uint64_t tmp = 0;
    char    *end;

    assert(value != NULL);

    errno = 0;

    if (value[0] == '-')
    {
        errno = ERANGE;
        tmp = -1;
    }
    else if (value[0] == '\0')
    {
        errno = EINVAL;
        tmp = -1;
    }
    else
    {
        tmp = strtoll(value, &end, 10);
    }

    return !(tmp <= 0 || errno != 0 || *end != '\0');
}

/*
**  ARC_PARAM_GET -- get a parameter from a set
**
**  Parameters:
**  	set -- set to search
**  	param -- parameter to find
**
**  Return value:
**  	Pointer to the parameter requested, or NULL if it's not in the set.
*/

static char *
arc_param_get(ARC_KVSET *set, const char *param)
{
    ARC_PLIST *plist;

    assert(set != NULL);
    assert(param != NULL);

    for (plist = set->set_plist[ARC_PHASH(param[0])]; plist != NULL;
         plist = plist->plist_next)
    {
        if (strcmp(plist->plist_param, param) == 0)
        {
            return plist->plist_value;
        }
    }

    return NULL;
}

/*
**  ARC_SET_FIRST -- return first set in a context
**
**  Parameters:
**  	msg -- ARC message context
**  	type -- type to find, or ARC_KVSETTYPE_ANY
**
**  Return value:
**  	Pointer to the first ARC_KVSET in the context, or NULL if none.
*/

static ARC_KVSET *
arc_set_first(ARC_MESSAGE *msg, arc_kvsettype_t type)
{
    ARC_KVSET *set;

    assert(msg != NULL);

    if (type == ARC_KVSETTYPE_ANY)
    {
        return msg->arc_kvsethead;
    }

    for (set = msg->arc_kvsethead; set != NULL; set = set->set_next)
    {
        if (set->set_type == type)
        {
            return set;
        }
    }

    return NULL;
}

/*
**  ARC_SET_NEXT -- return next set in a context
**
**  Parameters:
**  	set -- last set reported (i.e. starting point for this search)
**  	type -- type to find, or ARC_KVSETTYPE_ANY
**
**  Return value:
**  	Pointer to the next ARC_KVSET in the context, or NULL if none.
*/

static ARC_KVSET *
arc_set_next(ARC_KVSET *cur, arc_kvsettype_t type)
{
    ARC_KVSET *set;

    assert(cur != NULL);

    if (type == ARC_KVSETTYPE_ANY)
    {
        return cur->set_next;
    }

    for (set = cur->set_next; set != NULL; set = set->set_next)
    {
        if (set->set_type == type)
        {
            return set;
        }
    }

    return NULL;
}

/*
**  ARC_SET_TYPE -- return the type of a KVSET
**
**  Parameters:
**  	set -- set of interest
**
**  Return value:
**  	Its type field, one of the ARC_KVSETTYPE_* constants.
*/

static arc_kvsettype_t
arc_set_type(ARC_KVSET *set)
{
    return set->set_type;
}

/*
**  ARC_SET_UDATA -- return the udata of a KVSET
**
**  Parameters:
**  	set -- set of interest
**
**  Return value:
**  	Its udata, as provided to arc_process_set() originally.
*/

static void *
arc_set_udata(ARC_KVSET *set)
{
    return set->set_udata;
}

/*
**  ARC_KEY_SMTP -- return true iff a parameter set defines an SMTP key
**
**  Parameters:
**  	set -- set to be checked
**
**  Return value:
**  	true iff "set" contains an "s" parameter whose value is either
**  	"email" or "*".
*/

static bool
arc_key_smtp(ARC_KVSET *set)
{
    char *val;
    char *last;
    char *p;
    char  buf[BUFRSZ + 1];

    assert(set != NULL);
    assert(set->set_type == ARC_KVSETTYPE_KEY);

    val = arc_param_get(set, "s");

    if (val == NULL)
    {
        return true;
    }

    strlcpy(buf, val, sizeof buf);

    for (p = strtok_r(buf, ":", &last); p != NULL;
         p = strtok_r(NULL, ":", &last))
    {
        if (strcmp(p, "*") == 0 || strcasecmp(p, "email") == 0)
        {
            return true;
        }
    }

    return false;
}

/*
**  ARC_ADD_PLIST -- add an entry to a parameter-value set
**
**  Parameters:
**  	msg -- ARC message context in which this is performed
**  	set -- set to modify
**   	param -- parameter
**  	value -- value
**  	force -- override existing value, if any
**  	ignore_dups -- drop duplicate submissions
**
**  Return value:
**  	0 on success, -1 on failure.
**
**  Notes:
**  	Data is not copied; a reference to it is stored.
*/

static int
arc_add_plist(ARC_MESSAGE *msg,
              ARC_KVSET   *set,
              char        *param,
              char        *value,
              bool         force,
              bool         ignore_dups)
{
    ARC_PLIST *plist;

    assert(msg != NULL);
    assert(set != NULL);
    assert(param != NULL);
    assert(value != NULL);

    if (!isprint(param[0]))
    {
        arc_error(msg, "invalid parameter '%s'", param);
        return -1;
    }

    /* see if we have one already */
    for (plist = set->set_plist[ARC_PHASH(param[0])]; plist != NULL;
         plist = plist->plist_next)
    {
        if (strcasecmp(plist->plist_param, param) == 0)
        {
            if (ignore_dups)
            {
                return 0;
            }

            arc_error(msg, "duplicate parameter '%s'", param);
            return -1;
        }
    }

    /* nope; make one and connect it */
    if (plist == NULL)
    {
        int n;

        plist = ARC_MALLOC(sizeof(ARC_PLIST));
        if (plist == NULL)
        {
            arc_error(msg, "unable to allocate %d byte(s)", sizeof(ARC_PLIST));
            return -1;
        }
        force = true;
        n = ARC_PHASH(param[0]);
        plist->plist_next = set->set_plist[n];
        set->set_plist[n] = plist;
        plist->plist_param = param;
    }

    /* set the value if "force" was set (or this was a new entry) */
    if (force)
    {
        plist->plist_value = value;
    }

    return 0;
}

/*
**  ARC_PROCESS_SET -- process a parameter set, i.e. a string of the form
**                     param=value[; param=value]*
**
**  Parameters:
**  	msg -- ARC_MESSAGE context in which this is performed
**  	type -- an ARC_KVSETTYPE constant
**  	str -- string to be scanned
**  	len -- number of bytes available at "str"
**  	data -- opaque handle to store with the set
**  	out -- the set created by this function (returned)
**
**  Return value:
**  	An ARC_STAT constant.
*/

static ARC_STAT
arc_process_set(ARC_MESSAGE    *msg,
                arc_kvsettype_t type,
                char           *str,
                size_t          len,
                void           *data,
                ARC_KVSET     **out)
{
    bool        spaced;
    bool        first = true;
    bool        stop = false;
    int         state;
    int         status;
    char       *p;
    char       *param;
    char       *value;
    char       *hcopy;
    char       *ctx;
    ARC_KVSET  *set;
    const char *settype;

    assert(msg != NULL);
    assert(str != NULL);
    assert(type == ARC_KVSETTYPE_SEAL || type == ARC_KVSETTYPE_SIGNATURE ||
           type == ARC_KVSETTYPE_AR || type == ARC_KVSETTYPE_KEY);

    param = NULL;
    value = NULL;
    state = 0;
    spaced = false;

    hcopy = ARC_MALLOC(len + 1);
    if (hcopy == NULL)
    {
        arc_error(msg, "unable to allocate %d byte(s)", len + 1);
        return ARC_STAT_INTERNAL;
    }
    strlcpy(hcopy, str, len + 1);

    set = ARC_CALLOC(1, sizeof(ARC_KVSET));
    if (set == NULL)
    {
        ARC_FREE(hcopy);
        arc_error(msg, "unable to allocate %d byte(s)", sizeof(ARC_KVSET));
        return ARC_STAT_INTERNAL;
    }

    set->set_udata = data;
    set->set_type = type;
    settype = arc_code_to_name(settypes, type);

    if (msg->arc_kvsethead == NULL)
    {
        msg->arc_kvsethead = set;
    }
    else
    {
        msg->arc_kvsettail->set_next = set;
    }

    msg->arc_kvsettail = set;

    set->set_next = NULL;
    memset(&set->set_plist, '\0', sizeof set->set_plist);
    set->set_data = hcopy;
    set->set_bad = false;

    for (p = hcopy; *p != '\0' && !stop; p++)
    {
        if (isascii(*p) && !isprint(*p) && !isspace(*p))
        {
            /* FIXME: should this do more validation of UTF-8? */
            arc_error(
                msg, "invalid character (ASCII 0x%02x at offset %d) in %s data",
                *p, p - hcopy, settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        switch (state)
        {
        case 0: /* before param */
            if (isspace(*p))
            {
                continue;
            }
            else if (isalnum(*p))
            {
                param = p;
                state = 1;
            }
            else
            {
                arc_error(msg,
                          "syntax error in %s data (char 0x%02x at offset %d)",
                          settype, *p, p - hcopy);
                set->set_bad = true;
                return ARC_STAT_SYNTAX;
            }
            break;

        case 1: /* in param */
            if (isspace(*p))
            {
                spaced = true;
            }
            else if (*p == '=')
            {
                *p = '\0';
                state = 2;
                spaced = false;
            }
            else if (*p == ';' || spaced)
            {
                arc_error(msg,
                          "syntax error in %s data (char 0x%02x at offset %d)",
                          settype, *p, p - hcopy);
                set->set_bad = true;
                return ARC_STAT_SYNTAX;
            }
            break;

        case 2: /* before value */
            if (isspace(*p))
            {
                continue;
            }
            else if (*p == ';') /* empty value */
            {
                *p = '\0';
                value = p;

                /* collapse the parameter */
                arc_collapse(param);

                if (first && type != ARC_KVSETTYPE_KEY)
                {
                    /* definitely invalid */
                    set->set_bad = true;
                    arc_error(
                        msg,
                        "syntax error in %s data: blank %s instead of valid instance",
                        settype, param);
                    return ARC_STAT_SYNTAX;
                }

                /* create the ARC_PLIST entry */
                status = arc_add_plist(msg, set, param, value, true, false);
                if (status == -1)
                {
                    set->set_bad = true;
                    return ARC_STAT_INTERNAL;
                }

                /* reset */
                param = NULL;
                value = NULL;
                state = 0;
            }
            else
            {
                value = p;
                state = 3;
            }
            break;

        case 3: /* in value */
            if (*p == ';')
            {
                *p = '\0';

                /* collapse the parameter and value */
                arc_collapse(param);
                arc_collapse(value);

                if (first && type != ARC_KVSETTYPE_KEY &&
                    strcmp(param, "i") != 0)
                {
                    set->set_bad = true;
                    arc_error(
                        msg,
                        "syntax error in %s data: %s=%s instead of instance",
                        settype, param, value);
                    return ARC_STAT_SYNTAX;
                }

                /* create the ARC_PLIST entry */
                status = arc_add_plist(msg, set, param, value, true, false);
                if (status == -1)
                {
                    set->set_bad = true;
                    return ARC_STAT_INTERNAL;
                }

                first = false;

                /*
                **  Short-circuit ARC-Authentication-Results
                **  after one tag, which should be the "i="
                */

                if (type == ARC_KVSETTYPE_AR)
                {
                    stop = true;
                }

                /* reset */
                param = NULL;
                value = NULL;
                state = 0;
            }
            break;

        default: /* shouldn't happen */
            assert(0);
        }
    }

    switch (state)
    {
    case 0: /* before param */
    case 3: /* in value */
        /* parse the data found, if any */
        if (value != NULL)
        {
            /* collapse the parameter and value */
            arc_collapse(param);
            arc_collapse(value);

            /* create the ARC_PLIST entry */
            status = arc_add_plist(msg, set, param, value, true, false);
            if (status == -1)
            {
                set->set_bad = true;
                return ARC_STAT_INTERNAL;
            }
        }
        break;

    case 2: /* before value */
        /* create an empty ARC_PLIST entry */
        status = arc_add_plist(msg, set, param, "", true, false);
        if (status == -1)
        {
            set->set_bad = true;
            return ARC_STAT_INTERNAL;
        }
        break;

    case 1: /* after param */
        arc_error(msg, "tag without value at end of %s data", settype);
        set->set_bad = true;
        return ARC_STAT_SYNTAX;

    default: /* shouldn't happen */
        assert(0);
    }

    /* load up defaults, assert requirements */
    switch (set->set_type)
    {
    case ARC_KVSETTYPE_SIGNATURE:
        /* make sure required stuff is here */
        if (arc_param_get(set, "s") == NULL ||
            arc_param_get(set, "h") == NULL ||
            arc_param_get(set, "d") == NULL ||
            arc_param_get(set, "b") == NULL ||
            arc_param_get(set, "bh") == NULL ||
            arc_param_get(set, "i") == NULL ||
            arc_param_get(set, "c") == NULL || arc_param_get(set, "a") == NULL)
        {
            arc_error(msg, "missing parameter(s) in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        /* make sure nothing got signed that shouldn't be */
        p = arc_param_get(set, "h");
        hcopy = ARC_STRDUP(p);
        if (hcopy == NULL)
        {
            len = strlen(p);
            arc_error(msg, "unable to allocate %d byte(s)", len + 1);
            set->set_bad = true;
            return ARC_STAT_INTERNAL;
        }

        for (p = strtok_r(hcopy, ":", &ctx); p != NULL;
             p = strtok_r(NULL, ":", &ctx))
        {
            if (strcasecmp(p, ARC_SEAL_HDRNAME) == 0)
            {
                arc_error(msg, "ARC-Message-Signature signs %s", p);
                set->set_bad = true;
                ARC_FREE(hcopy);
                return ARC_STAT_INTERNAL;
            }
        }
        ARC_FREE(hcopy);

        /* test validity of "t", "x", and "i" */
        p = arc_param_get(set, "t");
        if (p != NULL && !arc_check_uint(p))
        {
            arc_error(msg, "invalid \"t\" value in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        p = arc_param_get(set, "x");
        if (p != NULL && !arc_check_uint(p))
        {
            arc_error(msg, "invalid \"x\" value in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        if (!arc_check_uint(arc_param_get(set, "i")))
        {
            arc_error(msg, "invalid \"i\" value in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        /* default for "q" */
        status = arc_add_plist(msg, set, "q", "dns/txt", false, true);
        if (status == -1)
        {
            set->set_bad = true;
            return ARC_STAT_INTERNAL;
        }

        break;

    case ARC_KVSETTYPE_KEY:
        status = arc_add_plist(msg, set, "k", "rsa", false, true);
        if (status == -1)
        {
            set->set_bad = true;
            return ARC_STAT_INTERNAL;
        }

        break;

    /* these have no defaults */
    case ARC_KVSETTYPE_SEAL:
        /* make sure required stuff is here */
        if (arc_param_get(set, "cv") == NULL ||
            arc_param_get(set, "i") == NULL ||
            arc_param_get(set, "b") == NULL ||
            arc_param_get(set, "s") == NULL ||
            arc_param_get(set, "d") == NULL || arc_param_get(set, "a") == NULL)
        {
            arc_error(msg, "missing parameter(s) in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        /* test validity of "i" */
        p = arc_param_get(set, "i");
        if (p != NULL && !arc_check_uint(p))
        {
            arc_error(msg, "invalid \"i\" value in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        /* RFC 8617 4.1.3 ARC-Seal (AS)
         *
         * Note especially that the DKIM "h" tag is NOT allowed and, if found,
         * MUST result in a cv status of "fail"
         */
        if (arc_param_get(set, "h") != NULL)
        {
            arc_error(msg, "invalid parameter \"h\" in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        break;

    case ARC_KVSETTYPE_AR:
        if (arc_param_get(set, "i") == NULL)
        {
            arc_error(msg, "missing parameter(s) in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        /* test validity of "i" */
        p = arc_param_get(set, "i");
        if (p != NULL && !arc_check_uint(p))
        {
            arc_error(msg, "invalid \"i\" value in %s data", settype);
            set->set_bad = true;
            return ARC_STAT_SYNTAX;
        }

        break;
    }

    if (out != NULL)
    {
        *out = set;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_GET_KEY -- acquire a public key used for verification
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	test -- skip signature-specific validity checks
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_get_key(ARC_MESSAGE *msg, bool test)
{
    int               status;
    struct arc_kvset *set = NULL;
    struct arc_kvset *nextset;
    char             *p;
    char              buf[BUFRSZ + 1];

    assert(msg != NULL);
    assert(msg->arc_selector != NULL);
    assert(msg->arc_domain != NULL);

    memset(buf, '\0', sizeof buf);

    /* use appropriate get method */
    switch (msg->arc_query)
    {
    case ARC_QUERY_DNS:
        status = (int) arc_get_key_dns(msg, buf, sizeof buf);
        if (status != (int) ARC_STAT_OK)
        {
            return (ARC_STAT) status;
        }
        break;

    case ARC_QUERY_FILE:
        status = (int) arc_get_key_file(msg, buf, sizeof buf);
        if (status != (int) ARC_STAT_OK)
        {
            return (ARC_STAT) status;
        }
        break;

    default:
        assert(0);
    }

    /* decode the payload */
    if (buf[0] == '\0')
    {
        arc_error(msg, "empty key record");
        return ARC_STAT_SYNTAX;
    }

    status = arc_process_set(msg, ARC_KVSETTYPE_KEY, buf, strlen(buf), NULL,
                             NULL);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    /* get the last key */
    set = arc_set_first(msg, ARC_KVSETTYPE_KEY);
    assert(set != NULL);
    for (;;)
    {
        nextset = arc_set_next(set, ARC_KVSETTYPE_KEY);
        if (nextset == NULL)
        {
            break;
        }
        set = nextset;
    }
    assert(set != NULL);

    /* verify key version first */
    p = arc_param_get(set, "v");
    if (p != NULL && strcmp(p, DKIM_VERSION_KEY) != 0)
    {
        arc_error(msg, "invalid key version '%s'", p);
        return ARC_STAT_SYNTAX;
    }

    /* then make sure the hash type is something we can handle */
    p = arc_param_get(set, "h");
    if (!arc_key_hashesok(msg->arc_library, p))
    {
        arc_error(msg, "unknown hash '%s'", p);
        return ARC_STAT_SYNTAX;
    }
    /* ...and that this key is approved for this signature's hash */
    else if (!test && !arc_key_hashok(msg, p))
    {
        arc_error(msg, "signature-key hash mismatch");
        return ARC_STAT_CANTVRFY;
    }

    /* make sure it's a key designated for e-mail */
    if (!arc_key_smtp(set))
    {
        arc_error(msg, "key type mismatch");
        return ARC_STAT_CANTVRFY;
    }

    /* then key type */
    p = arc_param_get(set, "k");
    if (p == NULL)
    {
        arc_error(msg, "key type missing");
        return ARC_STAT_SYNTAX;
    }
    else if (arc_name_to_code(keytypes, p) == -1)
    {
        arc_error(msg, "unknown key type '%s'", p);
        return ARC_STAT_SYNTAX;
    }

    /* decode the key */
    msg->arc_b64key = arc_param_get(set, "p");
    if (msg->arc_b64key == NULL)
    {
        arc_error(msg, "key missing");
        return ARC_STAT_SYNTAX;
    }
    else if (msg->arc_b64key[0] == '\0')
    {
        return ARC_STAT_REVOKED;
    }
    msg->arc_b64keylen = strlen(msg->arc_b64key);

    if (msg->arc_key != NULL)
    {
        ARC_FREE(msg->arc_key);
    }

    msg->arc_key = ARC_MALLOC(msg->arc_b64keylen);
    if (msg->arc_key == NULL)
    {
        arc_error(msg, "unable to allocate %d byte(s)", msg->arc_b64keylen);
        return ARC_STAT_NORESOURCE;
    }

    status = arc_base64_decode((unsigned char *) msg->arc_b64key, msg->arc_key,
                               msg->arc_b64keylen);
    if (status < 0)
    {
        arc_error(msg, "key missing");
        return ARC_STAT_SYNTAX;
    }

    msg->arc_keylen = status;
    msg->arc_flags = 0;

    /* store key flags */
    p = arc_param_get(set, "t");
    if (p != NULL)
    {
        unsigned int flag;
        char        *t;
        char        *last;
        char         tmp[BUFRSZ + 1];

        strlcpy(tmp, p, sizeof tmp);

        for (t = strtok_r(tmp, ":", &last); t != NULL;
             t = strtok_r(NULL, ":", &last))
        {
            flag = (unsigned int) arc_name_to_code(keyflags, t);
            if (flag != (unsigned int) -1)
            {
                msg->arc_flags |= flag;
            }
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_VERIFY_HASH -- verify a hash
**
**  Parameters:
**	msg -- ARC_MESSAGE handle
**	b64sig -- base64 encoded signature
**	h -- hash
**	hlen -- hash length
**
**  Return value:
**	An ARC_STAT_* constant.
*/

static ARC_STAT
arc_verify_hash(ARC_MESSAGE *msg, char *b64sig, void *h, size_t hlen)
{
    int           rc;
    size_t        b64siglen;
    size_t        siglen;
    size_t        keysize;
    ARC_STAT      status;
    void         *sig;
    BIO          *keydata = NULL;
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* get the key from DNS (or wherever) */
    status = arc_get_key(msg, false);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_get_key() failed");
        return status;
    }

    b64siglen = strlen(b64sig);

    sig = ARC_MALLOC(b64siglen);
    if (sig == NULL)
    {
        arc_error(msg, "unable to allocate %d bytes", b64siglen);
        return ARC_STAT_INTERNAL;
    }

    siglen = arc_base64_decode((unsigned char *) b64sig, sig, b64siglen);
    if (siglen < 0)
    {
        arc_error(msg, "unable to decode signature");
        status = ARC_STAT_SYNTAX;
        goto error;
    }

    keydata = BIO_new_mem_buf(msg->arc_key, msg->arc_keylen);
    if (keydata == NULL)
    {
        arc_error(msg, "BIO_new_mem_buf() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    pkey = d2i_PUBKEY_bio(keydata, NULL);
    if (pkey == NULL)
    {
        arc_error(msg, "d2i_PUBKEY_bio() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    keysize = EVP_PKEY_bits(pkey);
    if (keysize < msg->arc_library->arcl_minkeysize)
    {
        arc_error(msg, "key size (%u) below minimum (%u)", keysize,
                  msg->arc_library->arcl_minkeysize);
        status = ARC_STAT_BADSIG;
        goto error;
    }

    status = ARC_STAT_INTERNAL;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        arc_error(msg, "EVP_PKEY_CTX_new() failed");
        goto error;
    }

    rc = EVP_PKEY_verify_init(ctx);
    if (rc <= 0)
    {
        arc_error(msg, "EVP_PKEY_verify_init() failed");
        goto error;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (rc <= 0)
    {
        arc_error(msg, "EVP_PKEY_CTX_set_rsa_padding() failed");
        goto error;
    }

    if (msg->arc_hashtype == ARC_HASHTYPE_SHA1)
    {
        rc = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1());
    }
    else
    {
        rc = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    }
    if (rc <= 0)
    {
        arc_error(msg, "EVP_PKEY_CTX_set_signature_md() failed");
        goto error;
    }

    status = ARC_STAT_BADSIG;
    rc = EVP_PKEY_verify(ctx, sig, siglen, h, hlen);
    if (rc == 1)
    {
        status = ARC_STAT_OK;
    }

error:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(keydata);
    ARC_FREE(sig);

    return status;
}

/*
**  ARC_VALIDATE_MSG -- validate a specific ARC-Message-Signature
**
**  Parameters:
**  	msg -- ARC message handle
**  	set -- ARC set number whose AMS should be validated (zero-based)
**  	verify -- verify or sign
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

static ARC_STAT
arc_validate_msg(ARC_MESSAGE *msg, unsigned int setnum)
{
    size_t          elen;
    size_t          hhlen;
    size_t          bhlen;
    size_t          b64bhlen;
    ARC_STAT        status;
    char           *alg;
    char           *b64sig;
    unsigned char  *b64bh;
    char           *b64bhtag;
    void           *hh;
    void           *bh;
    struct arc_set *set;
    ARC_KVSET      *kvset;

    assert(msg != NULL);

    /* pull the (set-1)th ARC Set */
    set = &msg->arc_sets[setnum - 1];

    /*
    **  Validate the ARC-Message-Signature.
    */

    /* finalize body canonicalizations */
    status = arc_canon_closebody(msg);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_closebody() failed");
        return status;
    }

    /*
    **  The stub AMS was generated, canonicalized, and hashed by
    **  arc_canon_runheaders().  It should also have been finalized.
    */

    /* extract selector and domain */
    kvset = set->arcset_ams->hdr_data;
    msg->arc_selector = arc_param_get(kvset, "s");
    msg->arc_domain = arc_param_get(kvset, "d");

    /* store algorithm in msg, needed for arc_get_key() */
    alg = arc_param_get(kvset, "a");
    status = arc_parse_algorithm(msg, alg);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    /* extract the header and body hashes from the message */
    status = arc_canon_gethashes(msg, setnum, &hh, &hhlen, &bh, &bhlen);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_gethashes() failed");
        return status;
    }

    /* extract the signature and body hash from the message */
    b64sig = arc_param_get(kvset, "b");
    b64bhtag = arc_param_get(kvset, "bh");

    /* verify the signature against the header hash and the key */
    status = arc_verify_hash(msg, b64sig, hh, hhlen);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    /* verify the signature's "bh" against our computed one */
    b64bhlen = BASE64SIZE(bhlen);
    b64bh = ARC_CALLOC(1, b64bhlen + 1);
    if (b64bh == NULL)
    {
        arc_error(msg, "unable to allocate %d bytes", b64bhlen + 1);
        return ARC_STAT_INTERNAL;
    }
    elen = arc_base64_encode(bh, bhlen, b64bh, b64bhlen);
    if (elen != strlen(b64bhtag) || strcmp((char *) b64bh, b64bhtag) != 0)
    {
        ARC_FREE(b64bh);
        arc_error(msg, "body hash mismatch");
        return ARC_STAT_BADSIG;
    }

    ARC_FREE(b64bh);
    /* if we got this far, the signature was good */
    return ARC_STAT_OK;
}

/*
**  ARC_VALIDATE_SEAL -- validate a specific ARC seal
**
**  Parameters:
**  	msg -- ARC message handle
**  	set -- ARC set number to be validated (zero-based)
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Side effects:
**  	Updates msg->arc_cstate.
*/

static ARC_STAT
arc_validate_seal(ARC_MESSAGE *msg, unsigned int setnum)
{
    ARC_STAT        status;
    size_t          shlen;
    char           *b64sig;
    void           *sh;
    char           *alg;
    struct arc_set *set;
    ARC_KVSET      *kvset;

    assert(msg != NULL);

    /* pull the (set-1)th ARC Set */
    set = &msg->arc_sets[setnum - 1];

    /* extract selector and domain */
    kvset = set->arcset_as->hdr_data;
    msg->arc_selector = arc_param_get(kvset, "s");
    msg->arc_domain = arc_param_get(kvset, "d");

    /* store algorithm in msg, needed for arc_get_key() */
    alg = arc_param_get(kvset, "a");
    status = arc_parse_algorithm(msg, alg);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    if (msg->arc_selector == NULL)
    {
        arc_error(msg, "seal at i=%u has no selector", setnum);
        return ARC_STAT_SYNTAX;
    }
    if (msg->arc_domain == NULL)
    {
        arc_error(msg, "seal at i=%u has no domain", setnum);
        return ARC_STAT_SYNTAX;
    }

    /* extract the seal hash */
    status = arc_canon_getsealhash(msg, setnum, &sh, &shlen);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_getsealhashes() failed");
        return status;
    }

    /* extract the signature from the seal */
    b64sig = arc_param_get(kvset, "b");

    /* verify the signature against the header hash and the key */
    status = arc_verify_hash(msg, b64sig, sh, shlen);
    if (status == ARC_STAT_BADSIG)
    {
        msg->arc_cstate = ARC_CHAIN_FAIL;
    }

    return status;
}

/*
**  ARC_MESSAGE -- create a new message handle
**
**  Parameters:
**  	lib -- containing library instance
**  	canonhdr -- canonicalization mode to use on the header
**  	canonbody -- canonicalization mode to use on the body
**  	signalg -- signing algorithm
**  	err -- error string (returned)
**
**  Return value:
**  	A new message instance, or NULL on failure (and "err" is updated).
*/

ARC_MESSAGE *
arc_message(ARC_LIB     *lib,
            arc_canon_t  canonhdr,
            arc_canon_t  canonbody,
            arc_alg_t    signalg,
            arc_mode_t   mode,
            const char **err)
{
    ARC_MESSAGE *msg;

    if (mode == 0)
    {
        if (err != NULL)
        {
            *err = "no mode(s) selected";
        }
        return NULL;
    }

    msg = ARC_CALLOC(1, sizeof *msg);
    if (msg == NULL)
    {
        if (err != NULL)
        {
            *err = strerror(errno);
        }
        return NULL;
    }

    msg->arc_library = lib;
    if (lib->arcl_fixedtime != 0)
    {
        msg->arc_timestamp = lib->arcl_fixedtime;
    }
    else
    {
        time(&msg->arc_timestamp);
    }

    msg->arc_canonhdr = canonhdr;
    msg->arc_canonbody = canonbody;
    msg->arc_signalg = signalg;
    msg->arc_margin = ARC_HDRMARGIN;
    msg->arc_mode = mode;

    if (strlen(lib->arcl_queryinfo) > 0)
    {
        msg->arc_query = ARC_QUERY_FILE;
    }

    return msg;
}

/*
**  ARC_FREE -- deallocate a message object
**
**  Parameters:
**  	msg -- message object to be destroyed
**
**  Return value:
**  	None.
*/

void
arc_free(ARC_MESSAGE *msg)
{
    struct arc_hdrfield *h;
    struct arc_hdrfield *tmp;

    if (msg->arc_error != NULL)
    {
        ARC_FREE(msg->arc_error);
    }

    h = msg->arc_hhead;
    while (h != NULL)
    {
        tmp = h->hdr_next;
        ARC_FREE(h->hdr_text);
        ARC_FREE(h);
        h = tmp;
    }

    h = msg->arc_sealhead;
    while (h != NULL)
    {
        tmp = h->hdr_next;
        ARC_FREE(h->hdr_text);
        ARC_FREE(h);
        h = tmp;
    }

    if (msg->arc_hdrlist != NULL)
    {
        ARC_FREE(msg->arc_hdrlist);
    }

    arc_dstring_free(msg->arc_hdrbuf);

    while (msg->arc_kvsethead != NULL)
    {
        int        i;
        ARC_KVSET *set = msg->arc_kvsethead;

        msg->arc_kvsethead = set->set_next;
        ARC_FREE(set->set_data);

        for (i = 0; i < NITEMS(set->set_plist); i++)
        {
            while (set->set_plist[i] != NULL)
            {
                ARC_PLIST *plist = set->set_plist[i];
                set->set_plist[i] = plist->plist_next;
                ARC_FREE(plist);
            }
        }

        ARC_FREE(set);
    }

    arc_canon_cleanup(msg);

    ARC_FREE(msg->arc_sealcanons);
    ARC_FREE(msg->arc_sets);
    ARC_FREE(msg->arc_key);
    ARC_FREE(msg);
}

/*
**  ARC_PARSE_HEADER_FIELD -- parse a header field into an internal object
**
**  Parameters:
**  	msg -- message handle
**  	hdr -- full text of the header field
**  	hlen -- bytes to use at hname
**  	ret -- (returned) object, if it's good
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

static ARC_STAT
arc_parse_header_field(ARC_MESSAGE          *msg,
                       const char           *hdr,
                       size_t                hlen,
                       struct arc_hdrfield **ret)
{
    const char          *colon;
    const char          *semicolon;
    const char          *end = NULL;
    size_t               c;
    struct arc_hdrfield *h;

    assert(msg != NULL);
    assert(hdr != NULL);
    assert(hlen != 0);

    /* enforce RFC 5322, Section 2.2 as extended by RFC 6532, Section 3.2 */
    colon = NULL;
    for (c = 0; c < hlen; c++)
    {
        if (colon == NULL)
        {
            /*
            **  Field names are printable ASCII.
            */

            if (!isprint(hdr[c]))
            {
                return ARC_STAT_SYNTAX;
            }

            /* the colon is special */
            if (hdr[c] == ':')
            {
                colon = &hdr[c];
            }
        }
        else
        {
            /* field bodies are printable ASCII, HT (9), LF (10), CR (13), or
             * UTF-8 */
            if (isascii(hdr[c]) && !(isprint(hdr[c]) || hdr[c] == 9 ||
                                     hdr[c] == 10 || hdr[c] == 13))
            {
                return ARC_STAT_SYNTAX;
            }
        }
    }

    if (colon == NULL)
    {
        return ARC_STAT_SYNTAX;
    }

    end = colon;

    while (end > hdr && isascii(*(end - 1)) && isspace(*(end - 1)))
    {
        end--;
    }

    /* don't allow incredibly large field names */
    if (end - hdr > ARC_MAXHDRNAMELEN)
    {
        return ARC_STAT_SYNTAX;
    }

    /* don't allow a field name containing a semicolon */
    semicolon = memchr(hdr, ';', hlen);
    if (semicolon != NULL && colon != NULL && semicolon < colon)
    {
        return ARC_STAT_SYNTAX;
    }

    h = ARC_MALLOC(sizeof *h);
    if (h == NULL)
    {
        arc_error(msg, "unable to allocate %d byte(s)", sizeof *h);
        return ARC_STAT_NORESOURCE;
    }

    if ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF) != 0)
    {
        char                prev = '\0';
        struct arc_dstring *tmphdr;

        tmphdr = arc_dstring_new(BUFRSZ, MAXBUFRSZ, msg, &arc_error_cb);
        if (tmphdr == NULL)
        {
            ARC_FREE(h);
            return ARC_STAT_NORESOURCE;
        }

        for (const char *p = hdr, *q = hdr + hlen; p < q && *p != '\0'; p++)
        {
            if (*p == '\n' && prev != '\r') /* bare LF */
            {
                arc_dstring_catn(tmphdr, CRLF, 2);
            }
            else if (prev == '\r' && *p != '\n') /* bare CR */
            {
                arc_dstring_cat1(tmphdr, '\n');
                arc_dstring_cat1(tmphdr, *p);
            }
            else /* other */
            {
                arc_dstring_cat1(tmphdr, *p);
            }

            prev = *p;
        }

        if (prev == '\r') /* end CR */
        {
            arc_dstring_cat1(tmphdr, '\n');
        }

        h->hdr_text = strndup(arc_dstring_get(tmphdr), arc_dstring_len(tmphdr));

        arc_dstring_free(tmphdr);
    }
    else
    {
        h->hdr_text = strndup(hdr, hlen);
    }

    if (h->hdr_text == NULL)
    {
        ARC_FREE(h);
        return ARC_STAT_NORESOURCE;
    }

    h->hdr_namelen = end != NULL ? end - hdr : hlen;
    h->hdr_textlen = hlen;
    h->hdr_flags = 0;
    h->hdr_next = NULL;

    *ret = h;

    return ARC_STAT_OK;
}

/*
**  ARC_HEADER_FIELD -- consume a header field
**
**  Parameters:
**  	msg -- message handle
**  	hdr -- full text of the header field
**  	hlen -- bytes to use at hname
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_header_field(ARC_MESSAGE *msg, const char *hdr, size_t hlen)
{
    ARC_STAT             status;
    struct arc_hdrfield *h;

    assert(msg != NULL);
    assert(hdr != NULL);
    assert(hlen != 0);

    if (msg->arc_state > ARC_STATE_HEADER)
    {
        return ARC_STAT_INVALID;
    }
    msg->arc_state = ARC_STATE_HEADER;

    status = arc_parse_header_field(msg, hdr, hlen, &h);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    if (msg->arc_hhead == NULL)
    {
        msg->arc_hhead = h;
        msg->arc_htail = h;
    }
    else
    {
        msg->arc_htail->hdr_next = h;
        msg->arc_htail = h;
    }

    msg->arc_hdrcnt++;

    return ARC_STAT_OK;
}

/*
**  ARC_EOH_VERIFY -- verifying side of the end-of-header handler
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_eoh_verify(ARC_MESSAGE *msg)
{
    unsigned int         n;
    unsigned int         hashtype;
    char                *c;
    ARC_STAT             status;
    struct arc_hdrfield *h = NULL;
    char                *htag = NULL;
    arc_canon_t          hdr_canon;
    arc_canon_t          body_canon;

    /* if the chain is dead, nothing to do here */
    if (msg->arc_cstate == ARC_CHAIN_FAIL)
    {
        return ARC_STAT_OK;
    }

    if (msg->arc_nsets == 0)
    {
        return ARC_STAT_OK;
    }

    /*
    **  Request specific canonicalizations we want to run.
    */

    /* sets already in the chain, validation */
    msg->arc_sealcanons = ARC_CALLOC(msg->arc_nsets, sizeof(ARC_CANON *));
    msg->arc_hdrcanons = ARC_CALLOC(msg->arc_nsets, sizeof(ARC_CANON *));
    msg->arc_bodycanons = ARC_CALLOC(msg->arc_nsets, sizeof(ARC_CANON *));

    if (msg->arc_sealcanons == NULL || msg->arc_hdrcanons == NULL ||
        msg->arc_bodycanons == NULL)
    {
        arc_error(msg, "failed to allocate memory for canonicalizations");
        return ARC_STAT_INTERNAL;
    }

    for (n = 0; n < msg->arc_nsets; n++)
    {
        h = msg->arc_sets[n].arcset_as;

        if (strcmp(arc_param_get(h->hdr_data, "a"), "rsa-sha1") == 0)
        {
            hashtype = ARC_HASHTYPE_SHA1;
        }
        else
        {
            hashtype = ARC_HASHTYPE_SHA256;
        }

        status = arc_add_canon(msg, ARC_CANONTYPE_SEAL, ARC_CANON_RELAXED,
                               hashtype, NULL, h, (ssize_t) -1,
                               &msg->arc_sealcanons[n]);
        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "failed to initialize seal canonicalization object");
            return status;
        }

        /* AMS */
        h = msg->arc_sets[n].arcset_ams;
        htag = arc_param_get(h->hdr_data, "h");
        if (strcmp(arc_param_get(h->hdr_data, "a"), "rsa-sha1") == 0)
        {
            hashtype = ARC_HASHTYPE_SHA1;
        }
        else
        {
            hashtype = ARC_HASHTYPE_SHA256;
        }

        c = arc_param_get(h->hdr_data, "c");
        if (c != NULL)
        {
            status = arc_parse_canon_t(c, &hdr_canon, &body_canon);
            if (status != ARC_STAT_OK)
            {
                arc_error(msg, "failed to parse header c= tag with value %s",
                          c);
                hdr_canon = ARC_CANON_SIMPLE;
                body_canon = ARC_CANON_SIMPLE;
                msg->arc_cstate = ARC_CHAIN_FAIL;
            }
        }
        else
        {
            hdr_canon = ARC_CANON_SIMPLE;
            body_canon = ARC_CANON_SIMPLE;
        }

        status = arc_add_canon(msg, ARC_CANONTYPE_HEADER, hdr_canon, hashtype,
                               htag, h, (ssize_t) -1, &msg->arc_hdrcanons[n]);

        if (status != ARC_STAT_OK)
        {
            arc_error(msg,
                      "failed to initialize header canonicalization object");
            return status;
        }

        /* body, validation */
        status = arc_add_canon(msg, ARC_CANONTYPE_BODY, body_canon, hashtype,
                               NULL, NULL, (ssize_t) -1,
                               &msg->arc_bodycanons[n]);

        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "failed to initialize body canonicalization object");
            return status;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_EOH_SIGN -- signing side of the end-of-header handler
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_eoh_sign(ARC_MESSAGE *msg)
{
    ARC_STAT status;

    /* headers, signing */
    status = arc_add_canon(msg, ARC_CANONTYPE_AMS, msg->arc_canonhdr,
                           msg->arc_signalg, NULL, NULL, (ssize_t) -1,
                           &msg->arc_sign_hdrcanon);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "failed to initialize header canonicalization object");
        return status;
    }

    /* all sets, for the next chain, signing */
    status = arc_add_canon(msg, ARC_CANONTYPE_SEAL, ARC_CANON_RELAXED,
                           msg->arc_signalg, NULL, NULL, (ssize_t) -1,
                           &msg->arc_sealcanon);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "failed to initialize seal canonicalization object");
        return status;
    }

    /* body, signing */
    status = arc_add_canon(msg, ARC_CANONTYPE_BODY, msg->arc_canonbody,
                           msg->arc_signalg, NULL, NULL, (ssize_t) -1,
                           &msg->arc_sign_bodycanon);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "failed to initialize body canonicalization object");
        return status;
    }

    return ARC_STAT_OK;
}

/*
**  ARC_EOH -- declare no more header fields are coming
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_eoh(ARC_MESSAGE *msg)
{
    bool                 keep;
    unsigned int         c;
    unsigned int         n;
    unsigned int         nsets = 0;
    arc_kvsettype_t      type;
    ARC_STAT             status;
    char                *inst;
    char                *p;
    struct arc_hdrfield *h;
    ARC_KVSET           *set;

    assert(msg != NULL);

    if (msg->arc_state >= ARC_STATE_EOH)
    {
        return ARC_STAT_INVALID;
    }
    msg->arc_state = ARC_STATE_EOH;

    /*
    **  Process all the header fields that make up ARC sets.
    */

    for (h = msg->arc_hhead; h != NULL; h = h->hdr_next)
    {
        char hnbuf[ARC_MAXHDRNAMELEN + 1];
        assert(h->hdr_namelen <= ARC_MAXHDRNAMELEN);

        memset(hnbuf, '\0', sizeof hnbuf);
        strncpy(hnbuf, h->hdr_text, h->hdr_namelen);
        if (strcasecmp(hnbuf, ARC_AR_HDRNAME) == 0 ||
            strcasecmp(hnbuf, ARC_MSGSIG_HDRNAME) == 0 ||
            strcasecmp(hnbuf, ARC_SEAL_HDRNAME) == 0)
        {
            arc_kvsettype_t kvtype;

            kvtype = arc_name_to_code(archdrnames, hnbuf);
            status = arc_process_set(
                msg, kvtype, h->hdr_text + h->hdr_namelen + 1,
                h->hdr_textlen - h->hdr_namelen - 1, h, &set);
            if (status != ARC_STAT_OK)
            {
                msg->arc_cstate = ARC_CHAIN_FAIL;
            }
            h->hdr_data = set;
        }
    }

    /*
    **  Ensure all sets are complete.
    */

    /* find the highest instance number we've got */
    for (set = arc_set_first(msg, ARC_KVSETTYPE_ANY); set != NULL;
         set = arc_set_next(set, ARC_KVSETTYPE_ANY))
    {
        inst = arc_param_get(set, "i");
        if (inst != NULL)
        {
            n = strtoul(inst, NULL, 10);
            nsets = MAX(n, nsets);
        }
    }

    msg->arc_nsets = nsets;

    if (nsets > 50)
    {
        /* RFC 8617 5.2 Validator Actions
         * The maximum number of ARC Sets that can be attached to a
         * message is 50. If more than the maximum number exist, the
         * Chain Validation Status is "fail", and the algorithm stops
         * here.
         */
        arc_error(msg, "Too many ARC sets: %u", nsets);
        msg->arc_cstate = ARC_CHAIN_FAIL;
        msg->arc_infail = true;
        return ARC_STAT_SYNTAX;
    }

    /* build up the array of ARC sets, for use later */
    if (nsets > 0)
    {
        msg->arc_sets = ARC_CALLOC(nsets, sizeof(struct arc_set));
        if (msg->arc_sets == NULL)
        {
            return ARC_STAT_NORESOURCE;
        }
    }

    for (set = arc_set_first(msg, ARC_KVSETTYPE_ANY); set != NULL;
         set = arc_set_next(set, ARC_KVSETTYPE_ANY))
    {
        type = arc_set_type(set);

        /* if i= is missing or bogus, just skip it */
        inst = arc_param_get(set, "i");
        if (inst == NULL || !arc_check_uint(inst))
        {
            continue;
        }
        n = strtoul(inst, &p, 10);

        switch (type)
        {
        case ARC_KVSETTYPE_AR:
            if (msg->arc_sets[n - 1].arcset_aar != NULL)
            {
                arc_error(msg, "multiple ARC auth results at instance %u", n);
                msg->arc_cstate = ARC_CHAIN_FAIL;
                break;
            }

            msg->arc_sets[n - 1].arcset_aar = arc_set_udata(set);
            break;

        case ARC_KVSETTYPE_SIGNATURE:
            if (msg->arc_sets[n - 1].arcset_ams != NULL)
            {
                arc_error(msg, "multiple ARC signatures at instance %u", n);
                msg->arc_cstate = ARC_CHAIN_FAIL;
                break;
            }

            msg->arc_sets[n - 1].arcset_ams = arc_set_udata(set);
            break;

        case ARC_KVSETTYPE_SEAL:
            if (msg->arc_sets[n - 1].arcset_as != NULL)
            {
                arc_error(msg, "multiple ARC seals at instance %u", n);
                msg->arc_cstate = ARC_CHAIN_FAIL;
                break;
            }

            msg->arc_sets[n - 1].arcset_as = arc_set_udata(set);
            break;
        }
    }

    /* look for invalid stuff */
    for (c = 0; c < nsets; c++)
    {
        if (msg->arc_sets[c].arcset_aar == NULL ||
            msg->arc_sets[c].arcset_ams == NULL ||
            msg->arc_sets[c].arcset_as == NULL)
        {
            arc_error(msg, "missing or incomplete ARC set at instance %u", c);
            msg->arc_cstate = ARC_CHAIN_FAIL;
            break;
        }
    }

    /*
    **  Always call arc_eoh_verify() because the hashes it sets up are
    **  needed in either mode.
    */

    status = arc_eoh_verify(msg);
    if (status != ARC_STAT_OK)
    {
        return status;
    }

    /* only call the signing side stuff when we're going to make a seal */
    if ((msg->arc_mode & ARC_MODE_SIGN) != 0)
    {
        status = arc_eoh_sign(msg);
        if (status != ARC_STAT_OK)
        {
            return status;
        }
    }

    /* initialize the canonicalizations */
    keep = ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_KEEPFILES) != 0);
    status = arc_canon_init(msg, keep, keep);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_init() failed");
        return ARC_STAT_SYNTAX;
    }

    /* process everything */
    status = arc_canon_runheaders(msg);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_runheaders() failed");
        return ARC_STAT_SYNTAX;
    }

    /* need to verify previous sets even if running in sign mode */
    if (msg->arc_cstate != ARC_CHAIN_FAIL)
    {
        status = arc_canon_runheaders_seal(msg);
        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "arc_canon_runheaders_seal() failed");
            return ARC_STAT_SYNTAX;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_BODY -- process a body chunk
**
**  Parameters:
**  	msg -- an ARC message handle
**  	buf -- the body chunk to be processed, in canonical format
**  	len -- number of bytes to process starting at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_body(ARC_MESSAGE *msg, const unsigned char *buf, size_t len)
{
    assert(msg != NULL);
    assert(buf != NULL);

    if (msg->arc_state > ARC_STATE_BODY || msg->arc_state < ARC_STATE_EOH)
    {
        return ARC_STAT_INVALID;
    }
    msg->arc_state = ARC_STATE_BODY;

    return arc_canon_bodychunk(msg, (const char *) buf, len);
}

/*
**  ARC_EOM -- declare end of message
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_eom(ARC_MESSAGE *msg)
{
    ARC_STAT status;

    /* nothing to do if the chain has been expressly failed */
    if (msg->arc_cstate == ARC_CHAIN_FAIL)
    {
        return ARC_STAT_OK;
    }

    /*
    **  Verify the existing chain, if any.
    */

    if (msg->arc_nsets == 0)
    {
        msg->arc_cstate = ARC_CHAIN_NONE;
        return ARC_STAT_OK;
    }

    /* validate the final ARC-Message-Signature */
    status = arc_validate_msg(msg, msg->arc_nsets);
    if (status == ARC_STAT_INTERNAL)
    {
        return status;
    }
    if (status != ARC_STAT_OK)
    {
        msg->arc_cstate = ARC_CHAIN_FAIL;
        return ARC_STAT_OK;
    }

    /* determine the oldest-pass value */
    for (int i = msg->arc_nsets - 1; i > 0; i--)
    {
        if (arc_validate_msg(msg, i) != ARC_STAT_OK)
        {
            msg->arc_oldest_pass = i + 1;
            break;
        }
        if (i == 1)
        {
            /* everything passed */
            msg->arc_oldest_pass = 0;
        }
    }

    /* validate each ARC-Seal */
    msg->arc_cstate = ARC_CHAIN_PASS;
    for (int i = msg->arc_nsets; i > 0; i--)
    {
        char      *cv;
        ARC_KVSET *kvset;

        for (kvset = arc_set_first(msg, ARC_KVSETTYPE_SEAL); kvset != NULL;
             kvset = arc_set_next(kvset, ARC_KVSETTYPE_SEAL))
        {
            if (atoi(arc_param_get(kvset, "i")) == i)
            {
                break;
            }
        }

        cv = arc_param_get(kvset, "cv");
        if (!((i == 1 && strcasecmp(cv, "none") == 0) ||
              (i != 1 && strcasecmp(cv, "pass") == 0)))
        {
            /* the chain has already failed */
            msg->arc_cstate = ARC_CHAIN_FAIL;
            msg->arc_infail = true;
            return ARC_STAT_OK;
        }

        status = arc_validate_seal(msg, i);
        if (status == ARC_STAT_INTERNAL)
        {
            return status;
        }
        if (status != ARC_STAT_OK)
        {
            msg->arc_cstate = ARC_CHAIN_FAIL;
            return ARC_STAT_OK;
        }
    }

    return ARC_STAT_OK;
}

/*
**  ARC_SET_CV -- force the chain state
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	cv -- chain state
**
**  Return value:
**  	None.
*/

void
arc_set_cv(ARC_MESSAGE *msg, ARC_CHAIN cv)
{
    assert(msg != NULL);
    assert(cv == ARC_CHAIN_UNKNOWN || cv == ARC_CHAIN_NONE ||
           cv == ARC_CHAIN_FAIL || cv == ARC_CHAIN_PASS);

    /* none is only valid if there is no existing chain */
    if ((cv == ARC_CHAIN_NONE) && (msg->arc_nsets != 0))
    {
        cv = ARC_CHAIN_PASS;
    }

    /* only update the state if it's not a hard failure */
    if (!msg->arc_infail)
    {
        if (msg->arc_cstate != cv)
        {
            /* there's no way of knowing. */
            msg->arc_oldest_pass = -1;
        }
        msg->arc_cstate = cv;
    }
}

/*
**  ARC_GETSEAL -- get the "seal" to apply to this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	seal -- seal to apply (returned)
**      authservid -- authservid to use when generating the seal
**      selector -- selector name
**      domain -- domain name
**      key -- secret key, printable
**      keylen -- key length
**  	ar -- Authentication-Results to be enshrined
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_getseal(ARC_MESSAGE         *msg,
            ARC_HDRFIELD       **seal,
            const char          *authservid,
            const char          *selector,
            const char          *domain,
            const unsigned char *key,
            size_t               keylen,
            const char          *ar)
{
    int                 rstatus;
    size_t              siglen;
    ARC_STAT            status = ARC_STAT_INTERNAL;
    size_t              diglen;
    size_t              len;
    size_t              b64siglen;
    char               *sighdr = NULL;
    unsigned char      *digest = NULL;
    unsigned char      *sigout = NULL;
    unsigned char      *b64sig = NULL;
    ARC_HDRFIELD       *h;
    ARC_HDRFIELD        hdr;
    struct arc_dstring *dstr = NULL;
    BIO                *keydata = NULL;
    EVP_PKEY           *pkey = NULL;
    EVP_PKEY_CTX       *ctx = NULL;

    assert(msg != NULL);
    assert(seal != NULL);
    assert(authservid != NULL);
    assert(selector != NULL);
    assert(domain != NULL);
    assert(key != NULL);
    assert(keylen > 0);

    /* if the chain arrived already failed, don't add anything */
    if (msg->arc_infail)
    {
        *seal = NULL;
        return ARC_STAT_OK;
    }

    /* If there are already 50 sets we can't add anything */
    if (msg->arc_nsets >= 50)
    {
        *seal = NULL;
        return ARC_STAT_OK;
    }

    /* RFC 8617 5.1.2 Marking and Sealing "cv=fail" (Invalid) Chains
     *
     *    In the case of a failed Authenticated Received Chain, the
     *    header fields included in the signature scope of the AS header
     *    field b= value MUST only include the ARC Set header fields
     *    created by the MTA that detected the malformed chain, as if
     *    this newest ARC Set was the only set present.
     */
    if (msg->arc_cstate == ARC_CHAIN_FAIL)
    {
        status = arc_add_canon(msg, ARC_CANONTYPE_SEAL, ARC_CANON_RELAXED,
                               msg->arc_signalg, NULL, NULL, (ssize_t) -1,
                               &msg->arc_sealcanon);
        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "failed to initialize seal canonicalization object");
            return status;
        }
        bool keep = ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_KEEPFILES) !=
                     0);
        status = arc_canon_init(msg, keep, keep);
        if (status != ARC_STAT_OK)
        {
            arc_error(msg, "arc_canon_init() failed");
            return status;
        }
    }

    /* copy required stuff */
    msg->arc_domain = domain;
    msg->arc_selector = selector;
    msg->arc_authservid = authservid;

    /* load the key */
    keydata = BIO_new_mem_buf(key, keylen);
    if (keydata == NULL)
    {
        arc_error(msg, "BIO_new_mem_buf() failed");
        status = ARC_STAT_NORESOURCE;
        goto error;
    }

    if (strncmp((const char *) key, "-----", 5) == 0)
    {
        pkey = PEM_read_bio_PrivateKey(keydata, NULL, NULL, NULL);
        if (pkey == NULL)
        {
            arc_error(msg, "PEM_read_bio_PrivateKey() failed");
            status = ARC_STAT_NORESOURCE;
            goto error;
        }
    }
    else
    {
        pkey = d2i_PrivateKey_bio(keydata, NULL);
        if (pkey == NULL)
        {
            arc_error(msg, "d2i_PrivateKey_bio() failed");
            status = ARC_STAT_NORESOURCE;
            goto error;
        }
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        arc_error(msg, "EVP_PKEY_CTX_new() failed");
        status = ARC_STAT_NORESOURCE;
        goto error;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        arc_error(msg, "EVP_PKEY_sign_init() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        arc_error(msg, "EVP_PKEY_CTX_set_rsa_padding() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    {
        arc_error(msg, "EVP_PKEY_CTX_set_signature_md() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    dstr = arc_dstring_new(ARC_MAXHEADER, 0, msg, &arc_error_cb);

    /*
    **  Generate a new signature and store it.
    */

    /* purge any previous seal */
    if (msg->arc_sealhead != NULL)
    {
        ARC_HDRFIELD *tmphdr;
        ARC_HDRFIELD *next;

        tmphdr = msg->arc_sealhead;
        while (tmphdr != NULL)
        {
            next = tmphdr->hdr_next;
            ARC_FREE(tmphdr->hdr_text);
            ARC_FREE(tmphdr);
            tmphdr = next;
        }

        msg->arc_sealhead = NULL;
        msg->arc_sealtail = NULL;
    }

    /*
    **  Part 1: Construct a new AAR
    */

    arc_dstring_printf(dstr, "ARC-Authentication-Results: i=%u; %s",
                       msg->arc_nsets + 1, msg->arc_authservid);
    if (ar == NULL)
    {
        /* no-result per RFC 8601 2.2 */
        arc_dstring_printf(dstr, "; none");
    }
    else
    {
        arc_dstring_printf(dstr, "; %s", ar);
    }

    status = arc_parse_header_field(msg, arc_dstring_get(dstr),
                                    arc_dstring_len(dstr), &h);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_parse_header_field() failed");
        goto error;
    }

    msg->arc_sealhead = h;
    msg->arc_sealtail = h;

    /*
    **  Part B: Construct a new AMS (basically a no-frills DKIM signature)
    */

    /* finalize body canonicalizations */
    status = arc_canon_closebody(msg);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_closebody() failed");
        goto error;
    }

    /* construct the AMS */
    arc_dstring_blank(dstr);
    arc_dstring_cat(dstr, ARC_MSGSIG_HDRNAME ": ");

    status = arc_getamshdr_d(msg, arc_dstring_len(dstr), &sighdr, &len, false);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_getamshdr_d() failed");
        goto error;
    }

    arc_dstring_catn(dstr, sighdr, len);
    len = arc_dstring_len(dstr);

    hdr.hdr_text = arc_dstring_get(dstr);
    hdr.hdr_namelen = ARC_MSGSIG_HDRNAMELEN;
    hdr.hdr_textlen = len;
    hdr.hdr_flags = 0;
    hdr.hdr_next = NULL;

    /* canonicalize */
    status = arc_canon_signature(msg, &hdr, ARC_CANONTYPE_AMS);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_signature() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    status = arc_canon_getfinal(msg->arc_sign_hdrcanon, &digest, &diglen);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_getfinal() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* encrypt the digest; that's our signature */
    rstatus = EVP_PKEY_sign(ctx, NULL, &siglen, digest, diglen);
    if (rstatus >= 0)
    {
        sigout = ARC_MALLOC(siglen);
        if (sigout == NULL)
        {
            arc_error(msg, "can't allocate %d bytes for signature", siglen);
            status = ARC_STAT_NORESOURCE;
            goto error;
        }
        rstatus = EVP_PKEY_sign(ctx, sigout, &siglen, digest, diglen);
    }

    if (rstatus != 1 || siglen == 0)
    {
        arc_error(msg, "EVP_PKEY_sign() failed (status %d, length %d)", rstatus,
                  siglen);
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* base64 encode it */
    b64siglen = siglen * 3 + 5;
    b64siglen += (b64siglen / 60);
    b64sig = ARC_CALLOC(1, b64siglen);
    if (b64sig == NULL)
    {
        arc_error(msg, "can't allocate %d bytes for base64 signature",
                  b64siglen);
        status = ARC_STAT_NORESOURCE;
        goto error;
    }

    rstatus = arc_base64_encode(sigout, siglen, b64sig, b64siglen);
    if (rstatus == -1)
    {
        arc_error(msg, "signature base64 encoding failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* append it to the stub */
    arc_dstring_cat(dstr, (char *) b64sig);

    /* XXX -- wrapping needs to happen here */

    /* add it to the seal */
    h = ARC_MALLOC(sizeof hdr);
    if (h == NULL)
    {
        arc_error(msg, "can't allocate %d bytes", sizeof hdr);
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* This header is generated with \r\n so that simple canonicalization
     * will work, but the established interface is that the library returns
     * just \n.
     */
    arc_dstring_strip(dstr, "\r");
    h->hdr_text = ARC_STRDUP(arc_dstring_get(dstr));
    if (h->hdr_text == NULL)
    {
        arc_error(msg, "can't allocate %d bytes", arc_dstring_len(dstr));
        status = ARC_STAT_INTERNAL;
        ARC_FREE(h);
        goto error;
    }
    h->hdr_namelen = ARC_MSGSIG_HDRNAMELEN;
    h->hdr_textlen = arc_dstring_len(dstr);
    h->hdr_flags = 0;
    h->hdr_next = NULL;

    msg->arc_sealtail->hdr_next = h;
    msg->arc_sealtail = h;

    /*
    **  Part III: Construct a new AS
    */

    arc_dstring_blank(dstr);
    arc_dstring_cat(dstr, ARC_SEAL_HDRNAME ": ");

    /* feed the seal we have so far */
    status = arc_canon_add_to_seal(msg);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_add_to_seal() failed");
        goto error;
    }

    status = arc_getamshdr_d(msg, arc_dstring_len(dstr), &sighdr, &len, true);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_getamshdr_d() failed");
        goto error;
    }

    arc_dstring_catn(dstr, sighdr, len);

    hdr.hdr_text = arc_dstring_get(dstr);
    hdr.hdr_namelen = ARC_SEAL_HDRNAMELEN;
    hdr.hdr_textlen = len;
    hdr.hdr_flags = 0;
    hdr.hdr_next = NULL;

    /* canonicalize */
    status = arc_canon_signature(msg, &hdr, ARC_CANONTYPE_SEAL);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_signature() failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    status = arc_canon_getfinal(msg->arc_sealcanon, &digest, &diglen);
    if (status != ARC_STAT_OK)
    {
        arc_error(msg, "arc_canon_getseal() failed");
        goto error;
    }

    /* encrypt the digest; that's our signature */
    rstatus = EVP_PKEY_sign(ctx, sigout, &siglen, digest, diglen);
    if (rstatus != 1 || siglen == 0)
    {
        arc_error(msg, "EVP_PKEY_sign() failed (status %d, length %d)", rstatus,
                  siglen);
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* base64 encode it */
    memset(b64sig, '\0', b64siglen);
    rstatus = arc_base64_encode(sigout, siglen, b64sig, b64siglen);
    if (rstatus == -1)
    {
        arc_error(msg, "signature base64 encoding failed");
        status = ARC_STAT_INTERNAL;
        goto error;
    }

    /* append it to the stub */
    arc_dstring_cat(dstr, (char *) b64sig);

    /* XXX -- wrapping needs to happen here */

    /* add it to the seal */
    h = ARC_MALLOC(sizeof hdr);
    if (h == NULL)
    {
        arc_error(msg, "can't allocate %d bytes", sizeof hdr);
        status = ARC_STAT_INTERNAL;
        goto error;
    }
    arc_dstring_strip(dstr, "\r");
    h->hdr_text = ARC_STRDUP(arc_dstring_get(dstr));
    if (h->hdr_text == NULL)
    {
        arc_error(msg, "can't allocate %d bytes", sizeof hdr);
        ARC_FREE(h);
        status = ARC_STAT_INTERNAL;
        goto error;
    }
    h->hdr_namelen = ARC_SEAL_HDRNAMELEN;
    h->hdr_textlen = len;
    h->hdr_flags = 0;
    h->hdr_next = NULL;

    msg->arc_sealtail->hdr_next = h;
    msg->arc_sealtail = h;

    *seal = msg->arc_sealhead;

    status = ARC_STAT_OK;

error:
    /* tidy up */
    arc_dstring_free(dstr);
    ARC_FREE(b64sig);
    ARC_FREE(sigout);
    EVP_PKEY_free(pkey);
    BIO_free(keydata);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

/*
**  ARC_HDR_NAME -- extract name from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field name stored in the object.
*/

char *
arc_hdr_name(ARC_HDRFIELD *hdr, size_t *len)
{
    if (len != NULL)
    {
        *len = hdr->hdr_namelen;
    }
    return hdr->hdr_text;
}

/*
**  ARC_HDR_VALUE -- extract value from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field value stored in the object.
*/

char *
arc_hdr_value(ARC_HDRFIELD *hdr)
{
    return hdr->hdr_text + hdr->hdr_namelen + 1;
}

/*
**  ARC_HDR_NEXT -- return pointer to next ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Pointer to the next ARC_HDRFIELD in the sequence.
*/

ARC_HDRFIELD *
arc_hdr_next(ARC_HDRFIELD *hdr)
{
    return hdr->hdr_next;
}

/*
**  ARC_SSL_VERSION -- report the version of the crypto library against which
**  	the library was compiled, so the caller can ensure it matches
**
**  Parameters:
**  	None.
**
**  Return value:
**  	SSL library version, expressed as a uint64_t.
*/

uint64_t
arc_ssl_version(void)
{
    return OPENSSL_VERSION_NUMBER;
}

/*
**  ARC_LIBFEATURE -- determine whether or not a particular library feature
**                    is actually available
**
**  Parameters:
**  	lib -- library handle
**  	fc -- feature code to check
**
**  Return value:
**  	true iff the specified feature was compiled in
*/

bool
arc_libfeature(ARC_LIB *lib, unsigned int fc)
{
    unsigned int idx;
    unsigned int offset;

    idx = fc / (8 * sizeof(int));
    offset = fc % (8 * sizeof(int));

    if (idx > lib->arcl_flsize)
    {
        return false;
    }
    return ((lib->arcl_flist[idx] & (1 << offset)) != 0);
}

/*
**  ARC_GET_DOMAIN -- retrieve stored domain for this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**
**  Return value:
**  	Pointer to string containing the domain stored for this message
*/

const char *
arc_get_domain(ARC_MESSAGE *msg)
{
    return msg->arc_domain;
}

/*
**  ARC_CHAIN_STATUS -- retrieve chain status as an int
*/

ARC_CHAIN
arc_chain_status(ARC_MESSAGE *msg)
{
    return msg->arc_cstate;
}

/*
**  ARC_CHAIN_STATUS_STR -- retrieve chain status, as a string
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      Pointer to string containing the current chain status.
*/

const char *
arc_chain_status_str(ARC_MESSAGE *msg)
{
    return arc_code_to_name(chainstatus, msg->arc_cstate);
}

/*
**  ARC_CHAIN_CUSTODY_STR -- retrieve domain chain, as a string
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**      buf -- where to write
**      buflen -- bytes at "buf"
**
**  Return value:
**  	Number of bytes written. If value is greater than or equal to buflen
**  	argument, then buffer was too small and output was truncated.
*/

int
arc_chain_custody_str(ARC_MESSAGE *msg, char *buf, size_t buflen)
{
    int                 set;
    ARC_KVSET          *kvset;
    char               *str = NULL;
    struct arc_dstring *tmpbuf;
    int                 appendlen = 0;

    assert(msg != NULL);
    assert(buf != NULL);
    assert(buflen > 0);

    if (msg->arc_cstate != ARC_CHAIN_PASS)
    {
        return 0;
    }

    tmpbuf = arc_dstring_new(BUFRSZ, MAXBUFRSZ, msg, &arc_error_cb);
    if (tmpbuf == NULL)
    {
        arc_error(msg, "failed to allocate dynamic string");
        return ARC_STAT_NORESOURCE;
    }

    memset(buf, '\0', buflen);

    for (set = msg->arc_nsets - 1; set >= 0; set--)
    {
        kvset = msg->arc_sets[set].arcset_ams->hdr_data;
        str = arc_param_get(kvset, "d");
        (void) arc_dstring_printf(tmpbuf, "%s%s",
                                  (set < msg->arc_nsets - 1 ? ":" : ""), str);
    }

    appendlen = snprintf(buf, buflen, "%s", arc_dstring_get(tmpbuf));
    arc_dstring_free(tmpbuf);

    return appendlen;
}

/*
**  ARC_CHAIN_OLDEST_PASS -- retrieve the oldest-pass value
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      The lowest instance value where the AMS signature passed verification,
**      `0` if all signatures passed, or `-1` for unknown.
*/

int
arc_chain_oldest_pass(ARC_MESSAGE *msg)
{
    if (msg->arc_cstate == ARC_CHAIN_PASS)
    {
        return msg->arc_oldest_pass;
    }
    return -1;
}
