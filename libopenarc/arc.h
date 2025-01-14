/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef ARC_ARC_H_
#define ARC_ARC_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* system includes */
#include <inttypes.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */

/*
**  version -- 0xrrMMmmpp
**
**  	rr == release number
**  	MM == major revision number
**  	mm == minor revision number
**  	pp == patch number
*/

#define OPENARC_LIB_VERSION    0x00010000

/* definitions */
#define ARC_HDRMARGIN          78   /* standard email line length */
#define ARC_MAXHEADER          4096 /* buffer for caching one header */
#define ARC_MAXHOSTNAMELEN     256  /* max. FQDN we support */
#define ARC_MAXLINELEN         1000 /* physical line limit (RFC5321) */
#define ARC_MAXHDRNAMELEN      (ARC_MAXLINELEN - 3) /* deduct ":" CRLF */

#define ARC_AR_HDRNAME         "ARC-Authentication-Results"
#define ARC_DEFAULT_MINKEYSIZE 1024
#define ARC_MSGSIG_HDRNAME     "ARC-Message-Signature"
#define ARC_MSGSIG_HDRNAMELEN  sizeof(ARC_MSGSIG_HDRNAME) - 1
#define ARC_SEAL_HDRNAME       "ARC-Seal"
#define ARC_SEAL_HDRNAMELEN    sizeof(ARC_SEAL_HDRNAME) - 1

#define ARC_EXT_AR_HDRNAME     "Authentication-Results"

/* special DNS tokens */
#define ARC_DNSKEYNAME         "_domainkey"

#define DKIM_VERSION_KEY       "DKIM1"

/*
**  ARC_STAT -- status code type
*/

typedef int ARC_STAT;

#define ARC_STAT_OK            0  /* function completed successfully */
#define ARC_STAT_BADSIG        1  /* signature available but failed */
#define ARC_STAT_NOSIG         2  /* no signature available */
#define ARC_STAT_NOKEY         3  /* public key not found */
#define ARC_STAT_CANTVRFY      4  /* can't get domain key to verify */
#define ARC_STAT_SYNTAX        5  /* message is not valid syntax */
#define ARC_STAT_NORESOURCE    6  /* resource unavailable */
#define ARC_STAT_INTERNAL      7  /* internal error */
#define ARC_STAT_REVOKED       8  /* key found, but revoked */
#define ARC_STAT_INVALID       9  /* invalid function parameter */
#define ARC_STAT_NOTIMPLEMENT  10 /* function not implemented */
#define ARC_STAT_KEYFAIL       11 /* key retrieval failed */
#define ARC_STAT_MULTIDNSREPLY 12 /* multiple DNS replies */
#define ARC_STAT_SIGGEN        13 /* seal generation failed */
#define ARC_STAT_BADALG        14 /* unknown or invalid algorithm */

/*
**  ARC_CHAIN -- chain state
*/

typedef int ARC_CHAIN;

#define ARC_CHAIN_UNKNOWN (-1) /* unknown */
#define ARC_CHAIN_NONE    0    /* none */
#define ARC_CHAIN_FAIL    1    /* fail */
#define ARC_CHAIN_PASS    2    /* pass */

/*
** ARC_CANON_T -- a canoncalization mode
*/

typedef int arc_canon_t;

#define ARC_CANON_UNKNOWN (-1)
#define ARC_CANON_SIMPLE  0
#define ARC_CANON_RELAXED 1

/* generic DNS error codes */
#define ARC_DNS_ERROR     (-1) /* error in transit */
#define ARC_DNS_SUCCESS   0    /* reply available */
#define ARC_DNS_NOREPLY   1    /* reply not available (yet) */
#define ARC_DNS_EXPIRED   2    /* no reply, query expired */
#define ARC_DNS_INVALID   3    /* invalid request */

/*
**  ARC_SIGN -- signing method
*/

typedef int arc_alg_t;

#define ARC_SIGN_UNKNOWN   (-2) /* unknown method */
#define ARC_SIGN_DEFAULT   (-1) /* use internal default */
#define ARC_SIGN_RSASHA1   0    /* an RSA-signed SHA1 digest */
#define ARC_SIGN_RSASHA256 1    /* an RSA-signed SHA256 digest */

/*
**  ARC_QUERY -- key query method
*/

typedef int arc_query_t;

#define ARC_QUERY_UNKNOWN (-1) /* unknown method */
#define ARC_QUERY_DNS     0    /* DNS query method (per the draft) */
#define ARC_QUERY_FILE    1    /* text file method (for testing) */

#define ARC_QUERY_DEFAULT ARC_QUERY_DNS

/*
**  ARC_OPTS -- library-specific options
*/

typedef int arc_opt_t;

/* what operations can be done */
#define ARC_OP_GETOPT 0
#define ARC_OP_SETOPT 1

typedef int arc_opts_t;

/* what options can be set */
#define ARC_OPTS_FLAGS          0
#define ARC_OPTS_TMPDIR         1
#define ARC_OPTS_FIXEDTIME      2
#define ARC_OPTS_SIGNHDRS       3
#define ARC_OPTS_OVERSIGNHDRS   4
#define ARC_OPTS_MINKEYSIZE     5
#define ARC_OPTS_TESTKEYS       6
#define ARC_OPTS_SIGNATURE_TTL  7

/* flags */
#define ARC_LIBFLAGS_NONE       0x00000000
#define ARC_LIBFLAGS_FIXCRLF    0x00000001
#define ARC_LIBFLAGS_KEEPFILES  0x00000002

/* default */
#define ARC_LIBFLAGS_DEFAULT    ARC_LIBFLAGS_NONE

/*
**  ARC_DNSSEC -- results of DNSSEC queries
*/

#define ARC_DNSSEC_UNKNOWN      (-1)
#define ARC_DNSSEC_BOGUS        0
#define ARC_DNSSEC_INSECURE     1
#define ARC_DNSSEC_SECURE       2

/*
**  ARC_KEYFLAG -- key flags
*/

#define ARC_KEYFLAG_TESTKEY     0x01
#define ARC_KEYFLAG_NOSUBDOMAIN 0x02

/*
**  ARC_MODE -- operating modes
*/

typedef unsigned int arc_mode_t;

#define ARC_MODE_SIGN   0x01
#define ARC_MODE_VERIFY 0x02

/*
**  ARC_LIB -- library handle
*/

struct arc_lib;
typedef struct arc_lib ARC_LIB;

/* LIBRARY FEATURES */
#define ARC_FEATURE_SHA256 1

#define ARC_FEATURE_MAX    1

extern bool arc_libfeature(ARC_LIB *lib, unsigned int fc);

/*
**  ARC_MESSAGE -- ARC message context
*/

struct arc_msghandle;
typedef struct arc_msghandle ARC_MESSAGE;

/*
**  ARC_HDRFIELD -- a header field
*/

struct arc_hdrfield;
typedef struct arc_hdrfield ARC_HDRFIELD;

/*
**  PROTOTYPES
*/

/*
**  ARC_ERROR -- log an error message to an ARC message context
**
**  Parameters:
**  	msg -- ARC message context
**  	fmt -- format
**  	... -- arguments
**
**  Return value:
**  	None.
*/

extern void arc_error(ARC_MESSAGE *, const char *, ...);

/*
**  ARC_INIT -- create a library instance
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new library instance.
*/

extern ARC_LIB *arc_init(void);

/*
**  ARC_CLOSE -- terminate a library instance
**
**  Parameters:
**  	lib -- library instance to terminate
**
**  Return value:
**  	None.
*/

extern void arc_close(ARC_LIB *);

/*
**  ARC_GETERROR -- return any stored error string from within the DKIM
**                  context handle
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const char *arc_geterror(ARC_MESSAGE *);

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

extern ARC_STAT arc_options(ARC_LIB *, int, int, void *, size_t);

/*
**  ARC_SET_DNS -- override DNS resolver
*/

extern ARC_STAT arc_set_dns(
    ARC_LIB *,
    int (*)(void **),
    void (*)(const void *),
    int,
    void (*)(void *),
    int (*)(void *, int, const char *, unsigned char *, size_t, void **),
    int (*)(void *, void *),
    int (*)(void *, void *, struct timeval *, size_t *, int *, int *));

/*
**  ARC_GETSSLBUF -- retrieve SSL error buffer
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	Pointer to the SSL buffer in the library handle.
*/

extern const char *arc_getsslbuf(ARC_LIB *);

/*
**  ARC_MESSAGE -- create a new message handle
**
**  Parameters:
**  	lib -- containing library instance
**  	canonhdr -- canonicalization to use for the header
**  	canonbody -- canonicalization to use for the body
**  	signalg -- signing algorithm
**  	mode -- mask of mode bits
**  	err -- error string (returned)
**
**  Return value:
**  	A new message instance, or NULL on failure (and "err" is updated).
*/

extern ARC_MESSAGE *arc_message(
    ARC_LIB *, arc_canon_t, arc_canon_t, arc_alg_t, arc_mode_t, const char **);

/*
**  ARC_FREE -- deallocate a message object
**
**  Parameters:
**  	msg -- message object to be destroyed
**
**  Return value:
**  	None.
*/

extern void arc_free(ARC_MESSAGE *);

/*
**  ARC_HEADER_FIELD -- consume a header field
**
**  Parameters:
**  	msg -- message handle
**  	hname -- name of the header field
**  	hlen -- bytes to use at hname
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

extern ARC_STAT arc_header_field(ARC_MESSAGE *, const char *, size_t);

/*
**  ARC_EOH -- declare no more headers are coming
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	This can probably be merged with arc_eom().
*/

extern ARC_STAT arc_eoh(ARC_MESSAGE *);

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

extern ARC_STAT arc_body(ARC_MESSAGE *, const unsigned char *, size_t);

/*
**  ARC_EOM -- declare end of message
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

extern ARC_STAT arc_eom(ARC_MESSAGE *);

/*
**  ARC_SET_CV -- force the chain state
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**      cv -- chain state
**
**  Return value:
**  	None.
*/

extern void arc_set_cv(ARC_MESSAGE *, ARC_CHAIN);

/*
**  ARC_GETSEAL -- get the "seal" to apply to this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	seal -- seal to apply (returned)
**  	authservid -- authservid to use when generating A-R fields
**  	selector -- selector name
**  	domain -- domain name
**  	key -- secret key
**  	keylen -- key length
**  	ar -- Authentication-Results to be enshrined
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	The "seal" is a sequence of prepared header fields that should be
**  	prepended to the message in the presented order.
*/

extern ARC_STAT arc_getseal(ARC_MESSAGE *,
                            ARC_HDRFIELD **,
                            const char *,
                            const char *,
                            const char *,
                            const unsigned char *,
                            size_t,
                            const char *);

/*
**  ARC_HDR_NAME -- extract name from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
** 	len -- length of the header field name (returned)
**
**  Return value:
**  	Header field name stored in the object.
*/

extern char *arc_hdr_name(ARC_HDRFIELD *, size_t *);

/*
**  ARC_HDR_VALUE -- extract value from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field value stored in the object.
*/

extern char *arc_hdr_value(ARC_HDRFIELD *);

/*
**  ARC_HDR_NEXT -- return pointer to next ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Pointer to the next ARC_HDRFIELD in the sequence.
*/

extern ARC_HDRFIELD *arc_hdr_next(ARC_HDRFIELD *hdr);

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

extern uint64_t arc_ssl_version(void);

/*
**  ARC_GET_DOMAIN -- retrieve stored domain for this message
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      Pointer to string containing the domain stored for this message
*/

extern const char *arc_get_domain(ARC_MESSAGE *msg);

/*
**  ARC_CHAIN_STATUS -- retrieve chain status as an int
*/

extern ARC_CHAIN arc_chain_status(ARC_MESSAGE *msg);

/*
**  ARC_CHAIN_STATUS_STR -- retrieve chain status, as a string
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      Pointer to string containing the current chain status.
*/

extern const char *arc_chain_status_str(ARC_MESSAGE *msg);

/*
**  ARC_CHAIN_CUSTODY_STR -- retrieve domain chain, as a string
**
**  Parameters:
**	msg -- ARC_MESSAGE object
**	buf -- where to write
**	buflen -- bytes at "buf"
**
**  Return value:
**	Number of bytes written. If value is greater than or equal to buflen
**	argument, then buffer was too small and output was truncated.
*/

extern int arc_chain_custody_str(ARC_MESSAGE *, char *, size_t);

/*
**  ARC_CHAIN_OLDEST_PASS -- retrieve the oldest-pass value
*/

extern int arc_chain_oldest_pass(ARC_MESSAGE *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ARC_ARC_H_ */
