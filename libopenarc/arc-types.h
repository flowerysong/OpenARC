/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef ARC_ARC_TYPES_H_
#define ARC_ARC_TYPES_H_

#include "build-config.h"

/* system includes */
#include <regex.h>
#include <stdbool.h>
#include <sys/types.h>

/* OpenSSL includes */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc.h"

/* struct arc_hash -- stuff needed to do a hash */
struct arc_hash
{
    int           hash_tmpfd;
    BIO          *hash_tmpbio;
    EVP_MD_CTX   *hash_ctx;
    unsigned char hash_out[EVP_MAX_MD_SIZE];
    unsigned int  hash_outlen;
};

/* struct arc_qmethod -- signature query method */
struct arc_qmethod
{
    char               *qm_type;
    char               *qm_options;
    struct arc_qmethod *qm_next;
};

/* struct arc_xtag -- signature extension tag */
struct arc_xtag
{
    char            *xt_tag;
    char            *xt_value;
    struct arc_xtag *xt_next;
};

/* struct arc_hdrfield -- a header field */
struct arc_hdrfield
{
    uint32_t             hdr_flags;
    size_t               hdr_namelen;
    size_t               hdr_textlen;
    char                *hdr_text;
    void                *hdr_data;
    struct arc_hdrfield *hdr_next;
};

/* hdr_flags bits */
#define ARC_HDR_SIGNED 0x01

/* struct arc_set -- a complete single set of ARC header fields */
struct arc_set
{
    struct arc_hdrfield *arcset_aar;
    struct arc_hdrfield *arcset_ams;
    struct arc_hdrfield *arcset_as;
};

/* struct arc_plist -- a parameter/value pair */
struct arc_plist
{
    char             *plist_param;
    char             *plist_value;
    struct arc_plist *plist_next;
};

/* struct arc_kvset -- a set of parameter/value pairs */
struct arc_kvset
{
    bool              set_bad;
    arc_kvsettype_t   set_type;
    char             *set_data;
    void             *set_udata;
    struct arc_plist *set_plist[NPRINTABLE];
    struct arc_kvset *set_next;
};

/* struct arc_canon -- a canonicalization status handle */
struct arc_canon
{
    bool                 canon_done;
    bool                 canon_blankline;
    int                  canon_type;
    int                  canon_lastchar;
    int                  canon_bodystate;
    unsigned int         canon_hashtype;
    unsigned int         canon_blanks;
    size_t               canon_hashbuflen;
    size_t               canon_hashbufsize;
    ssize_t              canon_remain;
    ssize_t              canon_wrote;
    ssize_t              canon_length;
    arc_canon_t          canon_canon;
    char                *canon_hashbuf;
    const char          *canon_hdrlist;
    struct arc_hash     *canon_hash;
    struct arc_dstring  *canon_buf;
    struct arc_hdrfield *canon_sigheader;
    struct arc_canon    *canon_next;
};

/* struct arc_msghandle -- a complete ARC transaction context */
struct arc_msghandle
{
    bool                 arc_partial;
    bool                 arc_infail;
    int                  arc_dnssec_key;
    int                  arc_signalg;
    int                  arc_oldest_pass;
    unsigned int         arc_mode;
    unsigned int         arc_nsets;
    unsigned int         arc_margin;
    unsigned int         arc_state;
    unsigned int         arc_hdrcnt;
    unsigned int         arc_timeout;
    unsigned int         arc_keybits;
    unsigned int         arc_keytype;
    unsigned int         arc_hashtype;
    unsigned long        arc_flags;
    arc_query_t          arc_query;
    time_t               arc_timestamp;
    time_t               arc_sigttl;
    size_t               arc_siglen;
    size_t               arc_keylen;
    size_t               arc_errorlen;
    size_t               arc_b64keylen;
    ssize_t              arc_bodylen;
    arc_canon_t          arc_canonhdr;
    arc_canon_t          arc_canonbody;
    ARC_CHAIN            arc_cstate;
    ARC_SIGERROR         arc_sigerror;
    unsigned char       *arc_key;
    char                *arc_error;
    char                *arc_hdrlist;
    const char          *arc_domain;
    const char          *arc_selector;
    const char          *arc_authservid;
    char                *arc_b64sig;
    char                *arc_b64key;
    void                *arc_signature;
    struct arc_qmethod  *arc_querymethods;
    struct arc_xtag     *arc_xtags;
    struct arc_dstring  *arc_canonbuf;
    struct arc_dstring  *arc_hdrbuf;
    struct arc_canon    *arc_sealcanon;
    struct arc_canon   **arc_sealcanons;
    struct arc_canon   **arc_hdrcanons;
    struct arc_canon   **arc_bodycanons;
    struct arc_canon    *arc_sign_hdrcanon;
    struct arc_canon    *arc_sign_bodycanon;
    struct arc_canon    *arc_canonhead;
    struct arc_canon    *arc_canontail;
    struct arc_hdrfield *arc_hhead;
    struct arc_hdrfield *arc_htail;
    struct arc_hdrfield *arc_sealhead;
    struct arc_hdrfield *arc_sealtail;
    struct arc_kvset    *arc_kvsethead;
    struct arc_kvset    *arc_kvsettail;
    struct arc_set      *arc_sets;
    ARC_LIB             *arc_library;
    const void          *arc_user_context;
};

/* struct arc_lib -- a ARC library context */
struct arc_lib
{
    bool                arcl_signre;
    bool                arcl_dnsinit_done;
    unsigned int        arcl_flsize;
    uint32_t            arcl_flags;
    time_t              arcl_fixedtime;
    unsigned int        arcl_callback_int;
    unsigned int        arcl_minkeysize;
    unsigned int       *arcl_flist;
    struct arc_dstring *arcl_sslerrbuf;
    char              **arcl_oversignhdrs;
    void (*arcl_dns_callback)(const void *context);
    void *arcl_dns_service;
    int (*arcl_dns_init)(void **srv);
    void (*arcl_dns_close)(void *srv);
    int (*arcl_dns_start)(void                *srv,
                          int                  type,
                          const unsigned char *query,
                          unsigned char       *buf,
                          size_t               buflen,
                          void               **qh);
    int (*arcl_dns_cancel)(void *srv, void *qh);
    int (*arcl_dns_waitreply)(void           *srv,
                              void           *qh,
                              struct timeval *to,
                              size_t         *bytes,
                              int            *error,
                              int            *dnssec);
    regex_t arcl_hdrre;
    char    arcl_tmpdir[MAXPATHLEN - 11];
    char    arcl_queryinfo[MAXPATHLEN + 1];
};

#endif /* ARC_ARC_TYPES_H_ */
