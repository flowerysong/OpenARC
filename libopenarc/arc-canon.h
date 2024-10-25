/*
**  Copyright (c) 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _ARC_CANON_H_
#define _ARC_CANON_H_

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <sys/types.h>

/* libopenarc includes */
#include "arc-types.h"
#include "arc.h"

#define ARC_HASHBUFSIZE      4096

#define ARC_CANONTYPE_HEADER 0
#define ARC_CANONTYPE_BODY   1
#define ARC_CANONTYPE_SEAL   2
#define ARC_CANONTYPE_AMS    3

/* prototypes */
extern ARC_STAT arc_add_canon(ARC_MESSAGE *,
                              int,
                              arc_canon_t,
                              int,
                              const char *,
                              struct arc_hdrfield *,
                              ssize_t length,
                              ARC_CANON **);
extern ARC_STAT arc_canon_add_to_seal(ARC_MESSAGE *);
extern ARC_STAT arc_canon_bodychunk(ARC_MESSAGE *, const char *, size_t);
extern void     arc_canon_cleanup(ARC_MESSAGE *);
extern ARC_STAT arc_canon_closebody(ARC_MESSAGE *);
extern ARC_STAT arc_canon_getfinal(ARC_CANON *, unsigned char **, size_t *);
extern ARC_STAT arc_canon_gethashes(
    ARC_MESSAGE *, int, void **, size_t *, void **, size_t *);
extern ARC_STAT arc_canon_getsealhash(ARC_MESSAGE *, int, void **, size_t *);
extern ARC_STAT arc_canon_header_string(
    struct arc_dstring *, arc_canon_t, const char *, size_t, bool);
extern ARC_STAT      arc_canon_init(ARC_MESSAGE *, bool, bool);
extern unsigned long arc_canon_minbody(ARC_MESSAGE *);
extern ARC_STAT      arc_canon_runheaders(ARC_MESSAGE *);
extern ARC_STAT      arc_canon_runheaders_seal(ARC_MESSAGE *);
extern int           arc_canon_selecthdrs(ARC_MESSAGE *,
                                          const char *,
                                          struct arc_hdrfield **,
                                          int);
extern ARC_STAT arc_canon_signature(ARC_MESSAGE *, struct arc_hdrfield *, int);

extern ARC_STAT arc_parse_canon_t(char *, arc_canon_t *, arc_canon_t *);

#endif /* ! _ARC_CANON_H_ */
