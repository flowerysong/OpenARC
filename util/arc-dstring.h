/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef ARC_DSTRING_H_
#define ARC_DSTRING_H_

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <sys/param.h>
#include <sys/types.h>

/* struct arc_dstring -- a dynamically-sized string */
struct arc_dstring
{
    int ds_alloc;
    int ds_max;
    int ds_len;
    char *ds_buf;
    void *ds_ctx;
    void (*ds_cb)(void *, const char *, ...);
};

extern void arc_dstring_blank(struct arc_dstring *);
extern bool arc_dstring_cat(struct arc_dstring *, const char *);
extern bool arc_dstring_cat1(struct arc_dstring *, int);
extern bool arc_dstring_catn(struct arc_dstring *, const char *, size_t);
extern bool arc_dstring_copy(struct arc_dstring *, const char *);
extern void arc_dstring_strip(struct arc_dstring *, const char *);
extern void arc_dstring_free(struct arc_dstring *);
extern char *arc_dstring_get(struct arc_dstring *);
extern int arc_dstring_len(struct arc_dstring *);
extern struct arc_dstring *arc_dstring_new(int, int, void *,
                                           void (*)(void *, const char *, ...));
extern size_t arc_dstring_printf(struct arc_dstring *dstr, char *fmt, ...);
extern void arc_clobber_array(char **);
extern void arc_collapse(char *);
extern char **arc_copy_array(char **);

#endif /* ARC_DSTRING_H_ */
