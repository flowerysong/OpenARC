/*
**  Copyright (c) 2010, 2012, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef ARC_ARC_DNS_H_
#define ARC_ARC_DNS_H_

/* libopenarc includes */
#include "arc.h"

/* prototypes */
extern int  arc_res_cancel(void *, void *);
extern void arc_res_close(void *);
extern int  arc_res_init(void **);
extern int  arc_res_query(
     void *, int, const char *, unsigned char *, size_t, void **);
extern int arc_res_waitreply(
    void *, void *, struct timeval *, size_t *, int *, int *);

#endif /* ! ARC_ARC_DNS_H_ */
