/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

/* system includes */
#include <netinet/in.h>
#include <regex.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

/* openarc includes */
#include "build-config.h"

/* PROTOTYPES */
extern const char **arcf_mkarray(char *);
extern size_t       arcf_inet_ntoa(struct in_addr, char *, size_t);
extern void         arcf_lowercase(unsigned char *);
extern void         arcf_optlist(FILE *);
extern void         arcf_setmaxfd(void);
extern int          arcf_socket_cleanup(char *);

#endif /* _UTIL_H_ */
