/*
**  Copyright (c) 2006-2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, 2015, The Trusted Domain Project.  All rights
*reserved.
**
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "build-config.h"

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

/* types and things */
#define CONFIG_TYPE_STRING     0
#define CONFIG_TYPE_INTEGER    1
#define CONFIG_TYPE_BOOLEAN    2
#define CONFIG_TYPE_INCLUDE    3
#define CONFIG_TYPE_DEPRECATED 4

struct config
{
    bool           cfg_bool;
    unsigned int   cfg_type;
    int            cfg_int;
    char          *cfg_name;
    char          *cfg_string;
    struct config *cfg_next;
};

struct configdef
{
    char        *cd_name;
    unsigned int cd_type;
    bool         cd_req;
};

/* prototypes */
extern char          *config_check(struct config *, struct configdef *);
extern unsigned int   config_dump(struct config *, FILE *, const char *);
extern char          *config_error(void);
extern void           config_free(struct config *);
extern int            config_get(struct config *, const char *, void *, size_t);
extern struct config *config_load(
    char *, struct configdef *, unsigned int *, char *, size_t, char **);
extern bool config_validname(struct configdef *, const char *);

#endif /* _CONFIG_H_ */
