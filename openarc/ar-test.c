/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011-2014, 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <string.h>
#include <sysexits.h>

/* openarc includes */
#include "openarc-ar.h"

int
main(int argc, char **argv)
{
    int            c;
    int            d;
    int            status;
    char          *p;
    char          *progname;
    struct authres ar;
    char           buf[ARC_MAXHEADER + 2];
    char          *toks[1024];

    progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

    if (argc != 2)
    {
        printf("%s: usage: %s header-value\n", progname, progname);
        return EX_USAGE;
    }

    c = ares_tokenize(argv[1], buf, sizeof buf, toks, 1024);
    for (d = 0; d < c; d++)
    {
        printf("token %d = '%s'\n", d, toks[d]);
    }

    printf("\n");

    status = ares_parse(argv[1], &ar, NULL);
    if (status == -1)
    {
        printf("%s: ares_parse() returned -1\n", progname);
        return EX_OK;
    }

    printf("%d result%s found\n", ar.ares_count, ar.ares_count == 1 ? "" : "s");

    printf("authserv-id '%s'\n", ar.ares_host);
    printf("version '%s'\n", ar.ares_version);

    for (c = 0; c < ar.ares_count; c++)
    {
        printf("result #%d, %d propert%s\n", c, ar.ares_result[c].result_props,
               ar.ares_result[c].result_props == 1 ? "y" : "ies");

        printf("\tmethod \"%s\"\n",
               ares_getmethod(ar.ares_result[c].result_method));
        printf("\tresult \"%s\"\n",
               ares_getresult(ar.ares_result[c].result_result));
        printf("\treason \"%s\"\n", ar.ares_result[c].result_reason);

        for (d = 0; d < ar.ares_result[c].result_props; d++)
        {
            printf("\tproperty #%d\n", d);
            printf("\t\tptype \"%s\"\n",
                   ares_getptype(ar.ares_result[c].result_ptype[d]));
            printf("\t\tproperty \"%s\"\n",
                   ar.ares_result[c].result_property[d]);
            printf("\t\tvalue \"%s\"\n", ar.ares_result[c].result_value[d]);
        }
    }
}
