/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.
**  Copyright 2024 OpenARC contributors
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "arc-dstring.h"
#include "arc-malloc.h"

/*
**  ARC_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle
**  	len -- number of bytes desired
**
**  Return value:
**  	true iff the resize worked (or wasn't needed)
**
**  Notes:
**  	This will actually ensure that there are "len" bytes available.
**  	The caller must account for the NULL byte when requesting a
**  	specific size.
*/

static bool
arc_dstring_resize(struct arc_dstring *dstr, int len)
{
    int newsz;
    char *new;

    assert(dstr != NULL);
    assert(len > 0);

    if (dstr->ds_alloc >= len)
    {
        return true;
    }

    /* must resize */
    for (newsz = dstr->ds_alloc * 2; newsz < len; newsz *= 2)
    {
        /* impose ds_max limit, if specified */
        if (dstr->ds_max > 0 && newsz > dstr->ds_max)
        {
            if (len <= dstr->ds_max)
            {
                newsz = len;
                break;
            }

            if (dstr->ds_cb)
            {
                dstr->ds_cb(dstr->ds_ctx, "maximum string size exceeded");
            }

            return false;
        }

        /* check for overflow */
        if (newsz > INT_MAX / 2)
        {
            /* next iteration will overflow "newsz" */
            if (dstr->ds_cb)
            {
                dstr->ds_cb(dstr->ds_ctx, "internal string limit reached");
            }
            return false;
        }
    }

    new = ARC_MALLOC(newsz);
    if (new == NULL)
    {
        if (dstr->ds_cb)
        {
            dstr->ds_cb(dstr->ds_ctx, "unable to allocate %d bytes", newsz);
        }
        return false;
    }

    memcpy(new, dstr->ds_buf, dstr->ds_alloc);
    ARC_FREE(dstr->ds_buf);
    dstr->ds_alloc = newsz;
    dstr->ds_buf = new;

    return true;
}

/*
**  ARC_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length, including the NULL byte
**  	          (0 == unbounded)
**
**  Return value:
**  	A ARC_DSTRING handle, or NULL on failure.
*/

struct arc_dstring *
arc_dstring_new(int   len,
                int   maxlen,
                void *ctx,
                void (*callback)(void *, const char *, ...))
{
    struct arc_dstring *new;

    /* fail on invalid parameters */
    if ((maxlen > 0 && len > maxlen) || len < 0)
    {
        return NULL;
    }

    if (len < 1024)
    {
        len = 1024;
    }

    new = ARC_MALLOC(sizeof *new);
    if (new == NULL)
    {
        if (callback)
        {
            callback(ctx, "unable to allocate %d bytes", sizeof *new);
        }
        return NULL;
    }

    new->ds_ctx = ctx;
    new->ds_cb = callback;
    new->ds_buf = ARC_MALLOC(len);
    if (new->ds_buf == NULL)
    {
        if (callback)
        {
            callback(ctx, "unable to allocate %d bytes", sizeof len);
        }
        ARC_FREE(new);
        return NULL;
    }

    memset(new->ds_buf, '\0', len);
    new->ds_alloc = len;
    new->ds_len = 0;
    new->ds_max = maxlen;

    return new;
}

/*
**  ARC_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
arc_dstring_free(struct arc_dstring *dstr)
{
    if (dstr == NULL)
    {
        return;
    }

    ARC_FREE(dstr->ds_buf);
    ARC_FREE(dstr);
}

/*
**  ARC_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	true iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

bool
arc_dstring_copy(struct arc_dstring *dstr, const char *str)
{
    int len;

    assert(dstr != NULL);
    assert(str != NULL);

    len = strlen(str);

    /* too big? */
    if (dstr->ds_max > 0 && len >= dstr->ds_max)
    {
        return false;
    }

    /* fits now? */
    if (dstr->ds_alloc <= len)
    {
        /* nope; try to resize */
        if (!arc_dstring_resize(dstr, len + 1))
        {
            return false;
        }
    }

    /* copy */
    memcpy(dstr->ds_buf, str, len + 1);
    dstr->ds_len = len;

    return true;
}

/*
**  ARC_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	true iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

bool
arc_dstring_cat(struct arc_dstring *dstr, const char *str)
{
    size_t len;
    size_t needed;

    assert(dstr != NULL);
    assert(str != NULL);

    len = strlen(str);
    needed = dstr->ds_len + len;

    /* too big? */
    if (dstr->ds_max > 0 && needed >= dstr->ds_max)
    {
        return false;
    }

    /* fits now? */
    if (dstr->ds_alloc <= needed)
    {
        /* nope; try to resize */
        if (!arc_dstring_resize(dstr, needed + 1))
        {
            return false;
        }
    }

    /* append */
    memcpy(dstr->ds_buf + dstr->ds_len, str, len + 1);
    dstr->ds_len += len;

    return true;
}

/*
**  ARC_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	true iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

bool
arc_dstring_cat1(struct arc_dstring *dstr, int c)
{
    int len;

    assert(dstr != NULL);

    len = dstr->ds_len + 1;

    /* too big? */
    if (dstr->ds_max > 0 && len >= dstr->ds_max)
    {
        return false;
    }

    /* fits now? */
    if (dstr->ds_alloc <= len)
    {
        /* nope; try to resize */
        if (!arc_dstring_resize(dstr, len + 1))
        {
            return false;
        }
    }

    /* append */
    dstr->ds_buf[dstr->ds_len++] = c;
    dstr->ds_buf[dstr->ds_len] = '\0';

    return true;
}

/*
**  ARC_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**  	nbytes -- number of bytes to append
**
**  Return value:
**  	true iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

bool
arc_dstring_catn(struct arc_dstring *dstr, const char *str, size_t nbytes)
{
    size_t needed;

    assert(dstr != NULL);
    assert(str != NULL);

    needed = dstr->ds_len + nbytes;

    /* too big? */
    if (dstr->ds_max > 0 && needed >= dstr->ds_max)
    {
        return false;
    }

    /* fits now? */
    if (dstr->ds_alloc <= needed)
    {
        /* nope; try to resize */
        if (!arc_dstring_resize(dstr, needed + 1))
        {
            return false;
        }
    }

    /* append */
    memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
    dstr->ds_len += nbytes;
    dstr->ds_buf[dstr->ds_len] = '\0';

    return true;
}

/*
**  ARC_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

char *
arc_dstring_get(struct arc_dstring *dstr)
{
    assert(dstr != NULL);

    return dstr->ds_buf;
}

/*
**  ARC_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
arc_dstring_len(struct arc_dstring *dstr)
{
    assert(dstr != NULL);

    return dstr->ds_len;
}

/*
**  ARC_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
arc_dstring_blank(struct arc_dstring *dstr)
{
    assert(dstr != NULL);

    dstr->ds_len = 0;
    dstr->ds_buf[0] = '\0';
}

/*
**  ARC_DSTRING_PRINTF -- write variable length formatted output to a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
arc_dstring_printf(struct arc_dstring *dstr, char *fmt, ...)
{
    size_t  len;
    size_t  rem;
    va_list ap;
    va_list ap2;

    assert(dstr != NULL);
    assert(fmt != NULL);

    va_start(ap, fmt);
    va_copy(ap2, ap);
    rem = dstr->ds_alloc - dstr->ds_len;
    len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap);
    va_end(ap);

    if (len > rem)
    {
        if (!arc_dstring_resize(dstr, dstr->ds_len + len + 1))
        {
            va_end(ap2);
            return (size_t) -1;
        }

        rem = dstr->ds_alloc - dstr->ds_len;
        len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap2);
    }

    va_end(ap2);

    dstr->ds_len += len;

    return dstr->ds_len;
}

/*
**  ARC_DSTRING_STRIP -- remove matching characters from a string
**
**  Parameters:
**      dstr -- string to process
**      cset -- characters to remove
**
**  Return value:
**      None.
*/
void
arc_dstring_strip(struct arc_dstring *dstr, const char *cset)
{
    size_t newlen = 0;
    for (size_t i = 0; i <= dstr->ds_len; i++)
    {
        while (strchr(cset, dstr->ds_buf[i]) && i <= dstr->ds_len)
        {
            i++;
        }
        if (i <= dstr->ds_len)
        {
            dstr->ds_buf[newlen] = dstr->ds_buf[i];
            newlen++;
        }
    }
    dstr->ds_buf[newlen] = '\0';
    dstr->ds_len = newlen;
}

/*
**  ARC_COLLAPSE -- remove spaces from a string
**
**  Parameters:
**  	str -- string to process
**
**  Return value:
**  	None.
*/

void
arc_collapse(char *str)
{
    char *q;
    char *r;

    assert(str != NULL);

    for (q = str, r = str; *q != '\0'; q++)
    {
        if (!isspace(*q))
        {
            if (q != r)
            {
                *r = *q;
            }
            r++;
        }
    }

    *r = '\0';
}

/*
**  ARC_COPY_ARRAY -- copy an array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	A copy of "in" and its elements, or NULL on failure.
*/

char **
arc_copy_array(char **in)
{
    unsigned int c;
    unsigned int n;
    char       **out;

    assert(in != NULL);

    for (n = 0; in[n] != NULL; n++)
    {
        continue;
    }

    out = ARC_CALLOC(sizeof(char *), n + 1);
    if (out == NULL)
    {
        return NULL;
    }

    for (c = 0; c < n; c++)
    {
        out[c] = ARC_STRDUP(in[c]);
        if (out[c] == NULL)
        {
            for (n = 0; n < c; n++)
            {
                ARC_FREE(out[n]);
            }
            ARC_FREE(out);
            return NULL;
        }
    }

    out[c] = NULL;

    return out;
}

/*
**  ARC_CLOBBER_ARRAY -- clobber a cloned array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	None.
*/

void
arc_clobber_array(char **in)
{
    unsigned int n;

    assert(in != NULL);

    for (n = 0; in[n] != NULL; n++)
    {
        ARC_FREE(in[n]);
    }

    ARC_FREE(in);
}
