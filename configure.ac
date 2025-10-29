#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2009-2017, The Trusted Domain Project.  All rights reserved.
#

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 1)
m4_define([VERSION_MAJOR_REV], 3)
m4_define([VERSION_MINOR_REV], 1)
# leave this empty for an actual release
m4_define([VERSION_PRE], [pre0])

#
# Library version, only update at release time
#       - bump "revision" with internal source code changes
#       - bump "current" and reset "revision" with API changes
#       - bump age with backwards compatible API additions, reset age with
#         removal or modification
#
m4_define([LIBVERSION_CURRENT], 2)
m4_define([LIBVERSION_REVISION], 0)
m4_define([LIBVERSION_AGE], 1)

#
# Autotools setup
#
AC_INIT([OpenARC],
        [m4_join([], VERSION_RELEASE.VERSION_MAJOR_REV.VERSION_MINOR_REV, VERSION_PRE)],
        [simta@umich.edu])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11.1 foreign subdir-objects])
AC_CONFIG_HEADERS([build-config.h])

AC_CONFIG_MACRO_DIR([m4])

LT_INIT

#
# Hexadecimal version, for use in generating arc.h
#
HEX_VERSION=$(printf %08x $(( ((VERSION_RELEASE << 8 | VERSION_MAJOR_REV) << 8 | VERSION_MINOR_REV) << 8 )))
AC_SUBST([HEX_VERSION])

#
# library version, passed to libtool
#
LIBOPENARC_VERSION_INFO=$(printf %d:%d:%d LIBVERSION_CURRENT LIBVERSION_REVISION LIBVERSION_AGE)
AC_SUBST([LIBOPENARC_VERSION_INFO])

#
# Checks for programs
#
AC_PROG_CC
# autoconf 2.70 deprecated this, but it might still be necessary on old versions
m4_version_prereq([2.70], [:], [AC_PROG_CC_C99])
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG

#
# Check for how to compile threaded stuff
#
AX_PTHREAD

#
# save outer values
#
outer_CFLAGS="$CFLAGS"
outer_CPPFLAGS="$CPPFLAGS"
outer_LDFLAGS="$LDFLAGS"
outer_LIBS="$LIBS"

#
# Checks for libraries
#

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_SEARCH_LIBS(inet_pton, resolv,
               AC_DEFINE(HAVE_INET_PTON, 1,
                         [Define to 1 if you have the inet_pton() function.]))
AC_SEARCH_LIBS(inet_ntop, resolv nsl,
               AC_DEFINE(HAVE_INET_NTOP, 1,
                        [Define to 1 if you have the inet_ntop() function.]))
AC_SEARCH_LIBS(getaddrinfo, resolv,
               AC_DEFINE(HAVE_GETADDRINFO, 1,
                         [Define to 1 if you have the getaddrinfo() function.]))
AC_SEARCH_LIBS(getopt_long, iberty,
               AC_DEFINE(HAVE_GETOPT_LONG, 1,
                         [Define to 1 if you have the getopt_long() function.]))

AC_HEADER_RESOLV

# AC_SEARCH_LIBS doesn't work for this check because glibc doesn't
# actually export the expected symbol, there's a #define in `resolv.h`
# that points to the real symbol.
AC_CACHE_CHECK(
    [for library containing res_ninit],
    [ac_cv_search_res_ninit],
    [
        saved_LIBS=$LIBS
        AC_LANG_CONFTEST([AC_LANG_PROGRAM([@%:@include <resolv.h>], [res_ninit(NULL);])])
        for ac_lib in '' resolv
        do
            if test -z "$ac_lib"; then
                ac_res="none required"
            else
                ac_res=-l$ac_lib
                LIBS="-l$ac_lib $ac_func_search_save_LIBS"
            fi
            AC_LINK_IFELSE([], [AS_VAR_SET([ac_cv_search_res_ninit], [$ac_res])])
            AS_VAR_SET_IF([ac_cv_search_res_ninit], [break])
        done
        AS_VAR_SET_IF([ac_cv_search_res_ninit], [], [AS_VAR_SET([ac_cv_search_res_ninit], [no])])
        rm conftest.$ac_ext
        LIBS=$saved_LIBS
    ]
)
AS_IF([test "$ac_cv_search_res_ninit" != no],
    [
        test "$ac_cv_search_res_ninit" = "none required" || LIBS="$ac_res $LIBS"
        AC_DEFINE(
            HAVE_RES_NINIT, 1,
            [Define to 1 if you have the res_ninit() function.]
        )
    ]
)

#
# Check for types
#

AC_CHECK_TYPES([useconds_t])

#
# See if libopenarc will need -lresolv
#
dnscheck='
#include "confdefs.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
int main() {
res_mkquery (0, 0, 0, 0, 0, 0, 0, 0, 0);
dn_expand (0, 0, 0, 0, 0);
dn_skipname (0, 0);
dn_comp (0, 0, 0, 0, 0);
return 0;
}'
AC_MSG_CHECKING([whether the resolver works without -lresolv])
LIBRESOLV=
AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
])], [
    AC_MSG_RESULT(yes)
], [
    AC_MSG_RESULT(no)
    AC_MSG_CHECKING([whether the resolver works with -lresolv])
    saved_LIBS="$LIBS"
    LIBS="$outer_LIBS -lresolv"
    AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
    ])], [
        AC_MSG_RESULT(yes)
        LIBRESOLV=-lresolv
    ], [
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([need workable resolver library])
    ])
    LIBS="$saved_LIBS"
])
AC_SUBST([LIBRESOLV])

#
# Checks for header files
#
AC_CHECK_HEADER([sys/queue.h], [], [AC_MSG_ERROR([sys/queue.h not found])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h iso/limits_iso.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h stdint.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

#
# Checks for library functions.
#
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC

AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gethostbyname getaddrinfo gethostbyname2 gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul strtoull realpath strsep])

bsdstrl_h_found="no"
strl_found="no"
libstrl_found="no"
strl_h_found="no"

AC_CHECK_HEADERS([bsd/string.h], [bsdstrl_h_found="yes"])

AC_CHECK_FUNCS([strlcat strlcpy], [strl_found="yes"], [
    saved_LIBS="$LIBS"
    LIBS="$outer_LIBS"
    AC_SEARCH_LIBS([strlcat], [bsd strl], [libstrl_found="yes"], [strl_found="no"])
    AC_SEARCH_LIBS([strlcpy], [bsd strl], [libstrl_found="yes"], [strl_found="no"])
    STRL_LIBS="$LIBS"
    LIBS="$saved_LIBS"
])

AS_IF([test "x$libstrl_found" = xyes], [LIBS="$LIBS $STRL_LIBS"])

# we need something above to have worked
AS_IF([test "x$strl_found" != xyes -a "x$libstrl_found" != xyes], [
    AC_MSG_ERROR(no strlcpy/strlcat found)
])

AC_SUBST(STRL_LIBS)

AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
AS_IF([test "x$strl_h_found" != xyes], [
    strldirs="/usr/local/include /usr/include"

    for d in $strldirs
    do
        AC_MSG_CHECKING([for strl.h in $d/strl])
        AS_IF([test -f "$d/strl/strl.h"], [
            unset ac_cv_header_strl_h
            saved_CPPFLAGS="$CPPFLAGS"
            CPPFLAGS="$CPPFLAGS -I$d/strl"
            AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
            CPPFLAGS="$saved_CPPFLAGS"
        ])

        AS_IF([test "x$strl_h_found" = xyes], [
            CPPFLAGS="$CPPFLAGS -I$d/strl"
            break
        ])
    done
])

# we need to include <strl.h> if an installed strl.h was found and no
# bsd/string.h was found
AS_IF([test "x$strl_h_found" = xyes -a "x$bsdstrl_h_found" = xno], [
    AC_DEFINE([USE_STRL_H], 1, [Define to 1 if you need to include <strl.h> to get the strlcat() and strlcpy() functions.])
])

AS_IF([test "x$bsdstrl_h_found" = xyes], [
    AC_DEFINE([USE_BSD_H], 1, [Define to 1 if you need to include <bsd/string.h> to get the strlcat() and strlcpy() functions.])
])

#
# use rpath at load time?
#

AC_ARG_ENABLE([rpath],
    AS_HELP_STRING([--enable-rpath], [include library load paths in binaries]),
    [],
    enable_rpath="yes")
AM_CONDITIONAL([RPATH], [test x"$enable_rpath" = x"yes"])
AS_IF([test "x$enable_rpath" != xyes], [
    AC_MSG_RESULT([Suppressing -rpath use by libtool])
    hardcode_libdir_flag_spec=" -D__LIBTOOL_NO_RPATH__ "
    chmod 0755 libtool
])

#
# openarc
#
AC_ARG_ENABLE([filter],
    AS_HELP_STRING([--disable-filter], [do not compile the openarc filter]),
    [enable_filter=$enableval],
    [enable_filter=yes])
AM_CONDITIONAL([BUILD_FILTER], [test x"$enable_filter" != x"no"])

#
# Conditional stuff
#

LIBOPENARC_FEATURE_STRING="libopenarc $PACKAGE_VERSION:"

AC_ARG_ENABLE([allsymbols],
    AS_HELP_STRING([--enable-allsymbols], [export internal-use symbols for better test coverage]))
AM_CONDITIONAL(ALL_SYMBOLS, [test x"$enable_allsymbols" = x"yes"])

AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [produce debugging binaries and libraries]),
    AS_IF([test "x$enable_debug" = x"yes"], [
        LIBOPENARC_FEATURE_STRING="$LIBOPENARC_FEATURE_STRING debug"
        [[CFLAGS=`echo $CFLAGS | sed 's/ -O[1-9s]*//g'`]]
    ])
)

AM_CONDITIONAL([DEBUG], [test x"$enable_debug" = x"yes"])

#
# OpenSSL
#

PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.0])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

#
# Libidn2
#

PKG_CHECK_MODULES([LIBIDN2], [libidn2])
AC_SUBST(LIBIDN2_CFLAGS)
AC_SUBST(LIBIDN2_LIBS)

#
# libmilter
#

AC_ARG_VAR([LIBMILTER_CPPFLAGS], [C preprocessor flags for libmilter headers])
AC_ARG_VAR([LIBMILTER_LDFLAGS], [linker flags for libmilter library])

AS_IF([test "x$enable_filter" != xno], [
    saved_CC="$CC"
    saved_CFLAGS="$CFLAGS"
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LDFLAGS="$LDFLAGS"
    saved_LIBS="$LIBS"

    CC="$PTHREAD_CC"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    LDFLAGS="$PTHREAD_CFLAGS $LDFLAGS"

    AS_IF([test "x$LIBMILTER_CPPFLAGS" != x], [CPPFLAGS="$CPPFLAGS $LIBMILTER_CPPFLAGS"])
    AS_IF([test "x$LIBMILTER_LDFLAGS" != x], [LDFLAGS="$LDFLAGS $LIBMILTER_LDFLAGS"])

    AC_CHECK_HEADER([libmilter/mfapi.h],
        [AC_CHECK_LIB([milter], [smfi_register], [], [AC_MSG_ERROR([Unable to find libmilter])])],
        [AC_MSG_ERROR([Unable to find libmilter includes])])

    AC_CHECK_FUNC([smfi_insheader],
        AC_DEFINE([HAVE_SMFI_INSHEADER], 1, [Define if libmilter has smfi_insheader()]))

    AC_CHECK_FUNC([smfi_opensocket],
        AC_DEFINE([HAVE_SMFI_OPENSOCKET], 1, [Define if libmilter has smfi_opensocket()]))

    AC_CHECK_FUNC([smfi_progress],
        AC_DEFINE([HAVE_SMFI_PROGRESS], 1, [Define if libmilter has smfi_progress()]))

    AC_CHECK_FUNC([smfi_setsymlist],
        AC_DEFINE([HAVE_SMFI_SETSYMLIST], 1, [Define if libmilter has smfi_setsymlist()]))

    AC_CHECK_FUNC([smfi_version],
        AC_DEFINE([HAVE_SMFI_VERSION], 1, [Define if libmilter has smfi_version()]))

    CC="$saved_CC"
    CFLAGS="$saved_CFLAGS"
    CPPFLAGS="$saved_CPPFLAGS"
    LDFLAGS="$saved_LDFLAGS"
    LIBS="$saved_LIBS"

    LIBMILTER_LIBS='-lmilter'
])

AC_SUBST(LIBMILTER_CPPFLAGS)
AC_SUBST(LIBMILTER_LDFLAGS)
AC_SUBST(LIBMILTER_LIBS)

#
# header filtering requires libjansson
#

AC_ARG_WITH([libjansson], AS_HELP_STRING([--with-libjansson], [use Jansson for header field checks]))

AS_IF([test "x$enable_filter" != xno -a "x$with_libjansson" != xno], [
    PKG_CHECK_MODULES(
        [LIBJANSSON],
        [jansson >= 2.2.1],
        [AC_DEFINE([USE_JANSSON], [1], [use Jansson for header field checks])]
    )
])

AC_SUBST(LIBJANSSON_CFLAGS)
AC_SUBST(LIBJANSSON_LIBS)


AC_DEFINE_UNQUOTED([LIBOPENARC_FEATURE_STRING], "$LIBOPENARC_FEATURE_STRING",
    [Feature string for printing])

#
# final command line tweaks
#

CPPFLAGS="$CPPFLAGS -DCONFIG_BASE=\\\"$sysconfdir\\\""

test "x$prefix" = xNONE && prefix=$ac_default_prefix
SYSCONFDIR=`eval echo "$sysconfdir"`
AC_SUBST([SYSCONFDIR])

AS_IF([test "x$SOURCE_DATE_EPOCH" = x], [
    SOURCE_DATE_EPOCH=`git log -1 --pretty=%ct 2>/dev/null`
])
AS_IF([test "x$SOURCE_DATE_EPOCH" = x], [
    SOURCE_DATE_EPOCH=`date +%s 2>/dev/null`
])
BUILD_DATE=`date -d @$SOURCE_DATE_EPOCH +%F 2>/dev/null`
AC_SUBST([BUILD_DATE])

#
# Finish up
#

AC_CONFIG_FILES([
    Makefile
    contrib/Makefile
    contrib/openarc-keygen.1
    contrib/init/Makefile
    contrib/init/generic/Makefile
    contrib/init/redhat/Makefile
    contrib/init/redhat/openarc
    contrib/init/solaris/Makefile
    contrib/spec/Makefile
    contrib/spec/openarc.spec
    contrib/systemd/Makefile
    contrib/systemd/openarc.service
    libopenarc/openarc.pc
    openarc/openarc.8
    openarc/openarc.conf.5
    test/Makefile
])
AC_OUTPUT
