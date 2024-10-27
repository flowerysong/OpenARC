# Copyright (c) 2010-2014, 2016, 2017, The Trusted Domain Project.
# All rights reserved.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = contrib . test
dist_doc_DATA = LICENSE LICENSE.Sendmail README.md CHANGELOG.md
dist_noinst_SCRIPTS = libtool

DISTCLEANFILES = openarc-@VERSION@.tar.gz libopenarc/symbols.map *.gcno *.gcda

# TODO: get configure.ac to generate --enable-{feature} for all
# non-experimental features and substitute it here e.g  @SUPPORTED_FEATURES@.
# Perhaps all features would enable a more comprehensive test coverage map
# though.
DISTCHECK_CONFIGURE_FLAGS=--with-openssl=/usr/local

if DEBUG
AM_CFLAGS = -g
endif

LDADD = libopenarc/libopenarc.la

lib_LTLIBRARIES = libopenarc/libopenarc.la
libopenarc_libopenarc_la_SOURCES = \
	libopenarc/base64.c \
	libopenarc/base64.h \
	libopenarc/arc.c \
	libopenarc/arc.h \
	libopenarc/arc-canon.c \
	libopenarc/arc-canon.h \
	libopenarc/arc-dns.c \
	libopenarc/arc-dns.h \
	libopenarc/arc-internal.h \
	libopenarc/arc-keys.c \
	libopenarc/arc-keys.h \
	libopenarc/arc-tables.c \
	libopenarc/arc-tables.h \
	libopenarc/arc-types.h \
	libopenarc/arc-util.c \
	libopenarc/arc-util.h \
	util/arc-dstring.c \
	util/arc-dstring.h
libopenarc_libopenarc_la_CPPFLAGS = -I$(srcdir)/util $(OPENSSL_CFLAGS) $(LIBIDN2_CFLAGS)
libopenarc_libopenarc_la_LDFLAGS = -no-undefined -version-info $(LIBOPENARC_VERSION_INFO)
libopenarc_libopenarc_la_LIBADD = $(OPENSSL_LIBS) $(LIBIDN2_LIBS)
if !ALL_SYMBOLS
libopenarc_libopenarc_la_DEPENDENCIES = libopenarc/symbols.map
libopenarc_libopenarc_la_LDFLAGS += -export-symbols libopenarc/symbols.map
endif
if RPATH
libopenarc_libopenarc_la_LDFLAGS += -rpath $(libdir)
endif
libopenarc_libopenarc_includedir = $(includedir)/openarc
libopenarc_libopenarc_include_HEADERS = libopenarc/arc.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopenarc/openarc.pc

libopenarc/symbols.map: $(libopenarc_libopenarc_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /arc_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g -e s/\(.*// | \
		sort -u -o $@

if BUILD_FILTER
dist_doc_DATA += openarc/openarc.conf.sample
man_MANS = openarc/openarc.conf.5 openarc/openarc.8 openarc/openarc-genkey.8
sbin_PROGRAMS = openarc/openarc
dist_sbin_SCRIPTS = openarc/openarc-genkey

openarc_openarc_SOURCES = \
	openarc/config.c \
	openarc/config.h \
	openarc/openarc.c \
	openarc/openarc.h \
	openarc/openarc-ar.c \
	openarc/openarc-ar.h \
	openarc/openarc-config.h \
	openarc/openarc-crypto.c \
	openarc/openarc-crypto.h \
	openarc/openarc-test.c \
	openarc/openarc-test.h \
	openarc/util.c \
	openarc/util.h \
	util/arc-dstring.c \
	util/arc-dstring.h
openarc_openarc_CC = $(PTHREAD_CC)
openarc_openarc_CFLAGS = $(PTHREAD_CFLAGS)
openarc_openarc_CPPFLAGS = -I$(srcdir)/libopenarc -I$(srcdir)/util $(OPENSSL_CFLAGS) $(LIBIDN2_CFLAGS) $(LIBMILTER_CPPFLAGS) $(LIBJANSSON_CFLAGS)
openarc_openarc_LDFLAGS = $(LIBMILTER_LDFLAGS) $(PTHREAD_CFLAGS)
openarc_openarc_LDADD = libopenarc/libopenarc.la $(LIBMILTER_LIBS) $(OPENSSL_LIBS) $(LIBIDN2_LIBS) $(PTHREAD_LIBS) $(LIBJANSSON_LIBS) $(LIBRESOLV)

noinst_PROGRAMS = openarc/ar-test

openarc_ar_test_SOURCES = \
	openarc/openarc-ar.c \
	openarc/openarc-ar.h \
	openarc/ar-test.c

openarc_ar_test_CPPFLAGS = -I$(srcdir)/libopenarc -I$(srcdir)/util
endif

$(DIST_ARCHIVES).sha1: $(DIST_ARCHIVES)
	sha1sum $? > $@

$(DIST_ARCHIVES).sha256: $(DIST_ARCHIVES)
	sha256sum $? > $@

release: dist $(DIST_ARCHIVES) $(DIST_ARCHIVES).sha1 $(DIST_ARCHIVES).sha256

dist-hook:
	[ -f $(distdir)/libopenarc/arc.h ] && rm -f $(distdir)/libopenarc/arc.h
	sed -e '/OPENARC_LIB_VERSION/s/0x[0-9]*/0x@HEX_VERSION@/' < $(srcdir)/libopenarc/arc.h > $(distdir)/libopenarc/arc.h

rpm: dist-gzip
	rpmbuild -ta $(distdir).tar.gz

.PHONY: push
