[![build](https://github.com/flowerysong/OpenARC/actions/workflows/build.yml/badge.svg)](https://github.com/flowerysong/OpenARC/actions/workflows/build.yml)

# OpenARC

OpenARC is a community effort to develop and maintain both an open
source library for adding Authenticated Received Chain (ARC) support
to applications and an example filter application using the milter
protocol.

## Introduction

ARC is an experimental protocol defined in [RFC
8617](https://www.rfc-editor.org/info/rfc8617). It provides an
authenticated chain of custody for a message, allowing message
handlers to see who has handled it before and what those prior
handlers claim the message's authentication status was at that point.

ARC is still experimental and its specification may change. This
package is intended for use by operators willing to take part in the
experiment and provide their feedback to the development team.

A substantial amount of the code here is based on code developed as
part of the [OpenDKIM](http://www.opendkim.org/) project, a Trusted
Domain Project activity, which started as a code fork of version 2.8.3
of the open source `dkim-milter` package developed and maintained
by Sendmail, Inc. The license used by OpenDKIM and OpenARC is found
in the `LICENSE` file. Portions of this project are also covered
by the Sendmail Open Source License, which can be found in the
`LICENSE.Sendmail` file. See the copyright notice(s) in each source
file to determine which license(s) are applicable to that file.

## Dependencies

In order to build OpenARC, you will need:

* A C compiler. Compilation has been tested with [GCC](https://gcc.gnu.org/)
  and [clang](https://clang.llvm.org/), and other modern compilers should also
  work.
* make
* pkg-config or a compatible replacement.
* [OpenSSL](https://openssl.org/) >= 1.0.0
* Native implementations of `strlcat()` and `strlcpy()`,
  [libbsd](https://libbsd.freedesktop.org/), or some other library that
  provides them.
* [Libidn2](https://gitlab.com/libidn/libidn2)

If you are building the filter, you will also need:

* [libmilter](https://sendmail.org/)
* (optional) [Jansson](https://github.com/akheron/jansson) >= 2.2.1 for full
  `SealHeaderChecks` support.

If you are building from a git checkout instead of a release tarball,
you will also need:

* [Autoconf](https://www.gnu.org/software/autoconf/) >= 2.61
* [Automake](https://www.gnu.org/software/automake/) >= 1.11.1
* [libtool](https://www.gnu.org/software/libtool/) >= 2.2.6

The core OpenARC software will function without it, but tools distributed
alongside OpenARC (such as `openarc-keygen`) may require:

* Python >= 3.8

Compatibility with older versions of Python 3 has not been
deliberately broken, but this is the oldest version we test against.

### DNF-based systems

```
dnf install autoconf automake gcc jansson-devel libbsd-devel libidn2-devel libtool openssl-devel sendmail-milter-devel
```

### Ubuntu

```
apt install build-essential libbsd-dev libidn2-dev libjansson-dev libmilter-dev libssl-dev
```

### FreeBSD

```
pkg install autoconf autoconf-archive automake jansson libidn2 libtool pkgconf
```

### Alpine
```
apk add autoconf automake bsd-compat-headers gcc jansson-dev libidn2-dev libmilter-dev libtool make musl-dev openssl-dev
```

## Installation

Installation follows the standard Autotools process.

If you're building from a git checkout, you first need to generate the
build system:

```
$ autoreconf -fiv
```

Once that's done (or if you're building from a release tarball):

```
$ ./configure
$ make
$ make install
```

You can get a list of available flags and environment variables to
influence the build by running `./configure --help`.

## Testing

Tests can be run with `make check`. OpenARC's test suite requires:

* Python >= 3.8
* [pytest](https://pytest.org)
* The Python [miltertest](https://pypi.org/project/miltertest/) library

There are also optional test dependencies whose associated tests will be
skipped if the dependency is not found:

* [dkimpy](https://launchpad.net/dkimpy) >= 0.9.0
* [Mail::DKIM](https://metacpan.org/pod/Mail::DKIM)

## Additional Documentation

The man pages for the `openarc` filter are present in the `openarc`
directory of this source distribution.

## Legality

A number of legal regimes restrict the use or export of cryptography.
If you are potentially subject to such restrictions you should seek
legal advice before using, developing, or distributing cryptographic
code.

## Known Runtime Issues

### WARNING: symbol 'X' not available

The filter attempted to get some information from the MTA that the MTA
did not provide.

At various points in the interaction between the MTA and the filter,
macros containing information about the job in progress or the
connection being handled are passed from the MTA to the filter.

In the case of Sendmail, the names of the macros the MTA should
pass to the filter are defined by the `Milter.macros` settings in
`sendmail.cf`, e.g. `Milter.macros.connect`, `Milter.macros.envfrom`,
etc. This message indicates that the filter needed the contents of
macro `X`, but that macro was not passed down from the MTA.

Typically the values needed by this filter are passed from the MTA if
the `sendmail.cf` was generated by the usual M4 method. If you do not
have those options defined in your `sendmail.cf`, try rebuilding it
and then restarting Sendmail.

### MTA Timeouts

Querying nameservers for key data can take longer than the default MTA
timeouts for communication with the filter. This can cause messages to
be rejected, tempfailed, or delivered without processing by the filter,
depending on the MTA configuration.

The only way to address this issue if you encounter it is to increase
the time the MTA waits for replies. Consult your MTA's documentation
to find out how to do so, but note that increasing timeouts too much
can cause other problems.

### `d2i_PUBKEY_bio()` failed

After retrieving and decoding a public key to perform a message
verification, the OpenSSL library attempted to make use of that key
but failed. The known possible causes are:

* Memory exhaustion
* Key corruption

If you're set to tempfail messages in these cases the remote end
will probably retry the message. If the same message fails again
later, the key is probably corrupted or otherwise invalid.

### Message Modifications

In order to verify existing ARC signatures the filter needs to see the
message prior to any local modifications. In order to produce a valid
`ARC-Message-Signature` the filter needs to see the message after any
local modifications.

The only way to satisfy both requirements in ADMDs that
modify messages is to use two instances of the filter which
run at different points in email handling. The first one
must do verification and inject an `Authentication-Results`
header, and may do signing; the second one must enable
`PermitAuthenticationOverrides` (make sure that your environment
is compliant with the security requirements in [RFC 8601 section
1.6](https://datatracker.ietf.org/doc/html/rfc8601#section-1.6)) and
do signing.
