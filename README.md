[![build](https://github.com/flowerysong/OpenARC/actions/workflows/build.yml/badge.svg)](https://github.com/flowerysong/OpenARC/actions/workflows/build.yml)

# OpenARC

This directory has the latest open source ARC filter software from a
random person on the internet.

## Introduction

Authenticated Received Chain (ARC) is an experimental protocol
defined in [RFC 8617](https://www.rfc-editor.org/info/rfc8617). It
provides an authenticated chain of custody for a message, allowing
message handlers to see who has handled it before and what those prior
handlers claim the message's authentication status was at that point.

OpenARC is a community effort to develop and maintain an open source
library for producing ARC-aware applications, and a filter application
using the milter protocol.

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
* [OpenSSL](https://openssl.org) >= 1.0.0
* Native implementations of `strlcat()` and `strlcpy()`,
  [libbsd](https://libbsd.freedesktop.org/), or some other library that
  provides them.
* [Libidn2](https://gitlab.com/libidn/libidn2)

If you are building the filter, you will also need:

* [sendmail](https://sendmail.org) >= 8.13.0, or
  [Postfix](https://www.postfix.org/) >= 2.3 and libmilter.
* (optional) [Jansson](https://github.com/akheron/jansson) >= 2.2.1 for full
  `SealHeaderChecks` support.

If you are building from a git checkout instead of a release tarball,
you will also need:

* [Autoconf](https://www.gnu.org/software/autoconf/) >= 2.61
* [Automake](https://www.gnu.org/software/automake/) >= 1.11.1
* [libtool](https://www.gnu.org/software/libtool/) >= 2.2.6

### DNF-based systems

```
$ dnf install autoconf automake gcc jansson-devel libbsd-devel libidn2-devel libtool openssl-devel sendmail-milter-devel
```

### Ubuntu

```
$ apt install build-essential libbsd-dev libidn2-dev libjansson-dev libmilter-dev libssl-dev
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

## Testing

Tests can be run with `make check`. OpenARC's test suite requires:

* Python >= 3.8
* [pytest](https://pytest.org)
* The Python [miltertest](https://pypi.org/project/miltertest/) library

## Additional Documentation

The man page for the openarc filter is present in the openarc
directory of this source distribution.

## Warning

Since OpenARC uses cryptography, the following information from OpenSSL
applies to this package as well.

PLEASE REMEMBER THAT EXPORT/IMPORT AND/OR USE OF STRONG CRYPTOGRAPHY
SOFTWARE, PROVIDING CRYPTOGRAPHY HOOKS OR EVEN JUST COMMUNICATING
TECHNICAL DETAILS ABOUT CRYPTOGRAPHY SOFTWARE IS ILLEGAL IN SOME
PARTS OF THE WORLD.  SO, WHEN YOU IMPORT THIS PACKAGE TO YOUR
COUNTRY, RE-DISTRIBUTE IT FROM THERE OR EVEN JUST EMAIL TECHNICAL
SUGGESTIONS OR EVEN SOURCE PATCHES TO THE AUTHOR OR OTHER PEOPLE
YOU ARE STRONGLY ADVISED TO PAY CLOSE ATTENTION TO ANY EXPORT/IMPORT
AND/OR USE LAWS WHICH APPLY TO YOU.  THE AUTHORS ARE NOT LIABLE FOR
ANY VIOLATIONS YOU MAKE HERE.  SO BE CAREFUL, IT IS YOUR RESPONSIBILITY.

If you use OpenSSL then make sure you read their README file which
contains information about patents etc.


## Runtime Issues

### WARNING: symbol 'X' not available

The filter attempted to get some information from the MTA that the MTA
did not provide.

At various points in the interaction between the MTA and the filter,
certain macros containing information about the job in progress or the
connection being handled are passed from the MTA to the filter.

In the case of sendmail, the names of the macros the MTA should
pass to the filter are defined by the `Milter.macros` settings in
`sendmail.cf`, e.g. `Milter.macros.connect`, `Milter.macros.envfrom`,
etc. This message indicates that the filter needed the contents of
macro `X`, but that macro was not passed down from the MTA.

Typically the values needed by this filter are passed from the MTA
if the sendmail.cf was generated by the usual m4 method. If you do
not have those options defined in your `sendmail.cf`, make sure your
M4 configuration files are current and rebuild your `sendmail.cf` to
get appropriate lines added to your `sendmail.cf`, and then restart
sendmail.

### MTA timeouts

By default, the MTA is configured to wait up to ten seconds for
a response from a filter before giving up. When querying remote
nameservers for key and policy data, the ARC filter may not get a
response from the resolver within that time frame, and thus this
MTA timeout will occur. This can cause messages to be rejected,
temp-failed or delivered without verification, depending on the
failure mode selected for the filter.

When using the standard resolver library provided with your
system, the DNS timeout cannot be adjusted. If you encounter this
problem, you must increase the time the MTA waits for replies.
See the documentation in the sendmail open source distribution
(`libmilter/README` in particular) for instructions on changing these
timeouts.

### `d2i_PUBKEY_bio()` failed

After retrieving and decoding a public key to perform a message
verification, the OpenSSL library attempted to make use of that key
but failed. The known possible causes are:

* Memory exhaustion
* Key corruption

If you're set to temp-fail messages in these cases, the remote end
will probably retry the message. If the same message fails again
later, the key is probably corrupted or otherwise invalid.

### Incompatible Sendmail Features

There are two features of the sendmail MTA which, if activated,
can interfere with successful use of the `openarc` milter. The two
features are `MASQUERADE_AS` and `FEATURE(genericstable)`. `See
cf/README` in the open source sendmail source code distribution for
more information.

Due to the way the milter protocol is incorporated into the MTA,
`openarc` sees the headers before they are modified as required by
those two features. This means any signature is generated based on the
headers originally injected by the mail client and not on the headers
which are actually sent out by the MTA. As a result, the verifying
agent at the receiver's side will be unable to verify the signature as
the signed data and the received data don't match.

The suggested solutions to this problem are:

1. Send mail with the headers already written as needed, obviating the
   need for these features (or just turn them off).

2. Have two MTAs set up, either on separate boxes or on the same box.
   The first MTA should do all of the rewriting (i.e. use these two
   features) and the second one should use `openarc` to add the signature
   and do no rewriting at all.

3. Have multiple `DaemonPortOptions` lines in your configuration file.
   The first daemon port (port 25) does the header rewriting and then
   routes the message to the second port; the latter does no rewriting
   but does the signing and then sends the message on its way.

There is also a feature of Sendmail that will cause it to alter
addresses after signing but before they are transmitted. The feature,
which is on by default, passes addresses in header fields to the
resolver functions to ensure they are canonical. This can result
in the replacement of those strings in the sent message with their
canonical forms after the message is signed, which will invalidate the
signatures. To suppress this feature, add the following line to your
`sendmail.mc` and `submit.mc` configuration files, re-generate your
configuration, and restart the filter:
```
	FEATURE(`nocanonify')
```
