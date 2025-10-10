# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- milter - `AuthResComments` configuration option.

### Changed

### Fixed
- `configure` check for `res_ninit()`


## [1.2.2](https://github.com/flowerysong/OpenARC/releases/tag/v1.2.2) - 2025-07-01

Mainly documentation changes.

### Changed
- contrib - modernized systemd service.

## [1.2.1](https://github.com/flowerysong/OpenARC/releases/tag/v1.2.1) - 2025-01-06

### Added
- `make srpm` target

### Fixed
- Missing dependency in RPM spec.

## [1.2.0](https://github.com/flowerysong/OpenARC/releases/tag/v1.2.0) - 2024-11-22

Big thanks to [@lquidfire](https://github.com/lquidfire),
[@futatuki](https://github.com/futatuki), and
[@simotuki11](https://github.com/simotuki11) for reporting the issues
addressed in this release and/or providing fixes.

### Added
- libopenarc - `ARC_OPTS_SIGNATURE_TTL`
- milter - `SignatureTTL` configuration option.

### Changed
- libopenarc - Expired signatures cause chain validation to fail.

### Fixed
- Build issues on FreeBSD.
- RPM spec typo that could result in installation failure.
- libopenarc - `arc_free()` accepts NULL.
- libopenarc - `c` is not a required tag in `ARC-Message-Signature`.
- libopenarc - `ARC-Message-Signature` headers covering a limited body length
  are processed correctly.

## [1.1.0](https://github.com/flowerysong/OpenARC/releases/tag/v1.1.0) - 2024-11-05

In this development cycle all open issues and PRs in
https://github.com/trusteddomainproject/OpenARC were reviewed and
either addressed or rejected, changes in the ARC spec between the
drafts OpenARC initially implemented and the final version of RFC 8617
were reviewed and addressed, and all embedded comments indicating a
known issue with the code were addressed.

Other efforts focused on housekeeping tasks such as cleaning up unused
and broken parts of the build system, reducing code duplication, and
increasing test coverage.

### Added
- `oldest-pass` processing per [RFC 8617 section 5.2](https://datatracker.ietf.org/doc/html/rfc8617#section-5.2).
- `openarc-keygen`
- libopenarc - `arc_chain_oldest_pass()`
- milter - `AuthResIP` configuration option.
- milter - `RequireSafeKeys` configuration option.
- milter - `MinimumKeySizeRSA` configuration option.
- milter - `ResponseDisabled`, `ResponseUnable`, and `ResponseUnwilling`
  configuration options.

### Changed
- Custom OpenSSL locations must be configured using `OPENSSL_CFLAGS`
  and `OPENSSL_LIBS` environment variables instead of passing
  `--with-openssl=/path` to `configure`.
- Custom Jansson locations must be configured using `LIBJANSSON_CFLAGS`
  and `LIBJANSSON_LIBS` environment variables instead of passing
  `--with-libjansson=/path` to `configure`.
- Custom libmilter locations must be configured using `LIBMILTER_CPPFLAGS`
  and `LIBMILTER_LDFLAGS` environment variables instead of passing
  `--with-milter=/path` to `configure`.
- Building the milter defaults to requiring Jansson. You can explicitly
  disable it by passing `--without-libjansson` to `configure`.
- Libidn2 is now required to build OpenARC.
- libopenarc - `ARC-Message-Signature` and `ARC-Authentication-Results` headers
  are excluded from the AMS, as required by [RFC 8617 section 4.1.2](https://datatracker.ietf.org/doc/html/rfc8617#section-4.1.2).
- libopenarc - ARC headers are returned with a space before the header value.
- libopenarc - String arguments are marked as `const` where applicable.
- libopenarc - String arguments are normal strings (`char *`) unless the
  argument expects a binary string.
- libopenarc - `ARC-Seal` headers containing `h=` tags cause a validation
  failure, as required by [RFC 8617 section 4.1.3](https://datatracker.ietf.org/doc/html/rfc8617#section-4.1.3).
- milter - `Authentication-Results` and `ARC-Authentication-Results` include
  `header.oldest-pass` when appropriate.
- milter - An `ar-test` program for seeing how `Authentication-Results`
  headers are parsed is built without making you jump through weird hoops.
- milter - The default behaviour for messages that fail basic validity checks
  (malformed headers, too many headers) is to reject them.
- milter - `PermitAuthenticationOverrides` defaults to `false`.

### Removed
- libopenarc - `arc_mail_parse()`

### Fixed
- libopenarc - Seals on failed chains only cover the latest ARC header set,
  as required by [RFC 8617 section 5.1.2](https://datatracker.ietf.org/doc/html/rfc8617#section-5.1.2).
- libopenarc - Signing with simple header canonicalization works.
- libopenarc - ARC headers with a misplaced instance tag are rejected.
- libopenarc - Unlikely memory leak after memory allocation failures.
- libopenarc - The installed pkg-config file is more correct.
- libopenarc - U-labels (domain labels encoded as UTF-8) are allowed in `d=`
  and `s=` tags.
- libopenarc - `arc_eom()` propagates internal errors like memory allocation
  failure instead of marking the chain as failed.
- libopenarc - Signature fields are wrapped at the configured margin.
- libopenarc - Header margin wrapping is more accurate and precise.
- libopenarc - Signatures with FWS after the tag-name are canonicalized
  correctly.
- milter - Use after free.
- milter - Unlikely division by zero.
- milter - Small memory leak during config loading.
- milter - The `Authentication-Results` authserv-id can contain UTF-8.

## [1.0.0](https://github.com/flowerysong/OpenARC/releases/tag/v1.0.0) - 2024-10-18

No notable changes.

## [1.0.0rc0](https://github.com/flowerysong/OpenARC/releases/tag/v1.0.0rc0) - 2024-10-15

Changes since the last Trusted Domain Project release.

This release contains patches originally contributed by:
* [@abeverley](https://github.com/abeverley)
* [@futatuki](https://github.com/futatuki)
* [@glts](https://github.com/glts)
* [@mdomsch](https://github.com/mdomsch)
* [@minfrin](https://github.com/minfrin)
* [@nabbi](https://github.com/nabbi)
* [@rtista](https://github.com/rtista)
* [@seriv](https://github.com/seriv)

### Added

- Test suite.
- libopenarc - Support for custom resolvers.
- milter - `UMask` configuration option.
- milter - `TestKeys` configuration option.
- milter - `PermitAuthenticationOverrides` configuration option.

### Changed

- OpenSSL < 1.0.0 is no longer supported. OpenSSL 3 with deprecated interfaces
  disabled is.
- libopenarc - The RFC 8617 limit of 50 ARC sets is respected.
- milter - Trace headers are inserted at index 0 instead of index 1.
- milter - Verify mode can be used without configuring signing-specific options.
- milter - The current ARC validation state is always added to
  `ARC-Authentication-Results`.

### Fixed

- Multiple buffer overruns.
- libopenarc - The "t" flag on seals is optional.
- libopenarc - `arc_chain_custody_string()` no longer returns an empty first
  field.
- libopenarc - Previous ARC sets are still validated in sign mode.
- libopenarc - Key lookups respect the algorithm specified in the seal instead
  of always rejecting keys with "h=sha256".
- libopenarc - `arc_set_cv()` can ignore attempts to set an invalid chain status.
- libopenarc - `ARC-Authentication-Results` now uses "none" to indicate a lack
  of authentication results, as required by RFC 8601.
- libopenarc - `ARC_QUERY_FILE` is now usable.
- libopenarc - `arc_header_field()` will now reject invalid ASCII characters,
  as intended.
- milter - Log messages about the chain validation state use human-readable
  strings for the state.
- milter - General overhaul of `Authentication-Results` parsing and
  `ARC-Authentication-Results` generation, fixing multiple issues.
- milter - Removed incorrect reference count assertion.
- milter - Large ARC header sets are not truncated.
- milter - `MaximumHeaders` configuration option now has an effect.
- milter - Multiple arc `Authentication-Results` from the local authserv-id no
  longer forces the chain to fail.
