# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- milter - `AuthResIP` configuration option.

### Changed
- libopenarc - `ARC-Message-Signature` and `ARC-Authentication-Results` headers
  are excluded from the AMS, as required by RFC 8617.

### Fixed

## 1.0.0 - 2024-10-18

No notable changes.

## 1.0.0rc0 - 2024-10-15

Changes since the last Trusted Domain Project release.

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
- milter - general overhaul of `Authentication-Results` parsing and
  `ARC-Authentication-Results` generation, fixing multiple issues.
- milter - Removed incorrect reference count assertion.
- milter - Large ARC header sets are not truncated.
- milter - `MaximumHeaders` configuration option now has an effect.
- milter - Multiple arc `Authentication-Results` from the local authserv-id no
  longer forces the chain to fail.
