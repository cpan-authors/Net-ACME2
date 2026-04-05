# CLAUDE.md — Net::ACME2

## What is this?

A production-grade Perl client for the ACME v2 protocol (RFC 8555), used for
automated certificate management (e.g., Let's Encrypt). Supports RSA and ECDSA
keys, http-01/dns-01/tls-alpn-01 challenges, and experimental async I/O.

## Build & Test

```bash
perl Makefile.PL
make
make test
```

Dependencies are managed via `Makefile.PL` (not cpanfile). Install them with:

```bash
cpanm --notest --installdeps .
```

CI runs on `perldocker/perl-tester` containers across Perl 5.10–5.32.

## Key Architecture

```
Net::ACME2              — Main client (subclass to set HOST/DIRECTORY_PATH)
  ├── AccountKey        — Key abstraction (3 backends: Crypt::Perl, Crypt::OpenSSL::RSA, CryptX)
  ├── HTTP              — JOSE+JSON transport, nonce mgmt, badNonce retry
  │   ├── HTTP_Tiny     — Sync backend (default)
  │   ├── Curl          — Async backend (EXPERIMENTAL)
  │   ├── HTTP::Response— Response wrapper
  │   └── HTTP::Convert — HTTP::Tiny ↔ internal conversion
  ├── JWTMaker          — JWS construction
  │   ├── JWTMaker::RSA — RS256 signing
  │   └── JWTMaker::ECC— ES256/ES384 signing
  ├── Order             — ACME order object
  ├── Authorization     — ACME authorization object
  ├── Challenge/*       — http_01, dns_01, tls_alpn_01
  ├── Error             — ACME error parsing
  └── X/*               — Exception hierarchy (X::Tiny-based)
```

## Crypto Backends

AccountKey.pm selects backends in priority order:
- **RSA**: Crypt::OpenSSL::RSA → Crypt::PK::RSA → Crypt::Perl (pure Perl fallback)
- **ECDSA**: Crypt::PK::ECC → Crypt::Perl

Crypt::OpenSSL::RSA and CryptX are optional — not in PREREQ_PM. Tests must
handle their absence gracefully with `eval { require ... }` and SKIP blocks.

## Test Patterns

- Tests live in `t/` with naming convention `t/Net-ACME2-<Module>.t`
- Test helper `t/lib/Test::ACME2_Server` provides a mock ACME server by
  monkey-patching `Net::ACME2::HTTP_Tiny::_base_request`
- `t/lib/Test::Crypt` provides JWT decode/verify without depending on Crypt::JWT
- Use `Test::More`, `Test::Exception`, `Test::FailWarnings`, `Test::Deep`
- ECDSA signatures are non-deterministic — verify both, don't compare bytes
- New test files must be added to `MANIFEST` (regenerated via `make manifest`)

## Conventions

- **Minimum Perl**: 5.10.0
- **Commit messages**: Short, lowercase, descriptive (no conventional commits)
- **MANIFEST**: Generated via `make manifest`. Don't hand-edit or re-sort it.
- **Releases**: Done by the maintainer. Never bump versions or update Changes.
- **README.md**: Auto-generated via `pod2markdown lib/Net/ACME2.pm > README.md`.
  Don't edit it directly — update the POD in `lib/Net/ACME2.pm` instead.
- **Pure Perl**: Core library avoids XS. Optional XS backends for performance.
- **Promises**: All public methods that do I/O return promises in async mode,
  direct values in sync mode. Use `Net::ACME2::PromiseUtil::then()` internally.
- **Exceptions**: Use `Net::ACME2::X::Generic` (via X::Tiny). Some internal dies
  use plain strings — this is the existing pattern, not a bug to fix.

## Gotchas

- `Crypt::OpenSSL::RSA` 0.35+ changed `use_pkcs1_padding()` behavior — signing
  via `RSA_sign()` always uses PKCS#1 v1.5 internally, but the padding method
  affects `private_encrypt()`. Tests should handle this with eval + skip.
- The `Edit` tool can introduce Unicode smart quotes into `.pm`/`.pl` files.
  Always verify edited Perl files compile: `perl -c <file>`.
- Handler.pm's `$ASSUME_UNIX_PATHS` switches between File::Spec and simple
  string ops — both paths need testing.
- The Curl async backend is only activated when `async_ua` is passed to
  `Net::ACME2->new()`; the default path uses HTTP_Tiny.
