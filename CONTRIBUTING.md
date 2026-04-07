# Contributing to Net::ACME2

Contributions are welcome! Here's how to get started.

## Getting Started

```bash
git clone https://github.com/cpan-authors/Net-ACME2.git
cd Net-ACME2
cpanm --notest --installdeps .
perl Makefile.PL
make test
```

## Guidelines

- Keep changes focused: one concern per pull request.
- Add or update tests for any behavioral changes.
- Follow existing code style and conventions.
- Minimum Perl version is 5.14.0 -- avoid features from newer Perl.
- The core library is pure Perl (no XS). Optional XS backends are fine.

## Pull Requests

1. Fork the repository and create a topic branch.
2. Make your changes and ensure `make test` passes.
3. Submit a pull request against `main` with a clear description.

## Reporting Bugs

Open an issue at https://github.com/cpan-authors/Net-ACME2/issues.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
