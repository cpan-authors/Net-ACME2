#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

# _parse_link_alternates is a private function in Net::ACME2.
# We test it directly to verify RFC 8288 compliance:
# - relation types are case-insensitive (section 2.1.1)
# - link parameters may appear in any order (section 3)

use Net::ACME2 ();

{
    package MockResponse;

    sub new {
        my ($class, %opts) = @_;
        return bless \%opts, $class;
    }

    sub header {
        my ($self, $name) = @_;
        return $self->{ lc $name };
    }
}

# --- No Link header ---
{
    my $resp = MockResponse->new();
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is( scalar @urls, 0, 'no Link header returns empty list' );
}

# --- Single alternate link ---
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>;rel="alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'single alternate link',
    );
}

# --- Multiple alternate links (arrayref) ---
{
    my $resp = MockResponse->new(
        link => [
            '<https://ca.example/cert/alt1>;rel="alternate"',
            '<https://ca.example/cert/alt2>;rel="alternate"',
        ],
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1', 'https://ca.example/cert/alt2'],
        'multiple alternate links as arrayref',
    );
}

# --- Non-alternate link is ignored ---
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/directory>;rel="index"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is( scalar @urls, 0, 'non-alternate link ignored' );
}

# --- Mixed alternate and non-alternate ---
{
    my $resp = MockResponse->new(
        link => [
            '<https://ca.example/directory>;rel="index"',
            '<https://ca.example/cert/alt1>;rel="alternate"',
        ],
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'mixed link types: only alternate extracted',
    );
}

# --- RFC 8288 section 2.1.1: relation types are case-insensitive ---
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>;rel="Alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'mixed-case "Alternate" matches (RFC 8288 case-insensitive)',
    );
}

{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>;rel="ALTERNATE"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'uppercase "ALTERNATE" matches (RFC 8288 case-insensitive)',
    );
}

# --- Whitespace variations ---
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1> ; rel="alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'extra whitespace around semicolon',
    );
}

# --- RFC 8288 section 3: parameters may appear in any order ---
# The rel parameter does not need to be the first parameter after the URI.
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>; title="cross-signed"; rel="alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'rel after other params (title before rel)',
    );
}

{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>; type="application/pem-certificate-chain"; rel="alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'rel after type param',
    );
}

{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>; rel="alternate"; title="ISRG Root X2"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'rel before other params (rel then title)',
    );
}

# --- rel in any position with mixed links ---
{
    my $resp = MockResponse->new(
        link => [
            '<https://ca.example/directory>; rel="index"',
            '<https://ca.example/cert/alt1>; title="cross-signed"; rel="alternate"',
            '<https://ca.example/cert/alt2>; rel="alternate"; title="ISRG Root X2"',
        ],
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1', 'https://ca.example/cert/alt2'],
        'mixed links with rel in various positions',
    );
}

done_testing();
