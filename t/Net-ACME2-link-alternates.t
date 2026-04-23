#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

# _parse_link_alternates is a private function in Net::ACME2.
# We test it directly to verify RFC 8288 compliance (case-insensitive
# relation types).

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

# --- Single alternate link (lowercase) ---
{
    my $resp = MockResponse->new(
        link => '<https://ca.example/cert/alt1>;rel="alternate"',
    );
    my @urls = Net::ACME2::_parse_link_alternates($resp);
    is_deeply(
        \@urls,
        ['https://ca.example/cert/alt1'],
        'single lowercase alternate link',
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

# --- RFC 8288: relation types are case-insensitive ---
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

# --- Whitespace variations in Link header ---
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

done_testing();
