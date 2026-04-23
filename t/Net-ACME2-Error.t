#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;
use Test::Deep;

use Net::ACME2::Error ();

{
    my $err = Net::ACME2::Error->new(
        type => 'some:general:error',
    );

    is(
        $err->to_string(),
        'some:general:error',
        'to_string() when there’s no “status”',
    );
}

{
    my $err = Net::ACME2::Error->new(
        status => '499',
    );

    like(
        $err->to_string(),
        qr/499/,
        'to_string() when there’s no “type”',
    );
}

{
    my $err = Net::ACME2::Error->new(
        status => 400,
        type => 'urn:ietf:params:acme:error:rejectedIdentifier',
        detail => 'Error creating new order :: Cannot issue for "*.lottasubs.tld": Domain name does not end with a valid public suffix (TLD) (and 1 more problems. Refer to sub-problems for more information.)',
        subproblems => [
                {
                    'type'       => 'urn:ietf:params:acme:error:rejectedIdentifier',
                    'status'     => 400,
                    'identifier' => {
                        'type'  => 'dns',
                        'value' => '*.lottasubs.tld'
                    },
                    'detail' => 'Error creating new order :: Domain name does not end with a valid public suffix (TLD)'
                },
                {
                    'detail'     => 'Error creating new order :: Domain name does not end with a valid public suffix (TLD)',
                    'identifier' => {
                        'value' => 'www.sub103.lottasubs.tld',
                        'type'  => 'dns'
                    },
                    'status' => 400,
                    'type'   => 'urn:ietf:params:acme:error:rejectedIdentifier'
                },
        ],
    );

    unlike(
        $err->to_string(),
        qr<HASH>,
        'no HASH in a real-world error’s to_string()',
    );
}

{
    my $err = Net::ACME2::Error->new(
        status      => 490,
        type        => 'some:general:error',
        subproblems => [
            { status => 499, type => 'some:weird:error_yo',
                identifier => { type => 'dns', value => 'domain1' }, },
            { status => 499, type => 'some:weird:error2',
                identifier => { type => 'dns', value => 'domain2' }
             },
        ],
    );

    cmp_deeply(
        [ $err->subproblems() ],
        [
            all(
                Isa('Net::ACME2::Error::Subproblem'),
                methods(
                    identifier => { type => 'dns', value => 'domain1' },
                    to_string  => re(qr<dns/domain1: .*499.*some:weird:error_yo>),
                ),
            ),
            all(
                Isa('Net::ACME2::Error::Subproblem'),
                methods(
                    identifier => { type => 'dns', value => 'domain2' },
                    to_string  => re(qr<dns/domain2: .*499.*some:weird:error2>),
                ),
            ),
        ],
        'subproblems()',
    );

    like(
        $err->to_string(),
        qr<
            490 [ ] some:general:error
            .+
            dns/domain1: [ ] 499 [ ] some:weird:error_yo
            .+
            dns/domain2: [ ] 499 [ ] some:weird:error2
        >x,
        'to_string()',
    );
}

# Test type() defaults to 'about:blank' when unset
{
    my $err = Net::ACME2::Error->new();

    is(
        $err->type(),
        'about:blank',
        'type() defaults to about:blank',
    );
}

# Test description() with known ACME URN types
{
    my @known_types = (
        [ 'badNonce'          => qr/unacceptable anti-replay nonce/ ],
        [ 'rateLimited'       => qr/rate limit/ ],
        [ 'unauthorized'      => qr/lacks sufficient authorization/ ],
        [ 'serverInternal'    => qr/internal error/ ],
        [ 'malformed'         => qr/malformed/ ],
        [ 'badCSR'            => qr/unacceptable/ ],
        [ 'rejectedIdentifier'=> qr/will not issue/ ],
        [ 'caa'               => qr/CAA/ ],
        [ 'dns'               => qr/DNS query/ ],
    );

    for my $t (@known_types) {
        my ($short_type, $desc_re) = @$t;

        my $err = Net::ACME2::Error->new(
            type => "urn:ietf:params:acme:error:$short_type",
        );

        like(
            $err->description(),
            $desc_re,
            "description() for $short_type",
        );
    }
}

# Test description() returns undef for unknown types
{
    my $err = Net::ACME2::Error->new(
        type => 'urn:ietf:params:acme:error:totallyMadeUp',
    );

    is( $err->description(), undef, 'description() undef for unknown type' );
}

# Test to_string() includes description for known URN types
{
    my $err = Net::ACME2::Error->new(
        status => 429,
        type   => 'urn:ietf:params:acme:error:rateLimited',
        detail => 'too many requests',
    );

    my $str = $err->to_string();

    like( $str, qr/429/,         'to_string has status' );
    like( $str, qr/rateLimited/, 'to_string has type' );
    like( $str, qr/rate limit/,  'to_string has description' );
    like( $str, qr/too many/,    'to_string has detail' );
}

# Test subproblems() in list context enforcement
{
    my $err = Net::ACME2::Error->new(
        status => 400,
        type   => 'urn:ietf:params:acme:error:rejectedIdentifier',
    );

    # subproblems() requires list context
    my @subs = $err->subproblems();
    is( scalar @subs, 0, 'subproblems() returns empty list when none' );
}

done_testing();
