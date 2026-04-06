#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

use Net::ACME2::HTTP::Convert ();

#----------------------------------------------------------------------
# Test: successful 200 response returns Response object
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 200,
        reason  => 'OK',
        success => 1,
        url     => 'https://example.com/directory',
        headers => { 'content-type' => 'application/json' },
        content => '{"newNonce":"https://example.com/new-nonce"}',
    );

    my $obj = Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);

    isa_ok($obj, 'HTTP::Tiny::UA::Response', '200 response returns Response object');
    is($obj->status(), 200, 'status preserved');
    is($obj->url(), 'https://example.com/directory', 'url preserved');
    is($obj->content(), '{"newNonce":"https://example.com/new-nonce"}', 'content preserved');
}

#----------------------------------------------------------------------
# Test: 201 Created response (POST success)
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 201,
        reason  => 'Created',
        success => 1,
        url     => 'https://example.com/acct/1',
        headers => {
            'content-type' => 'application/json',
            'location'     => 'https://example.com/acct/1',
        },
        content => '{"status":"valid"}',
    );

    my $obj = Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('POST', \%resp);

    isa_ok($obj, 'HTTP::Tiny::UA::Response', '201 response returns Response object');
    is($obj->status(), 201, '201 status preserved');
}

#----------------------------------------------------------------------
# Test: 204 No Content response (HEAD for nonce)
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 204,
        reason  => 'No Content',
        success => 1,
        url     => 'https://example.com/new-nonce',
        headers => { 'replay-nonce' => 'nonce-abc123' },
        content => '',
    );

    my $obj = Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('HEAD', \%resp);

    isa_ok($obj, 'HTTP::Tiny::UA::Response', '204 response returns Response object');
    is($obj->status(), 204, '204 status preserved');
}

#----------------------------------------------------------------------
# Test: 3xx redirect response (not an error)
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 301,
        reason  => 'Moved Permanently',
        success => 0,
        url     => 'https://example.com/old',
        headers => { 'location' => 'https://example.com/new' },
        content => '',
    );

    my $obj = Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);

    isa_ok($obj, 'HTTP::Tiny::UA::Response', '301 response returns Response object (not error)');
    is($obj->status(), 301, '301 status preserved');
}

#----------------------------------------------------------------------
# Test: 599 status throws X::HTTP::Network
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 599,
        reason  => 'Internal Exception',
        success => 0,
        url     => 'https://example.com/directory',
        headers => {},
        content => 'Connection refused',
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);
        1;
    } or $err = $@;

    ok($err, '599 status throws exception');
    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Network') },
        '599 throws X::HTTP::Network',
    ) or diag("Got: " . ref($err) || $err);

    is($err->get('method'), 'GET', 'Network exception carries method');
    is($err->get('url'), 'https://example.com/directory', 'Network exception carries url');
    is($err->get('error'), 'Connection refused', 'Network exception carries error content');
}

#----------------------------------------------------------------------
# Test: 599 with TLS error content
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 599,
        reason  => 'Internal Exception',
        success => 0,
        url     => 'https://expired.example.com/directory',
        headers => {},
        content => 'SSL connect attempt failed because of handshake problems',
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);
        1;
    } or $err = $@;

    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Network') },
        'TLS failure throws X::HTTP::Network',
    );
    like($err->get('error'), qr/SSL/, 'Network exception preserves TLS error message');
}

#----------------------------------------------------------------------
# Test: 599 with redirects
#----------------------------------------------------------------------

{
    my @redirects = (
        { status => 301, url => 'https://example.com/old' },
    );

    my %resp = (
        status    => 599,
        reason    => 'Internal Exception',
        success   => 0,
        url       => 'https://example.com/new',
        headers   => {},
        content   => 'Connection timed out',
        redirects => \@redirects,
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);
        1;
    } or $err = $@;

    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Network') },
        '599 with redirects throws X::HTTP::Network',
    );

    my $got_redirects = $err->get('redirects');
    is(ref $got_redirects, 'ARRAY', 'Network exception carries redirects');
    is(scalar @$got_redirects, 1, 'redirects array has correct count');
}

#----------------------------------------------------------------------
# Test: 400 Bad Request throws X::HTTP::Protocol
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 400,
        reason  => 'Bad Request',
        success => 0,
        url     => 'https://example.com/new-order',
        headers => { 'content-type' => 'application/problem+json' },
        content => '{"type":"urn:ietf:params:acme:error:malformed"}',
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('POST', \%resp);
        1;
    } or $err = $@;

    ok($err, '400 status throws exception');
    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Protocol') },
        '400 throws X::HTTP::Protocol',
    ) or diag("Got: " . ref($err) || $err);

    is($err->get('method'), 'POST', 'Protocol exception carries method');
    is($err->get('status'), 400, 'Protocol exception carries status');
    is($err->get('reason'), 'Bad Request', 'Protocol exception carries reason');
    is($err->get('url'), 'https://example.com/new-order', 'Protocol exception carries url');
    like($err->get('content'), qr/malformed/, 'Protocol exception carries response content');
}

#----------------------------------------------------------------------
# Test: 403 Forbidden throws X::HTTP::Protocol
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 403,
        reason  => 'Forbidden',
        success => 0,
        url     => 'https://example.com/acct/1',
        headers => {
            'content-type' => 'application/problem+json',
            'replay-nonce' => 'new-nonce-xyz',
        },
        content => '{"type":"urn:ietf:params:acme:error:unauthorized"}',
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('POST', \%resp);
        1;
    } or $err = $@;

    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Protocol') },
        '403 throws X::HTTP::Protocol',
    );

    is($err->get('status'), 403, 'Protocol exception status is 403');

    # Verify headers are passed through (important for nonce extraction on errors)
    my $headers = $err->get('headers');
    is(ref $headers, 'HASH', 'Protocol exception carries headers hash');
    is($headers->{'replay-nonce'}, 'new-nonce-xyz', 'Protocol exception preserves nonce header');
}

#----------------------------------------------------------------------
# Test: 500 Internal Server Error throws X::HTTP::Protocol
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 500,
        reason  => 'Internal Server Error',
        success => 0,
        url     => 'https://example.com/finalize',
        headers => {},
        content => 'Internal Server Error',
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('POST', \%resp);
        1;
    } or $err = $@;

    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Protocol') },
        '500 throws X::HTTP::Protocol',
    );

    is($err->get('status'), 500, 'Protocol exception status is 500');
}

#----------------------------------------------------------------------
# Test: 4xx with redirects history
#----------------------------------------------------------------------

{
    my @redirects = (
        { status => 302, url => 'https://old.example.com/acme' },
        { status => 301, url => 'https://mid.example.com/acme' },
    );

    my %resp = (
        status    => 404,
        reason    => 'Not Found',
        success   => 0,
        url       => 'https://example.com/order/expired',
        headers   => {},
        content   => 'Not Found',
        redirects => \@redirects,
    );

    my $err;
    eval {
        Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);
        1;
    } or $err = $@;

    ok(
        eval { $err->isa('Net::ACME2::X::HTTP::Protocol') },
        '404 with redirects throws X::HTTP::Protocol',
    );

    my $got_redirects = $err->get('redirects');
    is(ref $got_redirects, 'ARRAY', 'Protocol exception carries redirects');
    is(scalar @$got_redirects, 2, 'redirects history has 2 entries');
}

#----------------------------------------------------------------------
# Test: boundary - status 399 is not an error
#----------------------------------------------------------------------

{
    my %resp = (
        status  => 399,
        reason  => 'Custom',
        success => 0,
        url     => 'https://example.com/resource',
        headers => {},
        content => '',
    );

    my $obj = Net::ACME2::HTTP::Convert::http_tiny_to_net_acme2('GET', \%resp);

    isa_ok($obj, 'HTTP::Tiny::UA::Response', '399 is not treated as error');
    is($obj->status(), 399, '399 status preserved');
}

done_testing();
