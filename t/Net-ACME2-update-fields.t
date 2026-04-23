#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Deep;
use Test::FailWarnings;

use Digest::MD5;
use HTTP::Status;
use URI;
use JSON;

use Crypt::Format ();
use MIME::Base64 ();

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::ACME2_Server;

#----------------------------------------------------------------------

{
    package MyCA;

    use parent qw( Net::ACME2 );

    use constant {
        HOST => 'acme.someca.net',
        DIRECTORY_PATH => '/acme-directory',
    };
}

my $_P256_KEY = <<END;
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKDv8TBijBVbTYB7lfUnwLn4qjqWD0GD7XOXzdp0wb61oAoGCCqGSM49
AwEHoUQDQgAEBJIULcFadtIBc0TuNzT80UFcfkQ0U7+EPqEJNXamG1H4/z8xVgE7
3hoBfX4xbN2Hx2p26eNIptt+1jj2H/M44g==
-----END EC PRIVATE KEY-----
END

#----------------------------------------------------------------------

subtest 'Order error field populated on invalid status' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );
    $acme->create_account( termsOfServiceAgreed => 1 );

    my $order = $acme->create_order(
        identifiers => [
            { type => 'dns', value => 'example.com' },
        ],
    );

    is( $order->error(), undef, 'no error on new order' );

    # Simulate the server marking the order invalid with an error
    $SERVER_OBJ->{'_order_invalid'} = 1;
    $SERVER_OBJ->{'_order_error'} = {
        type   => 'urn:ietf:params:acme:error:unauthorized',
        detail => 'CAA record forbids issuance',
        status => 403,
    };

    my $status = $acme->poll_order($order);
    is( $status, 'invalid', 'poll_order returns invalid' );
    is( $order->status(), 'invalid', 'order status updated' );

    my $error = $order->error();
    ok( $error, 'error field is populated' );
    is( ref $error, 'HASH', 'error is a hashref' );
    is( $error->{'type'}, 'urn:ietf:params:acme:error:unauthorized', 'error type' );
    is( $error->{'detail'}, 'CAA record forbids issuance', 'error detail' );
    is( $error->{'status'}, 403, 'error status' );
};

subtest 'Order error cleared when order becomes valid' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );
    $acme->create_account( termsOfServiceAgreed => 1 );

    my $order = $acme->create_order(
        identifiers => [
            { type => 'dns', value => 'example.com' },
        ],
    );

    # First, mark order invalid with error
    $SERVER_OBJ->{'_order_invalid'} = 1;
    $SERVER_OBJ->{'_order_error'} = {
        type   => 'urn:ietf:params:acme:error:unauthorized',
        detail => 'temporary issue',
    };

    $acme->poll_order($order);
    ok( $order->error(), 'error set after invalid poll' );

    # Now simulate recovery (server no longer reports error)
    $SERVER_OBJ->{'_order_invalid'} = 0;
    $SERVER_OBJ->{'_order_finalized'} = 1;
    delete $SERVER_OBJ->{'_order_error'};

    $acme->poll_order($order);
    is( $order->status(), 'valid', 'order recovered to valid' );
    is( $order->error(), undef, 'error cleared after valid poll' );
};

subtest 'Order expires updated on poll' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );
    $acme->create_account( termsOfServiceAgreed => 1 );

    my $order = $acme->create_order(
        identifiers => [
            { type => 'dns', value => 'example.com' },
        ],
    );

    # Initially no expires (our mock doesn't set one by default)
    my $initial_expires = $order->expires();

    # Set expires on the server
    $SERVER_OBJ->{'_order_expires'} = '2099-12-31T23:59:59Z';

    $acme->poll_order($order);
    is( $order->expires(), '2099-12-31T23:59:59Z', 'expires updated from poll response' );

    # Change expires again
    $SERVER_OBJ->{'_order_expires'} = '2100-06-15T12:00:00Z';

    $acme->poll_order($order);
    is( $order->expires(), '2100-06-15T12:00:00Z', 'expires updated again on subsequent poll' );
};

subtest 'Authorization expires updated on poll' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );
    $acme->create_account( termsOfServiceAgreed => 1 );

    my $order = $acme->create_order(
        identifiers => [
            { type => 'dns', value => 'example.com' },
        ],
    );

    my @authz_urls = $order->authorizations();
    my $authz = $acme->get_authorization( $authz_urls[0] );

    # Initially no expires
    my $initial_expires = $authz->expires();

    # Set expires on the server
    $SERVER_OBJ->{'_authz_expires'} = '2099-12-31T23:59:59Z';

    $acme->poll_authorization($authz);
    is( $authz->expires(), '2099-12-31T23:59:59Z', 'authz expires updated from poll response' );
};

done_testing();
