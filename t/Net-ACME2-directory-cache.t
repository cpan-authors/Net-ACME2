#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

use Digest::MD5;
use HTTP::Status;
use URI;
use JSON;

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

my $HOST = MyCA->HOST();

subtest 'directory option skips server fetch' => sub {
    my $server = Test::ACME2_Server->new( ca_class => 'MyCA' );

    my $dir_hr = {
        newNonce    => "https://$HOST/my-new-nonce",
        newAccount  => "https://$HOST/my-new-account",
        newOrder    => "https://$HOST/my-new-order",
        keyChange   => "https://$HOST/my-key-change",
        revokeCert  => "https://$HOST/my-revoke-cert",
        meta        => {
            termsOfService => 'https://example.com/tos',
        },
    };

    my $acme = MyCA->new(
        key       => $_P256_KEY,
        directory => $dir_hr,
    );

    my $created = $acme->create_account( termsOfServiceAgreed => 1 );
    is( $created, 1, 'create_account works with pre-cached directory' );
    ok( $acme->key_id(), 'key_id set after create_account' );
};

subtest 'directory option without newNonce throws' => sub {
    my $server = Test::ACME2_Server->new( ca_class => 'MyCA' );

    my $dir_hr = {
        newAccount => "https://$HOST/my-new-account",
    };

    my $acme = MyCA->new(
        key       => $_P256_KEY,
        directory => $dir_hr,
    );

    throws_ok(
        sub { $acme->create_account( termsOfServiceAgreed => 1 ) },
        qr/newNonce/,
        'missing newNonce in directory throws',
    );
};

subtest 'directory option is consumed once' => sub {
    my $server = Test::ACME2_Server->new( ca_class => 'MyCA' );

    my $dir_hr = {
        newNonce    => "https://$HOST/my-new-nonce",
        newAccount  => "https://$HOST/my-new-account",
        newOrder    => "https://$HOST/my-new-order",
        keyChange   => "https://$HOST/my-key-change",
        revokeCert  => "https://$HOST/my-revoke-cert",
        meta        => {
            termsOfService => 'https://example.com/tos',
        },
    };

    my $acme = MyCA->new(
        key       => $_P256_KEY,
        directory => $dir_hr,
    );

    $acme->create_account( termsOfServiceAgreed => 1 );

    my $order = $acme->create_order(
        identifiers => [
            { type => 'dns', value => 'example.com' },
        ],
    );

    isa_ok( $order, 'Net::ACME2::Order', 'subsequent requests use cached directory' );
};

done_testing();
