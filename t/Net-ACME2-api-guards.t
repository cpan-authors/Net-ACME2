#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

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
# new() requires key

subtest 'new() without key throws' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    throws_ok(
        sub { MyCA->new() },
        qr/key/i,
        'new() dies without key',
    );
};

#----------------------------------------------------------------------
# http_timeout() - sync mode passthrough

subtest 'http_timeout() in sync mode' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );

    my $timeout = $acme->http_timeout();
    ok( defined $timeout, 'http_timeout() returns a value in sync mode' );

    lives_ok(
        sub { $acme->http_timeout(30) },
        'http_timeout() accepts a new value',
    );

    is( $acme->http_timeout(), 30, 'http_timeout() reflects the new value' );
};

#----------------------------------------------------------------------
# http_timeout() - async mode dies

subtest 'http_timeout() in async mode dies' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    {
        package MockAsyncUA;

        sub new { bless {}, shift }
        sub request { die "should not be called" }
    }

    my $acme = MyCA->new(
        key => $_P256_KEY,
        async_ua => MockAsyncUA->new(),
    );

    throws_ok(
        sub { $acme->http_timeout() },
        qr/asynchronous mode/,
        'http_timeout() dies in async mode',
    );
};

#----------------------------------------------------------------------
# update_account() without key_id

subtest 'update_account() without key_id throws' => sub {
    my $SERVER_OBJ = Test::ACME2_Server->new(
        ca_class => 'MyCA',
    );

    my $acme = MyCA->new( key => $_P256_KEY );

    throws_ok(
        sub { $acme->update_account( contact => ['mailto:test@example.com'] ) },
        qr/key ID/i,
        'update_account() dies without key_id',
    );
};

done_testing();
