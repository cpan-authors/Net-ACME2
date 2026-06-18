#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

use Net::ACME2::LetsEncrypt;

# DIRECTORY_PATH constant
is(
    Net::ACME2::LetsEncrypt->DIRECTORY_PATH(),
    '/directory',
    'DIRECTORY_PATH is /directory',
);

# HOST: production (default)
is(
    Net::ACME2::LetsEncrypt->HOST(),
    'acme-v02.api.letsencrypt.org',
    'HOST() defaults to production',
);

# HOST: explicit production
is(
    Net::ACME2::LetsEncrypt->HOST( environment => 'production' ),
    'acme-v02.api.letsencrypt.org',
    'HOST(environment => production) returns production',
);

# HOST: staging
is(
    Net::ACME2::LetsEncrypt->HOST( environment => 'staging' ),
    'acme-staging-v02.api.letsencrypt.org',
    'HOST(environment => staging) returns staging',
);

# HOST: invalid environment throws
throws_ok(
    sub { Net::ACME2::LetsEncrypt->HOST( environment => 'bogus' ) },
    qr/Invalid/,
    'HOST(environment => bogus) dies',
);

# Subclass relationship
ok(
    Net::ACME2::LetsEncrypt->isa('Net::ACME2'),
    'LetsEncrypt is a Net::ACME2 subclass',
);

done_testing();
