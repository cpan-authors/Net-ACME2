#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

use Crypt::Format ();
use MIME::Base64 ();
use JSON ();

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Crypt;

use Net::ACME2::AccountKey;

#----------------------------------------------------------------------
# Test keys (same as in Net-ACME2.t for consistency)
#----------------------------------------------------------------------

my $RSA_KEY_PEM = <<END;
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCkOYWppsEFfKHqIntkpUjmuwnBH3sRYP00YRdIhrz6ypRpxX6H
c2Q0IrSprutu9/dUy0j9a96q3kRa9Qxsa7paQj7xtlTWx9qMHvhlrG3eLMIjXT0J
4+MSCw5LwViZenh0obBWcBbnNYNLaZ9o31DopeKcYOZBMogF6YqHdpIsFQIDAQAB
AoGAN7RjSFaN5qSN73Ne05bVEZ6kAmQBRLXXbWr5kNpTQ+ZvTSl2b8+OT7jt+xig
N3XY6WRDD+MFFoRqP0gbvLMV9HiZ4tJ/gTGOHesgyeemY/CBLRjP0mvHOpgADQuA
+VBZmWpiMRN8tu6xHzKwAxIAfXewpn764v6aXShqbQEGSEkCQQDSh9lbnpB/R9+N
psqL2+gyn/7bL1+A4MJwiPqjdK3J/Fhk1Yo/UC1266MzpKoK9r7MrnGc0XjvRpMp
JX8f4MTbAkEAx7FvmEuvsD9li7ylgnPW/SNAswI6P7SBOShHYR7NzT2+FVYd6VtM
vb1WrhO85QhKgXNjOLLxYW9Uo8s1fNGtzwJAbwK9BQeGT+cZJPsm4DpzpIYi/3Zq
WG2reWVxK9Fxdgk+nuTOgfYIEyXLJ4cTNrbHAuyU8ciuiRTgshiYgLmncwJAETZx
KQ51EVsVlKrpFUqI4H72Z7esb6tObC/Vn0B5etR0mwA2SdQN1FkKrKyU3qUNTwU0
K0H5Xm2rPQcaEC0+rwJAEuvRdNQuB9+vzOW4zVig6HS38bHyJ+qLkQCDWbbwrNlj
vcVkUrsg027gA5jRttaXMk8x9shFuHB9V5/pkBFwag==
-----END RSA PRIVATE KEY-----
END

my $P256_KEY_PEM = <<END;
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKDv8TBijBVbTYB7lfUnwLn4qjqWD0GD7XOXzdp0wb61oAoGCCqGSM49
AwEHoUQDQgAEBJIULcFadtIBc0TuNzT80UFcfkQ0U7+EPqEJNXamG1H4/z8xVgE7
3hoBfX4xbN2Hx2p26eNIptt+1jj2H/M44g==
-----END EC PRIVATE KEY-----
END

my $P384_KEY_PEM = <<END;
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBqmQFgqovKRpzWs0JST9p/vtRQCHQi3r+6N2zoOorRv/JQoGMHZB+i
c4d7oLnMpx+gBwYFK4EEACKhZANiAATXy7Zwmz5s98iSrQ+Y6lZ56g8/1INa4GY2
LeDDedG+NvKKcj0P3uJV994RSyitrijBQvN2ccSuL67IHUQ3I4O7S7eKRNsU8R7K
3ljffUl1vtb6GnjPgSZgt2zugJCwlH8=
-----END EC PRIVATE KEY-----
END

#----------------------------------------------------------------------
# Helper: verify an RS256 signature using Crypt::Perl
#----------------------------------------------------------------------

sub _verify_rs256 {
    my ($key_pem, $message, $signature) = @_;

    my $kobj = Crypt::Perl::PK::parse_key($key_pem);
    return $kobj->verify_RS256($message, $signature);
}

sub _verify_ecdsa {
    my ($key_pem, $message, $signature) = @_;

    my $kobj = Crypt::Perl::PK::parse_key($key_pem);
    return $kobj->verify_jwa($message, $signature);
}

#----------------------------------------------------------------------
# RSA key tests
#----------------------------------------------------------------------

subtest 'RSA key from PEM' => sub {
    my $ak = Net::ACME2::AccountKey->new($RSA_KEY_PEM);
    isa_ok($ak, 'Net::ACME2::AccountKey');
    is($ak->get_type(), 'rsa', 'key type is rsa');

    diag "RSA backend: " . $ak->{'engine'};

    # sign_RS256 produces valid signature
    my $msg = 'test message for RS256 signing';
    my $sig = $ak->sign_RS256($msg);
    ok(defined $sig && length($sig) > 0, 'sign_RS256 returns non-empty signature');
    ok(_verify_rs256($RSA_KEY_PEM, $msg, $sig), 'RS256 signature verifies');

    # Signature is deterministic for RSA PKCS#1 v1.5
    my $sig2 = $ak->sign_RS256($msg);
    is($sig, $sig2, 'RS256 signature is deterministic (PKCS#1 v1.5)');

    # Different messages produce different signatures
    my $sig_other = $ak->sign_RS256('different message');
    isnt($sig, $sig_other, 'different messages produce different signatures');

    # JWK export
    my $jwk = $ak->get_struct_for_public_jwk();
    is(ref $jwk, 'HASH', 'JWK is a hashref');
    is($jwk->{'kty'}, 'RSA', 'JWK kty is RSA');
    ok(defined $jwk->{'n'}, 'JWK has n (modulus)');
    ok(defined $jwk->{'e'}, 'JWK has e (exponent)');
    ok(!exists $jwk->{'d'}, 'JWK does not expose private key');

    # JWK thumbprint
    my $thumbprint = $ak->get_jwk_thumbprint();
    ok(defined $thumbprint && length($thumbprint) > 0, 'JWK thumbprint is non-empty');

    # Thumbprint is deterministic
    my $thumbprint2 = $ak->get_jwk_thumbprint();
    is($thumbprint, $thumbprint2, 'JWK thumbprint is deterministic');
};

subtest 'RSA key from DER' => sub {
    my $der = Crypt::Format::pem2der($RSA_KEY_PEM);
    my $ak = Net::ACME2::AccountKey->new($der);
    isa_ok($ak, 'Net::ACME2::AccountKey');
    is($ak->get_type(), 'rsa', 'key type is rsa from DER');

    my $msg = 'test DER key signing';
    my $sig = $ak->sign_RS256($msg);
    ok(_verify_rs256($RSA_KEY_PEM, $msg, $sig), 'DER-loaded key produces valid RS256 signature');

    # JWK should match PEM-loaded key
    my $ak_pem = Net::ACME2::AccountKey->new($RSA_KEY_PEM);
    is_deeply($ak->get_struct_for_public_jwk(), $ak_pem->get_struct_for_public_jwk(),
        'DER and PEM produce same JWK');
    is($ak->get_jwk_thumbprint(), $ak_pem->get_jwk_thumbprint(),
        'DER and PEM produce same thumbprint');
};

#----------------------------------------------------------------------
# ECDSA P-256 key tests
#----------------------------------------------------------------------

subtest 'ECDSA P-256 key from PEM' => sub {
    my $ak = Net::ACME2::AccountKey->new($P256_KEY_PEM);
    isa_ok($ak, 'Net::ACME2::AccountKey');
    is($ak->get_type(), 'ecdsa', 'key type is ecdsa');

    diag "P-256 backend: " . $ak->{'engine'};

    is($ak->get_jwa_alg(), 'ES256', 'JWA algorithm is ES256 for P-256');

    # sign_jwa produces valid signature
    my $msg = 'test message for ES256 signing';
    my $sig = $ak->sign_jwa($msg);
    ok(defined $sig && length($sig) > 0, 'sign_jwa returns non-empty signature');
    ok(_verify_ecdsa($P256_KEY_PEM, $msg, $sig), 'ES256 signature verifies');

    # ECDSA signatures are non-deterministic (random k)
    my $sig2 = $ak->sign_jwa($msg);
    # Both should verify even if different
    ok(_verify_ecdsa($P256_KEY_PEM, $msg, $sig2), 'second ES256 signature also verifies');

    # JWK export
    my $jwk = $ak->get_struct_for_public_jwk();
    is(ref $jwk, 'HASH', 'JWK is a hashref');
    is($jwk->{'kty'}, 'EC', 'JWK kty is EC');
    is($jwk->{'crv'}, 'P-256', 'JWK curve is P-256');
    ok(defined $jwk->{'x'}, 'JWK has x coordinate');
    ok(defined $jwk->{'y'}, 'JWK has y coordinate');
    ok(!exists $jwk->{'d'}, 'JWK does not expose private key');

    # JWK thumbprint
    my $thumbprint = $ak->get_jwk_thumbprint();
    ok(defined $thumbprint && length($thumbprint) > 0, 'JWK thumbprint is non-empty');
};

subtest 'ECDSA P-256 key from DER' => sub {
    my $der = Crypt::Format::pem2der($P256_KEY_PEM);
    my $ak = Net::ACME2::AccountKey->new($der);
    isa_ok($ak, 'Net::ACME2::AccountKey');
    is($ak->get_type(), 'ecdsa', 'key type is ecdsa from DER');

    my $msg = 'test DER ECDSA signing';
    my $sig = $ak->sign_jwa($msg);
    ok(_verify_ecdsa($P256_KEY_PEM, $msg, $sig), 'DER-loaded key produces valid ES256 signature');

    # Thumbprint should match PEM-loaded key
    my $ak_pem = Net::ACME2::AccountKey->new($P256_KEY_PEM);
    is($ak->get_jwk_thumbprint(), $ak_pem->get_jwk_thumbprint(),
        'DER and PEM produce same thumbprint');
};

#----------------------------------------------------------------------
# ECDSA P-384 key tests
#----------------------------------------------------------------------

subtest 'ECDSA P-384 key from PEM' => sub {
    my $ak = Net::ACME2::AccountKey->new($P384_KEY_PEM);
    isa_ok($ak, 'Net::ACME2::AccountKey');
    is($ak->get_type(), 'ecdsa', 'key type is ecdsa');

    diag "P-384 backend: " . $ak->{'engine'};

    is($ak->get_jwa_alg(), 'ES384', 'JWA algorithm is ES384 for P-384');

    my $msg = 'test message for ES384 signing';
    my $sig = $ak->sign_jwa($msg);
    ok(defined $sig && length($sig) > 0, 'sign_jwa returns non-empty signature');
    ok(_verify_ecdsa($P384_KEY_PEM, $msg, $sig), 'ES384 signature verifies');

    # JWK export
    my $jwk = $ak->get_struct_for_public_jwk();
    is(ref $jwk, 'HASH', 'JWK is a hashref');
    is($jwk->{'kty'}, 'EC', 'JWK kty is EC');
    is($jwk->{'crv'}, 'P-384', 'JWK curve is P-384');

    # Thumbprint
    my $thumbprint = $ak->get_jwk_thumbprint();
    ok(defined $thumbprint && length($thumbprint) > 0, 'JWK thumbprint is non-empty');
};

#----------------------------------------------------------------------
# Cross-backend consistency (RSA): if Crypt::Perl is available alongside
# an XS backend, verify they produce the same JWK and thumbprint.
#----------------------------------------------------------------------

subtest 'RSA cross-backend consistency' => sub {
    my $ak = Net::ACME2::AccountKey->new($RSA_KEY_PEM);
    my $engine = $ak->{'engine'};

    if ($engine eq 'crypt_perl') {
        plan skip_all => 'Only Crypt::Perl available, nothing to cross-check';
        return;
    }

    diag "Comparing $engine output against Crypt::Perl reference";

    # Get JWK and thumbprint from the XS backend
    my $xs_jwk = $ak->get_struct_for_public_jwk();
    my $xs_thumbprint = $ak->get_jwk_thumbprint();

    # Get reference values from Crypt::Perl
    require Crypt::Perl::PK;
    my $cp_key = Crypt::Perl::PK::parse_key($RSA_KEY_PEM);
    my $cp_jwk = $cp_key->get_struct_for_public_jwk();
    my $cp_thumbprint = $cp_key->get_jwk_thumbprint('sha256');

    # Compare JWK fields
    is($xs_jwk->{'kty'}, $cp_jwk->{'kty'}, 'JWK kty matches Crypt::Perl');
    is($xs_jwk->{'n'}, $cp_jwk->{'n'}, 'JWK n (modulus) matches Crypt::Perl');
    is($xs_jwk->{'e'}, $cp_jwk->{'e'}, 'JWK e (exponent) matches Crypt::Perl');

    # Compare thumbprint
    is($xs_thumbprint, $cp_thumbprint, 'JWK thumbprint matches Crypt::Perl');

    # Verify signature from XS backend using Crypt::Perl
    my $msg = 'cross-backend verification';
    my $sig = $ak->sign_RS256($msg);
    ok($cp_key->verify_RS256($msg, $sig),
        "$engine signature verified by Crypt::Perl");
};

#----------------------------------------------------------------------
# Backend detection diagnostic
#----------------------------------------------------------------------

subtest 'backend selection diagnostic' => sub {
    my $rsa_ak = Net::ACME2::AccountKey->new($RSA_KEY_PEM);
    my $ec_ak  = Net::ACME2::AccountKey->new($P256_KEY_PEM);

    my $rsa_engine = $rsa_ak->{'engine'};
    my $ec_engine  = $ec_ak->{'engine'};

    diag "RSA engine:   $rsa_engine";
    diag "ECDSA engine: $ec_engine";

    # Verify expected priority order
    SKIP: {
        skip 'Crypt::OpenSSL::RSA not available', 1
            unless eval { require Crypt::OpenSSL::RSA; require Crypt::OpenSSL::Bignum; 1 };
        is($rsa_engine, 'crypt_openssl_rsa',
            'RSA prefers Crypt::OpenSSL::RSA when available');
    }

    SKIP: {
        skip 'Crypt::PK::ECC not available', 1
            unless eval { require Crypt::PK::ECC; 1 };
        is($ec_engine, 'crypt_pk',
            'ECDSA prefers Crypt::PK::ECC when available');
    }

    pass('backend selection completed without error');
};

done_testing();
