#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

use JSON ();
use MIME::Base64 ();
use Crypt::Format ();

use Net::ACME2::AccountKey ();

#----------------------------------------------------------------------
# Test keys (same PEM strings used across the test suite)
#----------------------------------------------------------------------

my $_RSA_KEY = <<END;
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

my $_P256_KEY = <<END;
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKDv8TBijBVbTYB7lfUnwLn4qjqWD0GD7XOXzdp0wb61oAoGCCqGSM49
AwEHoUQDQgAEBJIULcFadtIBc0TuNzT80UFcfkQ0U7+EPqEJNXamG1H4/z8xVgE7
3hoBfX4xbN2Hx2p26eNIptt+1jj2H/M44g==
-----END EC PRIVATE KEY-----
END

my $_P384_KEY = <<END;
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBqmQFgqovKRpzWs0JST9p/vtRQCHQi3r+6N2zoOorRv/JQoGMHZB+i
c4d7oLnMpx+gBwYFK4EEACKhZANiAATXy7Zwmz5s98iSrQ+Y6lZ56g8/1INa4GY2
LeDDedG+NvKKcj0P3uJV994RSyitrijBQvN2ccSuL67IHUQ3I4O7S7eKRNsU8R7K
3ljffUl1vtb6GnjPgSZgt2zugJCwlH8=
-----END EC PRIVATE KEY-----
END

#----------------------------------------------------------------------
# Tests: constructor and get_type() with PEM inputs
#----------------------------------------------------------------------

{
    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    isa_ok($rsa, 'Net::ACME2::AccountKey', 'RSA PEM constructs AccountKey');
    is($rsa->get_type(), 'rsa', 'RSA PEM key type is rsa');
}

{
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    isa_ok($p256, 'Net::ACME2::AccountKey', 'P-256 PEM constructs AccountKey');
    is($p256->get_type(), 'ecdsa', 'P-256 PEM key type is ecdsa');
}

{
    my $p384 = Net::ACME2::AccountKey->new($_P384_KEY);
    isa_ok($p384, 'Net::ACME2::AccountKey', 'P-384 PEM constructs AccountKey');
    is($p384->get_type(), 'ecdsa', 'P-384 PEM key type is ecdsa');
}

#----------------------------------------------------------------------
# Tests: constructor with DER inputs (no PEM header to guess from)
#----------------------------------------------------------------------

{
    my $rsa_der = Crypt::Format::pem2der($_RSA_KEY);
    my $rsa = Net::ACME2::AccountKey->new($rsa_der);
    is($rsa->get_type(), 'rsa', 'RSA DER key type is rsa');
}

{
    my $ecc_der = Crypt::Format::pem2der($_P256_KEY);
    my $ecc = Net::ACME2::AccountKey->new($ecc_der);
    is($ecc->get_type(), 'ecdsa', 'P-256 DER key type is ecdsa');
}

#----------------------------------------------------------------------
# Tests: get_struct_for_public_jwk (RSA)
#----------------------------------------------------------------------

{
    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $jwk = $rsa->get_struct_for_public_jwk();

    is(ref($jwk), 'HASH', 'RSA JWK is a hashref');
    is($jwk->{'kty'}, 'RSA', 'RSA JWK kty is RSA');
    ok($jwk->{'n'}, 'RSA JWK has modulus (n)');
    ok($jwk->{'e'}, 'RSA JWK has exponent (e)');

    # Public JWK must not contain private components
    ok(!$jwk->{'d'}, 'RSA public JWK has no private exponent (d)');
    ok(!$jwk->{'p'}, 'RSA public JWK has no prime factor (p)');
}

#----------------------------------------------------------------------
# Tests: get_struct_for_public_jwk (ECDSA)
#----------------------------------------------------------------------

{
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    my $jwk = $p256->get_struct_for_public_jwk();

    is(ref($jwk), 'HASH', 'P-256 JWK is a hashref');
    is($jwk->{'kty'}, 'EC', 'P-256 JWK kty is EC');
    is($jwk->{'crv'}, 'P-256', 'P-256 JWK curve is P-256');
    ok($jwk->{'x'}, 'P-256 JWK has x coordinate');
    ok($jwk->{'y'}, 'P-256 JWK has y coordinate');
    ok(!$jwk->{'d'}, 'P-256 public JWK has no private key (d)');
}

{
    my $p384 = Net::ACME2::AccountKey->new($_P384_KEY);
    my $jwk = $p384->get_struct_for_public_jwk();

    is($jwk->{'crv'}, 'P-384', 'P-384 JWK curve is P-384');
}

#----------------------------------------------------------------------
# Tests: get_jwk_thumbprint
#----------------------------------------------------------------------

{
    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $tp = $rsa->get_jwk_thumbprint();
    ok(defined($tp) && length($tp) > 0, 'RSA thumbprint is non-empty');

    # Thumbprint must be deterministic
    my $tp2 = $rsa->get_jwk_thumbprint();
    is($tp2, $tp, 'RSA thumbprint is deterministic');
}

{
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    my $tp = $p256->get_jwk_thumbprint();
    ok(defined($tp) && length($tp) > 0, 'P-256 thumbprint is non-empty');

    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    isnt($tp, $rsa->get_jwk_thumbprint(), 'different keys yield different thumbprints');
}

#----------------------------------------------------------------------
# Tests: get_jwa_alg (ECDSA only)
#----------------------------------------------------------------------

{
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    is($p256->get_jwa_alg(), 'ES256', 'P-256 JWA alg is ES256');
}

{
    my $p384 = Net::ACME2::AccountKey->new($_P384_KEY);
    is($p384->get_jwa_alg(), 'ES384', 'P-384 JWA alg is ES384');
}

#----------------------------------------------------------------------
# Tests: sign_RS256 (RSA)
#----------------------------------------------------------------------

{
    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $sig = $rsa->sign_RS256('hello world');

    ok(defined($sig) && length($sig) > 0, 'RSA sign_RS256 produces a signature');

    # RSA signatures are deterministic (PKCS#1 v1.5)
    my $sig2 = $rsa->sign_RS256('hello world');
    is($sig2, $sig, 'RSA sign_RS256 is deterministic for same input');

    # Different messages yield different signatures
    my $sig3 = $rsa->sign_RS256('different message');
    isnt($sig3, $sig, 'RSA sign_RS256 differs for different input');
}

#----------------------------------------------------------------------
# Tests: sign_jwa (ECDSA)
#----------------------------------------------------------------------

{
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    my $sig = $p256->sign_jwa('hello world');

    ok(defined($sig) && length($sig) > 0, 'P-256 sign_jwa produces a signature');

    # ECDSA signatures are non-deterministic, so we can't compare
    # two signatures for equality. Just verify both are non-empty.
    my $sig2 = $p256->sign_jwa('hello world');
    ok(defined($sig2) && length($sig2) > 0, 'P-256 sign_jwa produces a second signature');
}

{
    my $p384 = Net::ACME2::AccountKey->new($_P384_KEY);
    my $sig = $p384->sign_jwa('test message');
    ok(defined($sig) && length($sig) > 0, 'P-384 sign_jwa produces a signature');
}

#----------------------------------------------------------------------
# Tests: signature verification round-trip
#----------------------------------------------------------------------
# Verify that what AccountKey signs can be verified by Crypt::Perl.

{
    require Crypt::Perl::PK;

    # RSA round-trip
    my $rsa = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $msg = 'verify this message';
    my $sig = $rsa->sign_RS256($msg);

    my $rsa_pub = Crypt::Perl::PK::parse_key($_RSA_KEY);
    ok($rsa_pub->verify_RS256($msg, $sig), 'RSA signature verifies via Crypt::Perl');

    # ECDSA round-trip
    my $p256 = Net::ACME2::AccountKey->new($_P256_KEY);
    my $ecc_sig = $p256->sign_jwa('ecc verify');

    my $ecc_pub = Crypt::Perl::PK::parse_key($_P256_KEY);
    ok($ecc_pub->verify_jwa('ecc verify', $ecc_sig), 'P-256 signature verifies via Crypt::Perl');
}

#----------------------------------------------------------------------
# Tests: constructor preserves caller's $@
#----------------------------------------------------------------------

{
    $@ = 'sentinel error value';
    my $key = Net::ACME2::AccountKey->new($_RSA_KEY);
    is($@, 'sentinel error value', 'constructor preserves caller $@');
}

#----------------------------------------------------------------------
# Tests: PEM vs DER produce equivalent keys
#----------------------------------------------------------------------

{
    my $pem_key = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $der_key = Net::ACME2::AccountKey->new(Crypt::Format::pem2der($_RSA_KEY));

    is_deeply(
        $pem_key->get_struct_for_public_jwk(),
        $der_key->get_struct_for_public_jwk(),
        'RSA PEM and DER produce identical public JWK',
    );

    is(
        $pem_key->get_jwk_thumbprint(),
        $der_key->get_jwk_thumbprint(),
        'RSA PEM and DER produce identical thumbprint',
    );
}

{
    my $pem_key = Net::ACME2::AccountKey->new($_P256_KEY);
    my $der_key = Net::ACME2::AccountKey->new(Crypt::Format::pem2der($_P256_KEY));

    is_deeply(
        $pem_key->get_struct_for_public_jwk(),
        $der_key->get_struct_for_public_jwk(),
        'P-256 PEM and DER produce identical public JWK',
    );
}

done_testing();
