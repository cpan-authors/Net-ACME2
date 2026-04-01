#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::FailWarnings;

use JSON ();
use MIME::Base64 ();

use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Crypt;

use Net::ACME2::AccountKey ();
use Net::ACME2::JWTMaker::RSA ();
use Net::ACME2::JWTMaker::ECC ();

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

sub _decode_jws {
    my ($jws_json) = @_;

    my $jws = JSON::decode_json($jws_json);

    my $header = JSON::decode_json(
        MIME::Base64::decode_base64url($jws->{'protected'})
    );

    my $payload_raw = MIME::Base64::decode_base64url($jws->{'payload'});

    # Try JSON decode; fall back to raw string
    my $payload = eval { JSON::decode_json($payload_raw) };
    $payload = $payload_raw if $@;

    return ($jws, $header, $payload);
}

#----------------------------------------------------------------------
# RSA JWTMaker
#----------------------------------------------------------------------

subtest 'RSA - create_full_jws structure' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $maker = Net::ACME2::JWTMaker::RSA->new(key => $key_obj);

    my $jws_json = $maker->create_full_jws(
        payload => { foo => 'bar' },
        extra_headers => { nonce => 'test-nonce', url => 'https://example.com/acme' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    # JWS structure
    ok(exists $jws->{'protected'}, 'JWS has protected header');
    ok(exists $jws->{'payload'}, 'JWS has payload');
    ok(exists $jws->{'signature'}, 'JWS has signature');

    # Header contents
    is($header->{'alg'}, 'RS256', 'alg is RS256');
    ok(exists $header->{'jwk'}, 'full JWS includes jwk');
    is($header->{'nonce'}, 'test-nonce', 'nonce passed through');
    is($header->{'url'}, 'https://example.com/acme', 'url passed through');

    # JWK structure
    is($header->{'jwk'}{'kty'}, 'RSA', 'JWK kty is RSA');
    ok($header->{'jwk'}{'n'}, 'JWK has modulus');
    ok($header->{'jwk'}{'e'}, 'JWK has exponent');

    # Payload
    is_deeply($payload, { foo => 'bar' }, 'payload decoded correctly');
};

subtest 'RSA - create_key_id_jws structure' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $maker = Net::ACME2::JWTMaker::RSA->new(key => $key_obj);

    my $jws_json = $maker->create_key_id_jws(
        key_id => 'https://example.com/acme/acct/12345',
        payload => { status => 'deactivated' },
        extra_headers => { nonce => 'n2', url => 'https://example.com/acme/acct/12345' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    is($header->{'alg'}, 'RS256', 'alg is RS256');
    is($header->{'kid'}, 'https://example.com/acme/acct/12345', 'kid set correctly');
    ok(!exists $header->{'jwk'}, 'key_id JWS does not include jwk');

    is_deeply($payload, { status => 'deactivated' }, 'payload correct');
};

subtest 'RSA - signature is verifiable' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $maker = Net::ACME2::JWTMaker::RSA->new(key => $key_obj);

    my $jws_json = $maker->create_full_jws(
        payload => { test => 1 },
        extra_headers => { nonce => 'n3', url => 'https://example.com' },
    );

    # Verify via key extraction from JWK header (full pipeline)
    my ($key_pub, $header, $payload) = Test::Crypt::decode_acme2_jwt_extract_key($jws_json);
    is($header->{'alg'}, 'RS256', 'verified JWS has correct alg');
    is_deeply($payload, { test => 1 }, 'verified payload matches');
    ok($key_pub->isa('Crypt::Perl::RSA::PublicKey'), 'extracted key is RSA public');
};

#----------------------------------------------------------------------
# ECC JWTMaker (P-256)
#----------------------------------------------------------------------

subtest 'ECC P-256 - create_full_jws structure' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_P256_KEY);
    my $maker = Net::ACME2::JWTMaker::ECC->new(key => $key_obj);

    my $jws_json = $maker->create_full_jws(
        payload => { domains => ['example.com'] },
        extra_headers => { nonce => 'n4', url => 'https://ca.example.com/new-order' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    is($header->{'alg'}, 'ES256', 'P-256 uses ES256');
    ok(exists $header->{'jwk'}, 'full JWS includes jwk');
    is($header->{'jwk'}{'kty'}, 'EC', 'JWK kty is EC');
    is($header->{'jwk'}{'crv'}, 'P-256', 'JWK curve is P-256');

    is_deeply($payload, { domains => ['example.com'] }, 'payload correct');
};

subtest 'ECC P-256 - signature is verifiable' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_P256_KEY);
    my $maker = Net::ACME2::JWTMaker::ECC->new(key => $key_obj);

    my $jws_json = $maker->create_full_jws(
        payload => { challenge => 'response' },
        extra_headers => { nonce => 'n5', url => 'https://ca.example.com' },
    );

    # Verify via key extraction from JWK header
    my ($key_pub, $header, $payload) = Test::Crypt::decode_acme2_jwt_extract_key($jws_json);
    is($header->{'alg'}, 'ES256', 'verified alg');
    is_deeply($payload, { challenge => 'response' }, 'verified payload');
    ok($key_pub->isa('Crypt::Perl::ECDSA::PublicKey'), 'extracted key is ECC public');
};

#----------------------------------------------------------------------
# ECC JWTMaker (P-384)
#----------------------------------------------------------------------

subtest 'ECC P-384 - create_full_jws structure' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_P384_KEY);
    my $maker = Net::ACME2::JWTMaker::ECC->new(key => $key_obj);

    my $jws_json = $maker->create_full_jws(
        payload => 'raw-string-payload',
        extra_headers => { nonce => 'n6', url => 'https://ca.example.com' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    is($header->{'alg'}, 'ES384', 'P-384 uses ES384');
    is($header->{'jwk'}{'crv'}, 'P-384', 'JWK curve is P-384');

    # String payloads are not JSON-wrapped
    is($payload, 'raw-string-payload', 'string payload preserved as-is');
};

subtest 'ECC P-384 - key_id JWS' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_P384_KEY);
    my $maker = Net::ACME2::JWTMaker::ECC->new(key => $key_obj);

    my $jws_json = $maker->create_key_id_jws(
        key_id => 'https://ca.example.com/acct/99',
        payload => { finalize => 1 },
        extra_headers => { nonce => 'n7', url => 'https://ca.example.com/order/1/finalize' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    is($header->{'alg'}, 'ES384', 'alg is ES384');
    is($header->{'kid'}, 'https://ca.example.com/acct/99', 'kid correct');
    ok(!exists $header->{'jwk'}, 'no jwk in key_id JWS');
};

#----------------------------------------------------------------------
# Empty/special payloads
#----------------------------------------------------------------------

subtest 'empty string payload (POST-as-GET)' => sub {
    my $key_obj = Net::ACME2::AccountKey->new($_RSA_KEY);
    my $maker = Net::ACME2::JWTMaker::RSA->new(key => $key_obj);

    my $jws_json = $maker->create_key_id_jws(
        key_id => 'https://ca.example.com/acct/1',
        payload => '',
        extra_headers => { nonce => 'n8', url => 'https://ca.example.com/order/1' },
    );

    my ($jws, $header, $payload) = _decode_jws($jws_json);

    is($header->{'alg'}, 'RS256', 'alg correct for POST-as-GET');
    is($payload, '', 'empty payload for POST-as-GET');
};

done_testing();
