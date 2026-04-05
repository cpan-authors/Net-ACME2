# This cpanfile is not shipped with the distribution.
# It exists to drive CI dependency installation via
# perl-actions/install-with-cpm.

requires 'autodie';
requires 'constant'                 => '1.23';
requires 'parent'                   => '0.225';
requires 'Call::Context'            => '0.02';
requires 'Crypt::Format'           => '0.06';
requires 'Crypt::Perl'             => '0.18';
requires 'HTTP::Tiny'              => '0.058';
requires 'HTTP::Tiny::UA::Response' => '0.004';
requires 'JSON'                    => '2.9';
requires 'MIME::Base64'            => '3.11';
requires 'Module::Runtime';
requires 'Promise::ES6';
requires 'X::Tiny'                 => '0.12';
requires 'IO::Socket::SSL';

recommends 'Crypt::OpenSSL::RSA';
recommends 'CryptX';
recommends 'Net::Curl::Multi';

on 'configure' => sub {
    requires 'ExtUtils::MakeMaker' => '6.64';
};

on 'build' => sub {
    requires 'ExtUtils::MakeMaker' => '6.64';
};

on 'test' => sub {
    requires 'File::Slurp';
    requires 'Test::More'         => '1.0';
    requires 'Test::Deep';
    requires 'Test::Exception'    => '0.40';
    requires 'Test::NoWarnings';
    requires 'Test::FailWarnings';
    requires 'HTTP::Status';
};
