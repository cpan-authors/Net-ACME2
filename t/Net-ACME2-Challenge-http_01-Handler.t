use strict;
use warnings;
use autodie;

use Test::More;
use Test::FailWarnings;
use Test::Deep;
use Test::Exception;

use File::Spec ();
use File::Slurp ();
use File::Temp ();

use Net::ACME2::Challenge::http_01 ();

use Net::ACME2::Challenge::http_01::Handler ();

#----------------------------------------------------------------------

my $challenge = Net::ACME2::Challenge::http_01->new(
    token => 'my_token',
);

my $docroot = File::Temp::tempdir( CLEANUP => 1 );

my $fs_path;

{
    my $handler = $challenge->create_handler( 'my_key_authz', $docroot );

    $fs_path = File::Spec->catdir( $docroot, $challenge->path() );

    ok(
        ( -e $fs_path ),
        'challenge path is created',
    );

    my $contents = File::Slurp::read_file($fs_path);

    is(
        $contents,
        'my_key_authz',
        '… and the contents match expectations',
    );
}

ok(
    !( -e $fs_path ),
    'challenge path is removed on DESTROY',
);

{
    my $authz = bless [], 'Mock::Authz';

    my $handler = $challenge->create_handler( $authz, $docroot );

    my $contents = File::Slurp::read_file($fs_path);

    is(
        $contents,
        'my_object_key_authz',
        'create_handler() does the right thing with an authz object',
    );
}

#This ensures that there's no warning or error otherwise
#if the file goes away prematurely.
{
    my $handler = $challenge->create_handler( 'my_key_authz', $docroot );

    my $fs_path = File::Spec->catdir( $docroot, $challenge->path() );

    unlink $fs_path;
}

# Test with $ASSUME_UNIX_PATHS enabled (exercises the substr-based
# directory extraction, which had a bug where it extracted the filename
# portion instead of the directory).
SKIP: {
    skip 'ASSUME_UNIX_PATHS test requires Unix-like OS', 3 if $^O eq 'MSWin32';

    my $docroot2 = File::Temp::tempdir( CLEANUP => 1 );

    local $Net::ACME2::Challenge::http_01::Handler::ASSUME_UNIX_PATHS = 1;

    my $expected_dir = "$docroot2/.well-known/acme-challenge";
    my $expected_file = "$expected_dir/my_token";

    my $handler = $challenge->create_handler( 'unix_key_authz', $docroot2 );

    ok(
        ( -d $expected_dir ),
        'ASSUME_UNIX_PATHS: challenge directory is created correctly',
    );

    ok(
        ( -e $expected_file ),
        'ASSUME_UNIX_PATHS: challenge file is created',
    );

    my $contents = File::Slurp::read_file($expected_file);

    is(
        $contents,
        'unix_key_authz',
        'ASSUME_UNIX_PATHS: file contents match expectations',
    );
}

done_testing();

#----------------------------------------------------------------------

package Mock::Authz;

use Test::More;

sub make_key_authorization {
    my ($self, $challenge) = @_;

    isa_ok( $challenge, 'Net::ACME2::Challenge::http_01', 'challenge given to make_key_authorization()');

    return 'my_object_key_authz';
}
