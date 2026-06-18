#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::FailWarnings;

use Net::ACME2::AccessorBase;

{
    package TestAccessor;

    use parent qw( Net::ACME2::AccessorBase );

    use constant _ACCESSORS => ( 'name', 'value', 'status' );
}

# Constructor prefixes keys with underscore
{
    my $obj = TestAccessor->new( name => 'foo', value => 42, status => 'ok' );
    isa_ok( $obj, 'TestAccessor' );
    isa_ok( $obj, 'Net::ACME2::AccessorBase' );
}

# Accessor dispatch via AUTOLOAD
{
    my $obj = TestAccessor->new( name => 'bar', value => 99, status => 'pending' );

    is( $obj->name(),   'bar',     'accessor: name' );
    is( $obj->value(),  99,        'accessor: value' );
    is( $obj->status(), 'pending', 'accessor: status' );
}

# Undef values are returned correctly
{
    my $obj = TestAccessor->new( name => undef );

    is( $obj->name(), undef, 'accessor returns undef when value is undef' );
}

# Missing keys return undef
{
    my $obj = TestAccessor->new( name => 'only' );

    is( $obj->name(),   'only', 'provided accessor works' );
    is( $obj->value(),  undef,  'unset accessor returns undef' );
    is( $obj->status(), undef,  'unset accessor returns undef' );
}

# Unknown method throws
{
    my $obj = TestAccessor->new( name => 'x' );

    throws_ok(
        sub { $obj->nonexistent() },
        qr/define a method/,
        'unknown method dies',
    );
}

# DESTROY does not throw
{
    my $obj = TestAccessor->new( name => 'temp' );
    lives_ok(
        sub { $obj->DESTROY() },
        'DESTROY does not throw',
    );
}

# Constructor with no arguments
{
    my $obj = TestAccessor->new();
    isa_ok( $obj, 'TestAccessor', 'empty constructor works' );
}

done_testing();
