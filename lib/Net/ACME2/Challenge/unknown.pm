package Net::ACME2::Challenge::unknown;

use strict;
use warnings;

use parent qw( Net::ACME2::Challenge );

=encoding utf-8

=head1 NAME

Net::ACME2::Challenge::unknown

=head1 DESCRIPTION

This module is instantiated by L<Net::ACME2::Authorization> and is a
subclass of L<Net::ACME2::Challenge>.

=head1 METHODS

NONE. If the ACME server returns an unknown challenge, this will be used.

=cut

1;
