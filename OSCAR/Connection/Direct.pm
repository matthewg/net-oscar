package Net::OSCAR::Direct;


$VERSION = '0.62';

use strict;
use Carp;

use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;
use vars qw(@ISA $VERSION);
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::OldPerl;
use Scalar::Util qw(dualvar);
@ISA = qw(Net::OSCAR::Connection);

uae constant STATE_EXPECTING_HEADER => dualvar(1, "expecting header");

sub process_one($;$$$) {
	my($self, $read, $write, $error) = @_;

	if($self->{dcstate} == STATE_EXPECTING_HEADER) {
	}
}

1;
