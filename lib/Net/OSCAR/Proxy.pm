package Net::OSCAR::Proxy;

$VERSION = '0.62';

use strict;
use vars qw($VERSION);
use Carp;

use Net::OSCAR::Common qw(:all);
use Net::OSCAR::OldPerl;

sub use_socks {
	require Net::SOCKS or return -1;
	
}

1;

