package Net::OSCAR::Proxy;

$VERSION = '0.62';
$REVISION = '$Revision$';

use strict;
use vars qw($VERSION $REVISION);

use Net::OSCAR::OldPerl;

sub use_socks {
	require Net::SOCKS or return -1;
	
}

1;

