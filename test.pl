# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 2 };
use Net::OSCAR;
ok(1); # If we made it this far, we're ok.

use Net::OSCAR::Protocol ();
use Net::OSCAR::Utility qw(protoparse);

my @ok = (1);
foreach (@Net::OSCAR::Protocol::EXPORT) {
	if(!eval("protoparse(Net::OSCAR::Protocol::$_)")) {
		@ok = ("protocol template $_ wouldn't parse");
		last;
	}
}

ok(@ok);
