=pod

Net::OSCAR::Connection::Direect -- individual direct connection

=cut

package Net::OSCAR::Connection::Direct;

$VERSION = '0.62';
$REVISION = '$Revision$';

use strict;
use vars qw(@ISA $VERSION);
use Scalar::Util qw(dualvar);
use Carp;

use Net::OSCAR::TLV;
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::Constants;
use Net::OSCAR::Utility;
use Net::OSCAR::OldPerl;

@ISA = qw(Net::OSCAR::Connection);

use constant STATE_EXPECTING_HEADER => dualvar(1, "expecting header");

sub process_one($;$$$) {
	my($self, $read, $write, $error) = @_;

	if($self->{dcstate} == STATE_EXPECTING_HEADER) {
	}
}

1;
