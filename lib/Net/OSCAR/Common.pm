package Net::OSCAR::Common;

$VERSION = 0.01;

use strict;
use warnings;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS $VERSION);
require Exporter;
@ISA = qw(Exporter);

%EXPORT_TAGS = (
	standard => [qw(
		VISMODE_PERMITALL
		VISMODE_DENYALL
		VISMODE_PERMITSOME
		VISMODE_DENYSOME
		VISMODE_PERMITBUDS
		RATE_CLEAR
		RATE_ALERT
		RATE_LIMIT
		RATE_DISCONNECT
	)],
	all => [qw(
		VISMODE_PERMITALL VISMODE_DENYALL VISMODE_PERMITSOME VISMODE_DENYSOME VISMODE_PERMITBUDS RATE_CLEAR RATE_ALERT RATE_LIMIT RATE_DISCONNECT
		FLAP_CHAN_NEWCONN FLAP_CHAN_SNAC FLAP_CHAN_ERR FLAP_CHAN_CLOSE
		CONNTYPE_LOGIN CONNTYPE_BOS CONNTYPE_ADMIN CONNTYPE_CHAT CONNTYPE_CHATNAV
		MODBL_ACTION_ADD MODBL_ACTION_DEL MODBL_WHAT_BUDDY MODBL_WHAT_GROUP MODBL_WHAT_PERMIT MODBL_WHAT_DENY
		GROUP_PERMIT GROUP_DENY
		ENCODING
		ERRORS
		randchars debug_print debug_printf hexdump normalize
	)]
);
@EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant FLAP_CHAN_NEWCONN => 0x01;
use constant FLAP_CHAN_SNAC => 0x02;
use constant FLAP_CHAN_ERR => 0x03;
use constant FLAP_CHAN_CLOSE => 0x04;

use constant CONNTYPE_LOGIN => 0;
use constant CONNTYPE_BOS => 0x2;
use constant CONNTYPE_ADMIN => 0x7;
use constant CONNTYPE_CHAT => 0xE;
use constant CONNTYPE_CHATNAV => 0xD;

use constant MODBL_ACTION_ADD => 0x1;
use constant MODBL_ACTION_DEL => 0x2;

use constant MODBL_WHAT_BUDDY => 0x1;
use constant MODBL_WHAT_GROUP => 0x2;
use constant MODBL_WHAT_PERMIT => 0x3;
use constant MODBL_WHAT_DENY => 0x4;

use constant VISMODE_PERMITALL  => 0x1;
use constant VISMODE_DENYALL    => 0x2;
use constant VISMODE_PERMITSOME => 0x3;
use constant VISMODE_DENYSOME   => 0x4;
use constant VISMODE_PERMITBUDS => 0x5;

use constant GROUP_PERMIT => 0x0002;
use constant GROUP_DENY   => 0x0003;

use constant RATE_CLEAR => 1;
use constant RATE_ALERT => 2;
use constant RATE_LIMIT => 3;
use constant RATE_DISCONNECT => 4;

use constant ENCODING => 'text/aolrtf; charset="us-ascii"';

use constant ERRORS => split(/\n/, <<EOF);
Invalid error
Invalid SNAC
Rate to host
Rate to client
Not logged in
Service unavailable
Service not defined
Obsolete SNAC
Not supported by host
Not supported by client
Refused by client
Reply too big
Responses lost
Request denied
Busted SNAC payload
Insufficient rights
In local permit/deny
Too evil (sender)
Too evil (receiver)
User temporarily unavailable
No match
List overflow
Request ambiguous
Queue full
Not while on AOL
EOF

sub randchars($) {
	my $count = shift;
	my $retval = "";
	for(my $i = 0; $i < $count; $i++) { $retval .= chr(int(rand(256))); }
	return $retval;
}

sub debug_print($@) {
	my($obj) = (shift);
	my $session = exists($obj->{session}) ? $obj->{session} : $obj;
	return unless $session->{DEBUG};
	print STDERR "(",$session->{screenname},") " if $session->{SNDEBUG};
	print STDERR $obj->{description}, ": " if $obj->{description};
	print STDERR join("", @_), "\n";
}

sub debug_printf($@) {
	my($obj, $fmtstr) = (shift, shift);
	my $session = exists($obj->{session}) ? $obj->{session} : $obj;
	return unless $session->{DEBUG};
	print STDERR "(",$session->{screenname},") " if $session->{SNDEBUG};
	print STDERR $obj->{description} . ": " if $obj->{description};
	printf STDERR $fmtstr, @_;
	print STDERR "\n";
}

sub hexdump($) {
	my $stuff = shift;
	my $retbuff = "";
	my @stuff;

	for(my $i = 0; $i < length($stuff); $i++) {
		push @stuff, substr($stuff, $i, 1);
	}

	return $stuff unless grep { $_ lt chr(0x20) or $_ gt chr(0x7E) } @stuff;
	while(@stuff) {
		my $i = 0;
		$retbuff .= "\n\t";
		my @currstuff = splice(@stuff, 0, 16);

		foreach my $currstuff(@currstuff) {
			$retbuff .= " " unless $i % 4;
			$retbuff .= " " unless $i % 8;
			$retbuff .= sprintf "%02X ", ord($currstuff);
			$i++;
		}
		for(; $i < 16; $i++) {
			$retbuff .= " " unless $i % 4;
			$retbuff .= " " unless $i % 8;
			$retbuff .= "   ";
		}

		$retbuff .= "  ";
		$i = 0;
		foreach my $currstuff(@currstuff) {
			$retbuff .= " " unless $i % 4;
			$retbuff .= " " unless $i % 8;
			if($currstuff ge chr(0x20) and $currstuff le chr(0x7E)) {
				$retbuff .= $currstuff;
			} else {
				$retbuff .= ".";
			}
			$i++;
		}
	}
	return $retbuff;
}

sub normalize($) {
	my $temp = shift;
	$temp =~ tr/ //d if $temp;
	return lc($temp);
}


1;
