=pod

Net::OSCAR::Connection::Chat -- OSCAR chat connections

=cut

package Net::OSCAR::Connection::Chat;


$VERSION = '0.62';

use strict;
use Carp;

use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;
use vars qw(@ISA $VERSION);
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::OldPerl;
@ISA = qw(Net::OSCAR::Connection);

sub invite($$;$) {
	my($self, $who, $message) = @_;
	my $packet = "";
	$message ||= "Join me in this Buddy Chat";

	$self->log_print(OSCAR_DBG_DEBUG, "Inviting $who to join us.");

	$packet .= randchars(8);
	$packet .= pack("nCa*", 2, length($who), $who);

	$packet .= tlv_encode(tlv(
		0x5 => pack("n18 a* n2 a* n5 C a* n3",
				0, 0x7EAF, 0x3A00, 0xB23A, 0, 0x748F, 0x2420, 0x6287,
				0x11D1, 0x8222, 0x4445, 0x5354, 0, 0xA, 2, 1, 0xD,
				length("us-ascii"), "us-ascii", 0xC, length($message), $message,
				0xF, 0, 0x2711, 9+length($self->{url}),
				$self->{exchange}, length($self->{url}),
				$self->{url}, 0, 3, 0
		)
	));

	$self->{session}->svcdo(CONNTYPE_BOS, family => 0x04, subtype => 0x06, data => $packet);
}

sub chat_send($$;$$) {
	my($self, $msg, $noreflect, $away) = @_;
	my $packet = "";

	$packet .= randchars(8);
	$packet .= pack("n", 3); # channel

	my $tlv = tlv;
	$tlv->{1} = "";
	$tlv->{6} = "" unless $noreflect;
	$tlv->{7} = "" if $away;
	$tlv->{5} = tlv_encode(tlv(
		2 => "us-ascii",
		3 => "",
		1 => $msg
	));
	$packet .= tlv_encode($tlv);

	$self->snac_put(family => 0x0E, subtype => 0x05, data => $packet);
}

sub part($) { shift->disconnect(); }	
sub url($) { shift->{url}; }
sub name($) { shift->{name}; }
sub exchange($) { shift->{exchange}; }

1;
