=pod

Net::OSCAR::Connection::Chat -- OSCAR chat connections

=cut

package Net::OSCAR::Connection::Chat;

$VERSION = '1.11';
$REVISION = '$Revision$';

use strict;
use Carp;

use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;
use vars qw(@ISA $VERSION);
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::Constants;
use Net::OSCAR::Utility;
@ISA = qw(Net::OSCAR::Connection);

sub invite($$;$) {
	my($self, $who, $message) = @_;
	$message ||= "Join me in this Buddy Chat";

	$self->log_print(OSCAR_DBG_DEBUG, "Inviting $who to join us.");
	$self->{session}->svcdo(CONNTYPE_BOS, protobit => "chat invite", protodata => {
		cookie => randchars(8),
		invitee => $who,
		message => $message,
		url => $self->{url},
		exchange => $self->{exchange},
	});
}

sub chat_send($$;$$) {
	my($self, $msg, $noreflect, $away) = @_;

	my %protodata = (
		cookie => randchars(8),
		message_encoding => "us-ascii",
		message => $msg
	);
	$protodata{reflect} = "" unless $noreflect;
	$protodata{is_automatic} = "" if $away;

	$self->proto_send(protobit => "outgoing chat IM", protodata => \%protodata);
}

sub part($) { shift->disconnect(); }	
sub url($) { shift->{url}; }
sub name($) { shift->{name}; }
sub exchange($) { shift->{exchange}; }

1;
