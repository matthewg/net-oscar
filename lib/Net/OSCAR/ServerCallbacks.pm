=pod

Net::OSCAR::ServerCallbacks -- Process responses from OSCAR client

=cut

package Net::OSCAR::ServerCallbacks;

$VERSION = '1.999';
$REVISION = '$Revision$';

use strict;
use vars qw($VERSION);
use Carp;

use Net::OSCAR::Common qw(:all);
use Net::OSCAR::Constants;
use Net::OSCAR::Utility;
use Net::OSCAR::TLV;
use Net::OSCAR::Buddylist;
use Net::OSCAR::_BLInternal;
use Net::OSCAR::XML;

use Digest::MD5 qw(md5);

our $SESSIONS = bltie();
our $SCREENNAMES = bltie();
our %COOKIES;
$SCREENNAMES->{somedude} = {sn => "Some Dude", pw => "somepass", email => 'some@dude.com'};
$SCREENNAMES->{otherdude} = {sn => "Other Dude", pw => "otherpass", email => 'other@dude.com'};


sub srv_send_error($$) {
	my($connection, $family, $errno) = @_;

	$connection->proto_send(family => $family, protobit => "error", protodata => {errno => $errno});
}

sub process_snac($$) {
	my($connection, $snac) = @_;
	my($conntype, $family, $subtype, $data, $reqid) = ($connection->{conntype}, $snac->{family}, $snac->{subtype}, $snac->{data}, $snac->{reqid});
	my $screenname = $connection->{screenname};

	my $reqdata = delete $connection->{reqdata}->[$family]->{pack("N", $reqid)};
	my $session = $connection->{session};

	my $protobit = snac_to_protobit(%$snac);
	if(!$protobit) {
		return $session->callback_snac_unknown($connection, $snac, $data);
	}

	my %data = protoparse($session, $protobit)->unpack($data);
	$connection->log_printf(OSCAR_DBG_DEBUG, "Got SNAC 0x%04X/0x%04X: %s", $snac->{family}, $snac->{subtype}, $protobit);

	if($protobit eq "initial signon request") {
		if(exists($SCREENNAMES->{$data{screenname}})) {
			$screenname = $data{screenname};
			my $key = sprintf("%08d", int(rand(99999999)));
			print "$screenname would like to sign on.  Generated key '$key'\n";

			$SESSIONS->{$screenname} ||= {};
			$SESSIONS->{$screenname}->{keys} ||= {};
			$SESSIONS->{$screenname}->{sessions} ||= [];
			$SESSIONS->{$screenname}->{status} ||= {
				online => 0,
			};

			$SESSIONS->{$screenname}->{keys}->{$key} = 1;
			$connection->proto_send(protobit => "authentication key", protodata => {key => $key});
		} else {
			$connection->proto_send(protobit => "authorization response", protodata => {error => 1});
			$session->delconn($connection);
		}
	} elsif($protobit eq "signon") {
		my $hash;
		($screenname, $hash) = ($data{screenname}, $data{auth_response});

		if(!$SCREENNAMES->{$screenname}) {
			$connection->proto_send(protobit => "authorization response", protodata => {error => 1});
		}

		my @valid_hashes = map {
			[$_, encode_password($session, exists($data{pass_is_hashed}) ? md5($SCREENNAMES->{$screenname}->{pw}) : $SCREENNAMES->{$screenname}->{pw}, $_)];
		} keys %{$SESSIONS->{$screenname}->{keys}};

		my $valid = 0;
		foreach (@valid_hashes) {
			next unless $_->[1] eq $hash;
			$valid = 1;
			delete $SCREENNAMES->{$screenname}->{keys}->{$_->[0]};
			last;
		}

		if($valid) {
			my $key = randchars(256);
			$connection->proto_send(protobit => "authorization response", protodata => {
				screenname => $SCREENNAMES->{$screenname}->{sn},
				email => $SCREENNAMES->{$screenname}->{email},
				auth_cookie => $key,
				server_ip => "127.0.0.1"
			});
			$session->delconn($connection);

			$COOKIES{$key} = {sn => $screenname, conntype => CONNTYPE_BOS};
		} else {
			$connection->proto_send(protobit => "authorization response", protodata => {error => 5});
			$session->delconn($connection);
		}
	} elsif($protobit eq "BOS signon") {
		my $cookie = pack("n", $reqid & 0xFFFF) . $data{cookie};
		if($COOKIES{$cookie}) {
			my $peer = delete $COOKIES{$cookie};
			my $screenname = $peer->{sn};
			print "$screenname initiating BOS handshake.\n";
			$connection->{screenname} = $screenname;

			my $sess = $SESSIONS->{$screenname};
			push @{$sess->{sessions}}, $connection;
			$sess->{extstatus} ||= "";
			$sess->{away} = 0;
			$sess->{stealth} = 0;
			
			$connection->proto_send(protobit => "server ready", protodata => {
				families => [grep { !OSCAR_TOOLDATA()->{$_}->{nobos} } keys %{OSCAR_TOOLDATA()}]
			});
		} else {
			$session->delconn($connection);
		}
	} elsif($protobit eq "set service versions") {
		send_versions($connection, 0, 1);
	} elsif($protobit eq "rate info request") {
		$connection->proto_send(protobit => "rate info response");
	} elsif($protobit eq "rate acknowledgement") {
		# Do nothing
	} elsif($protobit =~ /^(locate rights|buddy rights|IM parameter|BOS rights) request$/) {
		$connection->proto_send(protobit => "$1 response");
	} elsif($protobit eq "buddylist rights request") {
		$connection->proto_send(protobit => "buddylist 3 response");
	} elsif($protobit eq "personal info request") {
		$connection->proto_send(protobit => "self information", protodata => {
			screenname => $screenname,
			evil => 0,
			flags => 0x20,
			onsince => time(),
			idle => 0,
			session_length => 0,
			ip => 0
		});
	} elsif($protobit eq "buddylist request") {
		my $blist;

		my $visdata = tlv_encode(tlv(
			0xCA => 0+VISMODE_PERMITALL,
			0xCB => 0xFFFFFFFF,
		));
		$blist = "xxx";
		$blist .= pack("n5a*", 0, 0, 0xCB, 4, length($visdata), $visdata);
		$blist .= pack("na*n4", length("Buddies"), "Buddies", 1, 0, 1, 0);
		$blist .= pack("na*n4", length("SomeDude"), "SomeDude", 1, 1, 0, 0);
		$blist .= pack("na*n4", length("OtherDude"), "OtherDude", 1, 2, 0, 0);

		$connection->proto_send(protobit => "buddylist", protodata => {data => $blist});
	} elsif($protobit eq "set extended status") {
		if($data{status_message}) {
			$SESSIONS->{$screenname}->{status}->{extstatus} = $data{status_message}->{message};
		} elsif($data{stealth}) {
			$SESSIONS->{$screenname}->{status}->{stealth} = $data{stealth}->{state} & 0x100;
		}
	} elsif($protobit eq "set tool versions") {
		print "$screenname finished signing on.\n";
	} else {
		#srv_send_error($connection, $family, 1);
		print "Unhandled protobit: $protobit\n";
	}
}

1;

