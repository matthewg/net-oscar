package Net::OSCAR::Connection;

$VERSION = 0.55;

use strict;
use vars qw($VERSION);
use Carp;
use Socket;
use Symbol;
use Digest::MD5;
use Fcntl;
use POSIX qw(:errno_h);

use Net::OSCAR::Common qw(:all);
use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;
use Net::OSCAR::OldPerl;

sub new($$$$$$) { # Think you got enough parameters there, Chester?
	my $class = ref($_[0]) || $_[0] || "Net::OSCAR::Connection";
	shift;
	my $self = { };
	bless $self, $class;
	$self->{seqno} = 0;
	$self->{session} = shift;
	$self->{auth} = shift;
	$self->{conntype} = shift;
	$self->{description} = shift;
	$self->{paused} = 0;
	$self->connect(shift);

	return $self;
}

sub fileno($) {
	my $self = shift;
	if(!$self->{socket}) {
		$self->{sockerr} = 1;
		$self->disconnect();
		return undef;
	}
	return fileno $self->{socket};
}

sub flap_encode($$;$) {
	my ($self, $msg, $channel) = @_;

	$channel ||= FLAP_CHAN_SNAC;
	return pack("CCnna*", 0x2A, $channel, ++$self->{seqno}, length($msg), $msg);
}

sub flap_put($$;$) {
	my($self, $msg, $channel) = @_;

	return unless $self->{socket} and CORE::fileno($self->{socket}) and getpeername($self->{socket}); # and !$self->{socket}->error;

	my $emsg = $self->flap_encode($msg, $channel);
	syswrite($self->{socket}, $emsg, length($emsg)) or return $self->{session}->crapout($self, "Couldn't write to socket: $!");
	$self->log_print(OSCAR_DBG_PACKETS, "Put ", hexdump($emsg));
}

sub flap_get($) {
	my $self = shift;
	my $socket = $self->{socket};
	my ($buffer, $channel, $len);
	my $nchars;

	if(!exists($self->{buff_gotflap})) {
		$self->{buffsize} ||= 6;
		$self->{buffer} ||= "";

		if(!sysread($self->{socket}, $buffer, $self->{buffsize} - length($self->{buffer}))) {
			if($self == $self->{session}->{bos}) {
				return $self->{session}->crapout($self, "$!");
			} else {
				$self->log_print(OSCAR_DBG_NOTICE, "Lost connection.");
				$self->{sockerr} = 1;
				$self->disconnect();
				return undef;
			}
		} else {
			$self->{buffer} .= $buffer;
		}

		if(length($self->{buffer}) == 6) {
			$self->{buff_gotflap} = 1;
			($buffer) = delete $self->{buffer};
			(undef, $self->{channel}, undef, $self->{buffsize}) = unpack("CCnn", $buffer);
			$self->{buffer} = "";
		} else {
			return "";
		}
	}

	$nchars = sysread($self->{socket}, $buffer, $self->{buffsize} - length($self->{buffer}));
	if(!$nchars) {
		$self->log_print(OSCAR_DBG_NOTICE, "Lost connection.");
		$self->{sockerr} = 1;
		$self->disconnect();
		return undef;
	} else {
		$self->{buffer} .= $buffer;
	}

	if(length($self->{buffer}) == $self->{buffsize}) {
		$self->log_print(OSCAR_DBG_PACKETS, "Got ", hexdump($self->{buffer}));
		$buffer = $self->{buffer};

		delete $self->{buffer};
		delete $self->{buff_gotflap};
		delete $self->{buffsize};

		return $buffer;
	} else {
		return "";
	}
}

sub snac_encode($%) {
	my($self, %snac) = @_;

	$snac{family} ||= 0;
	$snac{subtype} ||= 0;
	$snac{flags1} ||= 0;
	$snac{flags2} ||= 0;
	$snac{data} ||= "";
	$snac{reqdata} ||= "";
	$snac{reqid} ||= ($snac{subtype}<<16) | (unpack("n", randchars(2)))[0];
	$self->{reqdata}->[$snac{family}]->{pack("N", $snac{reqid})} = $snac{reqdata} if $snac{reqdata};

	return pack("nnCCNa*", $snac{family}, $snac{subtype}, $snac{flags1}, $snac{flags2}, $snac{reqid}, $snac{data});
}

sub snac_put($%) {
	my($self, %snac) = @_;
	$snac{channel} ||= FLAP_CHAN_SNAC;
	$self->flap_put($self->snac_encode(%snac), $snac{channel});
}

sub snac_get($) {
	my($self) = shift;
	my $snac = $self->flap_get() or return 0;
	return $self->snac_decode($snac);
}

sub snac_decode($$) {
	my($self, $snac) = @_;
	my($family, $subtype, $flags1, $flags2, $reqid, $data) = (unpack("nnCCNa*", $snac));

	return {
		family => $family,
		subtype => $subtype,
		flags1 => $flags1,
		flags2 => $flags2,
		reqid => $reqid,
		data => $data
	};
}

sub snac_dump($$) {
	my($self, $snac) = @_;
	return "family=".$snac->{family}." subtype=".$snac->{subtype};
}

sub disconnect($) {
	my($self) = @_;

	$self->{session}->delconn($self);
}

sub set_blocking($$) {
	my $self = shift;
	my $blocking = shift;
	my $flags = 0;

	fcntl($self->{socket}, F_GETFL, $flags);
	if($blocking) {
		$flags &= ~O_NONBLOCK;
	} else {
		$flags |= O_NONBLOCK;
	}
	fcntl($self->{socket}, F_SETFL, $flags);

	return $self->{socket};
}

sub connect($$) {
	my($self, $host) = @_;
	my $temp;
	my %tlv;
	my $port;

	tie %tlv, "Net::OSCAR::TLV";

	return $self->{session}->crapout($self, "Empty host!") unless $host;
	$host =~ s/:(.+)//;
	if(!$1) {
		if(exists($self->{session})) {
			$port = $self->{session}->{port};
		} else {
			return $self->{session}->crapout($self, "No port!");
		}
	} else {
		$port = $1;
		if($port =~ /^[^0-9]/) {
			$port = $self->{session}->{port};
		}
	}
	$self->{host} = $host;
	$self->{port} = $port;

	$self->log_print(OSCAR_DBG_NOTICE, "Connecting to $host:$port.");
	$self->{socket} = gensym;
	socket($self->{socket}, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

	$self->{ready} = 0;
	$self->{connected} = 0;

	$self->set_blocking(0);
	my $addr = inet_aton($host) or return $self->{session}->crapout($self, "Couldn't resolve $host.");
	if(!connect($self->{socket}, sockaddr_in($port, $addr))) {
		return 1 if $! == EINPROGRESS;
		return $self->{session}->crapout($self, "Couldn't connect to $host:$port: $!");
	}

	return 1;
}

sub get_filehandle($) { shift->{socket}; }

sub process_one($) {
	my $self = shift;
	my $snac;
	my %tlv;

	tie %tlv, "Net::OSCAR::TLV";

	if(!$self->{connected}) {
		$self->log_print(OSCAR_DBG_NOTICE, "Connected.");
		$self->{connected} = 1;
		#$self->set_blocking(1);
		$self->{session}->callback_connection_changed($self, "read");
		return 1;
	} elsif(!$self->{ready}) {
		$self->log_print(OSCAR_DBG_DEBUG, "Getting connack.");
		my $flap = $self->flap_get();
		if(!defined($flap)) {
			$self->log_print(OSCAR_DBG_NOTICE, "Couldn't connect.");
			return 0;
		} else {
			$self->log_print(OSCAR_DBG_DEBUG, "Got connack.");
		}
		return $self->{session}->crapout($self, "Got bad connack from server") unless $self->{channel} == FLAP_CHAN_NEWCONN;

		if($self->{conntype} == CONNTYPE_LOGIN) {
			$self->log_print(OSCAR_DBG_DEBUG, "Got connack.  Sending connack.");
			$self->flap_put(pack("N", 1), FLAP_CHAN_NEWCONN) unless $self->{session}->{svcdata}->{hashlogin};
			$self->log_print(OSCAR_DBG_SIGNON, "Connected to login server.");
			$self->{ready} = 1;

			$self->log_print(OSCAR_DBG_SIGNON, "Sending screenname.");
			if(!$self->{session}->{svcdata}->{hashlogin}) {
				%tlv = (
					0x17 => pack("C6", 0, 0, 0, 0, 0, 0),
					0x01 => $self->{session}->{screenname}
				);
				$self->flap_put(tlv_encode(\%tlv));
			} else {
				%tlv = signon_tlv($self->{session}, $self->{auth});
				$self->flap_put(pack("N", 1) . tlv_encode(\%tlv), FLAP_CHAN_NEWCONN);
			}
		} else {
			$self->log_print(OSCAR_DBG_NOTICE, "Sending BOS-Signon.");
			#%tlv = (0x06 =>$self->{auth});
			#$self->flap_put(pack("N", 1) . tlv_encode(\%tlv), FLAP_CHAN_NEWCONN);
			$self->snac_put(family => 0, subtype => 1,
				flags2 => 0x6,
				reqid => 0x01000000 | (unpack("n", substr($self->{auth}, 0, 2)))[0],
				data => substr($self->{auth}, 2),
				channel => FLAP_CHAN_NEWCONN);
		}
		$self->log_print(OSCAR_DBG_DEBUG, "SNAC time.");
		return $self->{ready} = 1;
	} else {
		if(!$self->{session}->{svcdata}->{hashlogin}) {
			$snac = $self->snac_get() or return 0;
			return Net::OSCAR::Callbacks::process_snac($self, $snac);
		} else {
			my $data = $self->flap_get() or return 0;
			$snac = {data => $data, reqid => 0, family => 0x17, subtype => 0x3};
			if($self->{channel} == FLAP_CHAN_CLOSE) {
				$self->{conntype} = CONNTYPE_LOGIN;
				$self->{family} = 0x17;
				$self->{subtype} = 0x3;
				$self->{data} = $data;
				$self->{reqid} = 0;
				$self->{reqdata}->[0x17]->{pack("N", 0)} = "";
				return Net::OSCAR::Callbacks::process_snac($self, $snac);
			} else {
				return Net::OSCAR::Callbacks::process_snac($self, $self->snac_decode($data));
			}
		}
	}
}

sub ready($) {
	my($self) = shift;

	return if $self->{sentready}++;
	$self->log_print(OSCAR_DBG_DEBUG, "Sending client ready.");
	if($self->{conntype} == CONNTYPE_CHATNAV or $self->{conntype} == CONNTYPE_ADMIN or $self->{conntype} == CONNTYPE_CHAT) {
		$self->snac_put(family => 0x1, subtype => 0x2, data => pack("n*",
			1, 3, 0x10, 0x361, $self->{conntype}, 1, 0x10, 0x361
		));
	} else {
		$self->snac_put(family => 0x1, subtype => 0x2, data => pack("n*", 
			1, 3, 0x110, 0x361, 13, 1, 0x110, 0x361,
			2, 1, 0x101, 0x361, 3, 1, 0x110, 0x361,
			4, 1, 0x110, 0x361, 6, 1, 0x110, 0x361,
			8, 1, 0x104, 1, 9, 1, 0x110, 0x361,
			0xA, 1, 0x110, 0x361, 0xB, 1, 0x104, 1,
			0xC, 1, 0x104, 1
		));
	}
}
1;
