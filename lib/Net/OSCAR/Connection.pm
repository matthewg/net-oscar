package Net::OSCAR::Connection;

$VERSION = 0.06;

use strict;
use vars qw($VERSION);
if($[ > 5.005) {
	require warnings;
} else {
	$^W = 1;  
}
use Carp;
use Socket;
use Symbol;
use Digest::MD5;
use Fcntl;
use Errno;

use Net::OSCAR::Common qw(:all);
use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;

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
	$self->connect(shift);
	return $self;
}

sub DEBUG {
	my $self = shift;
	$self->{DEBUG} = shift;
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
	syswrite($self->{socket}, $self->flap_encode($msg, $channel)) or confess "$self->{description} Couldn't write to socket: $!";
}

sub flap_get($) {
	my $self = shift;
	my $socket = $self->{socket};
	my ($buffer, $channel, $len);
	my $nchars;

	if(!sysread($self->{socket}, $buffer, 6)) {
		if($self == $self->{session}->{bos}) {
			$self->{session}->crapout($self, "$!");
		} else {
			$self->debug_print("Lost connection.");
			$self->{sockerr} = 1;
			$self->disconnect();
			return undef;
		}
	}
	(undef, $channel, undef, $len) = unpack("CCnn", $buffer);
	$self->{channel} = $channel;
	$nchars = sysread($self->{socket}, $buffer, $len);
	if(!$nchars) {
		$self->debug_print("Lost connection.");
		$self->{sockerr} = 1;
		$self->disconnect();
		return undef;
	}
	if($len > $nchars) {
		my $abuff = "";
		$len -= $nchars;
		$nchars = sysread($self->{socket}, $abuff, $len);
		$buffer .= $abuff;
	}
		
	return $buffer;
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
	$self->flap_put($self->snac_encode(%snac));
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

sub tlv_decode($$;$) {
	my($self, $tlv, $tlvcnt) = @_;
	my($type, $len, $value, %retval);
	my $currtlv = 0;
	my $strpos = 0;

	tie %retval, "Net::OSCAR::TLV";

	while(length($tlv) >= 4 and (not $tlvcnt or $currtlv < $tlvcnt)) {
		($type, $len) = unpack("nn", $tlv);
		$len = 0x2 if $type == 0x13;
		$strpos += 4;
		substr($tlv, 0, 4) = "";
		if($len) {
			($value) = substr($tlv, 0, $len, "");
		} else {
			$value = "";
		}
		$strpos += $len;
		$currtlv++ unless $type == 0;
		$retval{$type} = $value;
		$self->debug_print(sprintf "\t<TLV 0x%04X: %s", $type, hexdump($value));
	}

	return $tlvcnt ? (\%retval, $strpos) : \%retval;
}

sub tlv_encode($$) {
	my($self, $tlv) = @_;
	my($buffer, $type, $value) = ("", 0, "");

	confess "You must use a tied Net::OSCAR::TLV hash!" unless ref($tlv) eq "HASH" and tied(%$tlv)->isa("Net::OSCAR::TLV");
	while (($type, $value) = each %$tlv) {
		$buffer .= pack("nna*", $type, length($value), $value);
		$self->debug_print(sprintf "\t>TLV 0x%04X: %s", $type, hexdump($value));

	}
	return $buffer;
}

sub encode_password($$$) {
	my($self, $password, $key) = @_;
	my $md5 = Digest::MD5->new;

	$md5->add($key);
	$md5->add($password);
	$md5->add("AOL Instant Messenger (SM)");
	return $md5->digest();
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

	croak "Empty host!" unless $host;
	$host =~ s/:(.+)//;
	if(!$1) {
		if(exists($self->{session})) {
			$port = $self->{session}->{port};
		} else {
			croak "No port!";
		}
	} else {
		$port = $1;
		if($port =~ /^[^0-9]/) {
			$port = $self->{session}->{port};
		}
	}
	$self->{host} = $host;
	$self->{port} = $port;

	$self->debug_print("Connecting to $host:$port.");
	$self->{socket} = gensym;
	socket($self->{socket}, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

	$self->{ready} = 0;
	$self->{connected} = 0;

	$self->set_blocking(0);
	if(!connect($self->{socket}, sockaddr_in($port, inet_aton($host)))) {
		return 1 if $!{EINPROGRESS};
		croak "Couldn't connect to $host:$port: $!";
	}

	return 1;
}

sub process_one($) {
	my $self = shift;
	my $snac;
	my %tlv;

	tie %tlv, "Net::OSCAR::TLV";

	if(!$self->{connected}) {
		$self->debug_print("Connected.");
		$self->{connected} = 1;
		$self->set_blocking(1);
		return 1;
	} elsif(!$self->{ready}) {
		$self->debug_print("Getting connack.");
		my $flap = $self->flap_get();
		if(!defined($flap)) {
			$self->debug_print("Couldn't connect.");
			return 0;
		} else {
			$self->debug_print("Got connack.");
		}
		confess "Got bad connack from server" unless $self->{channel} == FLAP_CHAN_NEWCONN;

		if($self->{conntype} == CONNTYPE_LOGIN) {
			$self->debug_print("Got connack.  Sending connack.");
			$self->flap_put(pack("N", 1), FLAP_CHAN_NEWCONN);
			$self->debug_print("Connack sent.");
			$self->{ready} = 1;

			$self->debug_print("Sending screenname.");
			%tlv = (
				0x17 => pack("C6", 0, 0, 0, 0, 0, 0),
				0x01 => $self->{session}->{screenname}
			);
			$self->flap_put($self->tlv_encode(\%tlv));
		} else {
			$self->debug_print("Sending BOS-Signon.");
			%tlv = (0x06 =>$self->{auth});
			$self->flap_put(pack("N", 1) . $self->tlv_encode(\%tlv), FLAP_CHAN_NEWCONN);
		}
		$self->debug_print("SNAC time.");
		return $self->{ready} = 1;
	} else {
		$snac = $self->snac_get() or return 0;
		return Net::OSCAR::Callbacks::process_snac($self, $snac);
	}
}

sub ready($) {
	my($self) = shift;

	return if $self->{sentready}++;
	$self->debug_print("Sending client ready.");
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
