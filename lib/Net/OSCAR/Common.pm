package Net::OSCAR::Common;

$VERSION = '0.62';

use strict;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS $VERSION);
use Scalar::Util qw(dualvar);
use Net::OSCAR::TLV;
use Carp;
require Exporter;
@ISA = qw(Exporter);

%EXPORT_TAGS = (
	standard => [qw(
		ADMIN_TYPE_PASSWORD_CHANGE
		ADMIN_TYPE_EMAIL_CHANGE
		ADMIN_TYPE_SCREENNAME_FORMAT
		ADMIN_TYPE_ACCOUNT_CONFIRM
		ADMIN_ERROR_UNKNOWN
		ADMIN_ERROR_BADPASS
		ADMIN_ERROR_BADINPUT
		ADMIN_ERROR_BADLENGTH
		ADMIN_ERROR_TRYLATER
		ADMIN_ERROR_REQPENDING
		ADMIN_ERROR_CONNREF
		VISMODE_PERMITALL
		VISMODE_DENYALL
		VISMODE_PERMITSOME
		VISMODE_DENYSOME
		VISMODE_PERMITBUDS
		RATE_CLEAR
		RATE_ALERT
		RATE_LIMIT
		RATE_DISCONNECT
		GROUPPERM_OSCAR
		GROUPPERM_AOL
		OSCAR_SVC_AIM
		OSCAR_SVC_ICQ
	)],
	loglevels => [qw(
		OSCAR_DBG_NONE
		OSCAR_DBG_WARN
		OSCAR_DBG_INFO
		OSCAR_DBG_SIGNON
		OSCAR_DBG_NOTICE
		OSCAR_DBG_DEBUG
		OSCAR_DBG_PACKETS
	)],
	all => [qw(
		OSCAR_DBG_NONE OSCAR_DBG_WARN OSCAR_DBG_INFO OSCAR_DBG_SIGNON OSCAR_DBG_NOTICE OSCAR_DBG_DEBUG OSCAR_DBG_PACKETS
		ADMIN_TYPE_PASSWORD_CHANGE ADMIN_TYPE_EMAIL_CHANGE ADMIN_TYPE_SCREENNAME_FORMAT ADMIN_TYPE_ACCOUNT_CONFIRM
		ADMIN_ERROR_UNKNOWN ADMIN_ERROR_BADPASS ADMIN_ERROR_BADINPUT ADMIN_ERROR_BADLENGTH ADMIN_ERROR_TRYLATER ADMIN_ERROR_REQPENDING ADMIN_ERROR_CONNREF
		VISMODE_PERMITALL VISMODE_DENYALL VISMODE_PERMITSOME VISMODE_DENYSOME VISMODE_PERMITBUDS RATE_CLEAR RATE_ALERT RATE_LIMIT RATE_DISCONNECT
		FLAP_CHAN_NEWCONN FLAP_CHAN_SNAC FLAP_CHAN_ERR FLAP_CHAN_CLOSE
		CONNTYPE_LOGIN CONNTYPE_BOS CONNTYPE_ADMIN CONNTYPE_CHAT CONNTYPE_CHATNAV
		MODBL_ACTION_ADD MODBL_ACTION_DEL MODBL_WHAT_BUDDY MODBL_WHAT_GROUP MODBL_WHAT_PERMIT MODBL_WHAT_DENY
		GROUPPERM_OSCAR GROUPPERM_AOL OSCAR_SVC_AIM OSCAR_SVC_ICQ
		BUDTYPES
		ENCODING
		ERRORS
		randchars log_print log_printf hexdump normalize tlv_decode tlv_encode tlv send_error tlvtie bltie signon_tlv encode_password
	)]
);
@EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant OSCAR_DBG_NONE => 0;
use constant OSCAR_DBG_WARN => 1;
use constant OSCAR_DBG_INFO => 2;
use constant OSCAR_DBG_SIGNON => 3;
use constant OSCAR_DBG_NOTICE => 4;
use constant OSCAR_DBG_DEBUG => 6;
use constant OSCAR_DBG_PACKETS => 10;

use constant ADMIN_TYPE_PASSWORD_CHANGE => dualvar(1, "password change");
use constant ADMIN_TYPE_EMAIL_CHANGE => dualvar(2, "email change");
use constant ADMIN_TYPE_SCREENNAME_FORMAT => dualvar(3, "screenname format");
use constant ADMIN_TYPE_ACCOUNT_CONFIRM => dualvar(4, "account confirm");

use constant ADMIN_ERROR_UNKNOWN => dualvar(0, "unknown error");
use constant ADMIN_ERROR_BADPASS => dualvar(1, "incorrect password");
use constant ADMIN_ERROR_BADINPUT => dualvar(2, "invalid input");
use constant ADMIN_ERROR_BADLENGTH => dualvar(3, "screenname/email/password is too long or too short");
use constant ADMIN_ERROR_TRYLATER => dualvar(4, "request could not be processed; wait a few minutes and try again");
use constant ADMIN_ERROR_REQPENDING => dualvar(5, "request pending");
use constant ADMIN_ERROR_CONNREF => dualvar(6, "couldn't connect to the admin server");

use constant FLAP_CHAN_NEWCONN => dualvar(0x01, "new connection");
use constant FLAP_CHAN_SNAC => dualvar(0x02, "SNAC");
use constant FLAP_CHAN_ERR => dualvar(0x03, "error");
use constant FLAP_CHAN_CLOSE => dualvar(0x04, "close connection");

use constant CONNTYPE_LOGIN => dualvar(0, "login");
use constant CONNTYPE_BOS => dualvar(0x2, "BOS");
use constant CONNTYPE_ADMIN => dualvar(0x7, "admin");
use constant CONNTYPE_CHAT => dualvar(0xE, "chat");
use constant CONNTYPE_CHATNAV => dualvar(0xD, "ChatNav");

use constant MODBL_ACTION_ADD => 0x1;
use constant MODBL_ACTION_DEL => 0x2;

use constant MODBL_WHAT_BUDDY => 0x1;
use constant MODBL_WHAT_GROUP => 0x2;
use constant MODBL_WHAT_PERMIT => 0x3;
use constant MODBL_WHAT_DENY => 0x4;

use constant VISMODE_PERMITALL  => dualvar(0x1, "permit all");
use constant VISMODE_DENYALL    => dualvar(0x2, "deny all");
use constant VISMODE_PERMITSOME => dualvar(0x3, "permit some");
use constant VISMODE_DENYSOME   => dualvar(0x4, "deny some");
use constant VISMODE_PERMITBUDS => dualvar(0x5, "permit buddies");

use constant GROUP_PERMIT => 0x0002;
use constant GROUP_DENY   => 0x0003;

use constant RATE_CLEAR => dualvar(1, "clear");
use constant RATE_ALERT => dualvar(2, "alert");
use constant RATE_LIMIT => dualvar(3, "limit");
use constant RATE_DISCONNECT => dualvar(4, "disconnect");

use constant GROUPPERM_OSCAR => dualvar(0x18, "AOL Instant Messenger users");
use constant GROUPPERM_AOL => dualvar(0x04, "AOL subscribers");

use constant OSCAR_SVC_AIM => (
	host => 'login.oscar.aol.com',
	port => 5190,
	supermajor => 0x0109,
	major => 4,
	minor => 7,
	subminor => 0,
	build => 2480,
	subbuild => 0x9F,
	clistr => "AOL Instant Messenger (SM), version 4.7.2480/WIN32",
	hashlogin => 0,
);
use constant OSCAR_SVC_ICQ => ( # Courtesy of SDiZ Cheng
	host => 'login.icq.com',
	port => 5190,
	supermajor => 266,
	major => 4,
	minor => 63,
	subminor => 1,
	build => 3279,
	subbuild => 85,
	clistr => "ICQ Inc. - Product of ICQ (TM).200b.4.63.1.3279.85",
	hashlogin => 1,
);

use constant BUDTYPES => ("buddy", "group", "permit entry", "deny entry", "visibility/misc. data", "presence");

use constant ENCODING => 'text/aolrtf; charset="us-ascii"';

# I'm not 100% sure about error 29
use constant ERRORS => split(/\n/, <<EOF);
Invalid error
Invalid SNAC
Sending too fast to host
Sending too fast to client
%s is not logged in, so the attempted operation (sending an IM, getting user information) was unsuccessful
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
%s is in your permit or deny list
Too evil (sender)
Too evil (receiver)
User temporarily unavailable
No match
List overflow
Request ambiguous
Queue full
Not while on AOL
Unknown error 25
Unknown error 26
Unknown error 27
Unknown error 28
There have been too many recent signons from this address.  Please wait a few minutes and try again.
EOF

sub randchars($) {
	my $count = shift;
	my $retval = "";
	for(my $i = 0; $i < $count; $i++) { $retval .= chr(int(rand(256))); }
	return $retval;
}

sub log_print($$@) {
	my($obj, $level) = (shift, shift);
	my $session = exists($obj->{session}) ? $obj->{session} : $obj;
	return unless defined($session->{LOGLEVEL}) and $session->{LOGLEVEL} >= $level;

	my $message = "";
	$message .= $obj->{description}. ": " if $obj->{description};
	$message .= join("", @_). "\n";

	if($session->{callbacks}->{log}) {
		$session->callback_log($level, $message);
	} else {
		$message = "(".$session->{screenname}.") $message" if $session->{SNDEBUG};
		print STDERR $message;
	}
}

sub log_printf($$$@) {
	my($obj, $level, $fmtstr) = (shift, shift, shift);

	$obj->log_print($level, sprintf($fmtstr, @_));
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
	return $temp ? lc($temp) : "";
}

sub tlv_decode($;$) {
	my($tlv, $tlvcnt) = @_;
	my($type, $len, $value, %retval);
	my $currtlv = 0;
	my $strpos = 0;

	tie %retval, "Net::OSCAR::TLV";

	$tlvcnt = 0 unless $tlvcnt;
	while(length($tlv) >= 4 and (!$tlvcnt or $currtlv < $tlvcnt)) {
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
	}

	return $tlvcnt ? (\%retval, $strpos) : \%retval;
}

sub tlv(@) {
	my %tlv = ();
	tie %tlv, "Net::OSCAR::TLV";
	while(@_) { my($key, $value) = (shift, shift); $tlv{$key} = $value; }
	return tlv_encode(\%tlv);
}

sub tlv_encode($) {
	my $tlv = shift;
	my($buffer, $type, $value) = ("", 0, "");

	confess "You must use a tied Net::OSCAR::TLV hash!" unless defined($tlv) and ref($tlv) eq "HASH" and defined(%$tlv) and tied(%$tlv)->isa("Net::OSCAR::TLV");
	while (($type, $value) = each %$tlv) {
		$value ||= "";
		$buffer .= pack("nna*", $type, length($value), $value);

	}
	return $buffer;
}

sub send_error($$$$$;@) {
	my($oscar, $connection, $error, $desc, $fatal, @reqdata) = @_;
	$desc = sprintf $desc, @reqdata;
	$oscar->callback_error($connection, $error, $desc, $fatal);
}

sub bltie(;$) {
	my $retval = {};
	tie %$retval, "Net::OSCAR::Buddylist", @_;
	return $retval;
}

sub tlvtie(;$) {
	my $retval = {};
	tie %$retval, "Net::OSCAR::TLV", shift;
	return $retval;
}

sub signon_tlv($;$$) {
	my($session, $password, $key) = @_;

	my %tlv = (
		0x01 => $session->{screenname},
		0x03 => $session->{svcdata}->{clistr},
		0x16 => pack("n", $session->{svcdata}->{supermajor}),
		0x17 => pack("n", $session->{svcdata}->{major}),
		0x18 => pack("n", $session->{svcdata}->{minor}),
		0x19 => pack("n", $session->{svcdata}->{subminor}),
		0x1A => pack("n", $session->{svcdata}->{build}),
		0x14 => pack("N", $session->{svcdata}->{subbuild}),
		0x0F => "en", # lang
		0x0E => "us", # country
	);

	if($session->{svcdata}->{hashlogin}) {
		$tlv{0x02} = encode_password($session, $password);
	} else {
		if($session->{auth_response}) {
			($tlv{0x25}) = delete $session->{auth_response};
		} else {
			$tlv{0x25} = encode_password($session, $password, $key);
		}
		$tlv{0x4A} = pack("C", 1);
	}

	return %tlv;
}

sub encode_password($$;$) {
	my($session, $password, $key) = @_;

	if(!$session->{svcdata}->{hashlogin}) { # Use new SNAC-based method
		my $md5 = Digest::MD5->new;

		$md5->add($key);
		$md5->add($password);
		$md5->add("AOL Instant Messenger (SM)");
		return $md5->digest();
	} else { # Use old roasting method.  Courtesy of SDiZ Cheng.
		my $ret = "";
		my @pass = map {ord($_)} split(//, $password);

		my @encoding_table = map {hex($_)} qw(
			F3 26 81 C4 39 86 DB 92 71 A3 B9 E6 53 7A 95 7C
		);

		for(my $i = 0; $i < length($password); $i++) {
			$ret .= chr($pass[$i] ^ $encoding_table[$i]);
		}

		return $ret;
	}
}


1;
