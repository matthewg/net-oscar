=pod

Net::OSCAR::Utility -- internal utility functions for Net::OSCAR

We're doing the fancy-schmancy Protocol.xml stuff here, so I'll explain it here.

Protocol.xml contains a number of "OSCAR protocol elements".  One E<lt>defineE<gt> block
is one OSCAR protocol element.

When the module is first loaded, Protocol.xml is parsed and two hashes are created,
one whose keys are the names the the elements and whose values are the contents
of the XML::Parser tree which represents the contents of those elements; the other
hash has a family/subtype tuple as a key and element names as a value.

To do something with an element, given its name, Net::OSCAR calls C<protoparse("element name")>.
This returns a reference to a function which will either take a hash of parameters and
transform that into a scalar which can be used as the body of the desired packet, or vice versa.
This function is memoized, so once it is called on a particular protocol element, it never has 
to do any work to return an answer for that protocol element again.

This is accomplished via the _protopack function, which takes a listref containing an interpretation
of the desired OSCAR protocol element as its first parameter.  So, what protoparse does is transforms the
array that XML::Parser into a friendlier format.

Think of _protopack as a magic function that is either C<pack> or C<unpack>, and automatically knows which
one you want it to be.  What C<protoparse> returns is a wrapper function that will call C<_protopack> with
correct the "pack template" for you.

=cut

package Net::OSCAR::Utility;

$VERSION = '0.62';
$REVISION = '$Revision$';

use strict;
use vars qw(@ISA @EXPORT $VERSION $xmlparser);
use Digest::MD5;
use XML::Parser;

use Net::OSCAR::TLV;
use Net::OSCAR::OldPerl;
use Carp;
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
	randchars log_print log_printf hexdump normalize tlv_decode tlv_encode tlv send_error bltie signon_tlv encode_password protoparse
);

use Memoize;
memoize('protoparse');

$xmlparser = new XML::Parser(Style => "Tree");
my $xmlfile = "";
foreach (@INC) {
	next unless -f "$_/Net/OSCAR/Protocol.xml";
	$xmlfile = "$_/Net/OSCAR/Protocol.xml";
	last;
}
croak "Couldn't find Net/OSCAR/Protocol.xml in search path: " . join(" ", @INC) unless $xmlfile;
open(XMLFILE, $xmlfile) or croak "Couldn't open $xmlfile: $!";
my $xml = join("", <XMLFILE>);
close XMLFILE;
my $xmlparse = $xmlparser->parse($xml) or croak "Couldn't parse XML from $xmlfile: $@";
my %xmlmap = ();
my %xml_revmap;
# We set the autovivification so that keys of xml_revmap are Net::OSCAR::TLV hashrefs.
tie %xml_revmap, "Net::OSCAR::TLV", 'tie %$value, ref($self)';

my @tags = @{$xmlparse->[1]}; # Get contents of <oscar>
shift @tags;
while(@tags) {
	my($name, $value);
	(undef, undef, $name, $value) = splice(@tags, 0, 4);
	next unless $name eq "define";
	
	$xmlmap{$value->[0]->{name}} = $value;
	$xml_revmap{$value->[0]->{family}}->{$value->[0]->{subtype}} = $value->[0]->{name} if $value->[0]->{family};
}

sub _xmldump {
	require Data::Dumper;
	print Data::Dumper::Dumper(\%xml_revmap);
	exit;
}

# Specification for _protopack "pack template":
#	-Listref whose elements are hashrefs.
#	-Hashrefs have following keys:
#		type: "num", "data", or "tlvchain"
#		If type = "num":
#			packlet: Pack template letter (C, n, N, v, V)
#			len: Length of datum, in bytes
#		If type = "data":
#			Same as type="num", except they represent something about a numeric length prefix.
#			If packlet/len aren't present, all available data will be gobbled.
#		If type = "tlvchain":
#			short: If true, this is a 'short' TLV, as per Protocol.dtd.
#			prefix: If present, "count" or "length", and "packlet" and "len" will also be present.
#			items: Listref containing TLVs, hashrefs in format identical to these, with extra key 'num'.
#		value: If present, default value of this datum.
#		name: If present, name in parameter list that this datum gets.

sub _protopack($@) {
	my $template = shift;

	if(wantarray) { # Unpack
		my $packet = shift;
		my %data = ();

		foreach my $datum (@$packet) {
			if($datum->{type} eq "num") {
				if($datum->{name}) {
					($data->{$datum->{name}}) = unpack($datum->{packlet}, substr($packet, 0, $datum->{len}, ""));
				} else {
					substr($packet, 0, $datum->{len}) = "";
				}
			} elsif($datum->{type} eq "data") {
				if($datum->{packlet}) {
					my(%tmp) = _protopack([{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, name => "len"}], substr($packet, 0, $datum->{len}, ""));
					if($datum->{name}) {
						$data->{$datum->{name}} = substr($packet, 0, $tmp{len}, "");
					} else {
						substr($packet, 0, $tmp{len}) = "";
					}
				} elsif($datum->{name}) {
					$data->{$datum->{name}} = $packet;
				}
			} elsif($datum->{type} eq "tlvchain") {
				my($tlvpacket, $tlvmax, $tlvcount) = ($packet, 0, 0);

				if($datum->{prefix}) {
					my(%tmp) = _protopack([{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, name => "len"}], substr($packet, 0, $datum->{len}, ""));
					if($datum->{prefix} eq "count") {
						$tlvmax = $tmp{len};
					} else {
						$tlvpacket = substr($packet, 0, $tmp{len}, "");
					}
				}

				my $tlvmap = tlv;
				if($datum->{short}) {
					$tlvmap->{$_->{num}} = tlv foreach (@{$datum->{items}});
					$tlvmap->{$_->{num}}->{$_->{shortno}} = $_ foreach (@{$datum->{utems}});
				} else {
					$tlvmap->{$_->{num}} = $_ foreach (@{$datum->{items}};
				}
				while($tlvpacket and ($tlvmax and $tlvcount < $tlvmax)) {
					my($type, $length, $shortno, $value);
					if($datum->{short}) {
						($type, $length, $shortno) = unpack("nCC", substr($tlvpacket, 0, 4, ""));
					} else {
						($type, $length) = unpack("nn", substr($tlvpacket, 0, 4, ""));
					}
					$value = substr($tlvpacket, 0, $length, "");

					if($datum->{short}) {
						$tlvmap->{$type}->{$shortno}->{data} = $value;
					} else {
						$tlvmap->{$type}->{data} = $value;
					}
				} continue {
					$tlvcount++;
				}

				while(my($num, $val) = each %$tlvmap) {
					next unless $val->{type};

					if($datum->{short}) {
						while(my($shortnum, $shortval) = each %$val) {
							my(%tmp) = _protopack([$shortval], $shortval->{data});
							$data{$_} = $tmp{$_} foreach keys %tmp;
						}
					} else {
						my(%tmp) = _protopack([$val], $val->{data});
						$data{$_} = $tmp{$_} foreach keys %tmp;
					}
				}
			}
		}

		return %data;
	} else { # Pack
		my %data = @_;
		my $packet = "";

		foreach my $datum (@$packet) {
			my $value = $data{$datum->{name}} || $datum->{value};
			next unless defined($value);

			if($datum->{type} eq "num") {
				$packet .= pack($datum->{packlet}, $value);
			} elsif($datum->{type} eq "data") {
				if($datum->{packlet}) {
					my $prefix = _protopack([{type => "num", packlet => $datum->{packlet}, len => $datum->{len}}], $value);
					$packet .= $prefix.
				}
				$packet .= $value;
			} elsif($datum->{type} eq "tlvchain") {
				my($tlvpacket, $tlvcount) = ($packet, 0);

				foreach (@{$datum->{items}}) {
					
				}
			}
		}

		return $packet;
	}
}

sub protoparse($) {
	my $wanted = shift;
	my $xml = $xmlmap{shift} or croak "Couldn't find requested protocol element '$wanted'.";

	my $attrs = shift @$xml;
	my $channel = $attrs->{channel};
	my $family = $attrs->{family};
	my $subtype = $attrs->{subtype};

	my $packcode = 'my $packet = ""; my %data = @_; my $num = 0;' . "\n";
	my $unpackcode = 'my $packet = shift; my %data = (); my $num = 0;' . "\n";

	while(@$xml) {
		my $tag = shift @$xml;
		my $value = shift @$xml;
		$attrs = shift @$value;
		next if $tag eq "0";

		my $name = $attrs->{name};
		if($tag eq "ref") {
			unshift @$xml, @{$xmlmap{$value->[0]->{name}}};
			next;
		} elsif($tag eq "byte" or $tag eq "word" or $tag eq "dword") {
			my $data = "";
			$data = $value->[1] if @$value;
			$data ||= '$data{'.$name.'}';

			my($p, $u) = _num_to_code($tag, $attrs->{order}, $name, $data);
			$packcode .= $p;
			$unpackcode .= $u;
		} elsif($tag eq "data") {
			my $data = "";
			$data = $value->[1] if @$value;
			$data ||= '$data{'.$name.'}';

			croak "data outside of tlv must have length prefix!" unless $attrs->{length_prefix};
			$packcode .= '$data{_data_len} = length('.$data.'); ';
			my($p, $u) = _num_to_code($attrs->{length_prefix}, $attrs->{prefix_order}, '_data_len', $data);
			$packcode .= $p;
			$unpackcode .= $u;

			$packcode .= '$packet .= '.$data.";\n";
			if($name) {
				$unpackcode .= '$data{'.$name.'} = substr($packet, 0, $data{_data_len}, "");' . "\n";
			} else {
				$unpackcode .= 'substr($packet, 0, $data{_data_len}) = "";' . "\n";
			}
		} elsif($tag eq "tlvchain") {
			if($attrs->{count_prefix}) {
				$packcode .= 'my $tlv = tlv();'
				my $u;
				(undef, $u) = _num_to_code($attrs->{count_prefix}, "network", '_tlv_len', "");
				$unpackcode .= $u;
				$unpackcode .= 'my $tlv_count = $data{_tlv_len};';
				$unpackcode .= 'while($packet) {' . "\n";
			} elsif($attrs->{length_prefix}) {
				
			} else {
			}

			while(@$data) {
				my($tlvtag, $tlvval) = splice(@$data, 0, 2);
				next if $tlvtag eq "0";

				
			}
		}
	}

=cut

=pod

<!ELEMENT tlvchain (tlv*)>
<!ATTLIST tlvchain
	name CDATA #IMPLIED
	short (yes|no) #DEFAULT no <!-- A 'short' TLV is type/num/length/value, where num and length are both bytes.  It's used in extended status. -->
	count_prefix (byte|word|dword) #IMPLIED
	length_prefix (byte|word|dword) #IMPLIED
>

<!ELEMENT tlv (ref|byte|word|dword|data|tlvchain|if)+>
<!ATTLIST tlv
	name CDATA #IMPLIED
	num CDATA #REQUIRED
	num2 CDATA #IMPLIED
>

<!ELEMENT if (condition+)>
<!ELEMENT condition (ref|byte|word|dword|data|tlvchain|if)+>
<!ATTLIST condition
	test CDATA #REQUIRED
>

}

=cut
	

sub tlv(;@) {
	my %tlv = ();
	tie %tlv, "Net::OSCAR::TLV";
	while(@_) { my($key, $value) = (shift, shift); $tlv{$key} = $value; }
	return \%tlv;
}


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

	my $retval = tlv;

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
		$retval->{$type} = $value;
	}

	return $tlvcnt ? ($retval, $strpos) : $retval;
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

sub signon_tlv($;$$) {
	my($session, $password, $key) = @_;

	my $tlv = tlv(
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
		0x4A => pack("C", 1), # Use SSI
	);

	if($session->{svcdata}->{hashlogin}) {
		$tlv->{0x02} = encode_password($session, $password);
	} else {
		if($session->{auth_response}) {
			($tlv->{0x25}) = delete $session->{auth_response};
		} else {
			$tlv->{0x25} = encode_password($session, $password, $key);
		}
		$tlv->{0x4A} = pack("C", 1);

		if($session->{svcdata}->{betainfo}) {
			$tlv->{0x4C} = $session->{svcinfo}->{betainfo};
		}
	}

	return $tlv;
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
