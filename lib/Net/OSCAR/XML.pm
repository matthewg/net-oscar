=pod

Net::OSCAR::XML -- XML functions for Net::OSCAR

We're doing the fancy-schmancy Protocol.xml stuff here, so I'll explain it here.

Protocol.xml contains a number of "OSCAR protocol elements".  One E<lt>defineE<gt> block
is one OSCAR protocol elemennt.

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

package Net::OSCAR::XML;

$VERSION = '1.11';
$REVISION = '$Revision$';

use strict;
use vars qw(@ISA @EXPORT $VERSION);
use XML::Parser;
use Carp;
use Memoize;
memoize('protoparse');

use Net::OSCAR::Common qw(:loglevels);
use Net::OSCAR::Utility qw(hexdump);
use Net::OSCAR::TLV;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(
	protoparse protobit_to_snacfam snacfam_to_protobit
);


sub _protopack($$;@);
sub _xmlnode_to_template($$);

my $xmlparser = new XML::Parser(Style => "Tree");
my $xmlfile = "";
foreach (@INC) {
	next unless -f "$_/Net/OSCAR/XML/Protocol.xml";
	$xmlfile = "$_/Net/OSCAR/XML/Protocol.xml";
	last;
}
croak "Couldn't find Net/OSCAR/XML/Protocol.xml in search path: " . join(" ", @INC) unless $xmlfile;
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
	next unless $name and $name eq "define";
	
	$xmlmap{$value->[0]->{name}} = {xml => $value};
	if($value->[0]->{family}) {
		$xmlmap{$value->[0]->{name}}->{family} = $value->[0]->{family};
		$xmlmap{$value->[0]->{name}}->{subtype} = $value->[0]->{subtype};
		$xmlmap{$value->[0]->{name}}->{channel} = $value->[0]->{channel};
		$xml_revmap{$value->[0]->{family}}->{$value->[0]->{subtype}} = $value->[0]->{name};
	}
}

sub _xmldump {
	require Data::Dumper;
	print Data::Dumper::Dumper(\%xml_revmap);
	exit;
}

# Specification for _protopack "pack template":
#	-Listref whose elements are hashrefs.
#	-Hashrefs have following keys:
#		type: "ref", "num", "data", or "tlvchain"
#		If type = "num":
#			packlet: Pack template letter (C, n, N, v, V)
#			len: Length of datum, in bytes
#		If type = "data":
#			Same as type="num", except they represent something about a numeric length prefix.
#			If packlet/len aren't present, all available data will be gobbled.
#			length: Size of data, in bytes
#		If type = "ref":
#			packet, len, length: Same as per 'data'
#			name: Name of protocol bit to punt to
#		If type = "tlvchain":
#			subtyped: If true, this is a 'subtyped' TLV, as per Protocol.dtd.
#			prefix: If present, "count" or "length", and "packlet" and "len" will also be present.
#			items: Listref containing TLVs, hashrefs in format identical to these, with extra key 'num' (and 'subtype', for subtyped TLVs.)
#		value: If present, default value of this datum.
#		name: If present, name in parameter list that this datum gets.
#		count: If present, number of repetitions of this datum.  count==-1 represents
#			infinite.  If a count is present when unpacking, the data will be encapsulated in a listref.  If the user
#			wants to pass in multiple data when packing, they should do so via a listref.  Listref-encapsulated data with
#			too many elements for the 'count' will trigger an exception when packing.

sub _protopack($$;@) {
	my $oscar = shift;
	my $template = shift;

	if(wantarray) { # Unpack
		# If we pass in a reference as the packet, modify it in place.
		# See what we do for unpacking type data with no length prefix
		# and yes items for why we need this...
		#
		my $x_packet = shift;
		my $packet = ref($x_packet) ? $$x_packet : $x_packet;

		my %data = ();

		$oscar->log_print(OSCAR_DBG_DEBUG, "Decoding:\n", hexdump($packet), "\n according to: ", Data::Dumper::Dumper($template));

		confess "Invalid template" unless ref($template);
		foreach my $datum (@$template) {
			if($datum->{type} eq "num") {
				my $count = $datum->{count} || 1;
				my @results;

				for(my $i = 0; $packet and ($count == -1 or $i < $count); $i++) {
					push @results, unpack($datum->{packlet}, substr($packet, 0, $datum->{len}, ""));
				}

				if($datum->{name}) {
					($data{$datum->{name}}) = $datum->{count} ? \@results : $results[0];
				}
			} elsif($datum->{type} eq "data" or $datum->{type} eq "ref") {
				my $count = $datum->{count} || 1;
				my @results;

				for(my $i = 0; $packet and ($count == -1 or $i < $count); $i++) {
					my $subpacket;
					my %tmp;

					if($datum->{packlet}) {
						(%tmp) = _protopack($oscar, [{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, name => "len"}], substr($packet, 0, $datum->{len}, ""));
						$subpacket = substr($packet, 0, $tmp{len}, "");
					} elsif($datum->{length}) {
						$subpacket = substr($packet, 0, $datum->{length}, "");
					} else {
						$subpacket = $packet;
						$packet = "";
					}

					if(@{$datum->{items}}) {
						# So, consider the structure:
						# <data count="-1" name="foo">
						#	<word name="bar" />
						#	<word name="baz" />
						# </data>
						# We don't know the size of 'foo' in advance.
						# Thus, we pass a reference to the actual packet into protopack.
						# subpacket will be modified to be the packet minus the bits that the contents of the data consumed.

						(%tmp) = _protopack($oscar, $datum->{items}, \$subpacket);

						# Now, if we *didn't* have a length prefix, we
						# want to cut out the bits of $packet which just got consumed.
						# If we had a length prefix, we already knew to cut away the right amount.
						#
						$packet = $subpacket unless $datum->{packet};
					}

					if($datum->{type} eq "ref") {
						(%tmp) = protoparse($oscar, $datum->{name})->(\$subpacket);
						push @results, \%tmp;
					} else {
						if($datum->{name}) {
							if(@{$datum->{items}}) {
								push @results, \%tmp;
							} else {
								push @results, $subpacket;
							}
						}
					}


					# If we didn't have an explicit length on this datum,
					# we couldn't take the right amount off of $packet,
					# so we took everything.  Now, put anything leftover
					# back.
					if(!$datum->{length} and !$datum->{packlet}) {
						$packet = $subpacket;
					}
				}

				if($datum->{name}) {
					if($datum->{count}) {
						$data{$datum->{name}} = \@results;
					} elsif(ref($datum->{items}) and @{$datum->{items}}) {
						$data{$_} = $results[0]->{$_} foreach keys %{$results[0]};
					} elsif($datum->{type} eq "ref") {
						$data{$_} = $results[0]->{$_} foreach keys %{$results[0]};
					} else {
						$data{$datum->{name}} = $results[0];
					}
				}
			} elsif($datum->{type} eq "tlvchain") {
				my($tlvpacket, $tlvmax, $tlvcount) = ($packet, 0, 0);

				# Process prefixes
				if($datum->{prefix}) {
					my(%tmp) = _protopack($oscar, [{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, name => "len"}], substr($tlvpacket, 0, $datum->{len}, ""));
					if($datum->{prefix} eq "count") {
						$tlvmax = $tmp{len};
					} else {
						$tlvpacket = substr($packet, 0, $tmp{len}, "");
					}
				}

				# Okay, now set up a hash for going from (sub)type to name
				my $tlvmap = tlv();
				if($datum->{subtyped}) {
					foreach (@{$datum->{items}}) {
						$tlvmap->{$_->{num}} ||= tlv();
						$tlvmap->{$_->{num}}->{$_->{subtype} || -1} = $_;
					}
				} else {
					$tlvmap->{$_->{num}} = $_ foreach (@{$datum->{items}});
				}

				# Next, split the chain up into types
				while($tlvpacket and (!$tlvmax or $tlvcount < $tlvmax)) {
					my($type, $length, $subtype, $value);
					if($datum->{subtyped}) {
						($type, $length, $subtype) = unpack("nCC", substr($tlvpacket, 0, 4, ""));
					} else {
						($type, $length) = unpack("nn", substr($tlvpacket, 0, 4, ""));
					}
					$value = substr($tlvpacket, 0, $length, "");

					if($datum->{subtyped}) {
						if(!exists($tlvmap->{$type}->{$subtype}) and exists($tlvmap->{$type}->{-1})) {
							$subtype = -1;
						}
						$tlvmap->{$type}->{$subtype}->{data} = $value;
					} else {
						$tlvmap->{$type}->{data} = $value;
					}
				} continue {
					$tlvcount++;
				}

				# Almost done!  Go back through the hash we made earlier, which now has the data in it, and cram stuff into the output
				while(my($num, $val) = each %$tlvmap) {
					if($datum->{subtyped}) {
						while(my($subtype, $subval) = each %$val) {
							next unless $subval->{type};

							if(defined($subval->{data})) {
								my(%tmp) = _protopack($oscar, [$subval], $subval->{data});
								$data{$_} = $tmp{$_} foreach keys %tmp;
							}
						}
					} else {
						next unless $val->{type};

						if(defined($val->{data})) {
							my(%tmp) = _protopack($oscar, [$val], $val->{data});
							$data{$_} = $tmp{$_} foreach keys %tmp;
						}
					}
				}

				$packet = $tlvpacket;
			}
		}

		
		$oscar->log_print(OSCAR_DBG_DEBUG, "Decoded:\n", join("\n", map { "\t$_ => ".hexdump($data{$_}) } keys %data));

		# Remember, passing in a ref to packet in place of actual packet data == in-place editing...
		$$x_packet = $packet if ref($x_packet);

		return %data;
	} else { # Pack
		my %data = @_;
		my $packet = "";

		$oscar->log_print(OSCAR_DBG_DEBUG, "Encoding:\n", join("\n", map { "\t$_ => ".hexdump($data{$_}) } keys %data));

		foreach my $datum (@$template) {
			my $value = undef;
			$value = $data{$datum->{name}} if $datum->{name};
			$value = $datum->{value} if !defined($value);
			next unless defined($value);

			if($datum->{type} eq "num") {
				my $count = $datum->{count} || 1;

				for(my $i = 0; ($count != -1 and $i < $count) or (ref($value) and @$value); $i++) {
					my $val = ref($value) ? shift(@$value) : $value;
					$packet .= pack($datum->{packlet}, $val);
				}
			} elsif($datum->{type} eq "data" or $datum->{type} eq "ref") {
				my $count = $datum->{count} || 1;
				confess "Asked to output too many data items!" if ref($value) and $count != -1 and @$value > $count;

				my $subpacket = "";
				for(my $i = 0; ($count != -1 and $i < $count) or (ref($value) and @$value); $i++) {
					my $val = ref($value) ? shift(@$value) : $value;

					if($datum->{items} and @{$datum->{items}}) {
						$subpacket .= _protopack($oscar, $datum->{items}, ref($val) ? %$val : %data);
					} elsif($datum->{type} eq "ref") {
						$subpacket .= protoparse($oscar, $datum->{name})->(ref($val) ? %$val : %data);
					} else {
						$subpacket .= $val;
					}
				}

				if($datum->{packlet}) {
					my $prefix = _protopack($oscar, [{name => "length", type => "num", packlet => $datum->{packlet}, len => $datum->{len}}], length => length($subpacket));
					$packet .= $prefix;
				}

				$packet .= $subpacket;
			} elsif($datum->{type} eq "tlvchain") {
				my($tlvpacket, $tlvcount) = ("", 0);

				foreach (@{$datum->{items}}) {
					$tlvcount++;

					if(ref($_->{items}) and @{$_->{items}} == 1) { # TLV contains a single element
						# If the TLV contains a single element,
						# AND that element has a name,
						# AND that name doesn't exist in our input hash...
						# ...then suppress this TLV.
						#
						# This allows us to handle TLVs which alter
						# the protocol behavior based on their presence
						# or absence, as opposed to their value.
						#
						# The alternative to this auto-suppression
						# would be to add a separate name attribute
						# onto the TLV when we wanted to allow the
						# user to control its presence, and then
						# the TLVs which have a dummy data element
						# under the current scheme would have no
						# elements.  That would wind up being even
						# less elegant than the auto-suppression
						# route, at least in terms of the effect on the
						# XML.  It'd probably wind up being a wash
						# in terms of the effect on this routine.

						if($_->[0]->{name} and
						   not exists($data{$_->[0]->{name}})) {
							next;
						}
					}

					my $tmp = _protopack($oscar, [$_], %data);
					next if $tmp eq "";
					confess "No num: ", Data::Dumper::Dumper($_) unless $_->{num};

					if($datum->{subtyped}) {
						my $subtype = 0;
						$subtype = $_->{subtype} if exists($_->{subtype});

						$tlvpacket .= _protopack($oscar, [
							{type => "num", packlet => "n", len => 2, value => $_->{num}},
							{type => "num", packlet => "C", len => 1, value => $subtype},
							{type => "data", packlet => "C", len => 1, value => $tmp},
						]);
					} else {
						$tlvpacket .= _protopack($oscar, [
							{type => "num", packlet => "n", len => 2, value => $_->{num}},
							{type => "data", packlet => "n", len => 2, value => $tmp},
						]);
					}
				}

				if($datum->{prefix}) {
					if($datum->{prefix} eq "count") {
						$packet .= _protopack($oscar, [{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, value => $tlvcount}]);
					} else {
						$packet .= _protopack($oscar, [{type => "num", packlet => $datum->{packlet}, len => $datum->{len}, value => length($tlvpacket)}]);
					}
				}

				$packet .= $tlvpacket;
			}
		}

		return $packet;
	}
}

sub _num_to_packlen($$) {
	my($type, $order) = @_;
	$order ||= "network";

	if($type eq "byte") {
		return ("C", 1);
	} elsif($type eq "word") {
		if($order eq "vax") {
			return ("v", 2);
		} else {
			return ("n", 2);
		}
	} elsif($type eq "dword") {
		if($order eq "vax") {
			return ("V", 4);
		} else {
			return ("N", 4);
		}
	}

	croak "Invalid num type: $type";
}

sub _xmlnode_to_template($$) {
	my($tag, $value) = @_;

	confess "Invalid value in xmlnode_to_template!" unless ref($value);
	my $attrs = shift @$value;

	my $datum = {};
	$datum->{name} = $attrs->{name} if $attrs->{name};
	$datum->{value} = $value->[1] if @$value;
	$datum->{type} = $attrs->{type} if exists($attrs->{type});
	$datum->{subtype} = $attrs->{subtype} if exists($attrs->{subtype});

	if($tag eq "ref") {
		$datum->{type} = "ref";
		$datum->{name} = $attrs->{name};
		$datum->{items} = [];
	} elsif($tag eq "byte" or $tag eq "word" or $tag eq "dword") {
		my($packlet, $len) = _num_to_packlen($tag, $attrs->{order});
		$datum->{type} = "num";
		$datum->{packlet} = $packlet;
		$datum->{len} = $len;
		$datum->{name} = $attrs->{name} if $attrs->{name};
		$datum->{value} = $value->[1] if @$value;
		$datum->{count} = $attrs->{count} if $attrs->{count};
	} elsif($tag eq "data" or $tag eq "tlvchain") { # Ones that have sub-elements
		$datum->{count} = $attrs->{count} if $attrs->{count};
		$datum->{length} = $attrs->{length} if $attrs->{length};

		$datum->{type} = $tag;
		if($attrs->{count_prefix} || $attrs->{length_prefix}) {
			my($packlet, $len) = _num_to_packlen($attrs->{count_prefix} || $attrs->{length_prefix}, $attrs->{prefix_order});
			$datum->{packlet} = $packlet;
			$datum->{len} = $len;
			$datum->{prefix} = $attrs->{count_prefix} ? "count" : "length";
		}

		if($tag eq "tlvchain") {
			$datum->{subtyped} = 1 if $attrs->{subtyped} and $attrs->{subtyped} eq "yes";
		}

		$datum->{items} = [];

		while(@$value) {
			my($subtag, $subval) = splice(@$value, 0, 2);
			next if $subtag eq "0";

			my $item;

			# In TLV chains, the structure is:
			# 	<tlvchain>
			# 		<tlv><SUBDATA /><SUBDATA /></tlv>
			# 	</tlvchain>
			# However, in data, we have:
			#	<data>
			#		<SUBDATA /><SUBDATA />
			#	</data>
			# So, here we break out that inner level for TLV chains.
			#
			if($tag eq "tlvchain") {
				my $attrs = shift @$subval;

				my($innertag, $innerval) = ("0", "");
				while($innertag eq "0") {
					($innertag, $innerval) = splice(@$subval, 0, 2);
				}
				$item = _xmlnode_to_template($innertag, $innerval);

				# In TLV chains, the 'name' is on the enclosing tlv layer.
				# Plus we have the 'num' attribute to worry about.
				$item->{name} = $attrs->{name} if $attrs->{name};
				$item->{num} = $attrs->{type};
				$item->{subtype} = $attrs->{subtype} if $attrs->{subtype};
			} else {
				$item = _xmlnode_to_template($subtag, $subval);
			}

			push @{$datum->{items}}, $item;
		}
	}

	return $datum;
}

sub protoparse($$) {
	my ($oscar, $wanted) = @_;
	my $xml = $xmlmap{$wanted}->{xml} or croak "Couldn't find requested protocol element '$wanted'.";

	confess "No oscar!" unless $oscar;

	my $attrs = shift @$xml;

	my @template = ();

	while(@$xml) {
		my $tag = shift @$xml;
		my $value = shift @$xml;
		next if $tag eq "0";
		push @template, _xmlnode_to_template($tag, $value);
	}

	return sub { _protopack($oscar, \@template, @_); };
}

# Map a "protobit" (XML <define name="foo">) to SNAC (family, subtype)
sub protobit_to_snacfam($) {
	my $protobit = shift;
	confess "Unknown protobit $protobit" unless $xmlmap{$protobit};
	return ($xmlmap{$protobit}->{family}, $xmlmap{$protobit}->{subtype});
}

# Map a SNAC (family, subtype) to "protobit" (XML <define name="foo">)
sub snacfam_to_protobit($$) {
	my($family, $subtype) = @_;
	if($xml_revmap{$family} and $xml_revmap{$family}->{$subtype}) {
		return $xml_revmap{$family}->{$subtype};
	} elsif($xml_revmap{0} and $xml_revmap{0}->{$subtype}) {
		return $xml_revmap{0}->{$subtype};
	} else {
		return undef;
	}
}

1;
