# These objects, initialized with an "OSCAR protocol template" from Net::OSCAR::XML::protoparse,
# pack and unpack data according to the specification of that template.

package Net::OSCAR::XML::Template;

use strict;
use warnings;

use Net::OSCAR::XML qw(protoparse);
use Net::OSCAR::Common qw(:loglevels);
use Net::OSCAR::Utility qw(hexdump);
use Net::OSCAR::TLV;
use Data::Dumper;
use Carp;

sub new($@) {
	my $class = shift;
	my $package = ref($class) || $class || "Net::OSCAR::XML::Template";
	my $self = {template => $_[0]};
	$self->{oscar} = $class->{oscar} if ref($class) and $class->{oscar};
	bless $self, $package;
	return $self;
}

# Net::OSCAR::XML caches Template objects that don't have an associated OSCAR,
# so that the same Template can be reused with multiple OSCAR objects.
# Before returning a Template to the user, it calls set_oscar, so here we clone
# ourself with the new OSCAR.
#
sub set_oscar($$) {
	my($self, $oscar) = @_;
	my $clone = $self->new($self->{template});
	$clone->{oscar} = $oscar;
	return $clone;
}


# If given a scalar ref instead of a scalar as the second argument,
# we will modify the packet in-place.
sub unpack($$) {
	my ($self, $x_packet) = @_;
	my $oscar = $self->{oscar};
	my $template = $self->{template};
	my $packet = ref($x_packet) ? $$x_packet : $x_packet;

	my %data = ();

	$oscar->log_print(OSCAR_DBG_XML, "Decoding:\n", hexdump($packet), "\n according to: ", Data::Dumper::Dumper($template));

	assert(ref($template) eq "ARRAY");
	foreach my $datum (@$template) {
		my $count = $datum->{count} || ($datum->{type} eq "tlvchain" ? -1 : 1);
		my @results;


		## Figure out how much input data this datum is dealing with

		if($datum->{prefix} and $datum->{prefix} eq "count") {
			($count) = unpack($datum->{prefix_packlet}, substr($packet, 0, $datum->{prefix_len}, ""));
		}

		my $size = undef;
		if($datum->{type} eq "num") {
			if($count != -1) {
				$size = $datum->{len} * $count;
			} else {
				$size = length($packet);
			}
		} else {
			if($datum->{prefix} and $datum->{prefix} eq "length") {
				($size) = unpack($datum->{prefix_packlet}, substr($packet, 0, $datum->{prefix_len}, ""));
			} elsif(exists($datum->{len})) {
				if($count == -1) {
					$size = length($packet);
				} else {
					$size = $datum->{len} * $count;
				}
			}
		}

		my $input;
		if(defined($size)) {
			$input = substr($packet, 0, $size, "");
		} else {
			$input = $packet;
		}


		## Okay, we have our input data -- act on it

		if($datum->{type} eq "num") {
			for(my $i = 0; $input and ($count == -1 or $i < $count); $i++) {
				push @results, unpack($datum->{packlet}, substr($input, 0, $datum->{len}, ""));
			}
		} elsif($datum->{type} eq "data" or $datum->{type} eq "ref") {
			# If we just have simple, no preset length, no subitems, raw data, it can't have a repeat count, since the first repetition will gobble up everything
			assert($datum->{type} ne "data" or @{$datum->{items}} or defined($size) or $count == 1);

			for(my $i = 0; $input and ($count == -1 or $i < $count); $i++) {
				# So, consider the structure:
				#	<data name="foo">
				#		<word />
				#		<word />
				#	</data>
				# We don't know the size of 'foo' in advance.
				# Thus, we pass a reference to the actual packet into protopack.
				# subpacket will be modified to be the packet minus the bits that the contents of the data consumed.

				my %tmp;
				if($datum->{type} eq "data") {
					my $subinput;
					if($datum->{len}) {
						$subinput = substr($input, 0, $datum->{len}, "");
					} else {
						$subinput = $input;
						$input = "";
					}

					if(@{$datum->{items}}) {
						(%tmp) = $self->new($datum->{items})->unpack(\$subinput);
						$input = $subinput unless $datum->{len};
					} else {
						# The simple case -- raw <data />
						push @results, $subinput if $datum->{name};
					}
				} elsif($datum->{type} eq "ref") {
					(%tmp) = protoparse($oscar, $datum->{name})->unpack(\$input);
				}

				push @results, \%tmp if %tmp;
			}
		} elsif($datum->{type} eq "tlvchain") {
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
			for(my $i = 0; $input and ($count == -1 or $i < $count); $i++) {
				my %tlv;
				if($datum->{subtyped}) {
					(%tlv) = protoparse($oscar, "subtyped TLV")->unpack(\$input);
				} else {
					(%tlv) = protoparse($oscar, "TLV")->unpack(\$input);
				}

				if($datum->{subtyped}) {
					assert(exists($tlv{subtype}));
					if(!exists($tlvmap->{$tlv{type}}->{$tlv{subtype}}) and exists($tlvmap->{$tlv{type}}->{-1})) {
						$tlv{subtype} = -1;
					}
					$tlvmap->{$tlv{type}}->{$tlv{subtype}}->{data} = $tlv{data};
				} else {
					$tlvmap->{$tlv{type}}->{data} = $tlv{data};
				}
			}


			# Almost done!  Go back through the hash we made earlier, which now has the
			# data in it, and do the processing for each TLV
			while(my($num, $val) = each %$tlvmap) {
				if($datum->{subtyped}) {
					while(my($subtype, $subval) = each %$val) {
						if(exists($subval->{data})) {
							if(ref($subval->{items}) and @{$subval->{items}} and $subval->{data}) {
								my(%tmp) = $self->new($subval->{items})->unpack($subval->{data});
								if($subval->{name}) {
									push @results, {$subval->{name} => \%tmp};
								} else {
									push @results, \%tmp;
								}
							}
						}
					}
				} else {
					if(exists($val->{data})) {
						if(ref($val->{items}) and @{$val->{items}} and $val->{data}) {
							my(%tmp) = $self->new($val->{items})->unpack($val->{data});
							if($val->{name}) {
								push @results, {$val->{name} => \%tmp};
							} else {
								push @results, \%tmp;
							}
						}
					}
				}
			}
		}


		# If we didn't know the length of the datum in advance,
		# we've been modifying the entire packet in-place.
		$packet = $input if !defined($size);


		## Okay, we have the results from this datum, store them away.

		if($datum->{name}) {
			if($datum->{count}) {
				$data{$datum->{name}} = \@results;
			} elsif(
			  $datum->{type} eq "ref" or
			  (ref($datum->{items}) and @{$datum->{items}})
			) {
				$data{$_} = $results[0]->{$_} foreach keys %{$results[0]};
			} else {
				$data{$datum->{name}} = $results[0];
			}
		} elsif(@results) {
			foreach my $result(@results) {
				next unless ref($result);
				$data{$_} = $result->{$_} foreach keys %$result;
			}
		}
	}

	$oscar->log_print(OSCAR_DBG_XML, "Decoded:\n", join("\n", map { "\t$_ => ".hexdump($data{$_}) } keys %data));

	# Remember, passing in a ref to packet in place of actual packet data == in-place editing...
	$$x_packet = $packet if ref($x_packet);

	return %data;
}


sub pack($%) {
	my($self, %data) = @_;
	my $packet = "";
	my $oscar = $self->{oscar};
	my $template = $self->{template};

	$oscar->log_print(OSCAR_DBG_XML, "Encoding:\n", join("\n", map { "\t$_ => ".hexdump($data{$_}) } keys %data));

	assert(ref($template) eq "ARRAY");
	foreach my $datum (@$template) {
		my $output = "";
		my $max_count = exists($datum->{count}) ? $datum->{count} : 1;
		my $count = 0;


		## Figure out what we're packing
		my $value = undef;
		$value = $data{$datum->{name}} if $datum->{name};
		$value = $datum->{value} if !defined($value);
		my @valarray = ref($value) eq "ARRAY" ? @$value : ($value); # Don't modify $value in-place!

		assert($max_count == -1 or @valarray <= $max_count);


		## Pack it
		if($datum->{type} eq "num") {
			next unless defined($value);

			for($count = 0; ($max_count == -1 or $count < $max_count) and @valarray; $count++) {
				$output .= pack($datum->{packlet}, shift @valarray);
			}
		} elsif($datum->{type} eq "data" or $datum->{type} eq "ref") {
			for($count = 0; ($max_count == -1 or $count < $max_count) and @valarray; $count++) {
				my $val = shift @valarray;

				if($datum->{items} and @{$datum->{items}}) {
					$output .= $self->new($datum->{items})->pack(ref($val) ? %$val : %data);
				} elsif($datum->{type} eq "ref") {
					assert($max_count == 1 or (ref($val) and ref($val) eq "HASH"));
					$output .= protoparse($oscar, $datum->{name})->pack(ref($val) ? %$val : %data);
				} else {
					$output .= $val if $val;
				}
			}
		} elsif($datum->{type} eq "tlvchain") {
			foreach my $tlv (@{$datum->{items}}) {
				my $tlvdata = undef;

				if(exists($tlv->{name})) {
					if(exists($data{$tlv->{name}})) {
						assert(ref($data{$tlv->{name}}) eq "HASH");
						$tlvdata = $self->new($tlv->{items})->pack(%{$data{$tlv->{name}}});
					}
				} else {
					my $tmp = $self->new($tlv->{items})->pack(%data);
					$tlvdata = $tmp if $tmp;
				}
	
				assert($tlv->{num});
				next unless defined($tlvdata);

				$count++;
				if($datum->{subtyped}) {
					my $subtype = 0;
					assert(exists($tlv->{subtype}));
					$subtype = $tlv->{subtype} if $tlv->{subtype} != -1;

					$output .= protoparse($oscar, "subtyped TLV")->pack(
						type => $tlv->{num},
						subtype => $subtype,
						data => $tlvdata
					);
				} else {
					$output .= protoparse($oscar, "TLV")->pack(
						type => $tlv->{num},
						data => $tlvdata
					);
				}
			}
		}


		## Handle any prefixes
		if($datum->{prefix}) {
			if($datum->{prefix} eq "count") {
				$packet .= pack($datum->{prefix_packlet}, $count);
			} else {
				$packet .= pack($datum->{prefix_packlet}, length($output));
			}
		}

		$packet .= $output;
	}

	$oscar->log_print(OSCAR_DBG_XML, "Encoded:\n", hexdump($packet));
	return $packet;
}


sub assert($) {
	my $test = shift;
	return if $test;
	confess("Net::OSCAR internal error");
}

# Why isn't this imported properly??
sub protoparse { Net::OSCAR::XML::protoparse(@_); }

1;
