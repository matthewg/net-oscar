package Net::OSCAR::_BLInternal;

use Net::OSCAR::Common qw(:all);

# Heh, this is fun.
# This is what we use as the first arg to Net::OSCAR::TLV when creating a new BLI.
# What this does is make it so that the hashref-keys (keys whose values are hashrefs)
# of the root BLI will be Net::OSCAR::TLVs.  Hashref-keys of those N::O::TLVs will also
# be N::O::TLVs.  Same for the next level.  The level after that gets a hashref
# with two keys: name is the empty string and data is a N::O::TLV.
# 
# Here's a better way to picture it:
#    $bli = Net::OSCAR::TLV->new(BLI_AUTOVIV);
#    $bli->{$type}->{$gid}->{$bid}->{data}->{0xABCD} = "foo";
#          ^^^^^^^  ^^^^^^  ^^^^^^  ^^^^^^
#          TLV      TLV     {name,  TLV
#                            data}      
#
# The subkeys are automagically TLV-ified.
#
use constant BLI_AUTOVIV =>
	q!
		tie %$value, ref($self), q#
			tie %$value, ref($self), q^
				$value->{name} = ""; $value->{data} = Net::OSCAR::Common::tlvtie;
			^
		#
	!;

sub blparse($$) {
	my($session, $data) = @_;

	# This stuff was figured out more through sheer perversity
	# than by actually understanding what all the random bits do.

	$session->{visibility} = VISMODE_PERMITALL; # If we don't have p/d data, this is default.

	substr($data, 0, 3, "");

	delete $session->{blinternal};
	$session->{blinternal} = tlvtie BLI_AUTOVIV;

	while(length($data) > 4) {
		my($name) = unpack("n/a*", $data);
		substr($data, 0, 2+length($name)) = "";
		my($gid, $bid, $type, $sublen) = unpack("n*", substr($data, 0, 8, ""));
		my $typedata = tlv_decode(substr($data, 0, $sublen, ""));

		$session->{blinternal}->{$type}->{$gid}->{$bid}->{name} = $name if $name;
		while(my($key, $value) = each %$typedata) {
			$session->{blinternal}->{$type}->{$gid}->{$bid}->{data}->{$key} = $value;
		}
		$session->log_printf(OSCAR_DBG_DEBUG, "Got BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $name, $type, $gid, $bid, $sublen, hexdump(tlv_encode($typedata)));
	}

	return BLI_to_NO($session);
}

# Buddylist-Internal -> Net::OSCAR
# Sets various $session hashkeys from blinternal.
# That's what Brian Bli-to-no'd do. ;)
#
# Optionally, only process one type/GID/BID.
# All three must be specified if any are.
# This is used by Callbacks.pm when we get an 0x13/0x0E error.
sub BLI_to_NO($;$$$) {
	my($session, $dotype, $dogid, $dobid) = @_;
	my $bli = $session->{blinternal};

	if(!defined($dotype)) {
		delete $session->{buddies};
		delete $session->{permit};
		delete $session->{deny};
		delete $session->{visibility};
		delete $session->{groupperms};
		delete $session->{profile};
		delete $session->{appdata};
		delete $session->{showidle};

		$session->{buddies} = bltie(1);
		$session->{permit} = bltie;
		$session->{deny} = bltie;
	} else {
		if($dotype == 0) {
			my $group = $session->findgroup($dogid);
			if($group and !exists($session->{blold}->{0}->{$dogid})) {
				delete $bli->{0}->{$dogid};
				delete $session->{buddies}->{$group};
				return 1;
			}
		} elsif($dotype == 1) {
			my $group = $session->findgroup($dogid);
			if($group) {
				my $buddy = $session->findbuddy_byid($session->{buddies}->{$group}->{members}, $dobid);
				if($buddy and !exists($session->{blold}->{1}->{$dogid}->{$dobid})) {
					delete $bli->{1}->{$dogid}->{$dobid};
					delete $session->{buddies}->{$group}->{members}->{$buddy};
					return 1;
				}
			}
		} elsif($dotype == 2) {
				my $buddy = $session->findbuddy_byid($session->{permit}, $dobid);
				if($buddy and !exists($session->{blold}->{2}->{$dogid}->{$dobid})) {
					delete $bli->{2}->{$dogid}->{$dobid};
					delete $session->{permit}->{$buddy};
					return 1;
				}
		} elsif($dotype == 3) {
				my $buddy = $session->findbuddy_byid($session->{deny}, $dobid);
				if($buddy and !exists($session->{blold}->{3}->{$dogid}->{$dobid})) {
					delete $bli->{3}->{$dogid}->{$dobid};
					delete $session->{deny}->{$buddy};
					return 1;
				}
		} elsif($dotype == 4) {
			delete $session->{visibility};
			delete $session->{groupperms};
			delete $session->{profile};
			delete $session->{appdata};
		} elsif($dotype == 5) {
			delete $session->{showidle};
		}
	}

	if(exists $bli->{2} and (!defined($dotype) or $dotype == 2)) {
		foreach my $bid(defined($dobid) ? ($dobid) : keys(%{$bli->{2}->{0}})) {
			$session->{permit}->{$bli->{2}->{0}->{$bid}->{name}} = {buddyid => $bid};
		}
	}

	if(exists $bli->{3} and (!defined($dotype) or $dotype == 3)) {
		foreach my $bid(defined($dobid) ? ($dobid) : keys(%{$bli->{3}->{0}})) {
			$session->{deny}->{$bli->{3}->{0}->{$bid}->{name}} = {buddyid => $bid};
		}
	}

	if(exists $bli->{4} and (!defined($dotype) or $dotype == 4)) {
		my $typedata = $bli->{4}->{0}->{(keys %{$bli->{4}->{0}})[0]}->{data};
		($session->{visibility}) = unpack("C", $typedata->{0xCA}) if $typedata->{0xCA};

		my $groupperms = $typedata->{0xCB};
		($session->{groupperms}) = unpack("N", $groupperms) if $groupperms;
		$session->{profile} = $typedata->{0x0100} if exists($typedata->{0x0100});

		delete $typedata->{0xCB};
		delete $typedata->{0xCA};
		delete $typedata->{0x0100};
		$session->{appdata} = $typedata;

		$session->set_info($session->{profile}) if exists($session->{profile});
	}

	if(exists $bli->{5} and (!defined($dotype) or $dotype == 5)) {
		# Not yet implemented
		($session->{showidle}) = unpack("N", $bli->{5}->{0}->{19719}->{data}->{0xC9});
	}

	my @gids = unpack("n*", (exists($bli->{1}) and exists($bli->{1}->{0}) and exists($bli->{1}->{0}->{0}) and exists($bli->{1}->{0}->{0}->{data}->{0xC8})) ? $bli->{1}->{0}->{0}->{data}->{0xC8} : "");
	push @gids, grep { # Find everything...
		my $ingrp = $_;
		not grep { # That's not in the 0xC8 GID list...
			$_ == $ingrp
		} @gids
	} grep { # Other than GID 0...
		$_ != 0
	} keys %{exists($bli->{1}) ? $bli->{1} : {}}; # That we have a type 1 entry for

	if(defined($dotype)) {
		if($dotype == 0 and $dogid == 0) { # Reset group order
			tied(%{$session->{buddies}})->setorder(
				map {
					$session->findgroup($_)
				} @gids
			);
			@gids = ();
		} elsif($dotype == 1 or $dotype == 0) { # We're doing a group/buddy
			@bids = ($dobid);
		} else { # We're doing something else
			@bids = ();
		}
	}

	foreach my $gid(@gids) {
		my $group = $bli->{1}->{$gid}->{0}->{name};

		if(!$group) {
			$bli->{1}->{$gid}->{0}->{name} = $group = sprintf "Group 0x%04X", $gid;
			$session->log_printf(OSCAR_DBG_WARN, "Couldn't get group name for group 0x%04X", $gid);
		}
		$session->{buddies}->{$group} ||= {};
		my $entry = $session->{buddies}->{$group};

		if(!defined($dotype) or $dotype == 1) { #Don't do this if doing a bud
			$entry->{groupid} = $gid;
			$entry->{members} = bltie unless $entry->{members};
			$entry->{data} = $bli->{1}->{$gid}->{0}->{data};
		}

		my @bids = unpack("n*", $bli->{1}->{$gid}->{0}->{data}->{0xC8} || "");
		delete $bli->{1}->{$gid}->{0}->{data}->{0xC8};

		push @bids, grep { # Find everything...
			my $inbud = $_;
			not grep { # That's not in the 0xC8 BID list...
				$_ == $inbud
			} @bids
		} keys %{exists($bli->{0}->{$gid}) ? $bli->{0}->{$gid} : {}}; # That we have a type 0 entry for in this GID

		if(defined($dotype)) {
			if($dotype == 1) { # Reset buddy order
				tied(%{$entry->{members}})->setorder(
					map {
						$session->findbuddy_byid($entry->{members}, $_)
					} @bids
				);
				@bids = ();
			} elsif($dotype == 0) { # We're doing a buddy
				@bids = ($dobid);
			} else { # We shouldn't even be here in this case, actually
				@bids = ();
			}
		}

		foreach my $bid(@bids) {
			my $buddy = $bli->{0}->{$gid}->{$bid};

			my $comment = undef;
			$comment = $buddy->{data}->{0x13C} if exists($buddy->{data}->{0x13C});
			delete $buddy->{data}->{0x13C};

			$session->{buddies}->{$group}->{members}->{$buddy->{name}} ||= {};
			my $entry = $session->{buddies}->{$group}->{members}->{$buddy->{name}};
			$entry->{buddyid} = $bid;
			$entry->{online} = 0 unless exists($entry->{online});
			$entry->{comment} = $comment;
			$entry->{data} = $buddy->{data};
		}
	}
	return 1;
}

# Gee, guess what this does?  Hint: see sub BLI_to_NO.
sub NO_to_BLI($) {
	my $session = shift;

	my $bli = tlvtie BLI_AUTOVIV;

	foreach my $permit (keys %{$session->{permit}}) {
		$bli->{2}->{0}->{$session->{permit}->{$permit}->{buddyid}}->{name} = $permit;
	}

	foreach my $deny (keys %{$session->{deny}}) {
		$bli->{2}->{0}->{$session->{deny}->{$deny}->{buddyid}}->{name} = $deny;
	}

	my $vistype;
	$vistype = (keys %{$session->{blinternal}->{4}->{0}})[0] if exists($session->{blinternal}->{4}) and exists($session->{blinternal}->{4}->{0}) and scalar keys %{$session->{blinternal}->{4}->{0}};
	$vistype ||= 2;
	$bli->{4}->{0}->{$vistype}->{data}->{0xCA} = pack("C", $session->{visibility} || VISMODE_PERMITALL);
	$bli->{4}->{0}->{$vistype}->{data}->{0xCB} = pack("N", $session->{groupperms} || 0xFFFFFFFF);
	$bli->{4}->{0}->{$vistype}->{data}->{0x0100} = $session->{profile} if exists($session->{profile});
	foreach my $appdata(keys %{$session->{appdata}}) {
		$bli->{4}->{0}->{$vistype}->{data}->{$appdata} = $session->{appdata}->{$appdata};
	}

	if(exists($session->{showidle})) {
		$bli->{5}->{0}->{0x4D07}->{data}->{0xC9} = pack("N", $session->{showidle});
	}

	$bli->{1}->{0}->{0}->{data}->{0xC8} = pack("n*", map { $_->{groupid} } values %{$session->{buddies}});
	foreach my $group(keys %{$session->{buddies}}) {
		my $gid = $session->{buddies}->{$group}->{groupid};
		$bli->{1}->{$gid}->{0}->{data}->{0xC8} = pack("n*", map { $_->{buddyid} } values %{$session->{buddies}->{$group}->{members}});

		foreach my $buddy(keys %{$session->{buddies}->{$group}->{members}}) {
			my $bid = $session->{buddies}->{$group}->{members}->{$buddy}->{buddyid};
			$bli->{0}->{$gid}->{$bid}->{name} = $buddy;
			while(my ($key, $value) = each(%{$session->{buddies}->{$group}->{members}->{$buddy}->{data}})) {
				$bli->{0}->{$gid}->{$bid}->{data}->{$key} = $value;
			}
			$bli->{0}->{$gid}->{$bid}->{data}->{0x13C} = $session->{buddies}->{$group}->{members}->{$buddy}->{comment} if defined $session->{buddies}->{$group}->{members}->{$buddy}->{comment};
		}
	}

	BLI_to_OSCAR($session, $bli);
}

# Send changes to BLI over to OSCAR
sub BLI_to_OSCAR($$) {
	my($session, $newbli) = @_;
	my $oldbli = $session->{blinternal};
	my $oscar = $session->{bos};
	my $modcount = 0;

	$oscar->snac_put(family => 0x13, subtype => 0x11); # Begin BL mods

	# First, delete stuff that we no longer use and modify everything else
	foreach my $type(keys %$oldbli) {
		foreach my $gid(keys %{$oldbli->{$type}}) {
			foreach my $bid(keys %{$oldbli->{$type}->{$gid}}) {
				my $oldentry = $oldbli->{$type}->{$gid}->{$bid};
				my $olddata = tlv_encode($oldentry->{data});
				$session->log_printf(OSCAR_DBG_DEBUG, "Old BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $oldentry->{name}, $type, $gid, $bid, length($olddata), hexdump($olddata));
				if(exists($newbli->{$type}) and exists($newbli->{$type}->{$gid}) and exists($newbli->{$type}->{$gid}->{$bid})) {
					my $newentry = $newbli->{$type}->{$gid}->{$bid};
					my $newdata = tlv_encode($newentry->{data});
					$session->log_printf(OSCAR_DBG_DEBUG, "New BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $newentry->{name}, $type, $gid, $bid, length($newdata), hexdump($newdata));

					next if
						$newentry->{name} eq $oldentry->{name}
					  and	$newdata eq $olddata;

					$session->log_print(OSCAR_DBG_DEBUG, "Modifying.");
					$modcount++;

					$oscar->snac_put(family => 0x13, subtype => 0x9, reqdata => {desc => "modifying ".(BUDTYPES)[$type]." $newentry->{name}", type => $type, gid => $gid, bid => $bid}, data =>
						pack("na* nnn na*",
							length($newentry->{name}),
							$newentry->{name},
							$gid,
							$bid,
							$type,
							length($newdata),
							$newdata
						)
					);
				} else {
					$session->log_print(OSCAR_DBG_DEBUG, "Deleting.");
					$modcount++;

					$oscar->snac_put(family => 0x13, subtype => 0xA, reqdata => {desc => "deleting ".(BUDTYPES)[$type]." $newentry->{name}", type => $type, gid => $gid, bid => $bid}, data => 
						pack("nnnnn", 0, $gid, $bid, $type, 0)
					);
				}
			}
		}
	}

	# Now, add the new stuff
	foreach my $type(keys %$newbli) {
		foreach my $gid(keys %{$newbli->{$type}}) {
			foreach my $bid(keys %{$newbli->{$type}->{$gid}}) {
				next if exists($oldbli->{$type}) and exists($oldbli->{$type}->{$gid}) and exists($oldbli->{$type}->{$gid}->{$bid});
				my $entry = $newbli->{$type}->{$gid}->{$bid};
				my $data = tlv_encode($entry->{data});

				$session->log_printf(OSCAR_DBG_DEBUG, "New BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $entry->{name}, $type, $gid, $bid, length($data), hexdump($data));
				$modcount++;

				$oscar->snac_put(family => 0x13, subtype => 0x8, reqdata => {desc => "adding ".(BUDTYPES)[$type]." $entry->{name}", type => $type, gid => $gid, bid => $bid}, data =>
					pack("na* nnn na*",
						length($entry->{name}),
						$entry->{name},
						$gid,
						$bid,
						$type,
						length($data),
						$data
					)
				);
			}
		}
	}

	$oscar->snac_put(family => 0x13, subtype => 0x12); # End BL mods

	$session->{blold} = $oldbli;
	$session->{blinternal} = $newbli;

	# OSCAR doesn't send an 0x13/0xE if we don't actually modify anything.
	$session->callback_buddylist_ok() unless $modcount;

	$session->{budmods} = $modcount;
}

1;
