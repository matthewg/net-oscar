=pod

Net::OSCAR::_BLInternal -- internal buddylist stuff

This handles conversion of Net::OSCAR to "OSCAR buddylist format",
and the sending of buddylist changes to the OSCAR server.

=cut

package Net::OSCAR::_BLInternal;

use strict;
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::Constants;
use Net::OSCAR::Utility;
use Net::OSCAR::XML;

use vars qw($VERSION $REVISION);
$VERSION = '1.11';
$REVISION = '$Revision$';

sub init_entry($$$$) {
	my($blinternal, $type, $gid, $bid) = @_;

	$blinternal->{$type} ||= tlv();
	$blinternal->{$type}->{$gid} ||= tlv();
	$blinternal->{$type}->{$gid}->{$bid} ||= {};
	$blinternal->{$type}->{$gid}->{$bid}->{name} ||= "";
	$blinternal->{$type}->{$gid}->{$bid}->{data} ||= tlv();
}

sub blparse($$) {
	my($session, $data) = @_;

	# This stuff was figured out more through sheer perversity
	# than by actually understanding what all the random bits do.

	$session->{visibility} = VISMODE_PERMITALL; # If we don't have p/d data, this is default.

	delete $session->{blinternal};
	$session->{blinternal} = tlv();

	while(length($data) > 4) {
		my($name) = unpack("n/a*", $data);
		substr($data, 0, 2+length($name)) = "";
		my($gid, $bid, $type, $sublen) = unpack("n4", substr($data, 0, 8, ""));
		init_entry($session->{blinternal}, $type, $gid, $bid);
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
sub BLI_to_NO($) {
	my($session) = @_;
	my $bli = $session->{blinternal};

	delete $session->{buddies};
	delete $session->{permit};
	delete $session->{deny};
	delete $session->{visibility};
	delete $session->{groupperms};
	delete $session->{profile};
	delete $session->{appdata};
	delete $session->{showidle};
	delete $session->{presence_unknown};

	$session->{buddies} = bltie(1);
	$session->{permit} = bltie;
	$session->{deny} = bltie;


	if(exists $bli->{2}) {
		foreach my $bid(keys(%{$bli->{2}->{0}})) {
			$session->{permit}->{$bli->{2}->{0}->{$bid}->{name}} = {buddyid => $bid};
		}
	}

	if(exists $bli->{3}) {
		foreach my $bid(keys(%{$bli->{3}->{0}})) {
			$session->{deny}->{$bli->{3}->{0}->{$bid}->{name}} = {buddyid => $bid};
		}
	}

	if(exists $bli->{4} and (my($visbid) = keys %{$bli->{4}->{0}})) {
		my $typedata = $bli->{4}->{0}->{$visbid}->{data};
		($session->{visibility}) = unpack("C", $typedata->{0xCA}) if $typedata->{0xCA};

		my $groupperms = $typedata->{0xCB};
		($session->{groupperms}) = unpack("N", $groupperms) if $groupperms;
		$session->{profile} = $typedata->{0x0100} if exists($typedata->{0x0100});
		($session->{icon_checksum}) = unpack("n", $typedata->{0x0101}) if exists($typedata->{0x0101});
		($session->{icon_timestamp}) = unpack("N", $typedata->{0x0102}) if exists($typedata->{0x0102});
		($session->{icon_length}) = unpack("N", $typedata->{0x0103}) if exists($typedata->{0x0103});

		delete $typedata->{0xCB};
		delete $typedata->{0xCA};
		delete $typedata->{0x0100};
		delete $typedata->{0x0101};
		delete $typedata->{0x0102};
		$session->{appdata} = $typedata;

		$session->set_info($session->{profile}) if exists($session->{profile});
	} else {
		# No permit info - we permit everyone
		$session->{visibility} = VISMODE_PERMITALL;
		$session->{groupperms} = 0xFFFFFFFF;
	}

	if(exists $bli->{5} and (my($presbid) = keys %{$bli->{5}->{0}})) {
		my $typedata = $bli->{5}->{0}->{$presbid}->{data};
		($session->{showidle}) = unpack("N", $typedata->{0xC9} || pack("F", 0x0061E7FF));
		($session->{presence_unknown}) = unpack("N", $typedata->{0xD6} || pack("F", 0x0077FFFF));
		delete $typedata->{0xC9};
		delete $typedata->{0xD6};
	} else {
		# OSCAR complains if we set presence when it didn't give it to us...
		#$session->{showidle} = 0x0061E7FF;
		#$session->{presence_unknown} = 0x0077FFFF;
	}

	if(exists $bli->{0x14}) {
		$session->{icon_md5sum} = $bli->{0x14}->{0}->{0x51F4}->{data}->{0xD5};
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

	foreach my $gid(@gids) {
		next unless exists($bli->{1}->{$gid});
		my $group = $bli->{1}->{$gid}->{0}->{name};

		if(!$group) {
			$bli->{1}->{$gid}->{0}->{name} = $group = sprintf "Group 0x%04X", $gid;
			$session->log_printf(OSCAR_DBG_WARN, "Couldn't get group name for group 0x%04X", $gid);
		}
		$session->{buddies}->{$group} ||= {};
		my $entry = $session->{buddies}->{$group};

		$entry->{groupid} = $gid;
		$entry->{members} = bltie unless $entry->{members};
		$entry->{data} = $bli->{1}->{$gid}->{0}->{data};

		my @bids = unpack("n*", $bli->{1}->{$gid}->{0}->{data}->{0xC8} || "");
		delete $bli->{1}->{$gid}->{0}->{data}->{0xC8};

		push @bids, grep { # Find everything...
			my $inbud = $_;
			not grep { # That's not in the 0xC8 BID list...
				$_ == $inbud
			} @bids
		} keys %{exists($bli->{0}->{$gid}) ? $bli->{0}->{$gid} : {}}; # That we have a type 0 entry for in this GID

		foreach my $bid(@bids) {
			# Yeah, this next condition seems impossible, but I've seen it happen
			next unless exists($bli->{0}->{$gid}) and exists($bli->{0}->{$gid}->{$bid});

			my $buddy = $bli->{0}->{$gid}->{$bid};

			my $comment = undef;
			$comment = $buddy->{data}->{0x13C} if exists($buddy->{data}->{0x13C});
			delete $buddy->{data}->{0x13C};

			my $alias = undef;
			$alias = $buddy->{data}->{0x131} if exists($buddy->{data}->{0x131});
			delete $buddy->{data}->{0x131};

			$session->{buddies}->{$group}->{members}->{$buddy->{name}} ||= {};
			my $entry = $session->{buddies}->{$group}->{members}->{$buddy->{name}};
			$entry->{buddyid} = $bid;
			$entry->{online} = 0 unless exists($entry->{online});
			$entry->{comment} = $comment;
			$entry->{alias} = $alias;
			$entry->{data} = $buddy->{data};
		}
	}

	return 1;
}

# Gee, guess what this does?  Hint: see sub BLI_to_NO.
sub NO_to_BLI($) {
	my $session = shift;

	my $bli = tlv();

	foreach my $permit (keys %{$session->{permit}}) {
		init_entry($bli, 2, 0, $session->{permit}->{$permit}->{buddyid});
		$bli->{2}->{0}->{$session->{permit}->{$permit}->{buddyid}}->{name} = $permit;
	}

	foreach my $deny (keys %{$session->{deny}}) {
		init_entry($bli, 3, 0, $session->{deny}->{$deny}->{buddyid});
		$bli->{3}->{0}->{$session->{deny}->{$deny}->{buddyid}}->{name} = $deny;
	}

	my $vistype;
	$vistype = (keys %{$session->{blinternal}->{4}->{0}})[0] if exists($session->{blinternal}->{4}) and exists($session->{blinternal}->{4}->{0}) and scalar keys %{$session->{blinternal}->{4}->{0}};
	$vistype ||= int(rand(30000)) + 1;
	init_entry($bli, 4, 0, $vistype);
	$bli->{4}->{0}->{$vistype}->{data}->{0xCA} = pack("C", $session->{visibility} || VISMODE_PERMITALL);
	$bli->{4}->{0}->{$vistype}->{data}->{0xCB} = pack("N", $session->{groupperms} || 0xFFFFFFFF);

	#Net::OSCAR protocol extensions
	$bli->{4}->{0}->{$vistype}->{data}->{0x0100} = $session->{profile} if $session->{profile};
	$bli->{4}->{0}->{$vistype}->{data}->{0x0101} = pack("n", $session->{icon_checksum}) if $session->{icon_checksum};
	$bli->{4}->{0}->{$vistype}->{data}->{0x0102} = pack("N", $session->{icon_timestamp}) if $session->{icon_timestamp};
	$bli->{4}->{0}->{$vistype}->{data}->{0x0103} = pack("N", $session->{icon_length}) if $session->{icon_length};

	foreach my $appdata(keys %{$session->{appdata}}) {
		$bli->{4}->{0}->{$vistype}->{data}->{$appdata} = $session->{appdata}->{$appdata};
	}

	if(exists($session->{showidle})) {
		my $presencetype;
		$presencetype = (keys %{$session->{blinternal}->{5}->{0}})[0] if exists($session->{blinternal}->{5}) and exists($session->{blinternal}->{5}->{0}) and scalar keys %{$session->{blinternal}->{5}->{0}};
		$presencetype ||= 0x0001;
		init_entry($bli, 5, 0, $presencetype);
		$bli->{5}->{0}->{$presencetype}->{data}->{0xC9} = pack("N", exists($session->{showidle}) ? $session->{showidle} : 0x0061E7FF);
		$bli->{5}->{0}->{$presencetype}->{data}->{0xD6} = pack("N", exists($session->{presence_unknown}) ? $session->{presence_unknown} : 0x0077FFFF);
	}


	if(exists($session->{icon_md5sum})) {
		init_entry($bli, 0x14, 0, 0x51F4);
		$bli->{0x14}->{0}->{0x51F4}->{name} = "1";
		$bli->{0x14}->{0}->{0x51F4}->{data}->{0xD5} = $session->{icon_md5sum};
	}

	init_entry($bli, 1, 0, 0);
	$bli->{1}->{0}->{0}->{data}->{0xC8} = pack("n*", map { $_->{groupid} } values %{$session->{buddies}});
	foreach my $group(keys %{$session->{buddies}}) {
		my $gid = $session->{buddies}->{$group}->{groupid};
		init_entry($bli, 1, $gid, 0);
		$bli->{1}->{$gid}->{0}->{name} = $group;
		$bli->{1}->{$gid}->{0}->{data}->{0xC8} = pack("n*",
			map { $_->{buddyid} }
			values %{$session->{buddies}->{$group}->{members}});

		foreach my $buddy(keys %{$session->{buddies}->{$group}->{members}}) {
			my $bid = $session->{buddies}->{$group}->{members}->{$buddy}->{buddyid};
			next unless $bid;
			init_entry($bli, 0, $gid, $bid);
			$bli->{0}->{$gid}->{$bid}->{name} = $buddy;
			while(my ($key, $value) = each(%{$session->{buddies}->{$group}->{members}->{$buddy}->{data}})) {
				$bli->{0}->{$gid}->{$bid}->{data}->{$key} = $value;
			}
			$bli->{0}->{$gid}->{$bid}->{data}->{0x13C} = $session->{buddies}->{$group}->{members}->{$buddy}->{comment} if defined $session->{buddies}->{$group}->{members}->{$buddy}->{comment};
			$bli->{0}->{$gid}->{$bid}->{data}->{0x131} = $session->{buddies}->{$group}->{members}->{$buddy}->{alias} if defined $session->{buddies}->{$group}->{members}->{$buddy}->{alias};
		}
	}

	BLI_to_OSCAR($session, $bli);
}

# Send changes to BLI over to OSCAR
sub BLI_to_OSCAR($$) {
	my($session, $newbli) = @_;
	my $oldbli = $session->{blinternal};
	my (@adds, @modifies, @deletes);
        $session->crapout($session->{services}->{0+CONNTYPE_BOS}, "You must wait for a buddylist_ok or buddylist_error callback before calling commit_buddylist again.") if $session->{budmods};
	$session->{budmods} = [];

	my %budmods;
	$budmods{add} = [];
	$budmods{modify} = [];
	$budmods{delete} = [];

	# First, delete stuff that we no longer use and modify everything else
	foreach my $type(keys %$oldbli) {
		foreach my $gid(keys %{$oldbli->{$type}}) {
			foreach my $bid(keys %{$oldbli->{$type}->{$gid}}) {
				my $oldentry = $oldbli->{$type}->{$gid}->{$bid};
				my $olddata = tlv_encode($oldentry->{data});
				$session->log_printf(OSCAR_DBG_DEBUG, "Old BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $oldentry->{name}, $type, $gid, $bid, length($olddata), hexdump($olddata));
				my $delete = 0;
				if(exists($newbli->{$type}) and exists($newbli->{$type}->{$gid}) and exists($newbli->{$type}->{$gid}->{$bid})) {
					my $newentry = $newbli->{$type}->{$gid}->{$bid};
					my $newdata = tlv_encode($newentry->{data});
					$session->log_printf(OSCAR_DBG_DEBUG, "New BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $newentry->{name}, $type, $gid, $bid, length($newdata), hexdump($newdata));

					next if
						$newentry->{name} eq $oldentry->{name}
					  and	$newdata eq $olddata;

					# Apparently, we can't modify the name of a buddylist entry?
					if($newentry->{name} ne $oldentry->{name}) {
						$delete = 1;
					} else {
						$session->log_print(OSCAR_DBG_DEBUG, "Modifying.");

						push @{$budmods{modify}}, {
							reqdata => {desc => "modifying ".(BUDTYPES)[$type]." $newentry->{name}", type => $type, gid => $gid, bid => $bid},
							protodata => {
								entry_name => $newentry->{name},
								group_id => $gid,
								buddy_id => $bid,
								entry_type => $type,
								entry_data => $newdata
							}
						};
					}
				} else {
					$delete = 1;
				}

				if($delete) {
					$session->log_print(OSCAR_DBG_DEBUG, "Deleting.");

					push @{$budmods{delete}}, {
						reqdata => {desc => "deleting ".(BUDTYPES)[$type]." $oldentry->{name}", type => $type, gid => $gid, bid => $bid},
						protodata => {
							entry_name => $oldentry->{name},
							group_id => $gid,
							buddy_id => $bid,
							entry_type => $type,
							entry_data => $olddata
						}
					};
				}
			}
		}
	}

	# Now, add the new stuff
	foreach my $type(keys %$newbli) {
		foreach my $gid(keys %{$newbli->{$type}}) {
			foreach my $bid(keys %{$newbli->{$type}->{$gid}}) {
				next if exists($oldbli->{$type}) and exists($oldbli->{$type}->{$gid}) and exists($oldbli->{$type}->{$gid}->{$bid}) and $oldbli->{$type}->{$gid}->{$bid}->{name} eq $newbli->{$type}->{$gid}->{$bid}->{name};
				my $entry = $newbli->{$type}->{$gid}->{$bid};
				my $data = tlv_encode($entry->{data});

				$session->log_printf(OSCAR_DBG_DEBUG, "New BLI entry %s 0x%04X/0x%04X/0x%04X with %d bytes of data:%s", $entry->{name}, $type, $gid, $bid, length($data), hexdump($data));

				push @{$budmods{add}}, {
					reqdata => {desc => "adding ".(BUDTYPES)[$type]." $entry->{name}", type => $type, gid => $gid, bid => $bid},
					protodata => {
						entry_name => $entry->{name},
						group_id => $gid,
						buddy_id => $bid,
						entry_type => $type,
						entry_data => $data
					}
				};
			}
		}
	}

	# Actually send the changes.  Don't send more than 7K in a single SNAC.
	# FLAP size limit is 8K, but that includes headers - good to have a safety margin
	foreach my $type (qw(add modify delete)) {
		my $changelist = $budmods{$type};

		my(@reqdata, @packets);
		my $packet = "";
		foreach my $change(@$changelist) {
			$packet .= protoparse($session, "buddylist modification")->(%{$change->{protodata}});
			push @reqdata, $change->{reqdata};

			if(length($packet) > 7*1024) {
				#$session->log_print(OSCAR_DBG_INFO, "Adding to blmod queue (max packet size reached): type $type, payload size ", scalar(@reqdata));
				push @packets, {
					type => $type,
					data => $packet,
					reqdata => [@reqdata],
				};
				$packet = "";
				@reqdata = ();
			}
		}
		if($packet) {
			#$session->log_print(OSCAR_DBG_INFO, "Adding to blmod queue (no more changes): type $type, payload size ", scalar(@reqdata));
			push @packets, {
				type => $type,
				data => $packet,
				reqdata => [@reqdata],
			};
		}

		push @{$session->{budmods}}, map {
			(protobit => "buddylist " . $_->{type},
			reqdata => $_->{reqdata},
			protodata => $_->{data});
		} @packets;
	}

	push @{$session->{budmods}}, {protobit => "end buddylist modifications"}; # End BL mods
	#$session->log_print(OSCAR_DBG_INFO, "Adding terminator to blmod queue.");

	$session->{blold} = $oldbli;
	$session->{blinternal} = $newbli;

	if(@{$session->{budmods}} <= 1) { # We only have the start/end modification packets, no actual changes
		#$session->log_print(OSCAR_DBG_INFO, "Empty blmod queue - calling buddylist_ok.");
		delete $session->{budmods};
		$session->callback_buddylist_ok();
	} else {
		#$session->log_print(OSCAR_DBG_INFO, "Non-empty blmod queue - sending initiator and first change packet.");
		$session->svcdo(CONNTYPE_BOS, protobit => "start buddylist modifications");
		$session->svcdo(CONNTYPE_BOS, %{shift @{$session->{budmods}}}); # Send the first modification
	}
}

1;
