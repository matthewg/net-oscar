package Net::OSCAR::Callbacks;
use strict;
use warnings;
use vars qw($connection $snac $conntype $family $subtype $data $reqid $reqdata $session $protobit %data);
sub {

# It looks like we get a blank family if the server sends
# no migration families (full migration.)  Filter out
# this dummy entry.
my @migfamilies = grep { $_ != 0 } @{$data{families}};

$connection->log_print(OSCAR_DBG_WARN, "Migration families received: ", join(" ", @migfamilies));

my $pause_queue;
if(@{$data{families}} == keys %{$connection->{families}} or @migfamilies == 0) {
	$connection->log_print(OSCAR_DBG_WARN, "Full migration, disconnecting...");
	$pause_queue = $connection->{pause_queue};
	$session->delconn($connection);
} else {
	$connection->log_print(OSCAR_DBG_WARN, "Partial migration");

	# Get the list of families which aren't being migrated
	my @all_families = keys %{$connection->{families}};
	$connection->{families} = {};
	foreach my $fam (@all_families) {
		next if grep { $_ == $fam } @migfamilies;
		$connection->{families}->{$fam} = 1;
	}

	# Filter the pause queue according to the migration split
	my $all_pause_queue = $connection->{pause_queue};
	$connection->{pause_queue} = [];
	foreach my $item (@$all_pause_queue) {
		if(grep { $item->{family} == $_ } @migfamilies) {
			push @$pause_queue, $item;
		} else {
			push @{$connection->{pause_queue}}, $item;
		}
	}

	$connection->log_printf(OSCAR_DBG_WARN, "Migration pause queue: %d/%d", @$pause_queue, @{$connection->{pause_queue}});
}

my $newconn = $session->addconn(
	auth => $data{cookie},
	conntype => $connection->{conntype},
	description => $connection->{description},
	peer => $data{peer},
	paused => 1,
	pause_queue => $pause_queue
);

};