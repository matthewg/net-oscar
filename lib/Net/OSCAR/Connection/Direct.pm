=pod

Net::OSCAR::Connection::Direct -- OSCAR direct connections

=cut

package Net::OSCAR::Connection::Direct;

$VERSION = '1.11';
$REVISION = '$Revision$';

use strict;
use Carp;

use vars qw(@ISA $VERSION $REVISION);
use Socket;
use Symbol;
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::Constants;
use Net::OSCAR::Utility;
use Net::OSCAR::XML;
@ISA = qw(Net::OSCAR::Connection);

sub new($@) {
	my $self = shift->SUPER::new(@_);

	$self->{checksum} = 0xFFFF0000;
	$self->{received_checksum} = 0xFFFF0000;
	$self->{sent_oft_header} = 0;
	$self->{bytes_recv} = 0;

	return $self;
}

sub process_one($;$$$) {
	my($self, $read, $write, $error) = @_;
	my $snac;

	if($error) {
		$self->{sockerr} = 1;
		return $self->disconnect();
	}

	$self->log_printf(OSCAR_DBG_DEBUG,
		"Called process_one on direct connection: st=%s, fts=%s, dir=%s, acp=%s, r=$read, w=$write, e=$error",
		$self->{state}, $self->{rv}->{ft_state}, $self->{rv}->{direction}, $self->{rv}->{accepted}
	);
	if($read and $self->{rv}->{ft_state} eq "listening") {
		my $newsock = gensym();

		if(accept($newsock, $self->{socket})) {
			$self->log_print(OSCAR_DBG_DEBUG, "Accepted incoming connection.");
			$self->{session}->callback_connection_changed($self, "deleted");
			close($self->{socket});
			$self->{socket} = $newsock;
			$self->set_blocking(0);

			if($self->{rv}->{direction} eq "send") {
				$self->{state} = "write";
			} else {
				$self->{state} = "read";
			}

			$self->{rv}->{ft_state} = "connected";
			$self->{session}->callback_connection_changed($self, $self->{state});

			return 1;
		} else {
			$self->log_print(OSCAR_DBG_WARN, "Failed to accept incoming connection: $!");
			return 0;
		}
	} elsif($write and $self->{rv}->{ft_state} eq "connecting") {
		$self->log_print(OSCAR_DBG_DEBUG, "Connected.");
		$self->{connected} = 1;

	        my %protodata;
	        $protodata{status} = 1;
	        $protodata{cookie} = $self->{rv}->{cookie};
		$protodata{capability} = OSCAR_CAPS()->{$self->{rv}->{type}} ? OSCAR_CAPS()->{$self->{rv}->{type}}->{value} : $self->{rv}->{type};
		$self->{session}->send_message($self->{rv}->{sender}, 2, protoparse($self->{session}, "rendezvous_IM")->pack(%protodata));

		$self->{rv}->{ft_state} = "connected";
		$self->{rv}->{accepted} = 1;
		if($self->{rv}->{direction} eq "receive") {
			$self->{state} = "read";
			$self->{session}->callback_connection_changed($self, $self->{state});
		}
	} elsif($write and $self->{rv}->{ft_state} eq "connected") {
		if($self->{rv}->{direction} eq "send") {
			return 1 unless $self->{rv}->{accepted};
		}

		$self->log_print(OSCAR_DBG_DEBUG, "Sending OFT header (SYN).");
		my $ret;
		if($self->{sent_oft_header}) {
			$self->log_print(OSCAR_DBG_DEBUG, "Flushing buffer");
			$ret = $self->write(); # Flush buffer
		} else {
			$self->log_print(OSCAR_DBG_DEBUG, "Sending initial header");
			$self->{sent_oft_header} = 1;
			$ret = $self->send_oft_header();
		}
		return $ret unless $ret;
		delete $self->{sent_oft_header};

		if($self->{rv}->{direction} eq "receive") {
			$self->{rv}->{ft_state} = "data";
		}

		$self->{state} = "read";
		$self->{session}->callback_connection_changed($self, "read");
	} elsif($read and $self->{rv}->{ft_state} eq "connected") {
		$self->log_print(OSCAR_DBG_DEBUG, "Getting OFT header");
		my $ret = $self->get_oft_header();
		return $ret unless $ret;

		if($self->{rv}->{direction} eq "send") {
			$self->{rv}->{ft_state} = "data";
		}

		$self->{state} = "write";
		$self->{session}->callback_connection_changed($self, "write");
	} elsif($self->{rv}->{ft_state} eq "data") {
		my $ret;

		if($write and $self->{rv}->{direction} eq "send") {
			$self->log_print(OSCAR_DBG_DEBUG, "Sending data");
			if($self->{sent_data}++) {
				$ret = $self->write();
			} else {
				$ret = $self->write($self->{rv}->{data}->[0]);
			}

			if($ret) {
				$self->log_print(OSCAR_DBG_DEBUG, "Done sending data");
				shift @{$self->{rv}->{data}};
				$self->{rv}->{ft_state} = "fin";
				$self->{state} = "read";
				$self->{session}->callback_connection_changed($self, "read");
			}
		} elsif($read and $self->{rv}->{direction} eq "receive") {
			$self->log_print(OSCAR_DBG_DEBUG, "Receiving data");
			$ret = $self->read();
		}
	} elsif($self->{rv}->{ft_state} eq "fin") {
		$self->log_print(OSCAR_DBG_DEBUG, "Getting OFT header");
		my $ret = $self->get_oft_header();
		return $ret unless $ret;

		$self->disconnect();
		return 1;
	}
}

sub send_oft_header($) {
	my $self = shift;

	my $total_size = 0;
	$total_size += length($_) foreach @{$self->{rv}->{data}};

	my $type;
	if($self->{rv}->{ft_state} eq "connected") {
		if($self->{rv}->{direction} eq "send") {
			$type = 0x101;
		} else {
			$type = 0x202;
		}
	} else {
		$type = 0x204;
	}

	$self->checksum($self->{rv}->{data}->[0]);
	my %protodata = (
		type => $type,
		cookie => chr(0) x 8,
		file_count => scalar @{$self->{rv}->{data}},
		files_left => scalar @{$self->{rv}->{data}},
		byte_count => $total_size,
		bytes_left => $total_size,
		mtime => time(),
		ctime => 0,
		bytes_received => $self->{bytes_recv},
		checksum => $self->{checksum},
		received_checksum => $self->{received_checksum},
		filename => $self->{rv}->{filenames}->[0]
	);
	$self->write(protoparse($self->{session}, "file_transfer_header")->pack(%protodata));
}

sub get_oft_header($) {
	my $self = shift;

	my $header = $self->read(6);
	return $header unless $header;
	my($magic, $length) = unpack("a4 n", $header);

	if($magic ne "OFT2") {
		$self->log_print(OSCAR_DBG_WARN, "Got unexpected data while reading file transfer header!");
                $self->{sockerr} = 1;
                $self->disconnect();
		return undef;
	}

	my $data = $self->read($length - 6);
	return $data unless $data;
	
	my %protodata = protoparse($self->{session}, "file_transfer_header")->unpack($header . $data);
	#TODO: Verify that this matches the initial proposal

	$self->log_print(OSCAR_DBG_DEBUG, "Got OFT header.");
	return 1;
}

# Adopted from Gaim's implementation
sub checksum($$) {
	my($self, $part) = @_;
	my $check = ($self->{checksum} >> 16) & 0xFFFF;

	foreach my $val (unpack("n*", $part)) {
		my $oldcheck = $check;

		$check -= $val;

		# Straight $check > $oldcheck you say?
		# Well, these are 32-bit unsigned values, and it tries to
		# compare them as signed.
		if(pack("N", $check) gt pack("N", $oldcheck)) {
			$check--;
		}
	}

	$check = (($check & 0x0000FFFF) + ($check >> 16));
	$check = (($check & 0x0000FFFF) + ($check >> 16));
	$check = $check << 16;

	$self->{checksum} = $check;
}

1;
