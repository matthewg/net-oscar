package Net::OSCAR::Connection::Direct::Listener;


$VERSION = '0.62';

use strict;
use Carp;
use Socket;
use Symbol;

use Net::OSCAR::TLV;
use Net::OSCAR::Callbacks;
use vars qw(@ISA $VERSION);
use Net::OSCAR::Common qw(:all);
use Net::OSCAR::OldPerl;
@ISA = qw(Net::OSCAR::Connection::Direct);

sub port($) { return shift->{port}; }

sub touch {
	my $self = shift;
	$self->{last_activity} = time;
	$self->{session}->callback_register_timer("listener", time()+30*60, sub { $self->disconnect(); });
}

sub connect($$) {
	my($self, $host) = @_;

	# accept has a connection waiting when select indicates readability.
	# If the user hasn't given us a register_timer callback, we also pretend we're interested in writability
	# and use that to do the timing ourselves...
	$self->{state} = $self->{session}->{callbacks}->{register_timer} ? "read" : "readwrite";

	if(defined($self->{session}->{proxy_type}) and $self->{session}->{proxy_type} =~ /^SOCKS(4|5)/) {
		my $socksver = $1;
		require Net::SOCKS or return $self->{session}->crapout($self, "SOCKS proxying not available - couldn't load Net::SOCKS: $!");

		my %socksargs = (
			socks_addr => $self->{session}->{proxy_host},
			socks_port => $self->{session}->{proxy_port} || 1080,
			protocol_version => $socksver
		);
		$socksargs{user_id} = $self->{session}->{proxy_username} if exists($self->{session}->{proxy_username});
		$socksargs{user_password} = $self->{session}->{proxy_password} if exists($self->{session}->{prox_password});
		$self->{socks} = new Net::SOCKS(%socksargs) or return $self->{session}->crapout($self, "Couldn't connect to SOCKS proxy: $@");

		$self->{socket} = $self->{socks};
		$self->set_blocking(0);
		(undef, undef, $self->{port}) = $self->{socks}->bind(peer_port => $self->{session}->{options}->{direct_connect_port}) or return $self->{session}->craout($self, "Couldn't SOCKS bind: $@");
	} else {
		$self->{socket} = gensym;
		socket($self->{socket}, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
		$self->set_blocking(0);
		setsockopt($self->{socket}, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or return $self->{session}->crapout($self, "Couldn't set SO_REUSEADDR: $!");
		bind($self->{socket}, sockaddr_in($self->{session}->{options}->{direct_connect_port}, INADDR_ANY)) or return $self->{session}->crapout($self, "Couldn't bind: $!");
		listen($self->{socket}, SOMAXCONN) or return $self->{session}->crapout($self, "Couldn't listen: $!");
		($self->{port}) = getsockname($self->{socket});
	}

	$self->touch();
}

sub disconnect($) {
	my $self = shift;

	if($self->{socks}) {
		$self->{socks}->close();
	} elsif($self->{socket}) {
		close $self->{socket};
	}

	$self->{session}->delconn($self);
}

sub process_one($;$$$) {
	my($self, $read, $write, $error) = @_;

	if($error) {
		$self->{sockerr} = 1;
		return $self->disconnect();
	}

	if($read) {
		my $newsock;
		if($self->{socks}) {
			$newsock = $self->{socks}->accept();
		} else {
			$newsock = gensym;
			accept($newsock, $self->{socket});
		}

		my $connection = $self->{session}->addconn(conntype => CONNTYPE_DIRECT_OUT, description => "direct connection", state => "read", dcstate => Net::OSCAR::Connection::Direct::STATE_EXPECTING_HEADER, socket => $newsock);
		$connection->set_blocking(0);
	} else {
		$self->log_print(OSCAR_DBG_DEBUG, "Listener got write notification...");
		$self->disconnect() if time() >= $self->{last_activity}+30*60;
	}
}

1;
