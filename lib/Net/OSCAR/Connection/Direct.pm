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
@ISA = qw(Net::OSCAR::Connection);

sub new($@) {
	my $self = shift->SUPER::new(@_);

	$self->{listening} = 0;
	return $self;
}

sub listen($$) {
	my($self, $port) = @_;
	my $temp;

	$self->{host} = "0.0.0.0";
	$self->{port} = $port;

	$self->log_print(OSCAR_DBG_NOTICE, "Listening.");
	if(defined($self->{session}->{proxy_type})) {
		die "Proxying not support for listening sockets.\n";
	} else {
		$self->{socket} = gensym;
		socket($self->{socket}, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

		setsockopt($self->{socket}, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or return $self->{session}->crapout($self, "Couldn't set listen socket options: $!");
		
		my($port, $iaddr) = sockaddr_in(0, inet_aton($self->{session}->{local_ip} || 0));
		bind($self->{socket}, $port, $iaddr) or return $self->{session}->crapout("Couldn't bind to desired IP: $!");
		$self->set_blocking(0);
		listen($self->{socket}, SOMAXCONN) or return $self->{session}->crapout("Couldn't listen: $!");
		$self->{state} = "read";
		$self->{listening} = 1;

		my $addr = inet_aton($host) or return $self->{session}->crapout($self, "Couldn't resolve $host.");
		if(!connect($self->{socket}, sockaddr_in($port, $addr))) {
			return 1 if $! == EINPROGRESS;
			return $self->{session}->crapout($self, "Couldn't connect to $host:$port: $!");
		}

		$self->{ready} = 0;
		$self->{connected} = 0;
	}

	return 1;
}

sub process_one($;$$$) {
	my($self, $read, $write, $error) = @_;
	my $snac;

	if($error) {
		$self->{sockerr} = 1;
		return $self->disconnect();
	}

	$read ||= 1;
	$write ||= 1;

	if($read && $self->{listening}) {
		my $newsock = gensym();

		if(accept($newsock, $self->{socket})) {
			$self->{session}->callback_connection_changed($self, "deleted");
			close($self->{socket});
			$self->{socket} = $newsock;
			$self->blocking(0);

			# Now, the person who's sending the file must send OFT header...
		} else {
			return 0;
		}
	}
}

1;
