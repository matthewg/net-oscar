package Net::OSCAR::TLV;

$VERSION = 0.01;

use strict;
use vars qw($VERSION);
use warnings;

sub new {
	my $pkg = shift;
	$pkg->TIEHASH(@_);
}


sub TIEHASH {
	my $class = shift;
	my $self = { DATA => {}, ORDER => [], CURRKEY => -1};
	return bless $self, $class;
}

sub FETCH {
	my($self, $key) = @_;
	$self->{DATA}->{pack("n", $key)};
}

sub STORE {
	my($self, $key, $value) = @_;
	return $self->{DATA}->{pack("n", $key)} = $value if exists $self->{DATA}->{pack("n", $key)};
	push @{$self->{ORDER}}, pack("n", $key);
	$self->{DATA}->{pack("n", $key)} = $value;
}

sub DELETE {
	my($self, $key) = @_;
	my($packedkey) = pack("n", $key);
	delete $self->{DATA}->{$packedkey};
	for(my $i = 0; $i < scalar @{$self->{ORDER}}; $i++) {
		next unless $packedkey eq $self->{ORDER}->[$i];
		splice(@{$self->{ORDER}}, $i, 1);
		last;
	}
}

sub CLEAR {
	my $self = shift;
	$self->{DATA} = {};
	$self->{ORDER} = [];
	$self->{CURRKEY} = -1;
	return $self;
}

sub EXISTS {
	my($self, $key) = @_;
	my($packedkey) = pack("n", $key);
	return exists $self->{DATA}->{$packedkey};
}

sub FIRSTKEY {
	$_[0]->{CURRKEY} = -1;
	goto &NEXTKEY;
}

sub NEXTKEY {
	my ($self, $currkey) = @_;
	$currkey = ++$self->{CURRKEY};
	my ($packedkey) = pack("n", $currkey);

	if($currkey >= scalar @{$self->{ORDER}}) {
		return wantarray ? () : undef;
	} else {
		my $packedkey = $self->{ORDER}->[$currkey];
		($currkey) = unpack("n", $packedkey);
		return wantarray ? ($currkey, $self->{DATA}->{$packedkey}) : $currkey;
	}
}

1;
