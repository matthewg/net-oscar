package Net::OSCAR::Buddylist;

$VERSION = 0.05;

use strict;
use vars qw($VERSION);
use warnings;
use Net::OSCAR::Common qw(:all);

sub new {
	my $pkg = shift;
	$pkg->TIEHASH(@_);
}


sub TIEHASH {
	my $class = shift;
	my $self = { DATA => {}, ORDERFORM => [], CURRKEY => -1};
	return bless $self, $class;
}

sub FETCH {
	my($self, $key) = @_;
	$self->{DATA}->{normalize($key)};
}

sub STORE {
	my($self, $key, $value) = @_;
	if(exists $self->{DATA}->{normalize($key)}) {
		foreach my $buddy(@{$self->{ORDERFORM}}) {
			next if normalize($buddy) ne normalize($value);
			$buddy = $value;
			return $value;
		}
	}
	push @{$self->{ORDERFORM}}, $key;
	$self->{DATA}->{normalize($key)} = $value;
}

sub DELETE {
	my($self, $key) = @_;
	my($normalkey) = normalize($key);
	delete $self->{DATA}->{$normalkey};
	for(my $i = 0; $i < scalar @{$self->{ORDERFORM}}; $i++) {
		next unless $normalkey eq normalize($self->{ORDERFORM}->[$i]);
		splice(@{$self->{ORDERFORM}}, $i, 1);
		last;
	}
}

sub CLEAR {
	my $self = shift;
	$self->{DATA} = {};
	$self->{ORDERFORM} = [];
	$self->{CURRKEY} = -1;
	return $self;
}

sub EXISTS {
	my($self, $key) = @_;
	my($normalkey) = normalize($key);
	return exists $self->{DATA}->{$normalkey};
}

sub FIRSTKEY {
	$_[0]->{CURRKEY} = -1;
	goto &NEXTKEY;
}

sub NEXTKEY {
	my ($self, $currkey) = @_;
	$currkey = ++$self->{CURRKEY};

	if($currkey >= scalar @{$self->{ORDERFORM}}) {
		return wantarray ? () : undef;
	} else {
		my $key = $self->{ORDERFORM}->[$currkey];
		my $normalkey = normalize($key);
		return wantarray ? ($key, $self->{DATA}->{$normalkey}) : $key;
	}
}

1;
