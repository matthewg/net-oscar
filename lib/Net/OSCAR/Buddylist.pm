package Net::OSCAR::Buddylist;

$VERSION = 0.07;

use strict;
use vars qw($VERSION);
use warnings;

use Carp;
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
	my($normalkey) = normalize($key);
	if(exists $self->{DATA}->{$normalkey}) {
		my $foo = 0;
		for(my $i = 0; $i < scalar @{$self->{ORDERFORM}}; $i++) {
			next unless $normalkey eq normalize($self->{ORDERFORM}->[$i]);
			$foo = 1;
			$self->{ORDERFORM}->[$i] = $key;
			last;
		}
	} else {
		push @{$self->{ORDERFORM}}, $key;
	}
	$self->{DATA}->{$normalkey} = $value;
}

sub DELETE {
	my($self, $key) = @_;
	my($normalkey) = normalize($key);
	my $retval = delete $self->{DATA}->{$normalkey};
	my $foo = 0;
	for(my $i = 0; $i < scalar @{$self->{ORDERFORM}}; $i++) {
		next unless $normalkey eq normalize($self->{ORDERFORM}->[$i]);
		$foo = 1;
		splice(@{$self->{ORDERFORM}}, $i, 1);
		last;
	}
	return $retval;
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
	return exists $self->{DATA}->{normalize($key)};
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
