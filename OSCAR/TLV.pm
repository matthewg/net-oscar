package Net::OSCAR::TLV;

$VERSION = 0.50;

use strict;
use vars qw($VERSION);

# Extra arguments: an optional scalar which modifies the behavior of $self->{foo}->{bar} = "baz"
# Iff foo doesn't exist, the scalar will be evaluated and assigned as the value of foo.
# So, instead of having foo be {bar => "baz"} , it could be another TLV.
# It will be given the key bar.
sub new {
	my $pkg = shift;
	my $self = $pkg->TIEHASH(@_);
}


sub getorder {
	my $self = shift;
	return map { (unpack("n", $_))[0] } @{$self->{ORDER}};
}

sub setorder {
	my $self = shift;

	# Anything not specified gets shoved at the end
	my @end = grep { my $inbud = $_; not grep { $_ eq $inbud } @_ } @{$self->{ORDER}};

	@{$self->{ORDER}} = map { pack("n", $_) } @_;
	push @{$self->{ORDER}}, @end;
}

sub TIEHASH {
	my $class = shift;
	my $self = { DATA => {}, ORDER => [], CURRKEY => -1, AUTOVIVIFY => shift};
	return bless $self, $class;
}

sub FETCH {
	my($self, $key) = @_;
	$self->{DATA}->{pack("n", $key)};
}

sub STORE {
	my($self, $key, $value) = @_;
	my($normalkey) = pack("n", $key);

	#print STDERR "Storing: ", Data::Dumper->Dump([$value], ["${self}->{$key}"]);
	if(!exists $self->{DATA}->{$normalkey}) {
		if(
			$self->{AUTOVIVIFY} and
			ref($value) eq "HASH" and
			!tied(%$value) and
			scalar keys %$value == 0
		) {
			#print STDERR "Autovivifying $key: $self->{AUTOVIVIFY}\n";
			eval $self->{AUTOVIVIFY};
			#print STDERR "New value: ", Data::Dumper->Dump([$self->{DATA}->{$normalkey}], ["${self}->{$key}"]);
		} else {
			#print STDERR "Not autovivifying $key.\n";
			#print STDERR "No autovivify.\n" unless $self->{AUTOVIVIFY};
			#printf STDERR "ref(\$value) eq %s\n", ref($value) unless ref($value) eq "HASH";
			#print STDERR "tied(\%\$value)\n" unless !tied(%$value);
			#printf STDERR "scalar keys \%\$value == %d\n", scalar keys %$value unless scalar keys %$value == 0;
		}
		push @{$self->{ORDER}}, $normalkey;
	} else {
		#print STDERR "Not autovivifying $key: already exists\n";
	}
	$self->{DATA}->{$normalkey} = $value;
	return $value;
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
