package Net::OSCAR::Screenname;

$VERSION = 0.25;

use strict;
use vars qw($VERSION);

use Net::OSCAR::Common qw(normalize);
use Net::OSCAR::OldPerl;

use overload
	"cmp" => "compare",
	'""' => "stringify";

sub new($$) {
	return $_[1] if ref($_[0]);
	my $class = ref($_[0]) || $_[0] || "Net::OSCAR::Screenname";
	shift;
	my $name = shift;
	my $self = \$name;
	bless $self, $class;
	return $self;
}

sub compare {
	my($self, $comparand) = @_;

	return normalize($$self) cmp normalize($comparand);
}

sub stringify { my $self = shift; return $$self; }

1;
