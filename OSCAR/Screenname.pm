package Net::OSCAR::Screenname;

$VERSION = 0.09;

use strict;
use vars qw($VERSION);
use warnings;

use Net::OSCAR::Common qw(normalize);

use overload
	"cmp" => "compare",
	'""' => "stringify";

sub new($$) {
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
