# Perl 5.005 apparently has a problem with 'use constant' subs not being
# recognized properly, so we add some gunk to force perl to recognize them as subs.
# Also, the n/a* template was added to unpack in 5.6, so we roll our own version of
# that.  It also seems to have weird issues with four-argument substr.

package Net::OSCAR::OldPerl;

use Filter::Util::Call;
use strict;

sub slash_unpack ($$) {
	return unpack($_[0], $_[1]) unless $_[0] =~ m!/!;
	my($template, $expr) = @_;
	my $offset = 0;
	#print "Called unpack($template, ".Net::OSCAR::Common::hexdump(substr($expr, 0, 16)).")\n";
	my @ret = ();
	my %lengths = (
		C => 1,
		c => 1,
		x => 1,
		n => 2,
		N => 4,
		a => 1,
		A => 1
	);

	while($template =~ m!([cCnN]/)?([aAcCnNx])(\d*|\*)!g) {
		my($lengthtype, $type, $repeats) = ($1, $2, $3);
		$repeats ||= 1;
		my $length = $lengths{$type};
		#print "\tGot ($lengthtype, $type, $repeats)\n";
		if($lengthtype) {
			chop $lengthtype;
			#print "\t\tDecoding ".Net::OSCAR::Common::hexdump(substr($expr, $offset, $lengths{$lengthtype}))."...\n";
			($repeats) = unpack($lengthtype, substr($expr, $offset, $lengths{$lengthtype}));
			#print "\t\tRepeats $repeats\n";
			if($repeats == 0) {
				push @ret, "";
				next;
			}
			$offset += $lengths{$lengthtype};
		}

		#print "\tCalling unpack($type$repeats, ".Net::OSCAR::Common::hexdump(substr($expr, $offset, $length*$repeats)).")\n";
		push @ret, unpack($type.$repeats, substr($expr, $offset, $length*$repeats));
		$offset += $length*$repeats;
	}
	#print "Returning (", join(",", map { "\"$_\"" } @ret), ")\n";
	return @ret;
}

sub my_substr($$$$) {
	my($expr, $offset, $length, $replacement) = @_;
	my $ret = substr($$expr, $offset, $length);
	substr($$expr, $offset, $length) = $replacement;
	return $ret;
}

sub import {
	my($type, @arguments) = @_;
	my(@constants) = ();

	return if $] > 5.006;

	open(OSCARCOMMON, $INC{"Net/OSCAR/Common.pm"});
	while(<OSCARCOMMON>) {
		next unless /use constant (.+?) =>/;
		push @constants, $1;
	}
	close OSCARCOMMON;

	filter_add(
		sub {
			my($status);
			$status = filter_read();

			s!unpack(\s*\("[^"]*/)!Net::OSCAR::OldPerl::slash_unpack$1!;
			s!substr\s*\(([^,]+),([^,]+),([^,]+),([^)]+)\)!Net::OSCAR::OldPerl::my_substr(\\$1, $2, $3, $4)!;

			foreach my $constant(@constants) {
				s/(?!&)$constant(?![a-zA-Z_])(?!\(\))/&$constant()/g;
			}

			$status;
		}
	);
}

1;
